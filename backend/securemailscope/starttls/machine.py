"""
STARTTLS detection and state machine.
Tracks transition from plaintext to TLS.
"""
from enum import Enum, auto
from typing import Optional, Dict
from dataclasses import dataclass
import re

from securemailscope.protocols.detector import EmailProtocol

class TLSState(Enum):
    PLAINTEXT = auto()
    STARTTLS_REQUESTED = auto()
    STARTTLS_ACCEPTED = auto()
    STARTTLS_REJECTED = auto()
    TLS_HANDSHAKE_STARTED = auto()
    TLS_ESTABLISHED = auto()

@dataclass
class StartTLSState:
    current_state: TLSState
    protocol: EmailProtocol
    starttls_command_seen: bool = False
    server_response_seen: bool = False
    tls_handshake_seen: bool = False
    anomalies: set = None

    def __post_init__(self):
        if self.anomalies is None:
            self.anomalies = set()


class StartTLSMachine:
    """State machine for tracking STARTTLS transitions across protocols."""

    # Protocol specific successful STARTTLS responses
    SMTP_READY = re.compile(r"^220(?:[ -].*)?")
    IMAP_READY = re.compile(r"^[a-zA-Z0-9]+\s+OK(?:.*)?")
    POP3_READY = re.compile(r"^\+OK(?:.*)?")

    # Rejection patterns
    SMTP_REJECT = re.compile(r"^5\d\d")
    IMAP_REJECT = re.compile(r"^[a-zA-Z0-9]+\s+(?:NO|BAD)")
    POP3_REJECT = re.compile(r"^-ERR")

    def __init__(self, protocol: EmailProtocol):
        self.state = StartTLSState(
            current_state=TLSState.PLAINTEXT,
            protocol=protocol
        )
        self.is_implicit_tls = False

    def mark_implicit_tls(self) -> None:
        """Mark as implicit TLS (traffic starts encrypted immediately, no STARTTLS negotiation)."""
        self.is_implicit_tls = True
        self.state.current_state = TLSState.TLS_HANDSHAKE_STARTED
        self.state.tls_handshake_seen = True

    def process_payload(self, text: str, is_from_client: bool) -> TLSState:
        """Process application layer text to track the STARTTLS state."""
        # Clean up any trailing bytes/newlines for easy regex matching
        text_lines = text.strip().split('\r\n')
        if not text_lines:
            return self.state.current_state

        first_line = text_lines[0]

        if self.state.current_state == TLSState.PLAINTEXT:
            if is_from_client:
                # Watch for STARTTLS command from client
                self._check_starttls_command(first_line)
        elif self.state.current_state == TLSState.STARTTLS_REQUESTED:
            if not is_from_client:
                # Watch for server's response to STARTTLS
                self._check_starttls_response(first_line)
            else:
                # Client speaking after requesting but before server replies (pipelining)
                # Technically allowed in SMTP but often a security posture issue (pipeline injection)
                pass
        elif self.state.current_state == TLSState.STARTTLS_ACCEPTED:
            # Reached TLS start state. Next payload should be TLS Handshake (binary)
            pass

        return self.state.current_state

    def process_binary(self, payload: bytes) -> TLSState:
        """Detect TLS Handshake beginning."""
        if not payload:
            return self.state.current_state

        # Check for TLS Handshake Record (Content Type 22, Handshake Type 1 'Client Hello')
        # Format: [22] [Version:2] [Length:2] [Handshake Type:1]
        if len(payload) >= 6 and payload[0] == 22:
            self.state.tls_handshake_seen = True

            if self.state.current_state == TLSState.STARTTLS_ACCEPTED or self.is_implicit_tls:
                self.state.current_state = TLSState.TLS_HANDSHAKE_STARTED
            else:
                # We saw a TLS handshake but we were not in an accepted state
                self.state.anomalies.add("unexpected_tls_handshake")
                self.state.current_state = TLSState.TLS_HANDSHAKE_STARTED

        # Check for TLS Application Data (Content Type 23)
        elif len(payload) >= 5 and payload[0] == 23:
            if self.state.current_state == TLSState.TLS_HANDSHAKE_STARTED:
                self.state.current_state = TLSState.TLS_ESTABLISHED

        return self.state.current_state

    def _check_starttls_command(self, line: str) -> None:
        """Check if client issued a STARTTLS/STLS command."""
        upper_line = line.upper()
        is_starttls = False

        if self.state.protocol == EmailProtocol.SMTP:
            is_starttls = upper_line.startswith("STARTTLS")
        elif self.state.protocol == EmailProtocol.IMAP:
            # IMAP commands are tagged, e.g., 'a001 STARTTLS'
            parts = upper_line.split()
            if len(parts) >= 2 and parts[1] == "STARTTLS":
                is_starttls = True
        elif self.state.protocol == EmailProtocol.POP3:
            is_starttls = upper_line.startswith("STLS")

        if is_starttls:
            self.state.starttls_command_seen = True
            self.state.current_state = TLSState.STARTTLS_REQUESTED

    def _check_starttls_response(self, line: str) -> None:
        """Evaluate the server's response to the STARTTLS command."""
        self.state.server_response_seen = True

        if self.state.protocol == EmailProtocol.SMTP:
            if self.SMTP_READY.match(line):
                self.state.current_state = TLSState.STARTTLS_ACCEPTED
            elif self.SMTP_REJECT.match(line):
                self.state.current_state = TLSState.STARTTLS_REJECTED

        elif self.state.protocol == EmailProtocol.IMAP:
            if self.IMAP_READY.match(line):
                self.state.current_state = TLSState.STARTTLS_ACCEPTED
            elif self.IMAP_REJECT.match(line):
                self.state.current_state = TLSState.STARTTLS_REJECTED

        elif self.state.protocol == EmailProtocol.POP3:
            if self.POP3_READY.match(line):
                self.state.current_state = TLSState.STARTTLS_ACCEPTED
            elif self.POP3_REJECT.match(line):
                self.state.current_state = TLSState.STARTTLS_REJECTED
