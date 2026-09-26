"""
STARTTLS / STLS state machine.

Consumes the plaintext phase of an SMTP, IMAP or POP3 session line by line
(per direction, with partial lines carried across TCP chunks) and tracks:

* whether STARTTLS/STLS was advertised, requested, accepted or rejected,
* whether the client pipelined commands after STARTTLS (CVE-2011-0411 class
  command-injection indicator),
* plaintext authentication attempts (mechanism names only; credential values
  are never retained),
* plaintext mail transactions.

A STARTTLS command alone never implies TLS was established; that requires an
observed TLS handshake (see ``process_binary`` and the TLS parser).
"""
from enum import Enum, auto
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import re

from securemailscope.protocols.detector import EmailProtocol

MAX_LINE = 8192
MAX_LINES_PER_DIRECTION = 5000


class TLSState(Enum):
    PLAINTEXT = auto()
    STARTTLS_REQUESTED = auto()
    STARTTLS_ACCEPTED = auto()
    STARTTLS_REJECTED = auto()
    TLS_HANDSHAKE_STARTED = auto()
    TLS_ESTABLISHED = auto()
    TLS_FAILED = auto()


CLEARTEXT_AUTH = {"PLAIN", "LOGIN", "USER/PASS", "IMAP LOGIN"}


@dataclass
class StartTLSState:
    current_state: TLSState
    protocol: EmailProtocol
    starttls_command_seen: bool = False
    server_response_seen: bool = False
    tls_handshake_seen: bool = False
    anomalies: set = None
    starttls_advertised: Optional[bool] = None   # None = capability list not observed
    starttls_attempts: int = 0
    starttls_response: Optional[str] = None
    pipelined_after_starttls: bool = False
    plaintext_auth_mechanisms: List[str] = field(default_factory=list)
    plaintext_mail_transaction: bool = False
    plaintext_after_rejection: bool = False
    evidence_frames: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        if self.anomalies is None:
            self.anomalies = set()


class StartTLSMachine:
    """State machine for tracking STARTTLS transitions across protocols."""

    SMTP_READY = re.compile(r"^220(?:[ -]|$)")
    IMAP_READY = re.compile(r"^(?P<tag>[A-Za-z0-9.]+)\s+OK\b", re.I)
    POP3_READY = re.compile(r"^\+OK\b", re.I)

    SMTP_REJECT = re.compile(r"^[45]\d\d(?:[ -]|$)")
    IMAP_REJECT = re.compile(r"^(?P<tag>[A-Za-z0-9.]+)\s+(?:NO|BAD)\b", re.I)
    POP3_REJECT = re.compile(r"^-ERR\b", re.I)

    def __init__(self, protocol: EmailProtocol):
        self.state = StartTLSState(current_state=TLSState.PLAINTEXT, protocol=protocol)
        self.is_implicit_tls = False
        self._partial = {True: "", False: ""}
        self._lines_seen = {True: 0, False: 0}
        self._imap_tag: Optional[str] = None
        self._frame = 0

    def mark_implicit_tls(self) -> None:
        """Traffic is TLS from the first byte (465/993/995); there is no STARTTLS phase."""
        self.is_implicit_tls = True
        self.state.current_state = TLSState.TLS_HANDSHAKE_STARTED
        self.state.tls_handshake_seen = True

    # ------------------------------------------------------------ plaintext
    def process_payload(self, text: str, is_from_client: bool, frame: int = 0) -> TLSState:
        """Feed plaintext bytes (decoded latin-1) from one direction."""
        if not text:
            return self.state.current_state
        self._frame = frame
        data = self._partial[is_from_client] + text
        lines = data.split("\n")
        # The last element is an unterminated line (a command split across TCP
        # segments): keep it until the rest arrives or ``flush`` is called.
        tail = lines.pop()
        complete = [ln.rstrip("\r") for ln in lines]
        self._partial[is_from_client] = tail[:MAX_LINE]
        return self._process_lines(complete, is_from_client)

    def flush(self) -> TLSState:
        """End of stream: evaluate any unterminated trailing lines."""
        for side in (False, True):
            tail, self._partial[side] = self._partial[side], ""
            if tail.strip():
                self._process_lines([tail.rstrip("\r")], side)
        return self.state.current_state

    def _process_lines(self, complete: List[str], is_from_client: bool) -> TLSState:
        for idx, line in enumerate(complete):
            if self._lines_seen[is_from_client] >= MAX_LINES_PER_DIRECTION:
                break
            self._lines_seen[is_from_client] += 1
            line = line[:MAX_LINE]
            if is_from_client:
                self._client_line(line, remaining=complete[idx + 1:])
            else:
                self._server_line(line)
            if self.state.current_state in (TLSState.STARTTLS_ACCEPTED, TLSState.TLS_HANDSHAKE_STARTED):
                break
        return self.state.current_state

    def _client_line(self, line: str, remaining: List[str]) -> None:
        st = self.state
        upper = line.upper().strip()
        if not upper:
            return
        if st.current_state == TLSState.PLAINTEXT and self._is_starttls(upper):
            st.starttls_command_seen = True
            st.starttls_attempts += 1
            st.current_state = TLSState.STARTTLS_REQUESTED
            st.evidence_frames.setdefault("starttls_command", self._frame)
            if any(r.strip() for r in remaining):
                st.pipelined_after_starttls = True
                st.anomalies.add("pipelined_command_after_starttls")
            return
        if st.current_state == TLSState.STARTTLS_REQUESTED:
            if not self._is_starttls(upper):
                st.pipelined_after_starttls = True
                st.anomalies.add("pipelined_command_after_starttls")
            return
        if st.current_state == TLSState.STARTTLS_REJECTED:
            if self._is_starttls(upper):
                st.starttls_attempts += 1
                st.current_state = TLSState.STARTTLS_REQUESTED
                return
            st.plaintext_after_rejection = True
        if st.current_state in (TLSState.PLAINTEXT, TLSState.STARTTLS_REJECTED):
            self._track_plaintext_client(upper)

    def _server_line(self, line: str) -> None:
        st = self.state
        upper = line.upper()
        if st.current_state in (TLSState.PLAINTEXT, TLSState.STARTTLS_REJECTED):
            self._track_capabilities(upper)
        if st.current_state == TLSState.STARTTLS_REQUESTED:
            self._check_starttls_response(line)

    def _is_starttls(self, upper: str) -> bool:
        p = self.state.protocol
        if p == EmailProtocol.SMTP:
            return upper == "STARTTLS" or upper.startswith("STARTTLS ")
        if p == EmailProtocol.IMAP:
            parts = upper.split()
            if len(parts) >= 2 and parts[1] == "STARTTLS":
                self._imap_tag = parts[0]
                return True
            return False
        if p == EmailProtocol.POP3:
            return upper == "STLS" or upper.startswith("STLS ")
        return False

    def _track_capabilities(self, upper: str) -> None:
        st = self.state
        p = st.protocol
        if p == EmailProtocol.SMTP and upper[:4] in ("250-", "250 "):
            if st.starttls_advertised is None:
                st.starttls_advertised = False
            if upper[4:].strip() == "STARTTLS":
                st.starttls_advertised = True
        elif p == EmailProtocol.IMAP and "CAPABILITY" in upper:
            st.starttls_advertised = bool(st.starttls_advertised) or " STARTTLS" in upper
        elif p == EmailProtocol.POP3 and upper.strip() == "STLS":
            st.starttls_advertised = True

    def _track_plaintext_client(self, upper: str) -> None:
        st = self.state
        p = st.protocol
        mech = None
        if p == EmailProtocol.SMTP:
            if upper.startswith("AUTH "):
                parts = upper.split()
                mech = parts[1] if len(parts) > 1 else "UNKNOWN"
            elif upper.startswith("MAIL FROM:"):
                st.plaintext_mail_transaction = True
        elif p == EmailProtocol.POP3:
            if upper.startswith("USER ") or upper.startswith("PASS "):
                mech = "USER/PASS"
            elif upper.startswith("APOP "):
                mech = "APOP"
            elif upper.startswith("AUTH "):
                parts = upper.split()
                mech = parts[1] if len(parts) > 1 else "UNKNOWN"
            elif upper.startswith("RETR "):
                st.plaintext_mail_transaction = True
        elif p == EmailProtocol.IMAP:
            parts = upper.split()
            if len(parts) >= 2 and parts[1] == "LOGIN":
                mech = "IMAP LOGIN"
            elif len(parts) >= 3 and parts[1] == "AUTHENTICATE":
                mech = parts[2]
            elif len(parts) >= 2 and parts[1] in ("FETCH", "UID"):
                st.plaintext_mail_transaction = True
        if mech:
            mech = re.sub(r"[^A-Z0-9/ _-]", "", mech)[:32]
            if mech not in st.plaintext_auth_mechanisms:
                st.plaintext_auth_mechanisms.append(mech)
                st.evidence_frames.setdefault("plaintext_auth", self._frame)

    def _check_starttls_response(self, line: str) -> None:
        st = self.state
        p = st.protocol
        accepted = rejected = False
        if p == EmailProtocol.SMTP:
            if self.SMTP_READY.match(line):
                # Multi-line 220- continuation: wait for the final line.
                accepted = not line.startswith("220-")
                if not accepted:
                    return
            elif self.SMTP_REJECT.match(line):
                rejected = not line[3:4] == "-"
                if not rejected:
                    return
        elif p == EmailProtocol.IMAP:
            m = self.IMAP_READY.match(line)
            r = self.IMAP_REJECT.match(line)
            if line.startswith("*"):
                return  # untagged data, not the STARTTLS completion
            if m and (self._imap_tag is None or m.group("tag").upper() == self._imap_tag):
                accepted = True
            elif r and (self._imap_tag is None or r.group("tag").upper() == self._imap_tag):
                rejected = True
        elif p == EmailProtocol.POP3:
            accepted = bool(self.POP3_READY.match(line))
            rejected = bool(self.POP3_REJECT.match(line))
        if accepted or rejected:
            st.server_response_seen = True
            st.starttls_response = re.sub(r"[^\x20-\x7e]", "?", line[:128])
            st.evidence_frames.setdefault("starttls_response", self._frame)
            st.current_state = TLSState.STARTTLS_ACCEPTED if accepted else TLSState.STARTTLS_REJECTED

    # --------------------------------------------------------------- binary
    def process_binary(self, payload: bytes) -> TLSState:
        """Observe the first bytes of the TLS phase."""
        if not payload:
            return self.state.current_state
        st = self.state
        if len(payload) >= 3 and payload[0] == 22 and payload[1] == 3:
            st.tls_handshake_seen = True
            if st.current_state in (TLSState.STARTTLS_ACCEPTED, TLSState.TLS_HANDSHAKE_STARTED) or self.is_implicit_tls:
                st.current_state = TLSState.TLS_HANDSHAKE_STARTED
            else:
                st.anomalies.add("unexpected_tls_handshake")
                st.current_state = TLSState.TLS_HANDSHAKE_STARTED
        elif len(payload) >= 3 and payload[0] == 23 and payload[1] == 3:
            if st.current_state == TLSState.TLS_HANDSHAKE_STARTED:
                st.current_state = TLSState.TLS_ESTABLISHED
        return st.current_state

    def finalize(self, handshake_status: Optional[str]) -> TLSState:
        """Reconcile the final state with what the TLS parser actually observed."""
        st = self.state
        if st.current_state in (TLSState.TLS_HANDSHAKE_STARTED, TLSState.TLS_ESTABLISHED):
            if handshake_status == "complete":
                st.current_state = TLSState.TLS_ESTABLISHED
            elif handshake_status == "failed":
                st.current_state = TLSState.TLS_FAILED
            elif handshake_status in ("incomplete", "not_observed"):
                st.current_state = TLSState.TLS_HANDSHAKE_STARTED
        return st.current_state

    # Backwards-compatible single-line helpers
    def _check_starttls_command(self, line: str) -> None:
        self._client_line(line, [])
