"""
Protocol Detection Module for SecureMailScope.

Detects SMTP, IMAP and POP3 from observed traffic using independent signals:
well-known server port, server greeting (banner), client command syntax, and
implicit-TLS (a TLS record as the very first bytes on 465/993/995).

Only a bounded prefix of the payload is inspected (``MAX_INSPECT_BYTES``), and all
regular expressions are anchored and linear, so hostile payloads cannot cause
catastrophic backtracking.
"""
from enum import Enum, auto
from typing import Optional
from dataclasses import dataclass
import re

MAX_INSPECT_BYTES = 2048


class EmailProtocol(Enum):
    SMTP = auto()
    IMAP = auto()
    POP3 = auto()
    UNKNOWN = auto()


@dataclass
class ProtocolDetection:
    protocol: EmailProtocol
    confidence: float  # 0.0 to 1.0
    detection_method: str  # port+banner | banner_only | port_only | implicit_tls_port | none | non_email
    banner_text: Optional[str] = None
    first_command: Optional[str] = None
    port: Optional[int] = None
    implicit_tls: bool = False


def looks_like_tls_record(data: bytes) -> bool:
    """True if ``data`` starts with a TLS handshake record or an SSLv2 ClientHello."""
    if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03 and data[2] <= 0x04:
        return True
    return len(data) >= 3 and bool(data[0] & 0x80) and data[2] == 0x01


class ProtocolDetector:
    """Multi-signal detector for email protocols."""

    SMTP_PORTS = {25, 587, 465, 2525}
    IMAP_PORTS = {143, 993}
    POP3_PORTS = {110, 995}
    IMPLICIT_TLS_PORTS = {465: EmailProtocol.SMTP, 993: EmailProtocol.IMAP, 995: EmailProtocol.POP3}

    SMTP_BANNERS = [re.compile(p, re.I | re.M) for p in (
        r"^220[ -][^\r\n]{0,256}\bE?SMTP\b",
        r"^220[ -][^\r\n]{0,256}\b(?:mail|mx|smtp|postfix|exim|sendmail|exchange)\b",
    )]
    IMAP_BANNERS = [re.compile(p, re.I | re.M) for p in (
        r"^\* (?:OK|PREAUTH)[^\r\n]{0,256}\bIMAP4",
        r"^\* OK[^\r\n]{0,256}\b(?:ready|dovecot|cyrus|courier)\b",
        r"^\* CAPABILITY IMAP4",
    )]
    POP3_BANNERS = [re.compile(p, re.I | re.M) for p in (
        r"^\+OK[^\r\n]{0,256}\bPOP3?\b",
        r"^\+OK[^\r\n]{0,256}\b(?:ready|dovecot|server)\b",
    )]

    SMTP_COMMANDS = re.compile(r"^(?:EHLO|HELO|MAIL FROM:|RCPT TO:|QUIT|STARTTLS|AUTH)\b", re.I | re.M)
    IMAP_COMMANDS = re.compile(r"^[A-Za-z0-9.]{1,32} (?:CAPABILITY|LOGIN|SELECT|STARTTLS|AUTHENTICATE|LOGOUT)\b",
                               re.I | re.M)
    POP3_COMMANDS = re.compile(r"^(?:USER|PASS|RETR|STLS|CAPA|APOP|STAT|LIST)\b", re.I | re.M)

    # Well-known non-email protocol greetings / requests.
    NON_EMAIL = re.compile(rb"^(?:SSH-\d|HTTP/\d|GET |POST |PUT |HEAD |OPTIONS |CONNECT |RFB \d|\xff[\xfb-\xfe])")

    def __init__(self):
        pass

    def detect(self, payload: bytes, port: int = 0, src_port: int = 0,
               client_payload: Optional[bytes] = None) -> ProtocolDetection:
        """Detect the protocol.

        ``payload`` is server-to-client data (or both directions concatenated for
        legacy callers); ``client_payload`` optionally carries client data.
        """
        server = (payload or b"")[:MAX_INSPECT_BYTES]
        client = (client_payload or b"")[:MAX_INSPECT_BYTES]

        if self.NON_EMAIL.match(server) or self.NON_EMAIL.match(client):
            return ProtocolDetection(EmailProtocol.UNKNOWN, 0.0, "non_email", port=port)

        if looks_like_tls_record(server) or looks_like_tls_record(client):
            proto = self.IMPLICIT_TLS_PORTS.get(port)
            if proto is not None:
                return ProtocolDetection(proto, 0.8, "implicit_tls_port", port=port, implicit_tls=True)
            return ProtocolDetection(EmailProtocol.UNKNOWN, 0.0, "tls_non_email_port", port=port)

        text = server.decode("latin-1")
        ctext = client.decode("latin-1")
        banner = "\r\n".join(text.strip().split("\r\n")[:3])[:256]

        scores = {
            EmailProtocol.SMTP: self._score(text, ctext, port, self.SMTP_PORTS, self.SMTP_BANNERS, self.SMTP_COMMANDS),
            EmailProtocol.IMAP: self._score(text, ctext, port, self.IMAP_PORTS, self.IMAP_BANNERS, self.IMAP_COMMANDS),
            EmailProtocol.POP3: self._score(text, ctext, port, self.POP3_PORTS, self.POP3_BANNERS, self.POP3_COMMANDS),
        }
        best = max(scores, key=lambda p: scores[p])
        best_score = scores[best]
        ports = {EmailProtocol.SMTP: self.SMTP_PORTS, EmailProtocol.IMAP: self.IMAP_PORTS,
                 EmailProtocol.POP3: self.POP3_PORTS}

        if best_score > 0.35:
            method = "port+banner" if port in ports[best] else "banner_only"
            return ProtocolDetection(best, round(best_score, 2), method, banner_text=banner, port=port)

        for proto, proto_ports in ports.items():
            if port in proto_ports and (server or client):
                return ProtocolDetection(proto, 0.6, "port_only", banner_text=banner, port=port)

        return ProtocolDetection(EmailProtocol.UNKNOWN, 0.0, "none", banner_text=banner, port=port)

    @staticmethod
    def _score(text: str, ctext: str, port: int, ports, banners, commands) -> float:
        score = 0.4 if port in ports else 0.0
        if any(p.search(text) for p in banners):
            score += 0.45
        if commands.search(ctext) or commands.search(text.split("\r\n", 1)[0] if text else ""):
            score += 0.15
        # Legacy callers pass both directions concatenated in ``payload``.
        elif not ctext and commands.search(text):
            score += 0.15
        return min(score, 1.0)
