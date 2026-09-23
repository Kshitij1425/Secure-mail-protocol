"""
Protocol Detection Module for SecureMailScope
Detects SMTP, IMAP, and POP3 from observed network traffic.
Uses multi-signal detection: well-known ports, banners, command/response signatures.
"""
from enum import Enum, auto
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import re

class EmailProtocol(Enum):
    SMTP = auto()
    IMAP = auto()
    POP3 = auto()
    UNKNOWN = auto()

@dataclass
class ProtocolDetection:
    protocol: EmailProtocol
    confidence: float  # 0.0 to 1.0
    detection_method: str  # "port+banner", "port+commands", "banner_only", etc.
    banner_text: Optional[str] = None
    first_command: Optional[str] = None
    port: Optional[int] = None

class ProtocolDetector:
    """Multi-signal detector for email protocols."""

    # Well-known ports (but we don't rely solely on them)
    SMTP_PORTS = {25, 587, 465, 2525}
    IMAP_PORTS = {143, 993, 2222}
    POP3_PORTS = {110, 995, 2220}

    # Banner signatures
    SMTP_BANNERS = [
        r"220[\s\S]*[\w\.-]+[\s\S]*E?SMTP",
        r"220.*SMTP.*ready",
        r"220\s+\S+.*SMTP",
    ]
    IMAP_BANNERS = [
        r"\*\s+OK.*IMAP",
        r"\*\s+OK.*ready",
        r"\*\s+CAPABILITY\s+IMAP4",
    ]
    POP3_BANNERS = [
        r"\+OK.*POP3",
        r"\+OK.*pop3",
        r"\+OK.*ready",
    ]

    # Command signatures (plaintext, pre-STARTTLS)
    SMTP_COMMANDS = [
        r"^EHLO\s",
        r"^HELO\s",
        r"^MAIL FROM:",
        r"^RCPT TO:",
        r"^QUIT",
        r"^STARTTLS",
    ]
    IMAP_COMMANDS = [
        r"^[A-Za-z0-9]+\s+CAPABILITY",
        r"^[A-Za-z0-9]+\s+LOGIN",
        r"^[A-Za-z0-9]+\s+SELECT",
        r"^[A-Za-z0-9]+\s+STARTTLS",
    ]
    POP3_COMMANDS = [
        r"^USER\s",
        r"^PASS\s",
        r"^RETR\s",
        r"^STLS\s",
        r"^CAPA",
    ]

    def __init__(self):
        pass

    def detect(self, payload: bytes, port: int = 0, src_port: int = 0) -> ProtocolDetection:
        """Detect protocol from payload bytes and port information."""
        text = payload.decode('latin-1', errors='ignore')

        # Try banner detection (first line of server greeting)
        first_lines = text.strip().split('\r\n')[:3]
        banner = '\r\n'.join(first_lines) if first_lines else text[:256]

        # Score all three protocols, pick best candidate.
        # Threshold: >0.35 (banner hit alone) or >0.6 (port only).
        # This allows non-standard-port detection when the banner is unambiguous.
        smtp_score = self._check_smtp(text, banner, port)
        imap_score = self._check_imap(text, banner, port)
        pop3_score = self._check_pop3(text, banner, port)

        best_score = max(smtp_score, imap_score, pop3_score)

        # Require banner evidence (score > 0.35) even on non-standard ports.
        # With port match the threshold can be 0.4 (port alone).
        if best_score > 0.35:
            if smtp_score == best_score:
                method = "port+banner" if port in self.SMTP_PORTS else "banner_only"
                return ProtocolDetection(
                    protocol=EmailProtocol.SMTP,
                    confidence=round(smtp_score, 2),
                    detection_method=method,
                    banner_text=banner[:256],
                    port=port
                )
            if imap_score == best_score:
                method = "port+banner" if port in self.IMAP_PORTS else "banner_only"
                return ProtocolDetection(
                    protocol=EmailProtocol.IMAP,
                    confidence=round(imap_score, 2),
                    detection_method=method,
                    banner_text=banner[:256],
                    port=port
                )
            if pop3_score == best_score:
                method = "port+banner" if port in self.POP3_PORTS else "banner_only"
                return ProtocolDetection(
                    protocol=EmailProtocol.POP3,
                    confidence=round(pop3_score, 2),
                    detection_method=method,
                    banner_text=banner[:256],
                    port=port
                )

        # Fallback to port-based detection
        if port in self.SMTP_PORTS:
            return ProtocolDetection(
                protocol=EmailProtocol.SMTP,
                confidence=0.6,
                detection_method="port_only",
                banner_text=banner[:256],
                port=port
            )
        if port in self.IMAP_PORTS:
            return ProtocolDetection(
                protocol=EmailProtocol.IMAP,
                confidence=0.6,
                detection_method="port_only",
                banner_text=banner[:256],
                port=port
            )
        if port in self.POP3_PORTS:
            return ProtocolDetection(
                protocol=EmailProtocol.POP3,
                confidence=0.6,
                detection_method="port_only",
                banner_text=banner[:256],
                port=port
            )

        return ProtocolDetection(
            protocol=EmailProtocol.UNKNOWN,
            confidence=0.0,
            detection_method="none",
            banner_text=banner[:256],
            port=port
        )

    def _check_smtp(self, text: str, banner: str, port: int) -> float:
        score = 0.0
        if port in self.SMTP_PORTS:
            score += 0.4
        if any(re.search(p, banner) for p in self.SMTP_BANNERS):
            score += 0.45
        if any(re.search(p, text.split('\r\n')[0]) for p in self.SMTP_COMMANDS):
            score += 0.15
        return min(score, 1.0)

    def _check_imap(self, text: str, banner: str, port: int) -> float:
        score = 0.0
        if port in self.IMAP_PORTS:
            score += 0.4
        if any(re.search(p, banner) for p in self.IMAP_BANNERS):
            score += 0.45
        if any(re.search(p, text.split('\r\n')[0]) for p in self.IMAP_COMMANDS):
            score += 0.15
        return min(score, 1.0)

    def _check_pop3(self, text: str, banner: str, port: int) -> float:
        score = 0.0
        if port in self.POP3_PORTS:
            score += 0.4
        if any(re.search(p, banner, re.IGNORECASE) for p in self.POP3_BANNERS):
            score += 0.45
        if any(re.search(p, text.split('\r\n')[0]) for p in self.POP3_COMMANDS):
            score += 0.15
        return min(score, 1.0)
