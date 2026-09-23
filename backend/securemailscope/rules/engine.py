"""
Deterministic Cryptographic Security Policy Engine for SecureMailScope.
Evaluates observed protocol, TLS, and certificate evidence against policy rules.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from securemailscope.protocols.detector import EmailProtocol
from securemailscope.starttls.machine import TLSState
from securemailscope.tls.parser import TLSSessionData
from securemailscope.certificates.analyzer import CertificateDetails

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class FindingResult:
    finding_id: str
    rule_id: str
    category: str
    title: str
    severity: Severity
    confidence: float
    description: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    standards_ref: str = ""
    session_id: str = ""  # M9: Track which session this finding belongs to

class SecurityPolicyEngine:
    """Evaluates mail session evidence against deterministic security rules."""

    DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
    WEAK_CIPHER_SUBSTRINGS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"]

    @classmethod
    def evaluate_session(
        cls,
        session_id: str,
        protocol: EmailProtocol,
        starttls_state: TLSState,
        tls_data: Optional[TLSSessionData],
        certs: List[CertificateDetails]
    ) -> List[FindingResult]:
        """Run all policy checks against a reconstructed session."""
        findings: List[FindingResult] = []

        # 1. Plaintext Email Check (No TLS at all)
        if starttls_state in {TLSState.PLAINTEXT, TLSState.STARTTLS_REJECTED} and (not tls_data or not tls_data.handshake_complete):
            findings.append(FindingResult(
                finding_id=f"{session_id}-PROTO-001",
                rule_id="PROTO-001",
                category="Protocol Security",
                title="Unencrypted Email Communication (Plaintext)",
                severity=Severity.CRITICAL,
                confidence=1.0,
                description=f"Observed {protocol.name} session communicated entirely in plaintext without establishing encryption.",
                recommendation="Enforce TLS encryption (STARTTLS or implicit TLS on standard secure ports).",
                evidence={"protocol": protocol.name, "state": starttls_state.name},
                standards_ref="RFC 8314 (Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access)",
                session_id=session_id
            ))

        # 2. STARTTLS Downgrade / Rejection
        if starttls_state == TLSState.STARTTLS_REJECTED:
            findings.append(FindingResult(
                finding_id=f"{session_id}-STLS-001",
                rule_id="STLS-001",
                category="STARTTLS Security",
                title="STARTTLS Negotiation Rejected (Potential Downgrade)",
                severity=Severity.HIGH,
                confidence=0.95,
                description="Client requested STARTTLS upgrade, but server rejected it, potentially indicating an active downgrade attack or misconfiguration.",
                recommendation="Configure mail server to properly advertise and accept STARTTLS upgrades; enforce Strict Transport Security (MTA-STS).",
                evidence={"protocol": protocol.name, "state": "STARTTLS_REJECTED"},
                standards_ref="RFC 3207 / RFC 8461 (MTA-STS)"
            ))

        # 3. TLS Protocol Checks
        if tls_data:
            # Check for Deprecated TLS Versions
            version = tls_data.server_version or tls_data.client_version
            if version in cls.DEPRECATED_TLS_VERSIONS:
                findings.append(FindingResult(
                    finding_id=f"{session_id}-TLS-001",
                    rule_id="TLS-001",
                    category="Cryptographic Posture",
                    title=f"Deprecated TLS Protocol Version In Use ({version})",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    description=f"The connection negotiated {version}, which is deprecated and contains known cryptographic vulnerabilities (e.g. POODLE, BEAST).",
                    recommendation="Disable SSLv3, TLS 1.0, and TLS 1.1 on mail servers. Enforce TLS 1.2 or TLS 1.3 as the minimum version.",
                    evidence={"negotiated_version": version},
                    standards_ref="RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)"
                ))

            # Check for Weak Ciphers
            cipher_name = tls_data.cipher_suite_name or ""
            if any(weak in cipher_name.upper() for weak in cls.WEAK_CIPHER_SUBSTRINGS):
                findings.append(FindingResult(
                    finding_id=f"{session_id}-TLS-003",
                    rule_id="TLS-003",
                    category="Cryptographic Posture",
                    title=f"Weak/Insecure Cipher Suite Negotiated ({cipher_name})",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    description=f"Negotiated cipher suite '{cipher_name}' uses legacy, broken, or export-grade primitives.",
                    recommendation="Remove broken ciphers (RC4, 3DES, CBC-mode ciphers without encrypt-then-mac) from the mail server cipher suite list.",
                    evidence={"cipher_suite": cipher_name},
                    standards_ref="NIST SP 800-52 Rev. 2"
                ))

            # Check Forward Secrecy
            if tls_data.server_version and not tls_data.has_forward_secrecy:
                findings.append(FindingResult(
                    finding_id=f"{session_id}-TLS-004",
                    rule_id="TLS-004",
                    category="Cryptographic Posture",
                    title="No Forward Secrecy in Key Exchange",
                    severity=Severity.MEDIUM,
                    confidence=1.0,
                    description="Negotiated cipher suite does not utilize Ephemeral Diffie-Hellman (DHE/ECDHE), meaning past recorded sessions can be decrypted if the private key is compromised later.",
                    recommendation="Configure mail server to prefer ECDHE or DHE key exchange algorithms.",
                    evidence={"cipher_suite": cipher_name, "has_forward_secrecy": False},
                    standards_ref="NIST SP 800-52 Rev. 2 / BSI TR-02102-2"
                ))

        # 4. X.509 Certificate Checks
        for cert in certs:
            if cert.is_expired:
                findings.append(FindingResult(
                    finding_id=f"{session_id}-CERT-001",
                    rule_id="CERT-001",
                    category="Certificate Security",
                    title="Expired X.509 Certificate In Use",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    description=f"Certificate for '{cert.subject}' expired on {cert.not_after.isoformat()}.",
                    recommendation="Renew the server certificate immediately using an automated ACME/Let's Encrypt or corporate CA workflow.",
                    evidence={"subject": cert.subject, "expired_on": cert.not_after.isoformat()},
                    standards_ref="RFC 5280"
                ))

            if cert.weak_key:
                findings.append(FindingResult(
                    finding_id=f"{session_id}-CERT-003",
                    rule_id="CERT-003",
                    category="Certificate Security",
                    title=f"Weak Public Key Size ({cert.public_key_algorithm} {cert.public_key_size_bits} bits)",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    description=f"The certificate uses a key size ({cert.public_key_size_bits} bits) below current industry standards (>= 2048-bit RSA or >= 256-bit ECC).",
                    recommendation="Generate new private keys with at least RSA 2048-bit (preferably 3072-bit/4096-bit) or ECDSA P-256 / P-384.",
                    evidence={"algo": cert.public_key_algorithm, "key_size": cert.public_key_size_bits},
                    standards_ref="NIST SP 800-57 Part 1 Rev. 5"
                ))

            if cert.weak_signature:
                findings.append(FindingResult(
                    finding_id=f"{session_id}-CERT-004",
                    rule_id="CERT-004",
                    category="Certificate Security",
                    title=f"Weak Certificate Signature Algorithm ({cert.signature_algorithm})",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    description=f"The certificate is signed using an obsolete/collision-vulnerable hash function ({cert.signature_algorithm}).",
                    recommendation="Re-issue certificate using SHA-256, SHA-384, or SHA-512 signatures.",
                    evidence={"signature_algo": cert.signature_algorithm},
                    standards_ref="RFC 6151 / CA/B Forum Baseline Requirements"
                ))

            if cert.is_self_signed:
                findings.append(FindingResult(
                    finding_id=f"{session_id}-CERT-005",
                    rule_id="CERT-005",
                    category="Certificate Security",
                    title="Self-Signed Certificate Detected",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    description=f"Certificate for '{cert.subject}' is self-signed and cannot be validated against public trust anchors by external mail servers (e.g. DANE/MTA-STS requirements).",
                    recommendation="Deploy a publicly-trusted certificate or ensure DANE TLSA records are configured in DNSSEC.",
                    evidence={"subject": cert.subject, "issuer": cert.issuer},
                    standards_ref="RFC 8461 (MTA-STS)"
                ))

        return findings
