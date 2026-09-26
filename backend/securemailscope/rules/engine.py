"""
Deterministic Cryptographic Security Policy Engine for SecureMailScope.

Every rule is declared once in ``RULE_CATALOGUE`` (id, category, scoring
dimension, severity, references, recommendation). ``evaluate_session`` turns the
evidence of one reconstructed email session into findings.

Evidence classes attached to every finding:

* ``OBSERVED``            directly visible in the capture
* ``INFERRED``            derived from observed values (e.g. forward secrecy from the suite)
* ``POTENTIAL_INDICATOR`` consistent with an attack or misconfiguration, not proof of one
* ``INSUFFICIENT_EVIDENCE`` the capture does not contain enough data to decide

Rules never fire on unknown values: a property that could not be observed
produces no finding rather than a pessimistic guess.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from securemailscope.protocols.detector import EmailProtocol
from securemailscope.starttls.machine import TLSState, CLEARTEXT_AUTH
from securemailscope.tls.parser import TLSSessionData
from securemailscope.tls.ciphers import classify_cipher, CipherInfo
from securemailscope.tls.cipher_registry import CIPHER_SUITE_NAMES
from securemailscope.certificates.analyzer import CertificateDetails, CertificateAnalyzer

POLICY_VERSION = "2.0"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    category: str
    dimension: str
    severity: Severity
    recommendation: str
    references: str
    false_positive_notes: str = ""


RULE_CATALOGUE: Dict[str, RuleDefinition] = {r.rule_id: r for r in [
    RuleDefinition("PROTO-001", "Unencrypted Email Communication (Plaintext)", "Protocol Security", "protocol",
                   Severity.CRITICAL,
                   "Require TLS for all mail submission/access (implicit TLS on 465/993/995 or mandatory STARTTLS); "
                   "reject plaintext sessions.",
                   "RFC 8314; NIST SP 800-177 Rev. 1",
                   "Captures that start after the TLS upgrade are not affected: TLS bytes are recognised."),
    RuleDefinition("PROTO-002", "Credentials Sent Over Unencrypted Channel", "Protocol Security", "protocol",
                   Severity.CRITICAL,
                   "Disable plaintext authentication before TLS (SMTP: advertise AUTH only after STARTTLS; "
                   "IMAP: LOGINDISABLED; POP3: require STLS).",
                   "RFC 8314 §4; RFC 3501 §6.2.3; RFC 2595",
                   "Only the mechanism name is recorded; credential values are never stored."),
    RuleDefinition("STLS-001", "STARTTLS Upgrade Rejected by Server", "STARTTLS Security", "starttls",
                   Severity.HIGH,
                   "Configure the server to accept STARTTLS; enforce TLS with MTA-STS (RFC 8461) or DANE (RFC 7672) "
                   "so that failures are not silently downgraded.",
                   "RFC 3207; RFC 8461; RFC 7672",
                   "A passive capture cannot distinguish a misconfigured server from an on-path downgrade."),
    RuleDefinition("STLS-002", "STARTTLS Requested but TLS Not Observed", "STARTTLS Security", "starttls",
                   Severity.INFO,
                   "Re-capture the full session; verify that the server completes STARTTLS.",
                   "RFC 3207",
                   "Usually a truncated capture. Informational: does not reduce the posture score."),
    RuleDefinition("STLS-003", "Commands Pipelined After STARTTLS", "STARTTLS Security", "starttls",
                   Severity.MEDIUM,
                   "Ensure the server discards buffered plaintext after STARTTLS (patched MTAs); "
                   "investigate the client.",
                   "CVE-2011-0411; RFC 3207 §4.2",
                   "Potential indicator only: legitimate clients should not pipeline after STARTTLS."),
    RuleDefinition("TLS-001", "Deprecated TLS/SSL Protocol Version Negotiated", "Cryptographic Posture",
                   "tls_protocol", Severity.HIGH,
                   "Disable SSLv3, TLS 1.0 and TLS 1.1; require TLS 1.2 or TLS 1.3.",
                   "RFC 8996; RFC 7568; NIST SP 800-52 Rev. 2 §3.1"),
    RuleDefinition("TLS-002", "TLS Handshake Failed", "Cryptographic Posture", "tls_protocol", Severity.INFO,
                   "Review the alert cause (protocol/cipher mismatch, certificate rejection).",
                   "RFC 8446 §6; RFC 5246 §7.2",
                   "Informational: a failed handshake transfers no protected data."),
    RuleDefinition("TLS-003", "Insecure or Weak Cipher Suite Negotiated", "Cryptographic Posture", "cryptography",
                   Severity.CRITICAL,
                   "Remove NULL, EXPORT, anonymous, RC4, DES and 3DES suites; prefer AEAD suites with (EC)DHE.",
                   "NIST SP 800-52 Rev. 2 §3.3; RFC 7465; RFC 9325"),
    RuleDefinition("TLS-004", "No Forward Secrecy in Key Exchange", "Cryptographic Posture", "cryptography",
                   Severity.MEDIUM,
                   "Prefer ECDHE/DHE key exchange (or TLS 1.3).",
                   "NIST SP 800-52 Rev. 2 §3.3.1; RFC 9325 §4.2",
                   "Only raised when the negotiated suite is known."),
    RuleDefinition("TLS-005", "Weak Key Exchange Parameters", "Cryptographic Posture", "cryptography",
                   Severity.HIGH,
                   "Use DH groups of at least 2048 bits (RFC 7919 ffdhe) or modern curves (x25519, P-256+).",
                   "NIST SP 800-57 Pt.1 Rev. 5; RFC 7919; Logjam (CVE-2015-4000)"),
    RuleDefinition("TLS-006", "Client Offers Insecure Cipher Suites", "Cryptographic Posture", "cryptography",
                   Severity.LOW,
                   "Remove NULL/EXPORT/anonymous/RC4/DES suites from client configurations.",
                   "RFC 7465; NIST SP 800-52 Rev. 2",
                   "Offered, not negotiated: exploitable only if the server selects one."),
    RuleDefinition("CERT-001", "Expired X.509 Certificate", "Certificate Security", "certificate", Severity.HIGH,
                   "Renew the certificate; automate renewal (ACME).", "RFC 5280 §4.1.2.5"),
    RuleDefinition("CERT-002", "X.509 Certificate Not Yet Valid", "Certificate Security", "certificate",
                   Severity.HIGH,
                   "Check server clock and certificate issuance.", "RFC 5280 §4.1.2.5"),
    RuleDefinition("CERT-003", "Weak Certificate Public Key", "Certificate Security", "certificate", Severity.HIGH,
                   "Use RSA >= 2048 bits (3072+ preferred) or ECDSA P-256/P-384 / Ed25519.",
                   "NIST SP 800-57 Pt.1 Rev. 5; NIST SP 800-131A Rev. 2"),
    RuleDefinition("CERT-004", "Weak Certificate Signature Algorithm", "Certificate Security", "certificate",
                   Severity.HIGH,
                   "Re-issue with SHA-256 or stronger.", "RFC 6194; CA/B Forum BR §7.1.3; NIST SP 800-131A",
                   "Not raised for self-signed roots, whose signature is not relied upon."),
    RuleDefinition("CERT-005", "Self-Signed Server Certificate", "Certificate Security", "certificate",
                   Severity.MEDIUM,
                   "Use a certificate from a CA trusted by peers, or publish DANE TLSA records.",
                   "RFC 5280; RFC 7672 (DANE for SMTP)",
                   "Trust depends on the peer's trust store, which a passive capture cannot see."),
    RuleDefinition("CERT-006", "Certificate Does Not Match Requested Hostname (SNI)", "Certificate Security",
                   "certificate", Severity.MEDIUM,
                   "Issue a certificate whose SAN covers every hostname clients use.", "RFC 6125; RFC 9525",
                   "Only evaluated when the client sent SNI."),
    RuleDefinition("CERT-007", "Presented Certificate Chain Is Inconsistent", "Certificate Security", "certificate",
                   Severity.MEDIUM,
                   "Serve the correct intermediate(s) in order: leaf, then its issuer.", "RFC 5246 §7.4.2; RFC 8446 §4.4.2",
                   "Linkage check only; trust anchors are not evaluated."),
]}

_NAME_TO_CODE = {v: k for k, v in CIPHER_SUITE_NAMES.items()}
DEPRECATED_VERSIONS = {"SSLv2": Severity.CRITICAL, "SSLv3": Severity.CRITICAL,
                       "TLSv1.0": Severity.HIGH, "TLSv1.1": Severity.HIGH}
TLS_STATES = {TLSState.TLS_HANDSHAKE_STARTED, TLSState.TLS_ESTABLISHED, TLSState.TLS_FAILED}


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
    session_id: str = ""
    evidence_type: str = "OBSERVED"
    evidence_frames: List[int] = field(default_factory=list)
    dimension: str = ""


class SecurityPolicyEngine:
    """Evaluates mail session evidence against deterministic security rules."""

    DEPRECATED_TLS_VERSIONS = set(DEPRECATED_VERSIONS)
    WEAK_CIPHER_SUBSTRINGS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"]
    RULES = RULE_CATALOGUE

    @staticmethod
    def _make(session_id: str, rule_id: str, description: str, evidence: Dict[str, Any], *,
              severity: Optional[Severity] = None, title: Optional[str] = None, confidence: float = 1.0,
              evidence_type: str = "OBSERVED", frames: Optional[List[int]] = None,
              suffix: str = "") -> FindingResult:
        rule = RULE_CATALOGUE[rule_id]
        fid = f"{session_id}:{rule_id}" + (f":{suffix}" if suffix else "")
        return FindingResult(
            finding_id=fid, rule_id=rule_id, category=rule.category, title=title or rule.title,
            severity=severity or rule.severity, confidence=confidence, description=description,
            recommendation=rule.recommendation, evidence=evidence, standards_ref=rule.references,
            session_id=session_id, evidence_type=evidence_type,
            evidence_frames=[f for f in (frames or []) if f], dimension=rule.dimension,
        )

    @staticmethod
    def _cipher_info(tls: TLSSessionData) -> Optional[CipherInfo]:
        if tls.cipher is not None:
            return tls.cipher
        if tls.cipher_suite_hex is not None:
            return classify_cipher(tls.cipher_suite_hex)
        if tls.cipher_suite_name and tls.cipher_suite_name in _NAME_TO_CODE:
            return classify_cipher(_NAME_TO_CODE[tls.cipher_suite_name])
        return None

    @classmethod
    def evaluate_session(
        cls,
        session_id: str,
        protocol: EmailProtocol,
        starttls_state: TLSState,
        tls_data: Optional[TLSSessionData],
        certs: List[CertificateDetails],
        session_context: Optional[Dict[str, Any]] = None,
    ) -> List[FindingResult]:
        """Run all policy checks against one reconstructed session."""
        ctx = session_context or {}
        frames = ctx.get("evidence_frames", {})
        findings: List[FindingResult] = []
        mk = cls._make
        tls_seen = bool(tls_data and tls_data.observed)

        # ---- Protocol / STARTTLS -------------------------------------------------
        if starttls_state in (TLSState.PLAINTEXT, TLSState.STARTTLS_REJECTED) and not tls_seen:
            ev = {"protocol": protocol.name, "state": starttls_state.name}
            if ctx.get("starttls_advertised") is not None:
                ev["starttls_advertised_by_server"] = ctx["starttls_advertised"]
            if ctx.get("plaintext_mail_transaction"):
                ev["mail_transaction_in_plaintext"] = True
            findings.append(mk(session_id, "PROTO-001",
                               f"The {protocol.name} session carried application data without any TLS "
                               f"protection (no TLS handshake was observed on the connection).", ev,
                               frames=[frames.get("first_plaintext", 0)]))

        mechs = ctx.get("plaintext_auth_mechanisms") or []
        if mechs:
            cleartext = [m for m in mechs if m in CLEARTEXT_AUTH]
            sev = Severity.CRITICAL if cleartext else Severity.HIGH
            findings.append(mk(session_id, "PROTO-002",
                               f"Authentication ({', '.join(mechs)}) was attempted before any TLS protection. "
                               + ("Cleartext mechanisms expose reusable credentials to anyone on the path."
                                  if cleartext else
                                  "Challenge-response mechanisms still expose material to offline attack."),
                               {"protocol": protocol.name, "mechanisms": mechs, "credential_values_recorded": False},
                               severity=sev, frames=[frames.get("plaintext_auth", 0)]))

        if starttls_state == TLSState.STARTTLS_REJECTED:
            findings.append(mk(session_id, "STLS-001",
                               "The client requested STARTTLS and the server refused it; the session continued "
                               "or ended without encryption. This is consistent with a misconfigured server or an "
                               "on-path STARTTLS-stripping attack; a passive capture cannot tell which.",
                               {"protocol": protocol.name, "state": "STARTTLS_REJECTED",
                                "server_response": ctx.get("starttls_response"),
                                "attempts": ctx.get("starttls_attempts", 1),
                                "plaintext_after_rejection": bool(ctx.get("plaintext_after_rejection"))},
                               confidence=0.95, evidence_type="POTENTIAL_INDICATOR",
                               frames=[frames.get("starttls_command", 0), frames.get("starttls_response", 0)]))

        if starttls_state in (TLSState.STARTTLS_REQUESTED, TLSState.STARTTLS_ACCEPTED) and not tls_seen:
            findings.append(mk(session_id, "STLS-002",
                               "STARTTLS was requested but no TLS handshake appears in the capture, so the "
                               "session's encryption status cannot be determined.",
                               {"protocol": protocol.name, "state": starttls_state.name,
                                "server_response": ctx.get("starttls_response")},
                               confidence=0.5, evidence_type="INSUFFICIENT_EVIDENCE",
                               frames=[frames.get("starttls_command", 0)]))

        if ctx.get("pipelined_after_starttls"):
            findings.append(mk(session_id, "STLS-003",
                               "The client sent further commands in the same plaintext flight as STARTTLS. "
                               "Servers that buffer them may execute injected commands inside the TLS session.",
                               {"protocol": protocol.name}, confidence=0.7, evidence_type="POTENTIAL_INDICATOR",
                               frames=[frames.get("starttls_command", 0)]))

        # ---- TLS -----------------------------------------------------------------
        if tls_data is not None:
            tf = tls_data.evidence_frames
            version = tls_data.server_version
            if version in DEPRECATED_VERSIONS:
                findings.append(mk(session_id, "TLS-001",
                                   f"The server negotiated {version}, which is deprecated and has known "
                                   f"cryptographic weaknesses (e.g. POODLE, BEAST).",
                                   {"negotiated_version": version,
                                    "client_max_version": tls_data.client_max_version},
                                   severity=DEPRECATED_VERSIONS[version],
                                   title=f"Deprecated Protocol Version Negotiated ({version})",
                                   frames=[tf.get("server_hello", 0)]))

            if tls_data.handshake_status == "failed":
                alert = next((a for a in tls_data.alert_details if a.get("level") == "fatal"), {})
                findings.append(mk(session_id, "TLS-002",
                                   f"The TLS handshake was aborted with a fatal alert "
                                   f"({alert.get('description', 'unknown')}).",
                                   {"alert": alert.get("description"), "direction": alert.get("direction")},
                                   frames=[alert.get("frame", 0)]))

            info = cls._cipher_info(tls_data)
            if info is not None and info.known:
                if info.strength in ("insecure", "weak"):
                    findings.append(mk(session_id, "TLS-003",
                                       f"Negotiated suite {info.name}: {'; '.join(info.weaknesses)}.",
                                       {"cipher_suite": info.name, "code": f"0x{info.code:04X}",
                                        "strength": info.strength, "weaknesses": info.weaknesses},
                                       severity=Severity.CRITICAL if info.strength == "insecure" else Severity.HIGH,
                                       title=f"{'Insecure' if info.strength == 'insecure' else 'Weak'} Cipher Suite "
                                             f"Negotiated ({info.name})",
                                       frames=[tf.get("server_hello", 0)]))
                fs = tls_data.has_forward_secrecy if tls_data.cipher is not None else info.forward_secrecy
                if tls_data.server_version == "TLSv1.3":
                    fs = True
                if fs is False and version:
                    findings.append(mk(session_id, "TLS-004",
                                       f"Suite {info.name} uses {info.key_exchange} key exchange, which is not "
                                       f"ephemeral: recorded traffic can be decrypted if the server's private key "
                                       f"is later compromised.",
                                       {"cipher_suite": info.name, "key_exchange": info.key_exchange,
                                        "has_forward_secrecy": False},
                                       evidence_type="INFERRED", frames=[tf.get("server_hello", 0)]))

            weak_kx = []
            if tls_data.dh_prime_bits is not None and tls_data.dh_prime_bits < 2048:
                weak_kx.append(f"{tls_data.dh_prime_bits}-bit DH group")
            if tls_data.key_exchange_group_weak:
                weak_kx.append(f"weak curve {tls_data.key_exchange_group}")
            if weak_kx:
                findings.append(mk(session_id, "TLS-005",
                                   f"Key exchange uses {', '.join(weak_kx)}.",
                                   {"group": tls_data.key_exchange_group, "dh_prime_bits": tls_data.dh_prime_bits},
                                   frames=[tf.get("server_key_exchange", 0) or tf.get("server_hello", 0)]))

            offered_bad = []
            for code in tls_data.client_supported_ciphers:
                ci = classify_cipher(code)
                if ci.strength == "insecure":
                    offered_bad.append(ci.name)
            if offered_bad:
                findings.append(mk(session_id, "TLS-006",
                                   f"The client offered {len(offered_bad)} insecure suite(s).",
                                   {"offered_insecure_suites": offered_bad[:20], "count": len(offered_bad)},
                                   frames=[tf.get("client_hello", 0)]))

        # ---- Certificates --------------------------------------------------------
        for cert in certs:
            pos = cert.chain_position
            cf = [tls_data.evidence_frames.get("certificate", 0)] if tls_data else []
            ref = cert.validity_reference
            base_ev = {"subject": cert.subject, "issuer": cert.issuer, "fingerprint_sha256": cert.fingerprint_sha256,
                       "chain_position": pos}
            if cert.is_expired:
                findings.append(mk(session_id, "CERT-001",
                                   f"Certificate '{cert.subject}' expired on {cert.not_after.isoformat()} "
                                   f"(evaluated at {ref}).",
                                   {**base_ev, "not_after": cert.not_after.isoformat(), "evaluated_at": ref},
                                   frames=cf, suffix=str(pos)))
            if cert.is_not_yet_valid:
                findings.append(mk(session_id, "CERT-002",
                                   f"Certificate '{cert.subject}' is not valid before "
                                   f"{cert.not_before.isoformat()} (evaluated at {ref}).",
                                   {**base_ev, "not_before": cert.not_before.isoformat(), "evaluated_at": ref},
                                   frames=cf, suffix=str(pos)))
            if cert.weak_key:
                findings.append(mk(session_id, "CERT-003",
                                   f"Certificate '{cert.subject}' uses a {cert.public_key_algorithm} key of "
                                   f"{cert.public_key_size_bits} bits.",
                                   {**base_ev, "algo": cert.public_key_algorithm, "key_size": cert.public_key_size_bits},
                                   title=f"Weak Public Key ({cert.public_key_algorithm} {cert.public_key_size_bits} bits)",
                                   frames=cf, suffix=str(pos)))
            if cert.weak_signature and not cert.is_self_signed:
                findings.append(mk(session_id, "CERT-004",
                                   f"Certificate '{cert.subject}' is signed with {cert.signature_algorithm}, "
                                   f"which relies on a collision-vulnerable hash.",
                                   {**base_ev, "signature_algo": cert.signature_algorithm},
                                   title=f"Weak Certificate Signature Algorithm ({cert.signature_algorithm})",
                                   frames=cf, suffix=str(pos)))
            if cert.is_self_signed and pos == 0:
                findings.append(mk(session_id, "CERT-005",
                                   f"The server's certificate '{cert.subject}' is self-signed (its signature "
                                   f"verifies with its own key). Peers can only trust it through explicit pinning "
                                   f"or DANE; trust-anchor context is not available to this analysis.",
                                   {**base_ev, "trust_status": "unknown"}, confidence=0.9,
                                   frames=cf, suffix=str(pos)))

        leaf = next((c for c in certs if c.chain_position == 0), None)
        if leaf is not None and tls_data is not None and tls_data.sni:
            if not CertificateAnalyzer.hostname_matches(tls_data.sni, leaf):
                findings.append(mk(session_id, "CERT-006",
                                   f"The client requested '{tls_data.sni}' but the certificate covers "
                                   f"{', '.join(leaf.san_list[:5]) or leaf.common_name or 'no DNS names'}.",
                                   {"sni": tls_data.sni, "san": leaf.san_list[:20], "common_name": leaf.common_name},
                                   frames=[tls_data.evidence_frames.get("certificate", 0)]))

        chain = ctx.get("chain")
        if chain and chain.get("status") == "broken":
            findings.append(mk(session_id, "CERT-007",
                               "At least one certificate in the presented chain is not signed by the next "
                               "certificate (name or signature mismatch).",
                               {"links": chain.get("links", [])}, confidence=0.9,
                               frames=[tls_data.evidence_frames.get("certificate", 0)] if tls_data else []))

        return findings
