"""
X.509 Certificate Analyzer for SecureMailScope.

Distinguishes clearly between:

* extraction   - DER bytes taken from a cleartext TLS Certificate message (TLS parser)
* parsing      - DER decoded into fields (``analyze_der``)
* chain linkage- each presented certificate cryptographically verified as issued
                 by the next one (``analyze_chain``)
* trust        - NOT evaluated: no trust store / trust-anchor context is used, so
                 trust is always reported as ``unknown``.

Validity is evaluated at a caller-supplied reference time (the capture time for
forensic analysis) so results are reproducible regardless of when the analysis runs.
"""
import hashlib
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.certificates.analyzer")

MAX_DER_BYTES = 64 * 1024
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(text: str, limit: int = 1024) -> str:
    """Neutralise control characters in attacker-controlled certificate text."""
    return _CTRL.sub("?", text)[:limit]


@dataclass
class CertificateDetails:
    fingerprint_sha256: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    is_expired: bool
    is_not_yet_valid: bool
    is_self_signed: bool
    public_key_algorithm: str
    public_key_size_bits: int
    signature_algorithm: str
    san_list: List[str] = field(default_factory=list)
    weak_key: bool = False
    weak_signature: bool = False
    # --- extended ---
    common_name: Optional[str] = None
    is_ca: Optional[bool] = None
    chain_position: int = 0
    self_issued: bool = False               # subject == issuer (names only)
    validity_reference: str = "analysis_time"
    validity_reference_time: Optional[datetime] = None
    trust_status: str = "unknown"           # never "trusted": no trust anchors are evaluated
    issued_by_next: Optional[str] = None    # verified | signature_invalid | name_mismatch | unsupported | none
    raw_der: bytes = b""


class CertificateAnalyzer:
    """Analyzes raw DER-encoded X.509 certificates."""

    WEAK_SIG_ALGOS = {"md5", "sha1", "md2"}
    MIN_RSA_KEY_SIZE = 2048
    MIN_DSA_KEY_SIZE = 2048
    MIN_EC_KEY_SIZE = 224

    @classmethod
    def analyze_der(cls, raw_der: bytes, reference_time: Optional[datetime] = None,
                    reference_label: str = "analysis_time", position: int = 0) -> Optional[CertificateDetails]:
        """Parse DER bytes. Returns None (never raises) for malformed input."""
        if not raw_der or len(raw_der) > MAX_DER_BYTES:
            return None
        try:
            cert = x509.load_der_x509_certificate(raw_der)
            now = reference_time or datetime.now(timezone.utc)
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            subject = _clean(cert.subject.rfc4514_string())
            issuer = _clean(cert.issuer.rfc4514_string())
            self_issued = cert.subject == cert.issuer

            pub_key = cert.public_key()
            pub_key_algo, pub_key_size, weak_key = "Unknown", 0, False
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key_algo, pub_key_size = "RSA", pub_key.key_size
                weak_key = pub_key_size < cls.MIN_RSA_KEY_SIZE
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key_algo, pub_key_size = f"EC ({pub_key.curve.name})", pub_key.key_size
                weak_key = pub_key_size < cls.MIN_EC_KEY_SIZE
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key_algo, pub_key_size = "DSA", pub_key.key_size
                weak_key = True  # DSA is withdrawn for signature generation (FIPS 186-5)
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                pub_key_algo, pub_key_size = "Ed25519", 256
            elif isinstance(pub_key, ed448.Ed448PublicKey):
                pub_key_algo, pub_key_size = "Ed448", 456

            try:
                sig_algo_name = cert.signature_algorithm_oid._name
            except Exception:
                sig_algo_name = cert.signature_algorithm_oid.dotted_string
            weak_sig = any(w in sig_algo_name.lower() for w in cls.WEAK_SIG_ALGOS)

            san_list: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = [_clean(v, 255) for v in san_ext.value.get_values_for_type(x509.DNSName)][:500]
            except x509.ExtensionNotFound:
                pass
            except Exception:
                logger.debug("Malformed SAN extension")

            is_ca = None
            try:
                is_ca = bool(cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value.ca)
            except x509.ExtensionNotFound:
                is_ca = None
            except Exception:
                is_ca = None

            cn = None
            try:
                attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = _clean(str(attrs[0].value), 255) if attrs else None
            except Exception:
                cn = None

            is_self_signed = False
            if self_issued:
                is_self_signed = cls._verify_issued_by(cert, cert) == "verified"

            return CertificateDetails(
                fingerprint_sha256=hashlib.sha256(raw_der).hexdigest(),
                subject=subject, issuer=issuer, serial_number=hex(cert.serial_number),
                not_before=not_before, not_after=not_after,
                is_expired=now > not_after, is_not_yet_valid=now < not_before,
                is_self_signed=is_self_signed, public_key_algorithm=pub_key_algo,
                public_key_size_bits=pub_key_size, signature_algorithm=sig_algo_name,
                san_list=san_list, weak_key=weak_key, weak_signature=weak_sig,
                common_name=cn, is_ca=is_ca, chain_position=position, self_issued=self_issued,
                validity_reference=reference_label, validity_reference_time=now, raw_der=raw_der,
            )
        except Exception as e:
            logger.warning(f"Failed to parse X.509 certificate ({len(raw_der)} bytes): {type(e).__name__}")
            return None

    @staticmethod
    def _verify_issued_by(cert: "x509.Certificate", issuer: "x509.Certificate") -> str:
        if cert.issuer != issuer.subject:
            return "name_mismatch"
        try:
            cert.verify_directly_issued_by(issuer)
            return "verified"
        except (ValueError, TypeError):
            return "unsupported"
        except Exception:
            return "signature_invalid"

    @classmethod
    def analyze_chain(cls, details: List[CertificateDetails]) -> Dict[str, Any]:
        """Verify each presented certificate against the next one in the list.

        This is chain *linkage* only; no trust anchor is consulted.
        """
        result: Dict[str, Any] = {"length": len(details), "links": [], "status": "not_observed",
                                  "trust": "unknown", "trust_reason": "no trust-anchor store is evaluated"}
        if not details:
            return result
        parsed = []
        for d in details:
            try:
                parsed.append(x509.load_der_x509_certificate(d.raw_der))
            except Exception:
                parsed.append(None)
        statuses = []
        for i, d in enumerate(details):
            if i + 1 < len(details) and parsed[i] is not None and parsed[i + 1] is not None:
                st = cls._verify_issued_by(parsed[i], parsed[i + 1])
            else:
                st = "none"
            d.issued_by_next = st
            statuses.append(st)
            result["links"].append({"position": i, "subject": d.subject, "issuer": d.issuer, "issued_by_next": st})
        leaf = details[0]
        if leaf.is_self_signed:
            result["status"] = "self_signed_leaf"
        elif any(s in ("signature_invalid", "name_mismatch") for s in statuses):
            result["status"] = "broken"
        elif len(details) == 1:
            result["status"] = "leaf_only"
        else:
            result["status"] = "linked" if all(s in ("verified", "none") for s in statuses) else "partially_verified"
        return result

    @staticmethod
    def hostname_matches(hostname: str, details: CertificateDetails) -> bool:
        """RFC 6125-style match of an SNI hostname against SAN dNSNames (CN only if no SAN)."""
        host = hostname.lower().rstrip(".")
        names = details.san_list or ([details.common_name] if details.common_name else [])
        for name in names:
            n = (name or "").lower().rstrip(".")
            if n == host:
                return True
            if n.startswith("*.") and "." in host:
                if host.split(".", 1)[1] == n[2:] and host.split(".", 1)[0]:
                    return True
        return False
