"""
X.509 Certificate Analyzer for SecureMailScope.
Extracts cryptographic properties and evaluates validity using PyCA cryptography.
"""
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.certificates.analyzer")

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

class CertificateAnalyzer:
    """Analyzes raw DER-encoded X.509 certificates."""

    WEAK_SIG_ALGOS = {"md5", "sha1", "md2"}
    MIN_RSA_KEY_SIZE = 2048
    MIN_EC_KEY_SIZE = 224

    @classmethod
    def analyze_der(cls, raw_der: bytes) -> Optional[CertificateDetails]:
        """Parse raw DER bytes into a structured CertificateDetails object."""
        try:
            cert = x509.load_der_x509_certificate(raw_der)
            now = datetime.now(timezone.utc)

            # Fingerprint (SHA-256)
            fingerprint = hashlib.sha256(raw_der).hexdigest()

            # Validity
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            is_expired = now > not_after
            is_not_yet_valid = now < not_before

            # Subject & Issuer
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            is_self_signed = (subject == issuer)

            # Serial number
            serial_number = hex(cert.serial_number)

            # Public Key Extraction
            pub_key = cert.public_key()
            pub_key_algo = "Unknown"
            pub_key_size = 0
            weak_key = False

            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key_algo = "RSA"
                pub_key_size = pub_key.key_size
                weak_key = pub_key_size < cls.MIN_RSA_KEY_SIZE
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key_algo = f"EC ({pub_key.curve.name})"
                pub_key_size = pub_key.key_size
                weak_key = pub_key_size < cls.MIN_EC_KEY_SIZE
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key_algo = "DSA"
                pub_key_size = pub_key.key_size
                weak_key = True # DSA is legacy/deprecated
            elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                pub_key_algo = "EdDSA"
                pub_key_size = 256

            # Signature Algorithm
            sig_algo_name = cert.signature_algorithm_oid._name
            sig_algo_lower = sig_algo_name.lower()
            weak_sig = any(weak in sig_algo_lower for weak in cls.WEAK_SIG_ALGOS)

            # SANs
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            return CertificateDetails(
                fingerprint_sha256=fingerprint,
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                is_expired=is_expired,
                is_not_yet_valid=is_not_yet_valid,
                is_self_signed=is_self_signed,
                public_key_algorithm=pub_key_algo,
                public_key_size_bits=pub_key_size,
                signature_algorithm=sig_algo_name,
                san_list=san_list,
                weak_key=weak_key,
                weak_signature=weak_sig
            )

        except Exception as e:
            logger.error(f"Failed to parse X.509 certificate: {e}")
            return None
