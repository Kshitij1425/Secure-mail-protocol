"""
M11 Feature Extractor: Extract numerical features from TLS sessions for anomaly detection.

Extracts features that characterize TLS session behavior:
- Protocol version as ordinal
- Cipher suite strength metrics
- Certificate properties (key size, age, expiration)
- Session duration and packet counts
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import numpy as np
from enum import Enum

from securemailscope.tls.parser import TLSSessionData
from securemailscope.certificates.analyzer import CertificateDetails
from securemailscope.protocols.detector import EmailProtocol


class TLSVersionOrdinal(Enum):
    """Map TLS versions to ordinal values for feature extraction."""
    SSL_20 = 0
    SSL_30 = 1
    TLS_10 = 2
    TLS_11 = 3
    TLS_12 = 4
    TLS_13 = 5


@dataclass
class SessionFeatures:
    """Extracted numerical features from a single TLS session."""
    session_id: str
    protocol: str
    tls_version_ordinal: float
    cipher_strength: float
    certificate_key_size: float
    certificate_age_days: float
    certificate_validity_days: float
    session_duration_seconds: float
    packet_count: float
    has_forward_secrecy: float
    signature_algorithm_strength: float
    certificate_chain_depth: float

    def to_numpy_array(self) -> np.ndarray:
        """Convert to feature vector for ML models."""
        return np.array([
            self.tls_version_ordinal,
            self.cipher_strength,
            self.certificate_key_size,
            self.certificate_age_days,
            self.certificate_validity_days,
            self.session_duration_seconds,
            self.packet_count,
            self.has_forward_secrecy,
            self.signature_algorithm_strength,
            self.certificate_chain_depth,
        ], dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "tls_version_ordinal": float(self.tls_version_ordinal),
            "cipher_strength": float(self.cipher_strength),
            "certificate_key_size": float(self.certificate_key_size),
            "certificate_age_days": float(self.certificate_age_days),
            "certificate_validity_days": float(self.certificate_validity_days),
            "session_duration_seconds": float(self.session_duration_seconds),
            "packet_count": float(self.packet_count),
            "has_forward_secrecy": bool(self.has_forward_secrecy),
            "signature_algorithm_strength": float(self.signature_algorithm_strength),
            "certificate_chain_depth": float(self.certificate_chain_depth),
        }


class FeatureExtractor:
    """Extract ML features from TLS sessions."""

    @staticmethod
    def extract_tls_version_ordinal(tls_version: Optional[str]) -> float:
        """Convert TLS version string to ordinal value. Handles both TLS 1.3 and TLSv1.3 formats."""
        if not tls_version:
            return 0.0

        version_map = {
            "SSL 2.0": TLSVersionOrdinal.SSL_20.value,
            "SSL 3.0": TLSVersionOrdinal.SSL_30.value,
            "TLS 1.0": TLSVersionOrdinal.TLS_10.value,
            "TLS 1.1": TLSVersionOrdinal.TLS_11.value,
            "TLS 1.2": TLSVersionOrdinal.TLS_12.value,
            "TLS 1.3": TLSVersionOrdinal.TLS_13.value,
            "TLSv1.0": TLSVersionOrdinal.TLS_10.value,
            "TLSv1.1": TLSVersionOrdinal.TLS_11.value,
            "TLSv1.2": TLSVersionOrdinal.TLS_12.value,
            "TLSv1.3": TLSVersionOrdinal.TLS_13.value,
            "SSLv3": TLSVersionOrdinal.SSL_30.value,
        }
        return float(version_map.get(tls_version, 0.0))

    @staticmethod
    def extract_cipher_strength(cipher_suite: Optional[str]) -> float:
        """Estimate cipher suite strength from suite name. 0-100 scale."""
        if not cipher_suite:
            return 50.0

        suite_lower = cipher_suite.lower()

        # Check TLS 1.3 ciphers first (they contain "aes" or "chacha20" but
        # should return 95, not 70)
        if "tls_aes" in suite_lower or "chacha20" in suite_lower:
            return 95.0
        # Broken/export ciphers (must check DES before 3DES)
        if any(x in suite_lower for x in ["export", "null", "anon"]):
            return 10.0
        # DES-CBC3-SHA contains "des-cbc" but is actually 3DES (cbc3)
        if "des-cbc" in suite_lower and "cbc3" not in suite_lower and "3des" not in suite_lower:
            return 10.0
        # Weak (RC4, DSS variants)
        if "rc4" in suite_lower or "dss" in suite_lower:
            return 25.0
        # Legacy but acceptable (3DES / DES-CBC3 / Triple-DES / EDE)
        if "3des" in suite_lower or "cbc3" in suite_lower or "des3" in suite_lower or "ede" in suite_lower:
            return 50.0
        # Modern with forward secrecy (ECDHE, DHE)
        if any(x in suite_lower for x in ["ecdhe", "dhe"]):
            return 90.0
        # Modern AES without PFS
        if "aes" in suite_lower:
            return 70.0
        return 70.0

    @staticmethod
    def extract_key_size(cert: Optional[CertificateDetails]) -> float:
        """Extract RSA/ECDSA key size in bits."""
        if not cert or not hasattr(cert, 'public_key_size_bits'):
            return 0.0
        return float(cert.public_key_size_bits) if cert.public_key_size_bits else 0.0

    @staticmethod
    def extract_certificate_age(cert: Optional[CertificateDetails]) -> float:
        """Days since certificate issuance (from not_before)."""
        if not cert or not hasattr(cert, 'not_before') or not cert.not_before:
            return 0.0
        from datetime import datetime, timezone
        try:
            now = datetime.now(timezone.utc)
            issued = cert.not_before
            if isinstance(issued, datetime):
                delta = now - issued
            else:
                delta = now - issued.replace(tzinfo=timezone.utc)
            return float(delta.days)
        except Exception:
            return 0.0

    @staticmethod
    def extract_certificate_validity(cert: Optional[CertificateDetails]) -> float:
        """Days until certificate expiration (from not_after). Negative if expired."""
        if not cert or not hasattr(cert, 'not_after') or not cert.not_after:
            return 0.0
        from datetime import datetime, timezone
        try:
            now = datetime.now(timezone.utc)
            expires = cert.not_after
            if isinstance(expires, datetime):
                delta = expires - now
            else:
                delta = expires.replace(tzinfo=timezone.utc) - now
            return float(delta.days)
        except Exception:
            return 0.0

    @staticmethod
    def extract_forward_secrecy(cipher_suite: Optional[str]) -> float:
        """Return 1.0 if cipher uses PFS (ECDHE, DHE, TLS 1.3 ciphers), 0.0 otherwise."""
        if not cipher_suite:
            return 0.0
        suite_lower = cipher_suite.lower()
        if any(x in suite_lower for x in ["ecdhe", "dhe", "tls_aes", "chacha20"]):
            return 1.0
        return 0.0

    @staticmethod
    def extract_signature_strength(cert: Optional[CertificateDetails]) -> float:
        """Estimate signature algorithm strength. 0-100 scale."""
        if not cert or not hasattr(cert, 'signature_algorithm') or not cert.signature_algorithm:
            return 50.0
        sig_algo_lower = cert.signature_algorithm.lower()
        if "md5" in sig_algo_lower or "md2" in sig_algo_lower:
            return 10.0
        if "sha1" in sig_algo_lower:
            return 40.0
        if any(x in sig_algo_lower for x in ["sha256", "sha384", "sha512"]):
            return 95.0
        if "ecdsa" in sig_algo_lower:
            return 90.0
        return 70.0

    @staticmethod
    def extract_certificate_chain_depth(certs: List[CertificateDetails]) -> float:
        """Return the depth of the certificate chain."""
        return float(len(certs)) if certs else 0.0

    @classmethod
    def extract_from_tls_session(
        cls,
        session_id: str,
        protocol: EmailProtocol,
        tls_data: Optional[TLSSessionData],
        certs: List[CertificateDetails],
        packet_count: int = 0,
        session_duration_seconds: float = 0.0
    ) -> Optional[SessionFeatures]:
        """
        Extract features from a complete TLS session.
        Returns None if insufficient data.
        """
        if not tls_data:
            return None

        tls_version_ord = cls.extract_tls_version_ordinal(tls_data.server_version)
        cipher_strength = cls.extract_cipher_strength(tls_data.cipher_suite_name)
        key_size = cls.extract_key_size(certs[0]) if certs else 0.0
        cert_age = cls.extract_certificate_age(certs[0]) if certs else 0.0
        cert_validity = cls.extract_certificate_validity(certs[0]) if certs else 0.0
        has_pfs = cls.extract_forward_secrecy(tls_data.cipher_suite_name)
        sig_strength = cls.extract_signature_strength(certs[0]) if certs else 50.0
        chain_depth = cls.extract_certificate_chain_depth(certs)

        return SessionFeatures(
            session_id=session_id,
            protocol=protocol.name,
            tls_version_ordinal=tls_version_ord,
            cipher_strength=cipher_strength,
            certificate_key_size=key_size,
            certificate_age_days=cert_age,
            certificate_validity_days=cert_validity,
            session_duration_seconds=session_duration_seconds,
            packet_count=float(packet_count),
            has_forward_secrecy=has_pfs,
            signature_algorithm_strength=sig_strength,
            certificate_chain_depth=chain_depth,
        )
