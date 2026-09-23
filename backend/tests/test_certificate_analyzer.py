import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from securemailscope.certificates.analyzer import CertificateAnalyzer

def generate_test_cert(
    rsa_bits: int = 2048,
    is_expired: bool = False,
    is_self_signed: bool = True
) -> bytes:
    """Helper to generate DER encoded X.509 certs for tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_bits
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.org"),
    ])

    if not is_self_signed:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Example Root CA")
        ])

    now = datetime.now(timezone.utc)
    if is_expired:
        not_before = now - timedelta(days=60)
        not_after = now - timedelta(days=10)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=90)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.example.org")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)

class TestCertificateAnalyzer:

    def test_valid_modern_certificate(self):
        der = generate_test_cert(rsa_bits=2048)
        details = CertificateAnalyzer.analyze_der(der)

        assert details is not None
        assert details.is_expired is False
        assert details.is_not_yet_valid is False
        assert details.is_self_signed is True
        assert details.public_key_algorithm == "RSA"
        assert details.public_key_size_bits == 2048
        assert details.weak_key is False
        assert details.weak_signature is False
        assert "mail.example.org" in details.san_list

    def test_expired_certificate(self):
        der = generate_test_cert(is_expired=True)
        details = CertificateAnalyzer.analyze_der(der)

        assert details is not None
        assert details.is_expired is True

    def test_weak_rsa_key(self):
        der = generate_test_cert(rsa_bits=1024) # 1024-bit is weak
        details = CertificateAnalyzer.analyze_der(der)

        assert details is not None
        assert details.public_key_size_bits == 1024
        assert details.weak_key is True

    def test_invalid_der_bytes_handled_gracefully(self):
        details = CertificateAnalyzer.analyze_der(b"not a real cert")
        assert details is None
