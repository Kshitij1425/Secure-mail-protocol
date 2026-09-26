"""Minimal test PKI for the mail lab (certificates relative to the real current time)."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass
class Issued:
    cert: x509.Certificate
    key: object

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Lab PKI (test only)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(cn: str, *, issuer: Optional[Issued] = None, ca: bool = False, san: Optional[List[str]] = None,
          key_bits: int = 2048, valid_from_days: int = -1, valid_to_days: int = 90) -> Issued:
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    b = (x509.CertificateBuilder()
         .subject_name(_name(cn))
         .issuer_name(issuer.cert.subject if issuer else _name(cn))
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + timedelta(days=valid_from_days))
         .not_valid_after(now + timedelta(days=valid_to_days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    return Issued(b.sign(issuer.key if issuer else key, hashes.SHA256()), key)


def lab_chain(host: str, **leaf_kw):
    root = issue("SecureMailScope Lab Root CA", ca=True, valid_from_days=-365, valid_to_days=3650)
    inter = issue("SecureMailScope Lab Issuing CA", issuer=root, ca=True, valid_from_days=-180, valid_to_days=1825)
    leaf = issue(host, issuer=inter, san=[host], **leaf_kw)
    return root, inter, leaf
