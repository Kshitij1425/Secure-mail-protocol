"""
Scenario Generator for Core Feature Validation (M1-M8)
Generates complex synthetic PCAPs covering STARTTLS transitions, TLS 1.2/1.3,
Certificate variations (expired, weak keys), and downgrade attacks.
"""
import dpkt
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from tests.robustness.packet_generator import SyntheticPCAPGenerator, GroundTruthGenerator

def build_cert_der(rsa_bits: int = 2048, is_expired: bool = False, is_self_signed: bool = True) -> bytes:
    """Helper to generate DER cert bytes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.org"),
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
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)

def build_tls_handshake_records(version: int, cipher_suite: int, cert_der: bytes = None) -> bytes:
    """Constructs real binary TLS records: ServerHello and Certificate."""
    # 1. ServerHello
    sh_body = bytes([(version >> 8) & 0xFF, version & 0xFF]) + (b"\x00" * 32) + bytes([0x00]) + bytes([(cipher_suite >> 8) & 0xFF, cipher_suite & 0xFF]) + bytes([0x00])

    # If TLS 1.3, add extension 43
    if version == 0x0304:
        ext_43 = bytes([0x00, 0x2B, 0x00, 0x02, 0x03, 0x04])
        sh_body += bytes([0x00, len(ext_43)]) + ext_43

    sh_len = len(sh_body)
    sh_msg = bytes([0x02, 0x00, (sh_len >> 8) & 0xFF, sh_len & 0xFF]) + sh_body
    sh_record = bytes([0x16, 0x03, 0x03, (len(sh_msg) >> 8) & 0xFF, len(sh_msg) & 0xFF]) + sh_msg

    # 2. Certificate Msg (if provided)
    cert_record = b""
    if cert_der:
        # cert structure: [CertLen:3] [CertData]
        c_len = len(cert_der)
        c_entry = bytes([(c_len >> 16) & 0xFF, (c_len >> 8) & 0xFF, c_len & 0xFF]) + cert_der
        # all certs structure: [AllCertsLen:3] [CertEntries]
        all_len = len(c_entry)
        cert_body = bytes([(all_len >> 16) & 0xFF, (all_len >> 8) & 0xFF, all_len & 0xFF]) + c_entry
        cert_msg_len = len(cert_body)
        cert_msg = bytes([0x0B, 0x00, (cert_msg_len >> 8) & 0xFF, cert_msg_len & 0xFF]) + cert_body
        cert_record = bytes([0x16, 0x03, 0x03, (len(cert_msg) >> 8) & 0xFF, len(cert_msg) & 0xFF]) + cert_msg

    return sh_record + cert_record

def generate_scenarios(base_dir: str):
    base = Path(base_dir)
    pcap_dir = base / "pcaps"
    gt_dir = base / "ground_truth"

    c_ip = b"\x0a\x00\x00\x01"
    s_ip = b"\x0a\x00\x00\x02"
    c_port = 54321
    s_port = 25
    ts = 1700000000.0

    # SCENARIO 1: STARTTLS Success + Modern TLS 1.3
    name = "smtp_starttls_tls13_secure"
    cert = build_cert_der(rsa_bits=2048, is_expired=False)
    tls_payload = build_tls_handshake_records(0x0304, 0x1301, cert) # TLS 1.3, AES_128_GCM

    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        # TCP Setup
        gen.write_packet(ts, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts+0.01, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts+0.02, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        # Plaintext STARTTLS Phase
        gen.write_packet(ts+0.03, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        gen.write_packet(ts+0.04, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"STARTTLS\r\n")
        gen.write_packet(ts+0.05, s_ip, c_ip, s_port, c_port, 229, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 2.0.0 Ready to start TLS\r\n")
        # TLS Handshake (Server sends ServerHello + Cert)
        gen.write_packet(ts+0.06, s_ip, c_ip, s_port, c_port, 259, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, tls_payload)

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", True,
        ["CERT-005"], # Only self-signed finding expected (since we generated a self-signed cert for testing)
        "complete"
    )

    # SCENARIO 2: Deprecated TLS 1.0 + Weak RSA 1024 + Expired Cert
    name = "smtp_weak_deprecated"
    weak_cert = build_cert_der(rsa_bits=1024, is_expired=True)
    tls_payload_weak = build_tls_handshake_records(0x0301, 0x002F, weak_cert) # TLS 1.0, RSA_AES_128_CBC_SHA (no FS)

    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts+0.01, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts+0.02, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        # Plaintext STARTTLS Phase
        gen.write_packet(ts+0.03, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        gen.write_packet(ts+0.04, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"STARTTLS\r\n")
        gen.write_packet(ts+0.05, s_ip, c_ip, s_port, c_port, 229, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 Go ahead\r\n")
        # TLS Handshake
        gen.write_packet(ts+0.06, s_ip, c_ip, s_port, c_port, 243, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, tls_payload_weak)

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", True,
        ["TLS-001", "TLS-004", "CERT-001", "CERT-003", "CERT-005"], # Deprecated TLS, No FS, Expired, Weak Key, Self-Signed
        "complete"
    )

    # SCENARIO 3: STARTTLS Downgrade / Rejection
    name = "smtp_starttls_downgrade"
    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts+0.01, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts+0.02, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        # Rejection
        gen.write_packet(ts+0.03, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        gen.write_packet(ts+0.04, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"STARTTLS\r\n")
        gen.write_packet(ts+0.05, s_ip, c_ip, s_port, c_port, 229, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"502 5.5.1 Command not implemented\r\n")

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", False,
        ["STLS-001", "PROTO-001"], # Expected STARTTLS Downgrade and Plaintext findings
        "complete"
    )

    # SCENARIO 4: IMAP STARTTLS Success + TLS 1.2
    name = "imap_starttls_tls12"
    cert = build_cert_der(rsa_bits=2048, is_expired=False)
    tls_payload = build_tls_handshake_records(0x0303, 0xC02F, cert) # TLS 1.2, ECDHE_RSA_AES_128_GCM

    c_ip = b"\x0a\x00\x00\x03"
    s_ip = b"\x0a\x00\x00\x04"
    c_port = 54322
    s_port = 143
    ts_imap = 1700000100.0

    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts_imap, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_imap+0.01, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_imap+0.02, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        gen.write_packet(ts_imap+0.03, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"* OK IMAP4 ready\r\n")
        # Packet [3] above (S->C seq=201) uses 18 bytes.
        # Next server seq should be 201 + 18 = 219.
        gen.write_packet(ts_imap+0.04, c_ip, s_ip, c_port, s_port, 101, 219, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"A001 STARTTLS\r\n")
        gen.write_packet(ts_imap+0.05, s_ip, c_ip, s_port, c_port, 219, 116, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"A001 OK STARTTLS completed\r\n")
        # Next server seq should be 219 + 28 = 247.
        gen.write_packet(ts_imap+0.06, s_ip, c_ip, s_port, c_port, 247, 116, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, tls_payload)

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "IMAP", True,
        ["CERT-005"], # Self-signed cert
        "complete"
    )

    # SCENARIO 5: POP3 STARTTLS Rejection
    name = "pop3_starttls_rejected"
    c_ip = b"\x0a\x00\x00\x05"
    s_ip = b"\x0a\x00\x00\x06"
    c_port = 54323
    s_port = 110
    ts_pop3 = 1700000200.0

    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts_pop3, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_pop3+0.01, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_pop3+0.02, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        gen.write_packet(ts_pop3+0.03, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"+OK POP3 ready\r\n")
        # Packet (S->C seq=201) uses 16 bytes. Next server seq 201+16=217.
        gen.write_packet(ts_pop3+0.04, c_ip, s_ip, c_port, s_port, 101, 217, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"STLS\r\n")
        gen.write_packet(ts_pop3+0.05, s_ip, c_ip, s_port, c_port, 217, 107, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"-ERR Command not understood\r\n")

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "POP3", False,
        ["STLS-001", "PROTO-001"], # STARTTLS rejected + plaintext
        "complete"
    )

    # SCENARIO 6: Truncated TLS Handshake (incomplete)
    name = "smtp_starttls_truncated"
    cert = build_cert_der(rsa_bits=2048, is_expired=False)
    # Only send partial ServerHello (no Certificate message)
    partial_tls = build_tls_handshake_records(0x0303, 0xC02F, cert)
    # Truncate the cert record (keep only first 20 bytes of TLS payload)
    truncated_tls = partial_tls[:len(partial_tls) - 50]

    c_ip = b"\x0a\x00\x00\x07"
    s_ip = b"\x0a\x00\x00\x08"
    c_port = 54324
    s_port = 25
    ts_trunc = 1700000300.0

    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts_trunc, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_trunc+0.01, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_trunc+0.02, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        gen.write_packet(ts_trunc+0.03, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        gen.write_packet(ts_trunc+0.04, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"STARTTLS\r\n")
        gen.write_packet(ts_trunc+0.05, s_ip, c_ip, s_port, c_port, 229, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 2.0.0 Ready to start TLS\r\n")
        gen.write_packet(ts_trunc+0.06, s_ip, c_ip, s_port, c_port, 243, 111, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, truncated_tls)

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", True,
        [], # No findings expected (incomplete handshake, no cert parsed)
        "complete"
    )

    print("Generated functional scenarios successfully.")

if __name__ == "__main__":
    generate_scenarios("C:/Users/kshit/SecureMailScope/backend/tests/robustness/fixtures")
