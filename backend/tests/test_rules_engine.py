import pytest
from datetime import datetime, timedelta, timezone

from securemailscope.protocols.detector import EmailProtocol
from securemailscope.starttls.machine import TLSState
from securemailscope.tls.parser import TLSSessionData
from securemailscope.certificates.analyzer import CertificateDetails
from securemailscope.rules.engine import SecurityPolicyEngine, Severity

class TestSecurityPolicyEngine:

    def test_plaintext_email_finding(self):
        """Test that unencrypted plaintext email triggers critical finding."""
        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-001",
            protocol=EmailProtocol.SMTP,
            starttls_state=TLSState.PLAINTEXT,
            tls_data=None,
            certs=[]
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "PROTO-001"
        assert findings[0].severity == Severity.CRITICAL
        assert "plaintext" in findings[0].title.lower()

    def test_starttls_rejected_finding(self):
        """Test that STARTTLS rejection is detected."""
        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-002",
            protocol=EmailProtocol.SMTP,
            starttls_state=TLSState.STARTTLS_REJECTED,
            tls_data=None,
            certs=[]
        )

        assert any(f.rule_id == "STLS-001" for f in findings)
        downgrade_finding = [f for f in findings if f.rule_id == "STLS-001"][0]
        assert downgrade_finding.severity == Severity.HIGH

    def test_deprecated_tls_version_finding(self):
        """Test TLS 1.0 is flagged as deprecated."""
        tls_data = TLSSessionData(
            server_version="TLSv1.0",
            cipher_suite_name="TLS_RSA_WITH_AES_128_CBC_SHA",
            has_forward_secrecy=False
        )
        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-003",
            protocol=EmailProtocol.SMTP,
            starttls_state=TLSState.TLS_ESTABLISHED,
            tls_data=tls_data,
            certs=[]
        )

        tls_findings = [f for f in findings if f.rule_id == "TLS-001"]
        assert len(tls_findings) >= 1
        assert tls_findings[0].severity == Severity.HIGH
        assert "TLSv1.0" in str(tls_findings[0].evidence)

    def test_weak_cipher_finding(self):
        """Test that weak ciphers are flagged."""
        tls_data = TLSSessionData(
            server_version="TLSv1.2",
            cipher_suite_name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            has_forward_secrecy=False
        )
        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-004",
            protocol=EmailProtocol.SMTP,
            starttls_state=TLSState.TLS_ESTABLISHED,
            tls_data=tls_data,
            certs=[]
        )

        weak_cipher_findings = [f for f in findings if f.rule_id == "TLS-003"]
        assert len(weak_cipher_findings) >= 1
        assert weak_cipher_findings[0].severity == Severity.CRITICAL

    def test_no_forward_secrecy_finding(self):
        """Test that lack of forward secrecy is detected."""
        tls_data = TLSSessionData(
            server_version="TLSv1.2",
            cipher_suite_name="TLS_RSA_WITH_AES_256_CBC_SHA",
            has_forward_secrecy=False
        )
        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-005",
            protocol=EmailProtocol.SMTP,
            starttls_state=TLSState.TLS_ESTABLISHED,
            tls_data=tls_data,
            certs=[]
        )

        fs_findings = [f for f in findings if f.rule_id == "TLS-004"]
        assert len(fs_findings) >= 1
        assert fs_findings[0].severity == Severity.MEDIUM

    def test_expired_certificate_finding(self):
        """Test that expired certificates are flagged."""
        now = datetime.now(timezone.utc)
        cert = CertificateDetails(
            fingerprint_sha256="abc123",
            subject="CN=mail.example.org",
            issuer="CN=Example CA",
            serial_number="0x123",
            not_before=now - timedelta(days=365),
            not_after=now - timedelta(days=10),  # Expired 10 days ago
            is_expired=True,
            is_not_yet_valid=False,
            is_self_signed=False,
            public_key_algorithm="RSA",
            public_key_size_bits=2048,
            signature_algorithm="sha256WithRSAEncryption",
            san_list=[],
            weak_key=False,
            weak_signature=False
        )

        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-006",
            protocol=EmailProtocol.IMAP,
            starttls_state=TLSState.TLS_ESTABLISHED,
            tls_data=TLSSessionData(server_version="TLSv1.2"),
            certs=[cert]
        )

        cert_findings = [f for f in findings if f.rule_id == "CERT-001"]
        assert len(cert_findings) >= 1
        assert cert_findings[0].severity == Severity.HIGH

    def test_weak_rsa_key_finding(self):
        """Test that weak RSA keys are flagged."""
        cert = CertificateDetails(
            fingerprint_sha256="abc123",
            subject="CN=mail.example.org",
            issuer="CN=Example CA",
            serial_number="0x123",
            not_before=datetime.now(timezone.utc) - timedelta(days=1),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            is_expired=False,
            is_not_yet_valid=False,
            is_self_signed=False,
            public_key_algorithm="RSA",
            public_key_size_bits=1024,  # Weak
            signature_algorithm="sha256WithRSAEncryption",
            san_list=[],
            weak_key=True,
            weak_signature=False
        )

        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-007",
            protocol=EmailProtocol.SMTP,
            starttls_state=TLSState.TLS_ESTABLISHED,
            tls_data=TLSSessionData(server_version="TLSv1.2"),
            certs=[cert]
        )

        key_findings = [f for f in findings if f.rule_id == "CERT-003"]
        assert len(key_findings) >= 1
        assert key_findings[0].severity == Severity.HIGH

    def test_self_signed_certificate_finding(self):
        """Test that self-signed certificates are flagged."""
        cert = CertificateDetails(
            fingerprint_sha256="abc123",
            subject="CN=mail.example.org",
            issuer="CN=mail.example.org",  # Self-signed
            serial_number="0x123",
            not_before=datetime.now(timezone.utc) - timedelta(days=1),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            is_expired=False,
            is_not_yet_valid=False,
            is_self_signed=True,
            public_key_algorithm="RSA",
            public_key_size_bits=2048,
            signature_algorithm="sha256WithRSAEncryption",
            san_list=[],
            weak_key=False,
            weak_signature=False
        )

        findings = SecurityPolicyEngine.evaluate_session(
            session_id="test-008",
            protocol=EmailProtocol.POP3,
            starttls_state=TLSState.TLS_ESTABLISHED,
            tls_data=TLSSessionData(server_version="TLSv1.2"),
            certs=[cert]
        )

        self_signed_findings = [f for f in findings if f.rule_id == "CERT-005"]
        assert len(self_signed_findings) >= 1
        assert self_signed_findings[0].severity == Severity.MEDIUM
