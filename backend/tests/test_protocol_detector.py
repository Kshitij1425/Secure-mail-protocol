import pytest
from securemailscope.protocols.detector import ProtocolDetector, EmailProtocol


class TestProtocolDetector:
    """Tests for multi-signal email protocol detection."""

    def setup_method(self):
        self.detector = ProtocolDetector()

    # --- SMTP Detection ---

    def test_smtp_banner_standard_port(self):
        payload = b"220 mail.example.com ESMTP Postfix\r\n"
        result = self.detector.detect(payload, port=25)
        assert result.protocol == EmailProtocol.SMTP
        assert result.confidence >= 0.85

    def test_smtp_banner_submission_port(self):
        payload = b"220 smtp.example.com ESMTP ready\r\n"
        result = self.detector.detect(payload, port=587)
        assert result.protocol == EmailProtocol.SMTP
        assert result.confidence >= 0.85

    def test_smtp_banner_no_port(self):
        payload = b"220 mx.example.org ESMTP Sendmail\r\n"
        result = self.detector.detect(payload, port=9999)
        assert result.protocol == EmailProtocol.SMTP
        assert result.confidence >= 0.4

    def test_smtp_port_only_no_banner(self):
        payload = b"some random data\r\n"
        result = self.detector.detect(payload, port=25)
        assert result.protocol == EmailProtocol.SMTP
        assert result.confidence > 0.0

    def test_smtp_ehlo_command(self):
        payload = b"220 mail.test.com ESMTP\r\nEHLO client.test.com\r\n"
        result = self.detector.detect(payload, port=25)
        assert result.protocol == EmailProtocol.SMTP
        assert result.confidence >= 0.85

    # --- IMAP Detection ---

    def test_imap_banner_standard_port(self):
        payload = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"
        result = self.detector.detect(payload, port=143)
        assert result.protocol == EmailProtocol.IMAP
        assert result.confidence >= 0.85

    def test_imap_banner_ssl_port(self):
        payload = b"* OK IMAP4rev1 Service Ready\r\n"
        result = self.detector.detect(payload, port=993)
        assert result.protocol == EmailProtocol.IMAP
        assert result.confidence >= 0.85

    def test_imap_banner_nonstandard_port(self):
        payload = b"* OK [CAPABILITY IMAP4rev1 STARTTLS] server ready\r\n"
        result = self.detector.detect(payload, port=8143)
        assert result.protocol == EmailProtocol.IMAP
        assert result.confidence >= 0.4

    def test_imap_port_only(self):
        payload = b"some random data\r\n"
        result = self.detector.detect(payload, port=143)
        assert result.protocol == EmailProtocol.IMAP
        assert result.confidence > 0.0

    # --- POP3 Detection ---

    def test_pop3_banner_standard_port(self):
        payload = b"+OK POP3 server ready\r\n"
        result = self.detector.detect(payload, port=110)
        assert result.protocol == EmailProtocol.POP3
        assert result.confidence >= 0.85

    def test_pop3_banner_ssl_port(self):
        payload = b"+OK pop3 server ready\r\n"
        result = self.detector.detect(payload, port=995)
        assert result.protocol == EmailProtocol.POP3
        assert result.confidence >= 0.85

    def test_pop3_banner_nonstandard_port(self):
        payload = b"+OK POP3 ready\r\n"
        result = self.detector.detect(payload, port=9110)
        assert result.protocol == EmailProtocol.POP3
        assert result.confidence >= 0.4

    def test_pop3_port_only(self):
        payload = b"some random data\r\n"
        result = self.detector.detect(payload, port=110)
        assert result.protocol == EmailProtocol.POP3
        assert result.confidence > 0.0

    # --- Unknown / Negative ---

    def test_unknown_protocol(self):
        payload = b"HTTP/1.1 200 OK\r\n"
        result = self.detector.detect(payload, port=80)
        assert result.protocol == EmailProtocol.UNKNOWN
        assert result.confidence == 0.0

    def test_empty_payload(self):
        payload = b""
        result = self.detector.detect(payload, port=0)
        assert result.protocol == EmailProtocol.UNKNOWN

    def test_binary_payload_no_crash(self):
        payload = b"\x00\x01\x02\xff\xfe\xfd" * 100
        result = self.detector.detect(payload, port=0)
        assert result.protocol == EmailProtocol.UNKNOWN
