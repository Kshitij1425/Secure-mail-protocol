import pytest
from securemailscope.tls.parser import TLSParser

class TestTLSParser:
    def test_client_hello_parsing(self):
        parser = TLSParser()

        # Build a minimal TLS 1.2 ClientHello
        # Handshake Record: [22] [03 01] [Length: 2 bytes]
        # Handshake Msg: Type 1 (ClientHello) [Length: 3 bytes]
        # Body: Version [03 03] (TLS 1.2), Random (32B), SessionID Len (0), Ciphers Len (4) [00 2F, 00 35], Comp Len (1) [00]
        ciphers = bytes([0x00, 0x2F, 0x00, 0x35])
        body = bytes([0x03, 0x03]) + (b"\x00" * 32) + bytes([0x00]) + bytes([0x00, 0x04]) + ciphers + bytes([0x01, 0x00])
        msg_len = len(body)
        handshake_msg = bytes([0x01, 0x00, (msg_len >> 8) & 0xFF, msg_len & 0xFF]) + body
        record_len = len(handshake_msg)
        record = bytes([0x16, 0x03, 0x01, (record_len >> 8) & 0xFF, record_len & 0xFF]) + handshake_msg

        session = parser.process_payload(record)
        assert session.client_version == "TLSv1.2"
        assert 0x002F in session.client_supported_ciphers
        assert 0x0035 in session.client_supported_ciphers

    def test_server_hello_parsing_tls12(self):
        parser = TLSParser()

        # Build a minimal ServerHello for TLS 1.2 with ECDHE
        # Body: Version [03 03], Random (32B), SessionID Len (0), Selected Cipher [C0 2F], Comp (0)
        body = bytes([0x03, 0x03]) + (b"\x00" * 32) + bytes([0x00]) + bytes([0xC0, 0x2F]) + bytes([0x00])
        msg_len = len(body)
        handshake_msg = bytes([0x02, 0x00, (msg_len >> 8) & 0xFF, msg_len & 0xFF]) + body
        record_len = len(handshake_msg)
        record = bytes([0x16, 0x03, 0x03, (record_len >> 8) & 0xFF, record_len & 0xFF]) + handshake_msg

        session = parser.process_payload(record)
        assert session.server_version == "TLSv1.2"
        assert session.cipher_suite_hex == 0xC02F
        assert session.cipher_suite_name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        assert session.has_forward_secrecy is True

    def test_server_hello_parsing_no_fs(self):
        parser = TLSParser()

        # Build ServerHello for standard RSA key exchange (No forward secrecy)
        body = bytes([0x03, 0x03]) + (b"\x00" * 32) + bytes([0x00]) + bytes([0x00, 0x2F]) + bytes([0x00])
        msg_len = len(body)
        handshake_msg = bytes([0x02, 0x00, (msg_len >> 8) & 0xFF, msg_len & 0xFF]) + body
        record_len = len(handshake_msg)
        record = bytes([0x16, 0x03, 0x03, (record_len >> 8) & 0xFF, record_len & 0xFF]) + handshake_msg

        session = parser.process_payload(record)
        assert session.server_version == "TLSv1.2"
        assert session.cipher_suite_hex == 0x002F
        assert session.cipher_suite_name == "TLS_RSA_WITH_AES_128_CBC_SHA"
        assert session.has_forward_secrecy is False

    def test_tls13_supported_versions_extension(self):
        parser = TLSParser()

        # TLS 1.3 ServerHello with legacy version 0x0303 in header, but 0x0304 in extension 43
        ext_43 = bytes([0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]) # Ext Type 43, Len 2, Val 0x0304
        extensions = bytes([0x00, len(ext_43)]) + ext_43
        body = bytes([0x03, 0x03]) + (b"\x00" * 32) + bytes([0x00]) + bytes([0x13, 0x01]) + bytes([0x00]) + extensions
        msg_len = len(body)
        handshake_msg = bytes([0x02, 0x00, (msg_len >> 8) & 0xFF, msg_len & 0xFF]) + body
        record_len = len(handshake_msg)
        record = bytes([0x16, 0x03, 0x03, (record_len >> 8) & 0xFF, record_len & 0xFF]) + handshake_msg

        session = parser.process_payload(record)
        assert session.server_version == "TLSv1.3"
        assert session.cipher_suite_name == "TLS_AES_128_GCM_SHA256"
        assert session.has_forward_secrecy is True
