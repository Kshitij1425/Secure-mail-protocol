import pytest
from securemailscope.protocols.detector import EmailProtocol
from securemailscope.starttls.machine import StartTLSMachine, TLSState

class TestStartTLSMachine:

    # --- SMTP ---

    def test_smtp_starttls_success(self):
        machine = StartTLSMachine(EmailProtocol.SMTP)
        assert machine.state.current_state == TLSState.PLAINTEXT

        # Client sends EHLO
        machine.process_payload("EHLO client.com\r\n", True)
        assert machine.state.current_state == TLSState.PLAINTEXT

        # Client sends STARTTLS
        machine.process_payload("STARTTLS\r\n", True)
        assert machine.state.current_state == TLSState.STARTTLS_REQUESTED

        # Server accepts
        machine.process_payload("220 2.0.0 Ready to start TLS\r\n", False)
        assert machine.state.current_state == TLSState.STARTTLS_ACCEPTED

        # Client starts TLS handshake
        # [22] (Handshake) [03 01] (TLS 1.0/1.2) [XX XX] (Length) [01] (ClientHello)
        client_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x41, 0x01])
        machine.process_binary(client_hello)
        assert machine.state.current_state == TLSState.TLS_HANDSHAKE_STARTED

        # Application data begins
        # [23] (App Data)
        app_data = bytes([0x17, 0x03, 0x03, 0x00, 0x20])
        machine.process_binary(app_data)
        assert machine.state.current_state == TLSState.TLS_ESTABLISHED

    def test_smtp_starttls_rejected(self):
        machine = StartTLSMachine(EmailProtocol.SMTP)
        machine.process_payload("STARTTLS\r\n", True)
        machine.process_payload("502 5.5.1 Command not implemented\r\n", False)
        assert machine.state.current_state == TLSState.STARTTLS_REJECTED

    # --- IMAP ---

    def test_imap_starttls_success(self):
        machine = StartTLSMachine(EmailProtocol.IMAP)
        machine.process_payload("a001 STARTTLS\r\n", True)
        assert machine.state.current_state == TLSState.STARTTLS_REQUESTED

        machine.process_payload("a001 OK Begin TLS negotiation now\r\n", False)
        assert machine.state.current_state == TLSState.STARTTLS_ACCEPTED

    def test_imap_starttls_rejected(self):
        machine = StartTLSMachine(EmailProtocol.IMAP)
        machine.process_payload("a001 STARTTLS\r\n", True)
        machine.process_payload("a001 BAD Unknown command\r\n", False)
        assert machine.state.current_state == TLSState.STARTTLS_REJECTED

    # --- POP3 ---

    def test_pop3_starttls_success(self):
        machine = StartTLSMachine(EmailProtocol.POP3)
        machine.process_payload("STLS\r\n", True)
        assert machine.state.current_state == TLSState.STARTTLS_REQUESTED

        machine.process_payload("+OK Begin TLS negotiation\r\n", False)
        assert machine.state.current_state == TLSState.STARTTLS_ACCEPTED

    def test_pop3_starttls_rejected(self):
        machine = StartTLSMachine(EmailProtocol.POP3)
        machine.process_payload("STLS\r\n", True)
        machine.process_payload("-ERR STLS not supported\r\n", False)
        assert machine.state.current_state == TLSState.STARTTLS_REJECTED

    # --- Anomalies / Implicit TLS ---

    def test_implicit_tls(self):
        machine = StartTLSMachine(EmailProtocol.SMTP)
        machine.mark_implicit_tls()
        assert machine.state.current_state == TLSState.TLS_HANDSHAKE_STARTED
        assert machine.is_implicit_tls is True

    def test_unexpected_tls_handshake_anomaly(self):
        machine = StartTLSMachine(EmailProtocol.SMTP)
        # Client sends greeting but then immediately starts TLS without STARTTLS
        machine.process_payload("EHLO client.com\r\n", True)

        client_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x41, 0x01])
        machine.process_binary(client_hello)

        assert machine.state.current_state == TLSState.TLS_HANDSHAKE_STARTED
        assert "unexpected_tls_handshake" in machine.state.anomalies
