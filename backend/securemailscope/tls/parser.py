"""
Passive TLS handshake parser using dpkt.
Extracts TLS version, cipher suites, key exchange, and X.509 certificates.
"""
import dpkt
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.tls.parser")

@dataclass
class ParsedCertificate:
    raw_der: bytes
    # Higher level X.509 logic will be in the certificates module

@dataclass
class TLSSessionData:
    client_version: Optional[str] = None
    server_version: Optional[str] = None
    cipher_suite_hex: Optional[int] = None
    cipher_suite_name: Optional[str] = None
    client_supported_ciphers: List[int] = field(default_factory=list)
    certificates: List[ParsedCertificate] = field(default_factory=list)
    sni: Optional[str] = None
    handshake_complete: bool = False
    alerts: List[str] = field(default_factory=list)
    has_forward_secrecy: bool = False

class TLSParser:
    """Parses TLS records and extracts cryptographic properties."""

    # Map TLS version bytes to human readable
    TLS_VERSIONS = {
        0x0300: "SSLv3",
        0x0301: "TLSv1.0",
        0x0302: "TLSv1.1",
        0x0303: "TLSv1.2",
        0x0304: "TLSv1.3",
    }

    # Common cipher suite mappings - limited set for initial detection
    # A full IANA registry should ideally map these.
    CIPHER_SUITES = {
        0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
        0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0x1301: "TLS_AES_128_GCM_SHA256", # TLS 1.3
        0x1302: "TLS_AES_256_GCM_SHA384", # TLS 1.3
        0x1303: "TLS_CHACHA20_POLY1305_SHA256", # TLS 1.3
    }

    # Ciphers providing Forward Secrecy (DHE, ECDHE)
    FS_PREFIXES = ("TLS_ECDHE", "TLS_DHE", "TLS_AES_", "TLS_CHACHA") # TLS 1.3 ciphers have implicit FS

    def __init__(self):
        self.session = TLSSessionData()
        self.buffer = b""

    def get_cipher_name(self, hex_val: int) -> str:
        return self.CIPHER_SUITES.get(hex_val, f"UNKNOWN_CIPHER_0x{hex_val:04X}")

    def process_payload(self, payload: bytes) -> TLSSessionData:
        """Process TCP payload bytes looking for TLS records."""
        if not payload:
            return self.session

        self.buffer += payload

        # Try to parse all complete TLS records in buffer
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(self.buffer)
            self.buffer = self.buffer[bytes_used:]

            for record in records:
                self._process_record(record)
        except dpkt.ssl.SSL3Exception:
            # Not enough data for a full record, or garbled
            pass
        except Exception as e:
            logger.debug(f"TLS parsing error: {e}")

        return self.session

    def _process_record(self, record: Any) -> None:
        """Process a single TLS generic record."""
        # Check record type
        if not hasattr(record, 'type'):
            return

        # Alert (21)
        if record.type == 21:
            if len(record.data) >= 2:
                level = record.data[0]
                description = record.data[1]
                self.session.alerts.append(f"Alert(Level:{level}, Desc:{description})")

        # Handshake (22)
        elif record.type == 22:
            self._process_handshakes(record.data)

        # Application Data (23) - indicates handshake is done
        elif record.type == 23:
            self.session.handshake_complete = True

    def _process_handshakes(self, data: bytes) -> None:
        """Process one or more Handshake messages inside a TLS Record."""
        offset = 0
        data_len = len(data)

        while offset + 4 <= data_len:
            msg_type = data[offset]
            msg_len = (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]

            if offset + 4 + msg_len > data_len:
                break # Incomplete message

            msg_data = data[offset+4 : offset+4+msg_len]

            if msg_type == 1: # ClientHello
                self._parse_client_hello(msg_data)
            elif msg_type == 2: # ServerHello
                self._parse_server_hello(msg_data)
            elif msg_type == 11: # Certificate
                self._parse_certificate(msg_data)

            offset += 4 + msg_len

    def _parse_client_hello(self, msg_data: bytes) -> None:
        """Parse ClientHello safely."""
        try:
            # Very basic extraction (version is at start)
            if len(msg_data) < 34: return
            client_version_int = (msg_data[0] << 8) | msg_data[1]
            self.session.client_version = self.TLS_VERSIONS.get(client_version_int, f"0x{client_version_int:04X}")

            # Skip random (32 bytes)
            offset = 34
            # Skip session id
            sess_id_len = msg_data[offset]
            offset += 1 + sess_id_len

            if offset + 2 > len(msg_data): return

            # Cipher suites
            cipher_len = (msg_data[offset] << 8) | msg_data[offset+1]
            offset += 2

            if offset + cipher_len > len(msg_data): return

            for i in range(0, cipher_len, 2):
                cipher = (msg_data[offset+i] << 8) | msg_data[offset+i+1]
                self.session.client_supported_ciphers.append(cipher)

        except Exception as e:
            logger.debug(f"Error parsing ClientHello: {e}")

    def _parse_server_hello(self, msg_data: bytes) -> None:
        """Parse ServerHello safely to get negotiated version and cipher suite."""
        try:
            if len(msg_data) < 34: return
            server_version_int = (msg_data[0] << 8) | msg_data[1]
            # Will be overwritten by supported_versions extension if TLS 1.3
            self.session.server_version = self.TLS_VERSIONS.get(server_version_int, f"0x{server_version_int:04X}")

            offset = 34
            sess_id_len = msg_data[offset]
            offset += 1 + sess_id_len

            if offset + 2 > len(msg_data): return

            cipher_suite = (msg_data[offset] << 8) | msg_data[offset+1]
            self.session.cipher_suite_hex = cipher_suite
            self.session.cipher_suite_name = self.get_cipher_name(cipher_suite)

            # Determine forward secrecy based on cipher name prefix
            name = self.session.cipher_suite_name
            self.session.has_forward_secrecy = any(name.startswith(p) for p in self.FS_PREFIXES)

            # TLS 1.3 Support detection via extensions (Supported Versions) would go here
            # Since dpkt doesn't easily parse v1.3 ServerHello extensions, we do a raw search
            # Often if TLS 1.2 is negotiated but it's really TLS 1.3, an extension exists.

            offset += 3 # skip compression
            if offset + 2 <= len(msg_data):
                ext_len = (msg_data[offset] << 8) | msg_data[offset+1]
                offset += 2
                self._parse_server_extensions(msg_data[offset:offset+ext_len])

        except Exception as e:
            logger.debug(f"Error parsing ServerHello: {e}")

    def _parse_server_extensions(self, ext_data: bytes) -> None:
        """Parse ServerHello extensions, specifically looking for Supported Versions (43) for TLS 1.3."""
        offset = 0
        while offset + 4 <= len(ext_data):
            ext_type = (ext_data[offset] << 8) | ext_data[offset+1]
            ext_len = (ext_data[offset+2] << 8) | ext_data[offset+3]
            offset += 4

            if offset + ext_len > len(ext_data):
                break

            # Supported Versions extension (43)
            if ext_type == 43 and ext_len >= 2:
                version_int = (ext_data[offset] << 8) | ext_data[offset+1]
                if version_int == 0x0304: # TLS 1.3
                    self.session.server_version = "TLSv1.3"

            offset += ext_len

    def _parse_certificate(self, msg_data: bytes) -> None:
        """Parse Certificate message (X.509 chain)."""
        try:
            if len(msg_data) < 3: return

            # The structure is: Length(3) | [certs...]
            # Inside the list, each cert is: Length(3) | RAW_DER
            certs_len = (msg_data[0] << 16) | (msg_data[1] << 8) | msg_data[2]

            if 3 + certs_len > len(msg_data): return

            offset = 3
            end_offset = offset + certs_len

            while offset + 3 <= end_offset:
                cert_len = (msg_data[offset] << 16) | (msg_data[offset+1] << 8) | msg_data[offset+2]
                offset += 3

                if offset + cert_len > end_offset: break

                raw_der = msg_data[offset : offset+cert_len]
                self.session.certificates.append(ParsedCertificate(raw_der=raw_der))

                offset += cert_len

        except Exception as e:
            logger.debug(f"Error parsing TLS Certificate message: {e}")
