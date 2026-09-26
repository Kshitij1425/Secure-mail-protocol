"""
Passive TLS handshake parser.

Parses TLS records from reassembled TCP byte streams, one buffer per direction,
and reassembles handshake messages that are fragmented across records.

What a passive observer can see (no keys):

* TLS 1.0-1.2: ClientHello, ServerHello, Certificate, ServerKeyExchange,
  ServerHelloDone, ChangeCipherSpec, unencrypted alerts. Finished and all later
  records are encrypted.
* TLS 1.3: ClientHello and ServerHello only. EncryptedExtensions, Certificate,
  CertificateVerify and Finished are encrypted, so certificates are
  NOT observable (``certificate_visibility == "encrypted_tls13"``).

All input is hostile: every length is bounds-checked, buffers are capped, and
a direction that stops looking like TLS is abandoned instead of buffered.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from securemailscope.tls.ciphers import CipherInfo, classify_cipher, cipher_name, is_grease
from securemailscope.tls.cipher_registry import CIPHER_SUITE_NAMES
from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.tls.parser")

TLS_VERSIONS = {
    0x0002: "SSLv2",
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

NAMED_GROUPS = {
    1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2", 6: "sect233k1",
    7: "sect233r1", 8: "sect239k1", 9: "sect283k1", 10: "sect283r1", 11: "sect409k1", 12: "sect409r1",
    13: "sect571k1", 14: "sect571r1", 15: "secp160k1", 16: "secp160r1", 17: "secp160r2",
    18: "secp192k1", 19: "secp192r1", 20: "secp224k1", 21: "secp224r1", 22: "secp256k1",
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 26: "brainpoolP256r1", 27: "brainpoolP384r1",
    28: "brainpoolP512r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072",
    258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192", 0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024", 0x6399: "X25519Kyber768Draft00",
}
# Curves below ~112-bit security (NIST SP 800-57) or deprecated by RFC 8422.
WEAK_GROUPS = set(range(1, 22))

ALERT_DESCRIPTIONS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed",
    22: "record_overflow", 30: "decompression_failure", 40: "handshake_failure", 41: "no_certificate",
    42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error", 60: "export_restriction",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity", 116: "certificate_required",
    120: "no_application_protocol",
}

# RFC 8446 4.1.3: ServerHello.random of a HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

MAX_RECORD_LEN = (1 << 14) + 2048            # RFC 5246 ciphertext limit
MAX_HANDSHAKE_MSG = 256 * 1024
MAX_CERTS_PER_CHAIN = 20
MAX_CLIENT_CIPHERS = 512


@dataclass
class ParsedCertificate:
    raw_der: bytes
    position: int = 0           # 0 = leaf as sent by the server
    frame: int = 0              # capture frame that completed the Certificate message


@dataclass
class TLSSessionData:
    client_version: Optional[str] = None      # ClientHello.legacy_version
    server_version: Optional[str] = None      # negotiated version (ServerHello / supported_versions)
    cipher_suite_hex: Optional[int] = None
    cipher_suite_name: Optional[str] = None
    client_supported_ciphers: List[int] = field(default_factory=list)
    certificates: List[ParsedCertificate] = field(default_factory=list)
    sni: Optional[str] = None
    handshake_complete: bool = False
    alerts: List[str] = field(default_factory=list)
    has_forward_secrecy: Optional[bool] = False
    # --- extended evidence ---
    client_offered_versions: List[str] = field(default_factory=list)
    client_max_version: Optional[str] = None
    client_offered_groups: List[str] = field(default_factory=list)
    alpn: List[str] = field(default_factory=list)
    key_exchange: Optional[str] = None
    key_exchange_group: Optional[str] = None
    key_exchange_group_weak: bool = False
    dh_prime_bits: Optional[int] = None
    cipher: Optional[CipherInfo] = None
    hello_retry_request: bool = False
    fallback_scsv_offered: bool = False
    sslv2_client_hello: bool = False
    certificate_visibility: str = "not_observed"  # observed | encrypted_tls13 | not_observed
    handshake_status: str = "not_observed"        # not_observed | incomplete | complete | failed
    alert_details: List[Dict[str, Any]] = field(default_factory=list)
    ccs_seen: Dict[str, bool] = field(default_factory=lambda: {"c2s": False, "s2c": False})
    app_data_seen: Dict[str, bool] = field(default_factory=lambda: {"c2s": False, "s2c": False})
    evidence_frames: Dict[str, int] = field(default_factory=dict)
    protocol_violations: List[str] = field(default_factory=list)
    parse_errors: int = 0

    @property
    def tls_version(self) -> Optional[str]:
        return self.server_version

    @property
    def observed(self) -> bool:
        return bool(self.client_version or self.server_version or self.sslv2_client_hello)


@dataclass
class _DirState:
    buffer: bytearray = field(default_factory=bytearray)
    hs_buffer: bytearray = field(default_factory=bytearray)
    abandoned: bool = False
    records: int = 0


class TLSParser:
    """Stateful passive parser for one TLS connection (both directions)."""

    TLS_VERSIONS = TLS_VERSIONS
    CIPHER_SUITES = CIPHER_SUITE_NAMES

    def __init__(self):
        self.session = TLSSessionData()
        self._dirs: Dict[str, _DirState] = {"c2s": _DirState(), "s2c": _DirState(), "unknown": _DirState()}
        self._frame = 0

    # Kept for callers that used the old helper.
    def get_cipher_name(self, hex_val: int) -> str:
        return cipher_name(hex_val)

    def process_payload(self, payload: bytes, direction: str = "unknown", frame: int = 0) -> TLSSessionData:
        """Feed reassembled bytes from one direction."""
        if not payload:
            return self.session
        st = self._dirs.setdefault(direction, _DirState())
        if st.abandoned:
            return self.session
        self._frame = frame
        st.buffer += payload
        try:
            self._drain_records(st, direction)
        except Exception as e:  # defensive: parser bugs must never crash analysis
            self.session.parse_errors += 1
            st.abandoned = True
            st.buffer.clear()
            logger.debug(f"TLS parsing error ({direction}): {e}")
        self._update_status()
        return self.session

    # ------------------------------------------------------------ records
    def _drain_records(self, st: _DirState, direction: str) -> None:
        buf = st.buffer
        while True:
            if st.records == 0 and len(buf) >= 3 and buf[0] & 0x80 and buf[2] in (1, 4):
                self._parse_sslv2(bytes(buf), direction)
                st.abandoned = True
                buf.clear()
                return
            if len(buf) < 5:
                return
            ctype, major, minor = buf[0], buf[1], buf[2]
            length = (buf[3] << 8) | buf[4]
            if ctype not in (20, 21, 22, 23, 24) or major != 3 or minor > 4 or length > MAX_RECORD_LEN:
                # Not (or no longer) TLS: stop buffering this direction.
                if st.records == 0:
                    logger.debug(f"{direction}: data is not TLS")
                else:
                    self.session.protocol_violations.append(f"invalid_tls_record_{direction}")
                    self.session.parse_errors += 1
                st.abandoned = True
                buf.clear()
                return
            if len(buf) < 5 + length:
                return
            fragment = bytes(buf[5:5 + length])
            del buf[:5 + length]
            st.records += 1
            self._process_record(ctype, fragment, st, direction)

    def _process_record(self, ctype: int, data: bytes, st: _DirState, direction: str) -> None:
        s = self.session
        if ctype == 20:
            s.ccs_seen[direction] = True
        elif ctype == 21:
            self._process_alert(data, direction)
        elif ctype == 22:
            if self._encrypted_handshake_expected(direction):
                # TLS 1.2 Finished after CCS is encrypted; so is everything in 1.3
                # after ServerHello. Do not interpret it as plaintext.
                return
            st.hs_buffer += data
            if len(st.hs_buffer) > MAX_HANDSHAKE_MSG + 4:
                s.protocol_violations.append(f"oversized_handshake_{direction}")
                st.hs_buffer.clear()
                st.abandoned = True
                return
            self._process_handshakes(st, direction)
        elif ctype == 23:
            s.app_data_seen[direction] = True
            s.evidence_frames.setdefault(f"application_data_{direction}", self._frame)

    def _encrypted_handshake_expected(self, direction: str) -> bool:
        s = self.session
        if s.ccs_seen.get(direction) and s.server_version != "TLSv1.3":
            return True
        return False

    def _process_alert(self, data: bytes, direction: str) -> None:
        s = self.session
        if len(data) != 2 or s.ccs_seen.get(direction) or (
                s.server_version == "TLSv1.3" and direction == "s2c" and "server_hello" in s.evidence_frames):
            s.alert_details.append({"direction": direction, "encrypted": True, "frame": self._frame})
            return
        level, desc = data[0], data[1]
        name = ALERT_DESCRIPTIONS.get(desc, f"unknown_{desc}")
        s.alerts.append(f"Alert(Level:{level}, Desc:{desc})")
        s.alert_details.append({"direction": direction, "encrypted": False, "level": "fatal" if level == 2 else "warning",
                                "description": name, "code": desc, "frame": self._frame})

    # --------------------------------------------------------- handshake
    def _process_handshakes(self, st: _DirState, direction: str) -> None:
        hb = st.hs_buffer
        while len(hb) >= 4:
            msg_type = hb[0]
            msg_len = (hb[1] << 16) | (hb[2] << 8) | hb[3]
            if msg_len > MAX_HANDSHAKE_MSG:
                self.session.protocol_violations.append(f"oversized_handshake_{direction}")
                hb.clear()
                st.abandoned = True
                return
            if len(hb) < 4 + msg_len:
                return  # wait for the rest of a fragmented message
            body = bytes(hb[4:4 + msg_len])
            del hb[:4 + msg_len]
            try:
                self._dispatch_handshake(msg_type, body, direction)
            except (IndexError, ValueError, UnicodeDecodeError) as e:
                self.session.parse_errors += 1
                logger.debug(f"Malformed handshake type {msg_type}: {e}")

    def _dispatch_handshake(self, msg_type: int, body: bytes, direction: str) -> None:
        if msg_type == 1:
            self._parse_client_hello(body)
        elif msg_type == 2:
            self._parse_server_hello(body)
        elif msg_type == 11:
            self._parse_certificate(body)
        elif msg_type == 12:
            self._parse_server_key_exchange(body)

    def _parse_sslv2(self, buf: bytes, direction: str) -> None:
        # SSLv2 record: 2-byte header with MSB set, then msg type.
        if len(buf) < 5:
            return
        if buf[2] == 1:
            self.session.sslv2_client_hello = True
            ver = (buf[3] << 8) | buf[4]
            self.session.client_version = TLS_VERSIONS.get(ver, f"0x{ver:04X}")
            self.session.evidence_frames.setdefault("client_hello", self._frame)
        elif buf[2] == 4 and len(buf) >= 7:
            ver = (buf[5] << 8) | buf[6]
            self.session.server_version = TLS_VERSIONS.get(ver, "SSLv2")
            self.session.evidence_frames.setdefault("server_hello", self._frame)

    @staticmethod
    def _u16(b: bytes, o: int) -> int:
        if o + 2 > len(b):
            raise IndexError("truncated u16")
        return (b[o] << 8) | b[o + 1]

    def _parse_client_hello(self, m: bytes) -> None:
        s = self.session
        if len(m) < 35:
            raise ValueError("ClientHello too short")
        ver = self._u16(m, 0)
        s.client_version = TLS_VERSIONS.get(ver, f"0x{ver:04X}")
        s.evidence_frames.setdefault("client_hello", self._frame)
        o = 34
        sid_len = m[o]
        o += 1 + sid_len
        cs_len = self._u16(m, o)
        o += 2
        if o + cs_len > len(m) or cs_len % 2:
            raise ValueError("bad cipher_suites length")
        ciphers = []
        for i in range(0, min(cs_len, MAX_CLIENT_CIPHERS * 2), 2):
            code = (m[o + i] << 8) | m[o + i + 1]
            if code == 0x5600:
                s.fallback_scsv_offered = True
            if not is_grease(code):
                ciphers.append(code)
        s.client_supported_ciphers = ciphers
        o += cs_len
        if o >= len(m):
            return
        comp_len = m[o]
        o += 1 + comp_len
        if o + 2 > len(m):
            return
        for etype, edata in self._iter_extensions(m[o + 2:o + 2 + self._u16(m, o)]):
            if etype == 0:          # server_name
                self._parse_sni(edata)
            elif etype == 10:       # supported_groups
                n = self._u16(edata, 0)
                s.client_offered_groups = [NAMED_GROUPS.get(self._u16(edata, 2 + i), f"0x{self._u16(edata, 2 + i):04X}")
                                           for i in range(0, min(n, len(edata) - 2) - 1, 2)
                                           if not is_grease(self._u16(edata, 2 + i))]
            elif etype == 16:       # ALPN
                s.alpn = self._parse_alpn(edata)
            elif etype == 43 and edata:  # supported_versions (client form: 1-byte length)
                n = edata[0]
                vers = []
                for i in range(1, min(1 + n, len(edata)) - 1, 2):
                    v = self._u16(edata, i)
                    if not is_grease(v):
                        vers.append(v)
                s.client_offered_versions = [TLS_VERSIONS.get(v, f"0x{v:04X}") for v in vers]
                known = [v for v in vers if v in TLS_VERSIONS]
                if known:
                    s.client_max_version = TLS_VERSIONS[max(known)]
        if not s.client_max_version and ver in TLS_VERSIONS:
            s.client_max_version = TLS_VERSIONS[ver]

    def _parse_server_hello(self, m: bytes) -> None:
        s = self.session
        if len(m) < 38:
            raise ValueError("ServerHello too short")
        ver = self._u16(m, 0)
        if m[2:34] == HRR_RANDOM:
            s.hello_retry_request = True
        s.server_version = TLS_VERSIONS.get(ver, f"0x{ver:04X}")
        s.evidence_frames.setdefault("server_hello", self._frame)
        o = 34
        sid_len = m[o]
        o += 1 + sid_len
        code = self._u16(m, o)
        o += 2
        s.cipher_suite_hex = code
        info = classify_cipher(code)
        s.cipher = info
        s.cipher_suite_name = info.name
        s.has_forward_secrecy = info.forward_secrecy
        s.key_exchange = info.key_exchange if info.known else None
        o += 1  # compression method
        if o + 2 <= len(m):
            for etype, edata in self._iter_extensions(m[o + 2:o + 2 + self._u16(m, o)]):
                if etype == 43 and len(edata) >= 2:
                    v = self._u16(edata, 0)
                    s.server_version = TLS_VERSIONS.get(v, f"0x{v:04X}")
                elif etype == 51 and len(edata) >= 2:  # key_share (server: one entry / HRR: group)
                    g = self._u16(edata, 0)
                    self._set_group(g)
                elif etype == 16:
                    s.alpn = self._parse_alpn(edata) or s.alpn
        if s.server_version == "TLSv1.3":
            s.certificate_visibility = "encrypted_tls13"
            s.has_forward_secrecy = True
            if info.known and "_WITH_" in info.name:
                s.protocol_violations.append("tls12_cipher_with_tls13")

    def _parse_certificate(self, m: bytes) -> None:
        s = self.session
        if s.server_version == "TLSv1.3":
            # A cleartext Certificate after a TLS 1.3 ServerHello is impossible in a
            # genuine handshake; record it, never report it as observed evidence.
            s.protocol_violations.append("plaintext_certificate_in_tls13")
            return
        if len(m) < 3:
            raise ValueError("Certificate too short")
        total = (m[0] << 16) | (m[1] << 8) | m[2]
        end = min(3 + total, len(m))
        o = 3
        certs = []
        while o + 3 <= end and len(certs) < MAX_CERTS_PER_CHAIN:
            clen = (m[o] << 16) | (m[o + 1] << 8) | m[o + 2]
            o += 3
            if clen == 0 or o + clen > end:
                s.parse_errors += 1
                break
            certs.append(ParsedCertificate(raw_der=m[o:o + clen], position=len(certs), frame=self._frame))
            o += clen
        if certs:
            s.certificates = certs
            s.certificate_visibility = "observed"
            s.evidence_frames.setdefault("certificate", self._frame)

    def _parse_server_key_exchange(self, m: bytes) -> None:
        s = self.session
        kx = (s.cipher.key_exchange if s.cipher else "") or ""
        s.evidence_frames.setdefault("server_key_exchange", self._frame)
        if kx.startswith("ECDHE") or kx.startswith("ECDH_anon"):
            if len(m) >= 3 and m[0] == 3:  # named_curve
                self._set_group(self._u16(m, 1))
        elif kx.startswith("DHE") or kx.startswith("DH_anon"):
            plen = self._u16(m, 0)
            p = m[2:2 + plen]
            if len(p) == plen and plen:
                s.dh_prime_bits = int.from_bytes(p, "big").bit_length()
                s.key_exchange_group = f"DH-{s.dh_prime_bits}"

    def _set_group(self, g: int) -> None:
        self.session.key_exchange_group = NAMED_GROUPS.get(g, f"0x{g:04X}")
        self.session.key_exchange_group_weak = g in WEAK_GROUPS

    # ---------------------------------------------------------- helpers
    def _iter_extensions(self, data: bytes):
        o = 0
        count = 0
        while o + 4 <= len(data) and count < 128:
            etype = self._u16(data, o)
            elen = self._u16(data, o + 2)
            o += 4
            if o + elen > len(data):
                self.session.parse_errors += 1
                return
            yield etype, data[o:o + elen]
            o += elen
            count += 1

    def _parse_sni(self, edata: bytes) -> None:
        if len(edata) < 5:
            return
        o = 2
        if edata[o] != 0:
            return
        n = self._u16(edata, o + 1)
        raw = edata[o + 3:o + 3 + min(n, 255)]
        name = raw.decode("ascii", errors="replace")
        # Hostnames only; anything else is recorded but neutralised.
        self.session.sni = "".join(ch if (ch.isalnum() or ch in "-._") else "?" for ch in name)

    def _parse_alpn(self, edata: bytes) -> List[str]:
        out = []
        if len(edata) < 2:
            return out
        o = 2
        while o < len(edata) and len(out) < 16:
            n = edata[o]
            out.append(edata[o + 1:o + 1 + n].decode("ascii", errors="replace"))
            o += 1 + n
        return out

    def _update_status(self) -> None:
        s = self.session
        fatal = any(a.get("level") == "fatal" for a in s.alert_details if not a.get("encrypted"))
        both_app = s.app_data_seen.get("c2s") and s.app_data_seen.get("s2c")
        if not s.observed:
            s.handshake_status = "not_observed"
        elif s.server_version == "TLSv1.3":
            # Encrypted handshake + data both look like application_data records.
            s.handshake_complete = bool(both_app)
            s.handshake_status = "complete" if both_app else ("failed" if fatal else "incomplete")
        else:
            ccs_both = s.ccs_seen.get("c2s") and s.ccs_seen.get("s2c")
            s.handshake_complete = bool(ccs_both and (s.app_data_seen.get("c2s") or s.app_data_seen.get("s2c")))
            s.handshake_status = "complete" if s.handshake_complete else ("failed" if fatal else "incomplete")
