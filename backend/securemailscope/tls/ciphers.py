"""
Cipher suite classification.

Derives key exchange, authentication, bulk cipher, MAC, forward secrecy and a
strength class from the IANA suite name. Classes follow NIST SP 800-52 Rev. 2
and RFC 7465 / RFC 8996 / RFC 9325 guidance:

* ``insecure``    NULL / EXPORT / anonymous / RC4 / DES / 3DES / RC2 / MD5 MAC
* ``weak``        IDEA (64-bit block)
* ``legacy``      acceptable but not recommended (CBC mode, no forward secrecy)
* ``recommended`` AEAD with ephemeral key exchange (incl. all TLS 1.3 suites)
* ``unknown``     code point not in the registry (never treated as insecure)
"""
from dataclasses import dataclass, field
from typing import List, Optional

from securemailscope.tls.cipher_registry import CIPHER_SUITE_NAMES

SIGNALING_SUITES = {0x00FF, 0x5600}  # renegotiation_info SCSV, TLS_FALLBACK_SCSV


def is_grease(code: int) -> bool:
    """RFC 8701 GREASE values (0x?A?A)."""
    return (code & 0x0F0F) == 0x0A0A and (code >> 8) == (code & 0xFF)


@dataclass
class CipherInfo:
    code: int
    name: str
    known: bool
    key_exchange: str = "UNKNOWN"
    authentication: str = "UNKNOWN"
    encryption: str = "UNKNOWN"
    mac: str = "UNKNOWN"
    aead: bool = False
    forward_secrecy: Optional[bool] = None   # None = cannot be determined
    strength: str = "unknown"
    weaknesses: List[str] = field(default_factory=list)


def cipher_name(code: int) -> str:
    return CIPHER_SUITE_NAMES.get(code, f"UNKNOWN_CIPHER_0x{code:04X}")


def classify_cipher(code: int) -> CipherInfo:
    name = CIPHER_SUITE_NAMES.get(code)
    if name is None:
        return CipherInfo(code=code, name=cipher_name(code), known=False)
    info = CipherInfo(code=code, name=name, known=True)
    if code in SIGNALING_SUITES:
        info.strength = "signaling"
        info.key_exchange = info.authentication = info.encryption = info.mac = "NONE"
        return info

    body = name[4:] if name.startswith("TLS_") else name.split("_", 1)[-1]
    if "_WITH_" in body:
        kx_part, enc_part = body.split("_WITH_", 1)
    else:
        # TLS 1.3 suites (TLS_AES_128_GCM_SHA256) carry no key exchange: it is
        # always (EC)DHE or PSK-(EC)DHE negotiated via extensions.
        kx_part, enc_part = "TLS13", body

    if kx_part == "TLS13":
        info.key_exchange, info.authentication, info.forward_secrecy = "ECDHE/DHE (TLS 1.3)", "CERT/PSK", True
    else:
        parts = kx_part.split("_")
        kx = parts[0]
        info.key_exchange = kx_part
        auth = [x for x in parts[1:] if x != "EXPORT"]
        info.authentication = "_".join(auth) if auth else kx
        if kx in ("DHE", "ECDHE"):
            info.forward_secrecy = True
        elif kx in ("DH", "ECDH") and "anon" in parts:
            info.forward_secrecy = True  # ephemeral but unauthenticated
        else:
            info.forward_secrecy = False  # RSA, static DH/ECDH, PSK, KRB5, SRP, NULL ...

    tokens = enc_part.split("_")
    mac = tokens[-1] if tokens[-1] in ("MD5", "SHA", "SHA256", "SHA384", "SHA512", "NULL") else ""
    info.mac = mac or "AEAD"
    info.encryption = "_".join(tokens[:-1]) if mac else enc_part
    info.aead = any(t in enc_part for t in ("GCM", "CCM", "CHACHA20_POLY1305", "POLY1305", "MGM"))
    if info.aead and mac:
        info.mac = f"AEAD ({mac} PRF)"

    upper = name.upper()
    w = info.weaknesses
    if "NULL" in info.encryption.upper().split("_") or info.encryption.upper() == "NULL" or "WITH_NULL" in upper:
        w.append("no encryption (NULL cipher)")
    if "EXPORT" in upper:
        w.append("export-grade cryptography")
    if "_ANON_" in upper or upper.endswith("_ANON") or "anon" in kx_part:
        w.append("anonymous key exchange (no server authentication)")
    if "RC4" in upper:
        w.append("RC4 stream cipher (RFC 7465 prohibits)")
    if "RC2" in upper:
        w.append("RC2 cipher")
    if ("_DES_" in upper or "_DES40_" in upper or upper.endswith("_DES_CBC_SHA")) and "3DES" not in upper:
        w.append("single DES (56-bit)")
    if info.mac == "MD5":
        w.append("MD5 MAC")
    if "3DES" in upper or "DES_EDE" in upper:
        # TDEA encryption is disallowed after 2023 (NIST SP 800-131A Rev. 2); SWEET32.
        w.append("3DES 64-bit block cipher (SWEET32; disallowed by NIST SP 800-131A)")
    insecure = bool(w)
    if "IDEA" in upper:
        w.append("IDEA 64-bit block cipher")
    weak = not insecure and bool(w)

    if insecure:
        info.strength = "insecure"
    elif weak:
        info.strength = "weak"
    elif info.aead and info.forward_secrecy:
        info.strength = "recommended"
    else:
        info.strength = "legacy"
        if not info.aead:
            w.append("CBC-mode cipher (no AEAD)")
        if info.forward_secrecy is False:
            w.append("no forward secrecy")
    return info
