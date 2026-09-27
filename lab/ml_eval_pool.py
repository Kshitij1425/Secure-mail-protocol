"""
Labelled session pool for evaluating the ML anomaly detector.

Real TLS mail sessions between a real server (aiosmtpd on Python ssl / OpenSSL) and a real
client (Python smtplib), one capture per server configuration, recorded with the same relay
as lab/real_mail_lab.py (application bytes and timing real; TCP/IP headers reconstructed).

Each configuration is labelled **by design**, before any analysis:
  healthy - modern configuration with no known weakness
  weak    - at least one deliberate weakness (named in `weakness`)
The labels are therefore independent of SecureMailScope's rule engine.

Usage (from the repository root):
    python lab/ml_eval_pool.py      # writes backend/tests/ml_eval/pool/*.pcap + pool_manifest.json
"""
import hashlib
import json
import platform
import smtplib
import ssl
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lab.pki import issue, lab_chain  # noqa: E402
from lab.recording_relay import RecordingRelay, write_pcap  # noqa: E402

OUT = ROOT / "backend" / "tests" / "ml_eval" / "pool"
SESSIONS_PER_CONFIG = 4
MSG = "From: alice@lab.test\r\nTo: bob@lab.test\r\nSubject: pool\r\n\r\n{body}\r\n"
TMP = Path(tempfile.mkdtemp(prefix="sms_pool_"))

V10, V11, V12, V13 = (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)

# name, label, weakness, server settings
CONFIGS = [
    ("h_tls13_rsa2048", "healthy", None, dict(max_v=V13)),
    ("h_tls13_ecdsa_p256", "healthy", None, dict(max_v=V13, cert=dict(curve="secp256r1"))),
    ("h_tls13_implicit", "healthy", None, dict(max_v=V13, implicit=True)),
    ("h_tls12_ecdhe_rsa_aes128gcm", "healthy", None, dict(max_v=V12, ciphers="ECDHE-RSA-AES128-GCM-SHA256")),
    ("h_tls12_ecdhe_rsa3072_aes256gcm", "healthy", None,
     dict(max_v=V12, ciphers="ECDHE-RSA-AES256-GCM-SHA384", cert=dict(key_bits=3072))),
    ("h_tls12_ecdhe_rsa4096_chacha", "healthy", None,
     dict(max_v=V12, ciphers="ECDHE-RSA-CHACHA20-POLY1305", cert=dict(key_bits=4096))),
    ("h_tls12_ecdhe_ecdsa_p256_aes128gcm", "healthy", None,
     dict(max_v=V12, ciphers="ECDHE-ECDSA-AES128-GCM-SHA256", cert=dict(curve="secp256r1"))),
    ("h_tls12_ecdhe_ecdsa_p384_chacha", "healthy", None,
     dict(max_v=V12, ciphers="ECDHE-ECDSA-CHACHA20-POLY1305", cert=dict(curve="secp384r1"))),
    ("h_tls12_dhe2048_aes256gcm", "healthy", None, dict(max_v=V12, ciphers="DHE-RSA-AES256-GCM-SHA384", dh=2048)),
    ("h_tls12_implicit_aes256gcm", "healthy", None,
     dict(max_v=V12, ciphers="ECDHE-RSA-AES256-GCM-SHA384", implicit=True)),
    ("h_tls12_long_validity_leaf", "healthy", None,
     dict(max_v=V12, ciphers="ECDHE-RSA-AES128-GCM-SHA256", cert=dict(valid_from_days=-200, valid_to_days=190))),

    ("w_tls10_static_rsa1024", "weak", "TLS 1.0 + static RSA + RSA-1024 key",
     dict(min_v=V10, max_v=V10, ciphers="AES128-SHA:@SECLEVEL=0", cert=dict(key_bits=1024))),
    ("w_tls10_ecdhe", "weak", "TLS 1.0", dict(min_v=V10, max_v=V10, ciphers="ECDHE-RSA-AES256-SHA:@SECLEVEL=0")),
    ("w_tls11_ecdhe", "weak", "TLS 1.1", dict(min_v=V11, max_v=V11, ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0")),
    ("w_tls12_static_rsa", "weak", "no forward secrecy (static RSA key exchange)",
     dict(max_v=V12, ciphers="AES128-GCM-SHA256")),
    ("w_tls12_expired_cert", "weak", "expired certificate",
     dict(max_v=V12, ciphers="ECDHE-RSA-AES128-GCM-SHA256", cert=dict(valid_from_days=-400, valid_to_days=-20))),
    ("w_tls12_selfsigned", "weak", "self-signed certificate",
     dict(max_v=V12, ciphers="ECDHE-RSA-AES128-GCM-SHA256", selfsigned=True)),
    ("w_tls12_rsa1024_cert", "weak", "RSA-1024 certificate key",
     dict(max_v=V12, ciphers="ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", cert=dict(key_bits=1024))),
    ("w_tls12_dhe1024", "weak", "1024-bit DHE group",
     dict(max_v=V12, ciphers="DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", dh=1024)),
    ("w_tls12_cbc_sha1_static_rsa", "weak", "static RSA + CBC/SHA-1 suite",
     dict(max_v=V12, ciphers="AES256-SHA:@SECLEVEL=0")),
]


def _dh_file(bits: int) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dh
    params = dh.generate_parameters(generator=2, key_size=bits)
    p = TMP / f"dh{bits}.pem"
    p.write_bytes(params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))
    return str(p)


def server_context(cfg: dict, host: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if cfg.get("min_v"):
        ctx.minimum_version = cfg["min_v"]
    ctx.maximum_version = cfg["max_v"]
    if cfg.get("ciphers"):
        ctx.set_ciphers(cfg["ciphers"])
    if cfg.get("dh"):
        ctx.load_dh_params(_dh_file(cfg["dh"]))
    ck = cfg.get("cert", {})
    if cfg.get("selfsigned"):
        leaf, chain = issue(host, san=[host], **ck), []
    else:
        _, inter, leaf = lab_chain(host, **ck)
        chain = [inter]
    cp, kp = TMP / f"{host}.pem", TMP / f"{host}.key"
    cp.write_bytes(leaf.pem + b"".join(c.pem for c in chain))
    kp.write_bytes(leaf.key_pem)
    ctx.load_cert_chain(str(cp), str(kp))
    return ctx


def client_context(cfg: dict) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab certificates are not in any trust store
    ctx.minimum_version = cfg.get("min_v") or V12
    ctx.maximum_version = cfg["max_v"]
    ctx.set_ciphers("ALL:@SECLEVEL=0" if cfg.get("min_v") in (V10, V11) or "SECLEVEL=0" in cfg.get("ciphers", "")
                    else "DEFAULT")
    return ctx


def run():
    from aiosmtpd.controller import Controller
    from aiosmtpd.handlers import Sink
    OUT.mkdir(parents=True, exist_ok=True)
    entries = []
    for idx, (name, label, weakness, cfg) in enumerate(CONFIGS):
        host = f"{name.replace('_', '-')}.lab.test"
        sctx = server_context(cfg, host)
        implicit = cfg.get("implicit", False)
        port = 30000 + idx
        ctl = Controller(Sink(), hostname="127.0.0.1", port=port, server_hostname=host, ident=f"{host} ESMTP",
                         ssl_context=sctx if implicit else None, tls_context=None if implicit else sctx,
                         require_starttls=False)
        ctl.start()
        server_ip, server_port = f"10.88.{idx // 200}.{idx % 200 + 1}", 465 if implicit else 587
        relays = []
        try:
            for n in range(SESSIONS_PER_CONFIG):
                r = RecordingRelay(("127.0.0.1", port), server_port=server_port,
                                   client_ip=f"10.88.100.{n + 10}", server_ip=server_ip)
                cctx = client_context(cfg)
                if implicit:
                    s = smtplib.SMTP_SSL("127.0.0.1", r.port, context=cctx, local_hostname="client.lab.test", timeout=10)
                    s.ehlo()
                else:
                    s = smtplib.SMTP("127.0.0.1", r.port, local_hostname="client.lab.test", timeout=10)
                    s.ehlo()
                    s.starttls(context=cctx)
                    s.ehlo()
                # Message size varies per session so traffic volume is not constant.
                s.sendmail("alice@lab.test", ["bob@lab.test"], MSG.format(body="\r\n".join(["lab message line"] * (12 * (n + 1) ** 2))))
                s.quit()
                time.sleep(0.2)
                r.close()
                relays.append(r)
        finally:
            ctl.stop()
        path = OUT / f"{name}.pcap"
        frames = write_pcap(path, relays)
        entries.append({"config": name, "label": label, "weakness": weakness, "file": path.name,
                        "server": f"{server_ip}:{server_port}", "implicit_tls": implicit,
                        "sessions": SESSIONS_PER_CONFIG, "frames": frames,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        print(f"{name:40s} {label:8s} {frames} frames")
    manifest = {
        "description": "Labelled pool of real TLS mail sessions for evaluating the ML anomaly detector. Labels are "
                       "assigned by server configuration before analysis (not by SecureMailScope rules).",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "lab/ml_eval_pool.py",
        "capture_method": "lab/recording_relay.py (application bytes and timing real; TCP/IP headers reconstructed)",
        "environment": {"os": platform.platform(), "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION},
        "configs": entries,
    }
    (OUT / "pool_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    run()
