"""
Validation layer 2: real email server/client captures from a controlled local lab
(lab/real_mail_lab.py; Mailpit, aiosmtpd and pymap servers, Python smtplib/poplib/imaplib clients).

Each capture in tests/real_captures/manifest.json declares the condition it was
generated to exhibit and the expected per-session observations. The synthetic
fixture layer (tests/robustness) remains the primary functional corpus.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from securemailscope.core.orchestrator import Orchestrator
from tests.robustness.validate_fixtures import session_view

DIR = Path(__file__).parent / "real_captures"
MANIFEST = json.loads((DIR / "manifest.json").read_text(encoding="utf-8")) if (DIR / "manifest.json").exists() else None
CAPTURES = MANIFEST["captures"] if MANIFEST else []

pytestmark = pytest.mark.skipif(not CAPTURES, reason="real capture manifest not present")


def test_manifest_describes_provenance_honestly():
    assert "controlled local test environment" in MANIFEST["description"]
    assert "not real-world" in MANIFEST["description"]
    assert "reconstructed" in MANIFEST["capture_method"]
    assert len(CAPTURES) >= 5


@pytest.mark.parametrize("cap", CAPTURES, ids=[c["name"] for c in CAPTURES])
def test_real_capture_integrity(cap):
    assert hashlib.sha256((DIR / cap["file"]).read_bytes()).hexdigest() == cap["sha256"]


@pytest.mark.parametrize("cap", CAPTURES, ids=[c["name"] for c in CAPTURES])
def test_real_capture_matches_intended_condition(cap):
    result = Orchestrator().analyze(str(DIR / cap["file"]))
    got = sorted((session_view(s) for s in result.sessions), key=lambda v: json.dumps(v, sort_keys=True))
    want = sorted(cap["expected_sessions"], key=lambda v: json.dumps(v, sort_keys=True))
    assert len(got) == len(want), f"sessions: {got}"
    for g, w in zip(got, want):
        for k, v in w.items():
            if k == "handshake_status" and v is None:
                continue
            assert g[k] == v, f"{cap['name']} {k}: expected {v!r}, got {g[k]!r}\n{g}"


def test_real_capture_hostname_substitution_only_touches_plaintext():
    """The lab host name never appears; TLS sessions still parse (ciphertext untouched)."""
    import socket
    host = socket.gethostname().encode()
    for cap in CAPTURES:
        assert host not in (DIR / cap["file"]).read_bytes()


PLAINTEXT_CREDENTIALS = {
    # smtplib AUTH PLAIN: base64 of "\0alice\0lab-password-123", and the raw password
    "real_smtp_starttls_rejected_plain_auth.pcap": ["lab-password-123", "AGFsaWNlAGxhYi1wYXNzd29yZC0xMjM="],
    # imaplib LOGIN alice "lab-imap-password" in cleartext
    "real_imap_starttls_rejected_plain_login.pcap": ["lab-imap-password"],
}


@pytest.mark.parametrize("name", sorted(PLAINTEXT_CREDENTIALS))
def test_real_plaintext_credentials_not_persisted(name, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from securemailscope.api.config import get_settings
    from securemailscope.api.database import reset_engine
    from securemailscope.api.main import app
    secrets = PLAINTEXT_CREDENTIALS[name]
    assert any(x.encode() in (DIR / name).read_bytes() for x in secrets)  # really in the capture
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_URL", f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    monkeypatch.setenv("SECUREMAILSCOPE_UPLOAD_DIR", str(tmp_path / "u"))
    monkeypatch.setenv("SECUREMAILSCOPE_REPORTS_DIR", str(tmp_path / "r"))
    get_settings.cache_clear()
    reset_engine()
    try:
        with TestClient(app) as c:
            r = c.post("/analyze", files={"file": (name, (DIR / name).read_bytes())})
            assert r.status_code == 200
            cid = r.json()["capture_id"]
            outputs = [c.get(f"/captures/{cid}/document").text, c.get(f"/captures/{cid}/bundle").content.hex(),
                       c.get(f"/captures/{cid}/stix").text]
            for fmt in ("json", "html"):
                rep = c.post(f"/captures/{cid}/reports", params={"format": fmt}).json()
                outputs.append(c.get(f"/reports/{rep['report_id']}/download").text)
        dump = "\n".join(sqlite3.connect(tmp_path / "r.db").iterdump())
        for secret in secrets:
            assert secret not in dump
            assert all(secret not in o and secret.encode().hex() not in o for o in outputs)
    finally:
        reset_engine()
        get_settings.cache_clear()


def test_real_corpus_covers_each_protocol_healthy_and_weak():
    """SMTP, IMAP and POP3 each have at least one healthy and one weak/problematic real capture."""
    cover = {}
    for cap in CAPTURES:
        for s in cap["expected_sessions"]:
            cover.setdefault(s["protocol"], set()).add("weak" if s["findings"] else "healthy")
    assert cover == {"SMTP": {"healthy", "weak"}, "IMAP": {"healthy", "weak"}, "POP3": {"healthy", "weak"}}


def test_real_imap_captures_identify_imap_on_standard_ports():
    by_name = {c["name"]: c for c in CAPTURES}
    for name, port, implicit in (("real_imaps_tls12_chain", 993, True), ("real_imaps_tls13", 993, True),
                                 ("real_imap_starttls_tls12", 143, False)):
        result = Orchestrator().analyze(str(DIR / by_name[name]["file"]))
        (s,) = result.sessions
        assert s.protocol.name == "IMAP" and s.stream.dst_port == port and s.implicit_tls is implicit
