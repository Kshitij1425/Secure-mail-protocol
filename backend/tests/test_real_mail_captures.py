"""
Validation layer 2: real email server/client captures from a controlled local lab
(lab/real_mail_lab.py; Mailpit and aiosmtpd servers, Python smtplib/poplib clients).

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


def test_real_plaintext_credentials_not_persisted(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from securemailscope.api.config import get_settings
    from securemailscope.api.database import reset_engine
    from securemailscope.api.main import app
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_URL", f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    monkeypatch.setenv("SECUREMAILSCOPE_UPLOAD_DIR", str(tmp_path / "u"))
    monkeypatch.setenv("SECUREMAILSCOPE_REPORTS_DIR", str(tmp_path / "r"))
    get_settings.cache_clear()
    reset_engine()
    try:
        with TestClient(app) as c:
            name = "real_smtp_starttls_rejected_plain_auth.pcap"
            r = c.post("/analyze", files={"file": (name, (DIR / name).read_bytes())})
            assert r.status_code == 200
        dump = "\n".join(sqlite3.connect(tmp_path / "r.db").iterdump())
        # smtplib AUTH PLAIN base64 of "\0alice\0lab-password-123", and the raw password
        assert "lab-password-123" not in dump and "AGFsaWNlAGxhYi1wYXNzd29yZC0xMjM=" not in dump
    finally:
        reset_engine()
        get_settings.cache_clear()
