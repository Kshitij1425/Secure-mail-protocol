"""
API tests: validation, persistence, isolation and cross-layer consistency.

Each test runs against its own temporary SQLite database, upload directory and
report directory (configured through SECUREMAILSCOPE_* settings).
"""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from securemailscope.api.config import get_settings
from securemailscope.api.database import reset_engine
from securemailscope.api.main import app
from securemailscope.core.orchestrator import Orchestrator

PCAPS = Path(__file__).parent / "robustness" / "fixtures" / "pcaps"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    monkeypatch.setenv("SECUREMAILSCOPE_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("SECUREMAILSCOPE_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SECUREMAILSCOPE_MAX_UPLOAD_SIZE_MB", "2")
    get_settings.cache_clear()
    reset_engine()
    yield tmp_path
    reset_engine()
    get_settings.cache_clear()


@pytest.fixture
def client(env):
    with TestClient(app) as c:
        yield c


def upload(client, name, as_name=None):
    data = (PCAPS / name).read_bytes()
    r = client.post("/analyze", files={"file": (as_name or name, data, "application/octet-stream")})
    return r


# --------------------------------------------------------------------- basics
def test_health_check(client):
    r = client.get("/")
    assert r.status_code == 200 and r.json()["database_connected"] is True
    assert r.headers["x-content-type-options"] == "nosniff"


def test_upload_invalid_extension(client):
    r = client.post("/analyze", files={"file": ("test.txt", b"test content", "text/plain")})
    assert r.status_code == 422


def test_upload_not_a_capture(client, env):
    r = client.post("/analyze", files={"file": ("fake.pcap", b"GIF89a not a pcap", "application/octet-stream")})
    assert r.status_code == 422
    assert "PCAP" in r.json()["detail"]
    assert not list((env / "uploads").glob("*")), "rejected upload must not be left on disk"


def test_upload_empty(client):
    r = client.post("/analyze", files={"file": ("empty.pcap", b"", "application/octet-stream")})
    assert r.status_code == 400


def test_upload_too_large(client, env):
    r = client.post("/analyze", files={"file": ("large.pcap", b"\xd4\xc3\xb2\xa1" + b"x" * (3 * 1024 * 1024),
                                                "application/octet-stream")})
    assert r.status_code == 413
    assert not [p for p in (env / "uploads").glob("*") if p.is_file()]


@pytest.mark.parametrize("evil", ["../../evil.pcap", "..\\..\\evil.pcap", "C:\\Windows\\evil.pcap",
                                  "/etc/evil.pcap", "\\\\server\\share\\evil.pcap", "ev\x00il.pcap",
                                  "a" * 400 + ".pcap", "evil.pcap:ads.pcap"])
def test_upload_filename_cannot_escape(client, env, evil):
    r = upload(client, "clean_baseline.pcap", as_name=evil)
    assert r.status_code == 200, r.text
    cid = r.json()["capture_id"]
    stored = [p.name for p in (env / "uploads").iterdir()]
    assert stored == [f"{cid}.pcap"], "stored name must be server generated"
    shown = client.get(f"/captures/{cid}").json()["filename"]
    assert "/" not in shown and "\\" not in shown and "\x00" not in shown and len(shown) <= 200


def test_errors_do_not_leak_internal_paths(client, env):
    r = client.post("/analyze", files={"file": ("fake.pcap", b"\xd4\xc3\xb2\xa1garbage", "application/octet-stream")})
    assert r.status_code == 422
    assert str(env) not in r.text and "Traceback" not in r.text


def test_nonexistent_resources(client):
    for url in ("/captures/nope", "/sessions/nope", "/findings/nope", "/anomalies/999999", "/certificates/nope",
                "/captures/nope/posture", "/reports/nope", "/captures/nope/sessions"):
        assert client.get(url).status_code == 404, url


def test_cors_policy(client):
    ok = client.options("/captures", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options("/captures", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers


# --------------------------------------------------------- cross-layer checks
@pytest.mark.parametrize("name", ["implicit_tls_mixed.pcap", "ml_mixed_estate.pcap", "smtp_plaintext_auth.pcap",
                                  "smtp_weak_deprecated.pcap", "unrelated_traffic.pcap"])
def test_engine_db_api_consistency(client, env, name):
    direct = Orchestrator().analyze(str(PCAPS / name))
    r = upload(client, name)
    assert r.status_code == 200, r.text
    cid = r.json()["capture_id"]

    cap = client.get(f"/captures/{cid}").json()
    assert cap["analysis_status"] == "completed"
    assert cap["file_hash"] == hashlib.sha256((PCAPS / name).read_bytes()).hexdigest()
    assert cap["packet_count"] == direct.packet_count
    assert cap["stream_count"] == direct.reconstructed_stream_count
    assert cap["email_session_count"] == cap["sessions_count"] == direct.email_session_count
    assert cap["tls_session_count"] == direct.tls_session_count
    assert cap["findings_count"] == len(direct.findings)
    assert cap["certificates_count"] == sum(len(s.certificates) for s in direct.sessions)
    assert cap["anomalies_count"] == sum(a.is_anomaly for a in direct.anomalies)
    assert cap["posture_score"] == direct.posture.overall_score
    assert cap["posture_status"] == direct.posture.status.value

    sessions = client.get(f"/captures/{cid}/sessions").json()
    findings = client.get(f"/captures/{cid}/findings").json()
    certs = client.get(f"/captures/{cid}/certificates").json()
    anomalies = client.get(f"/captures/{cid}/anomalies").json()
    assert sorted(s["stream_id"] for s in sessions) == sorted(s.stream.stream_id for s in direct.sessions)
    assert sorted((f["rule_id"], f["severity"]) for f in findings) == \
        sorted((f.rule_id, f.severity.value) for f in direct.findings)
    assert len(certs) == cap["certificates_count"]
    assert len(anomalies) == len(direct.anomalies)
    assert all(f["session_id"] and f["session_id"].startswith(cid) for f in findings)

    posture = client.get(f"/captures/{cid}/posture")
    if direct.email_session_count == 0:
        assert posture.status_code == 200 and posture.json()["overall_score"] is None
        assert posture.json()["status"] == "Unknown"
    else:
        p = posture.json()
        assert p["overall_score"] == direct.posture.overall_score
        assert len(p["dimension_scores"]) == 5
        assert {d["dimension"] for d in p["dimension_scores"]} == {d.dimension for d in direct.posture.dimension_scores}
        assert p["findings_count"] == len(direct.findings)

    doc = client.get(f"/captures/{cid}/document").json()
    rep = client.post(f"/captures/{cid}/reports", params={"format": "json"}).json()
    report = json.loads(client.get(f"/reports/{rep['report_id']}/download").content)
    assert report == doc
    assert len(report["findings"]) == len(findings) and len(report["sessions"]) == len(sessions)


def test_detail_endpoints_and_relationships(client):
    cid = upload(client, "smtp_weak_deprecated.pcap").json()["capture_id"]
    sess = client.get(f"/captures/{cid}/sessions").json()[0]
    detail = client.get(f"/sessions/{sess['session_id']}").json()
    assert set(detail["findings"]) == {f["finding_id"] for f in client.get(f"/captures/{cid}/findings").json()}
    assert len(detail["certificates"]) == 1
    assert detail["detail"]["tls"]["negotiated_version"] == "TLSv1.0"

    f = client.get(f"/findings/{detail['findings'][0]}").json()
    assert f["affected_sessions"] == [sess["session_id"]]
    assert f["recommendation"] and f["evidence_frames"]

    cert = client.get(f"/certificates/{detail['certificates'][0]}").json()
    assert cert["session_id"] == sess["session_id"] and cert["is_expired"] is True
    assert cert["trust_status"] == "unknown" and cert["validity_reference"] == "capture_time"


def test_anomaly_detail(client):
    cid = upload(client, "ml_mixed_estate.pcap").json()["capture_id"]
    flagged = client.get("/anomalies", params={"capture_id": cid, "is_anomaly": True}).json()
    assert len(flagged) >= 1
    d = client.get(f"/anomalies/{flagged[0]['id']}").json()
    assert d["features"]["tls_version_ordinal"] == 2.0  # the TLS 1.0 outlier
    assert "not a confirmed vulnerability" in d["classification"]


def test_capture_isolation(client):
    a = upload(client, "smtp_weak_deprecated.pcap").json()["capture_id"]
    b = upload(client, "smtp_weak_deprecated.pcap").json()["capture_id"]
    c = upload(client, "clean_baseline.pcap").json()["capture_id"]
    fa = client.get(f"/captures/{a}/findings").json()
    fb = client.get(f"/captures/{b}/findings").json()
    fc = client.get("/findings", params={"capture_id": c}).json()
    assert len(fa) == len(fb) == 5 and {f["rule_id"] for f in fc} == {"PROTO-001"}
    assert not {f["finding_id"] for f in fa} & {f["finding_id"] for f in fb}
    assert all(f["capture_id"] == a for f in fa) and all(f["capture_id"] == c for f in fc)
    sa = client.get(f"/captures/{a}/sessions").json()[0]["session_id"]
    assert client.get(f"/sessions/{sa}").json()["capture_id"] == a
    assert all(x["capture_id"] == b for x in client.get("/certificates", params={"capture_id": b}).json())


def test_reports_all_formats(client):
    cid = upload(client, "smtp_starttls_tls12_chain.pcap").json()["capture_id"]
    for fmt, magic in (("json", b"{"), ("html", b"<!DOCTYPE html>"), ("pdf", b"%PDF-")):
        r = client.post(f"/captures/{cid}/reports", params={"format": fmt})
        assert r.status_code == 200, r.text
        dl = client.get(f"/reports/{r.json()['report_id']}/download")
        assert dl.status_code == 200 and dl.content.startswith(magic)
        assert hashlib.sha256(dl.content).hexdigest() == r.json()["sha256"]
        assert "attachment" in dl.headers["content-disposition"]
    assert len(client.get("/reports", params={"capture_id": cid}).json()) == 3
    assert client.post(f"/captures/{cid}/reports", params={"format": "exe"}).status_code == 422


def test_finding_status_workflow(client):
    cid = upload(client, "clean_baseline.pcap").json()["capture_id"]
    fid = client.get(f"/captures/{cid}/findings").json()[0]["finding_id"]
    r = client.patch(f"/findings/{fid}/status", json={"status": "acknowledged"})
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    assert client.patch(f"/findings/{fid}/status", json={"status": "deleted"}).status_code == 422
    assert client.get(f"/captures/{cid}/posture").json()["overall_score"] == 32.5  # triage never alters score


def test_credentials_never_persisted(client, env):
    cid = upload(client, "smtp_plaintext_auth.pcap").json()["capture_id"]
    assert {f["rule_id"] for f in client.get(f"/captures/{cid}/findings").json()} == {"PROTO-001", "PROTO-002"}
    con = sqlite3.connect(env / "api.db")
    dump = "\n".join(con.iterdump())
    con.close()
    for secret in ("YWxpY2U=", "c2VjcmV0"):
        assert secret not in dump


def test_repeat_analysis_is_reproducible(client):
    a = upload(client, "ml_mixed_estate.pcap").json()["capture_id"]
    b = upload(client, "ml_mixed_estate.pcap").json()["capture_id"]
    da, db_ = client.get(f"/captures/{a}/document").json(), client.get(f"/captures/{b}/document").json()
    strip = lambda d: json.loads(json.dumps(d).replace(a, "X").replace(b, "X"))
    for d in (da, db_):
        d["analysis"]["analyzed_at"] = d["posture"]["analyzed_at"] = None
    assert strip(da) == strip(db_)


def test_timestamps_are_timezone_aware_utc(client):
    """Regression: SQLite dropped tzinfo, so browsers rendered capture times in local time."""
    cid = upload(client, "ml_mixed_estate.pcap").json()["capture_id"]
    cap = client.get(f"/captures/{cid}").json()
    assert cap["capture_start"].startswith("2025-03-01T10:00:00") and cap["capture_start"].endswith(("Z", "+00:00"))
    s = client.get(f"/captures/{cid}/sessions").json()[0]
    assert s["start_timestamp"].endswith(("Z", "+00:00"))
