"""
Analyst workflow features: policy profiles, history, re-analysis, comparison, timeline,
certificate inventory, evidence chain, evidence bundle, redaction, STIX export.
All tests use real persisted analyses of the real-mail lab captures.
"""
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from securemailscope.api.config import get_settings
from securemailscope.api.database import reset_engine
from securemailscope.api.main import app
from securemailscope.core.orchestrator import Orchestrator
from securemailscope.policy import PROFILES, get_profile

REAL = Path(__file__).parent / "real_captures"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_URL", f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    monkeypatch.setenv("SECUREMAILSCOPE_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("SECUREMAILSCOPE_REPORTS_DIR", str(tmp_path / "reports"))
    get_settings.cache_clear()
    reset_engine()
    with TestClient(app) as c:
        yield c
    reset_engine()
    get_settings.cache_clear()


def up(client, name, policy="balanced"):
    r = client.post("/analyze", files={"file": (name, (REAL / name).read_bytes())}, data={"policy": policy})
    assert r.status_code == 200, r.text
    return r.json()["capture_id"]


def rules(client, cid):
    return {f["rule_id"]: f["severity"] for f in client.get(f"/captures/{cid}/findings").json()}


# ------------------------------------------------------------------ policy profiles
def test_policy_catalogue_documents_every_threshold(client):
    pol = {p["id"]: p for p in client.get("/policies").json()}
    assert set(pol) == {"balanced", "strict", "legacy_audit"}
    for p in pol.values():
        assert p["rationale"] and p["description"]
    assert pol["strict"]["min_rsa_bits"] == 3072 and pol["balanced"]["min_rsa_bits"] == 2048


def test_balanced_profile_is_the_previous_behaviour():
    r = Orchestrator().analyze(str(REAL / "real_smtp_tls10_legacy.pcap"))
    b = Orchestrator(policy_profile="balanced").analyze(str(REAL / "real_smtp_tls10_legacy.pcap"))
    assert [(f.rule_id, f.severity) for f in r.findings] == [(f.rule_id, f.severity) for f in b.findings]


def test_profiles_change_rules_in_documented_ways(client):
    bal = rules(client, up(client, "real_smtp_tls10_legacy.pcap", "balanced"))
    strict = rules(client, up(client, "real_smtp_tls10_legacy.pcap", "strict"))
    legacy = rules(client, up(client, "real_smtp_tls10_legacy.pcap", "legacy_audit"))
    assert bal == {"TLS-001": "HIGH", "TLS-004": "MEDIUM", "CERT-003": "HIGH"}
    assert strict["TLS-001"] == "CRITICAL" and strict["TLS-004"] == "HIGH" and strict["TLS-007"] == "MEDIUM"
    assert legacy["TLS-001"] == "MEDIUM" and legacy["TLS-004"] == "LOW" and "TLS-007" not in legacy
    # strict flags the 2048-bit intermediate too (3072-bit threshold), balanced does not
    strict_certs = [f for f in client.get("/findings", params={"rule_id": "CERT-003"}).json()]
    assert len(strict_certs) >= 3


def test_unknown_profile_rejected(client):
    r = client.post("/analyze", files={"file": ("x.pcap", (REAL / "real_smtp_tls10_legacy.pcap").read_bytes())},
                    data={"policy": "lenient"})
    assert r.status_code == 422
    with pytest.raises(ValueError):
        get_profile("nope")


def test_every_report_names_its_policy(client):
    cid = up(client, "real_smtp_tls10_legacy.pcap", "strict")
    doc = client.get(f"/captures/{cid}/document").json()
    assert doc["analysis"]["policy_profile"] == "strict"
    assert doc["analysis"]["policy_profile_detail"]["min_rsa_bits"] == 3072
    html = client.get(f"/reports/{client.post(f'/captures/{cid}/reports', params={'format': 'html'}).json()['report_id']}/download").text
    assert "Strict" in html and "strict" in html


# ------------------------------------------------------------------ history / re-analysis
def test_history_uses_persisted_data(client):
    a = up(client, "real_remediation_before.pcap")
    b = up(client, "real_remediation_after.pcap")
    hist = {c["capture_id"]: c for c in client.get("/captures").json()}
    assert hist[a]["severity_counts"] == {"HIGH": 3, "MEDIUM": 2}
    assert hist[b]["severity_counts"] == {} and hist[b]["posture_score"] == 100.0
    assert hist[a]["policy_profile"] == "balanced" and hist[a]["capture_start"]


def test_reanalyze_creates_new_analysis_of_same_evidence(client):
    a = up(client, "real_smtp_tls10_legacy.pcap")
    r = client.post(f"/captures/{a}/reanalyze", params={"policy": "strict"})
    assert r.status_code == 200
    b = r.json()["capture_id"]
    ca, cb = client.get(f"/captures/{a}").json(), client.get(f"/captures/{b}").json()
    assert ca["file_hash"] == cb["file_hash"] and cb["policy_profile"] == "strict" and a != b
    assert cb["posture_score"] < ca["posture_score"]


# ------------------------------------------------------------------ comparison
def test_remediation_comparison(client):
    a = up(client, "real_remediation_before.pcap")
    b = up(client, "real_remediation_after.pcap")
    c = client.get("/compare", params={"a": a, "b": b}).json()
    assert c["posture"]["delta"] > 0 and c["posture"]["score_b"] == 100.0
    assert {f["rule_id"] for f in c["findings"]["resolved"]} == {"TLS-001", "TLS-004", "CERT-001", "CERT-003", "CERT-005"}
    assert c["findings"]["new"] == [] and c["findings"]["persisting"] == []
    asset = next(x for x in c["assets"] if x["asset"] == "SMTP 10.77.0.50:587")
    assert asset["present_in"] == "both"
    assert asset["tls_versions"] == {"a": ["TLSv1.0"], "b": ["TLSv1.2"], "changed": True}
    assert asset["leaf_certificates"]["changed"] is True
    assert c["notes"] == []


def test_comparison_warns_on_policy_difference_and_unrelated_assets(client):
    a = up(client, "real_smtp_tls10_legacy.pcap", "balanced")
    b = up(client, "real_mixed_multiprotocol.pcap", "strict")
    notes = " ".join(client.get("/compare", params={"a": a, "b": b}).json()["notes"])
    assert "Policy profiles differ" in notes and "share no server asset" in notes
    assert client.get("/compare", params={"a": a, "b": a}).status_code == 422


# ------------------------------------------------------------------ timeline / inventory / chain
def test_timeline_uses_capture_timestamps(client):
    cid = up(client, "real_smtp_tls10_legacy.pcap")
    cap = client.get(f"/captures/{cid}").json()
    tl = client.get(f"/captures/{cid}/timeline").json()
    kinds = [e["type"] for e in tl]
    for k in ("tcp_open", "protocol_identified", "starttls_command", "starttls_response", "client_hello",
              "server_hello", "certificate", "finding", "tcp_close"):
        assert k in kinds
    stamped = [e["ts"] for e in tl if e["ts"]]
    assert stamped == sorted(stamped)
    assert cap["capture_start"][:19] <= stamped[0][:19] and stamped[-1][:19] <= cap["capture_end"][:19]


def test_certificate_inventory_distinguishes_extraction_from_trust(client):
    cid = up(client, "real_mixed_multiprotocol.pcap")
    inv = client.get(f"/captures/{cid}/certificate-inventory").json()
    assert inv and all(c["trust_validation"].startswith("not performed") for c in inv)
    assert all(c["extraction"].startswith("observed") for c in inv)
    leaf = next(c for c in inv if 0 in c["chain_positions"])
    assert leaf["chain_linkage"] == ["verified"] and leaf["days_to_expiry_at_capture"] is not None


def test_evidence_chain_links_are_explicit(client):
    cid = up(client, "real_remediation_before.pcap")
    f = next(x for x in client.get(f"/captures/{cid}/findings").json() if x["rule_id"] == "CERT-001")
    ch = client.get(f"/findings/{f['finding_id']}/chain").json()
    assert ch["session"]["protocol"] == "SMTP" and ch["session"]["starttls_state"] == "TLS_ESTABLISHED"
    assert ch["tls"]["status"] == "OBSERVED" and ch["tls"]["negotiated_version"] == "TLSv1.0"
    assert ch["certificate"]["status"] == "OBSERVED" and ch["certificate"]["is_expired"] is True
    assert ch["certificate"]["trust"].startswith("NOT_EVALUATED")
    assert ch["evidence"]["frames"] and any(e["type"] == "certificate" for e in ch["evidence"]["events"])
    assert ch["recommendation"]["why_it_matters"] and ch["recommendation"]["expected_effect"]


def test_evidence_chain_tls13_certificate_not_observable(client):
    cid = up(client, "real_mixed_multiprotocol.pcap")
    f = next(x for x in client.get(f"/captures/{cid}/findings").json() if x["rule_id"] == "PROTO-001")
    ch = client.get(f"/findings/{f['finding_id']}/chain").json()
    assert ch["tls"]["status"] == "NOT_OBSERVED" and ch["certificate"]["status"] == "NOT_OBSERVED"


# ------------------------------------------------------------------ bundle / redaction / STIX
def test_evidence_bundle_integrity_and_determinism(client):
    cid = up(client, "real_mixed_multiprotocol.pcap")
    z1 = client.get(f"/captures/{cid}/bundle").content
    z2 = client.get(f"/captures/{cid}/bundle").content
    assert z1 == z2
    z = zipfile.ZipFile(io.BytesIO(z1))
    manifest = json.loads(z.read("manifest.json"))
    assert manifest["contains_packet_payloads"] is False and manifest["redaction"]["mode"] == "RAW"
    for f in manifest["files"]:
        assert hashlib.sha256(z.read(f["path"])).hexdigest() == f["sha256"]
    assert z.read("manifest.sha256").decode().split()[0] == hashlib.sha256(z.read("manifest.json")).hexdigest()
    assert manifest["capture_sha256"] == hashlib.sha256((REAL / "real_mixed_multiprotocol.pcap").read_bytes()).hexdigest()
    # no message content in the bundle
    blob = b"".join(z.read(n) for n in z.namelist())
    assert b"Test message generated" not in blob


def test_redacted_outputs_hide_identities_keep_crypto(client):
    cid = up(client, "real_mixed_multiprotocol.pcap")
    doc = client.get(f"/captures/{cid}/document", params={"redact": True}).json()
    blob = json.dumps(doc)
    for secret in ("10.77.", "lab.test", "Lab PKI", "real_mixed_multiprotocol"):
        assert secret not in blob, secret
    assert doc["redaction"]["mode"] == "REDACTED"
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in blob and doc["certificates"][0]["fingerprint_sha256"]
    z = zipfile.ZipFile(io.BytesIO(client.get(f"/captures/{cid}/bundle", params={"redact": True}).content))
    assert b"10.77." not in b"".join(z.read(n) for n in z.namelist())
    rep = client.post(f"/captures/{cid}/reports", params={"format": "html", "redact": True}).json()
    assert rep["redacted"] is True
    html = client.get(f"/reports/{rep['report_id']}/download")
    assert "10.77." not in html.text and "REDACTED" in html.text
    assert "redacted" in html.headers["content-disposition"]


def test_stix_export_is_valid_observation_only(client):
    stix2 = pytest.importorskip("stix2")
    cid = up(client, "real_remediation_before.pcap")
    raw = client.get(f"/captures/{cid}/stix").content
    parsed = stix2.parse(raw, allow_custom=True)
    types = {o.type for o in parsed.objects}
    assert {"observed-data", "network-traffic", "x509-certificate", "note", "report", "identity"} <= types
    assert not types & {"indicator", "malware", "attack-pattern", "threat-actor"}
    assert b"malicious" not in raw.lower()
    assert raw == client.get(f"/captures/{cid}/stix").content  # deterministic
