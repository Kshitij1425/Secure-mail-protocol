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


def test_redacted_stix_export_is_valid_and_leaks_no_addresses(client):
    """Regression: redacted pseudonyms (ip-001) crashed the STIX export with a 500."""
    stix2 = pytest.importorskip("stix2")
    cid = up(client, "real_remediation_before.pcap")
    r = client.get(f"/captures/{cid}/stix?redact=true")
    assert r.status_code == 200, r.text
    parsed = stix2.parse(r.content, allow_custom=True)
    types = {o["type"] for o in parsed.objects}
    assert "x-securemailscope-redacted-session" in types
    assert not types & {"ipv4-addr", "ipv6-addr", "network-traffic", "indicator"}
    assert b"10.77.0.50" not in r.content
    assert r.content == client.get(f"/captures/{cid}/stix?redact=true").content


def test_redacted_download_names_do_not_reveal_capture_filename(client):
    cid = up(client, "real_remediation_before.pcap")
    for url in (f"/captures/{cid}/bundle?redact=true", f"/captures/{cid}/stix?redact=true"):
        cd = client.get(url).headers["content-disposition"]
        assert "real_remediation_before" not in cd and "capture_" in cd, cd
    rid = client.post(f"/captures/{cid}/reports", params={"format": "json", "redact": True})
    assert rid.status_code < 400, rid.text
    cd = client.get(f"/reports/{rid.json()['report_id']}/download").headers["content-disposition"]
    assert "real_remediation_before" not in cd and "_redacted" in cd, cd
    raw = client.get(f"/captures/{cid}/bundle").headers["content-disposition"]
    assert "real_remediation_before" in raw


# ------------------------------------------------------------------ annotations (notes / report selection)
def test_annotations_validate_targets_and_persist(client):
    cid = up(client, "real_remediation_before.pcap")
    f = client.get(f"/captures/{cid}/findings").json()[0]
    s = client.get(f"/captures/{cid}/sessions").json()[0]
    fp = client.get(f"/captures/{cid}/certificate-inventory").json()[0]["fingerprint_sha256"]
    for ttype, tid in (("capture", cid), ("finding", f["finding_id"]), ("session", s["session_id"]),
                       ("certificate", fp)):
        r = client.post(f"/captures/{cid}/annotations", json={"target_type": ttype, "target_id": tid, "text": f"note {ttype}"})
        assert r.status_code == 201, r.text
    assert client.post(f"/captures/{cid}/annotations",
                       json={"target_type": "finding", "target_id": "nope", "text": "x"}).status_code == 422
    assert client.post(f"/captures/{cid}/annotations",
                       json={"target_type": "bogus", "target_id": cid, "text": "x"}).status_code == 422
    assert client.post(f"/captures/{cid}/annotations",
                       json={"target_type": "capture", "target_id": cid, "text": "   "}).status_code == 422
    assert client.post(f"/captures/{cid}/annotations",
                       json={"target_type": "capture", "target_id": cid, "text": "x" * 4001}).status_code == 422
    notes = client.get(f"/captures/{cid}/annotations").json()
    assert len(notes) == 4
    only = client.get(f"/captures/{cid}/annotations", params={"target_type": "finding"}).json()
    assert [n["target_id"] for n in only] == [f["finding_id"]]
    nid = notes[0]["id"]
    assert client.patch(f"/annotations/{nid}", json={"include_in_report": True}).json()["include_in_report"] is True
    assert client.delete(f"/annotations/{nid}").status_code == 204
    assert client.delete(f"/annotations/{nid}").status_code == 404
    # analyst metadata never changes findings or the score
    before = client.get(f"/captures/{cid}").json()["posture_score"]
    assert client.get(f"/captures/{cid}").json()["posture_score"] == before


def test_selected_annotations_appear_in_reports_and_are_redacted(client):
    cid = up(client, "real_remediation_before.pcap")
    f = client.get(f"/captures/{cid}/findings").json()[0]
    client.post(f"/captures/{cid}/annotations", json={"target_type": "finding", "target_id": f["finding_id"],
                "text": "Owner confirmed relay 10.77.0.50 is scheduled for replacement", "include_in_report": True})
    client.post(f"/captures/{cid}/annotations", json={"target_type": "capture", "target_id": cid,
                "text": "internal only - not selected"})
    outs = {}
    for fmt in ("json", "html"):
        for redact in (False, True):
            rep = client.post(f"/captures/{cid}/reports", params={"format": fmt, "redact": redact}).json()
            outs[(fmt, redact)] = client.get(f"/reports/{rep['report_id']}/download").text
    assert "scheduled for replacement" in outs[("html", False)] and "Appendix" in outs[("html", False)]
    assert "internal only" not in outs[("html", False)] and "internal only" not in outs[("json", False)]
    doc = json.loads(outs[("json", False)])
    assert doc["analyst_annotations"][0]["target"].startswith(f["rule_id"])
    for fmt in ("json", "html"):
        assert "10.77.0.50" in outs[(fmt, False)]
        assert "10.77.0.50" not in outs[(fmt, True)] and "scheduled for replacement" in outs[(fmt, True)]
    # without selections the report has no appendix
    cid2 = up(client, "real_remediation_after.pcap")
    rep = client.post(f"/captures/{cid2}/reports", params={"format": "json"}).json()
    assert "analyst_annotations" not in json.loads(client.get(f"/reports/{rep['report_id']}/download").text)


def test_pdf_report_has_the_same_14_sections_and_appendix(client):
    pypdf = pytest.importorskip("pypdf")
    cid = up(client, "real_remediation_before.pcap")
    client.post(f"/captures/{cid}/annotations", json={"target_type": "capture", "target_id": cid,
                "text": "Selected for the report", "include_in_report": True})
    rep = client.post(f"/captures/{cid}/reports", params={"format": "pdf"}).json()
    data = client.get(f"/reports/{rep['report_id']}/download").content
    text = " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(data)).pages)
    heads = ["1. Executive summary", "2. Capture metadata", "3. Security posture", "4. Protocol summary",
             "5. TLS summary", "6. Certificate summary", "7. Findings", "8. Affected sessions", "9. Anomalies",
             "10. Evidence timeline", "11. Recommendations", "12. Methodology", "13. Limitations", "14. Integrity",
             "Appendix A"]
    pos = [text.find(h) for h in heads]
    assert all(p >= 0 for p in pos), dict(zip(heads, pos))
    assert pos == sorted(pos)


# ------------------------------------------------------------------ posture trend
def test_trend_links_analyses_that_share_a_server(client):
    before = up(client, "real_remediation_before.pcap")
    after = up(client, "real_remediation_after.pcap")
    other = up(client, "real_imaps_tls13.pcap")
    trend = client.get(f"/captures/{after}/trend").json()
    ids = [t["capture_id"] for t in trend]
    assert set(ids) == {before, after} and other not in ids
    assert ids.index(before) < ids.index(after)  # ordered by capture time
    by = {t["capture_id"]: t for t in trend}
    assert by[after]["is_selected"] and by[before]["shared_servers"] == ["SMTP 10.77.0.50:587"]
    assert by[before]["severe_findings_count"] > by[after]["severe_findings_count"] == 0
    assert by[before]["posture_score"] < by[after]["posture_score"]
    assert client.get("/captures/does-not-exist/trend").status_code == 404


def test_hostile_note_text_is_escaped_in_reports(client):
    cid = up(client, "real_remediation_after.pcap")
    payload = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    client.post(f"/captures/{cid}/annotations", json={"target_type": "capture", "target_id": cid,
                "text": payload, "include_in_report": True})
    rep = client.post(f"/captures/{cid}/reports", params={"format": "html"}).json()
    html = client.get(f"/reports/{rep['report_id']}/download").text
    assert payload not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    rep = client.post(f"/captures/{cid}/reports", params={"format": "pdf"}).json()
    assert client.get(f"/reports/{rep['report_id']}/download").content.startswith(b"%PDF")


# ------------------------------------------------------------------ compare: per-session ML anomaly changes
FIXTURES = Path(__file__).parent / "robustness" / "fixtures" / "pcaps"


def up_fixture(client, name, policy="balanced"):
    r = client.post("/analyze", files={"file": (name, (FIXTURES / name).read_bytes())}, data={"policy": policy})
    assert r.status_code == 200, r.text
    return r.json()["capture_id"]


def test_compare_lists_anomalous_sessions_new_resolved_persisting(client):
    mixed = up_fixture(client, "ml_mixed_estate.pcap")          # 1 ML-anomalous session (legacy TLS 1.0 server)
    mixed_again = up_fixture(client, "ml_mixed_estate.pcap")    # same file re-analysed
    clean = up(client, "real_remediation_after.pcap")          # different system, no anomaly

    same = client.get("/compare", params={"a": mixed, "b": mixed_again}).json()["anomaly_sessions"]
    assert len(same["persisting"]) == 1 and not same["new"] and not same["resolved"]
    p = same["persisting"][0]
    assert p["match"] == "same session" and p["a"]["stream_id"] == p["b"]["stream_id"]
    b = p["b"]
    assert b["protocol"] == "SMTP" and b["server"].endswith(":25") and b["anomaly_level"] in ("mild", "moderate", "severe")
    assert b["properties"]["tls_version"] == "TLSv1.0" and b["properties"]["certificate_key"] == "RSA 1024"
    assert "Weaker than this capture's norm" in b["explanation"]

    gone = client.get("/compare", params={"a": mixed, "b": clean}).json()["anomaly_sessions"]
    assert len(gone["resolved"]) == 1 and not gone["new"] and not gone["persisting"]
    assert gone["resolved"][0]["in_other"] == "not observed"

    appeared = client.get("/compare", params={"a": clean, "b": mixed}).json()["anomaly_sessions"]
    assert len(appeared["new"]) == 1 and appeared["new"][0]["in_other"] == "not observed"
    # the count summary stays consistent with the per-session lists
    full = client.get("/compare", params={"a": clean, "b": mixed}).json()
    assert full["anomalies"]["delta"] == len(appeared["new"]) - len(appeared["resolved"])


# ------------------------------------------------------------------ report preview
def test_report_preview_is_the_real_report(client):
    cid = up(client, "real_remediation_before.pcap", policy="strict")
    pv = client.get(f"/captures/{cid}/report-preview").json()
    titles = [s["title"] for s in pv["sections"]]
    assert [s["number"] for s in pv["sections"]] == [str(i) for i in range(1, 15)]
    assert titles[0] == "Executive summary" and titles[-1] == "Integrity"
    assert pv["mode"] == "RAW" and pv["policy_profile"] == "strict"
    cap = client.get(f"/captures/{cid}").json()
    assert pv["score"] == cap["posture_score"] and pv["findings"] == cap["findings_count"]
    assert pv["capture_sha256"] == cap["file_hash"] and "10.77.0.50" in pv["html"]
    # byte-identical to the HTML report a download produces
    rep = client.post(f"/captures/{cid}/reports", params={"format": "html"}).json()
    assert client.get(f"/reports/{rep['report_id']}/download").content.decode("utf-8") == pv["html"]
    assert rep["sha256"] == pv["sha256"]


def test_report_preview_redacted_and_with_analyst_appendix(client):
    cid = up(client, "real_remediation_before.pcap")
    red = client.get(f"/captures/{cid}/report-preview", params={"redact": True}).json()
    assert red["mode"] == "REDACTED" and "10.77.0.50" not in red["html"] and red["filename"] != "real_remediation_before.pcap"
    assert not any(s["number"] == "A" for s in red["sections"])
    client.post(f"/captures/{cid}/annotations", json={"target_type": "capture", "target_id": cid,
                "text": "Include me", "include_in_report": True})
    pv = client.get(f"/captures/{cid}/report-preview").json()
    assert pv["sections"][-1]["number"] == "A" and pv["selected_annotations"] == 1 and "Include me" in pv["html"]
    assert client.get("/captures/nope/report-preview").status_code == 404
