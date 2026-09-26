"""
Real-capture validation: every fixture (TLS bytes produced by OpenSSL, TCP framing with
tracked sequence numbers) is analysed by the full pipeline and compared with its
ground truth: per-session protocol, STARTTLS state, negotiated TLS version, handshake
status, certificate count, reconstruction quality and the exact set of rule IDs.
"""
import json

import pytest

from tests.robustness.validate_fixtures import check_case, load_cases
from securemailscope.core.orchestrator import Orchestrator

CASES = load_cases()


def test_fixture_corpus_present():
    assert len(CASES) >= 28


@pytest.mark.parametrize("case", CASES, ids=[c["truth"]["name"] for c in CASES])
def test_fixture_matches_ground_truth(case):
    errors = check_case(case)
    assert not errors, "\n".join(errors)


def _case(name):
    return next(c for c in CASES if c["truth"]["name"] == name)


def test_implicit_tls_is_never_plaintext():
    """Regression: IMAPS/POP3S/SMTPS were reported as PLAINTEXT with a CRITICAL PROTO-001."""
    r = Orchestrator().analyze(str(_case("implicit_tls_mixed")["pcap"]))
    assert {s.dst_port for s in (x.stream for x in r.sessions)} == {993, 995, 465}
    for s in r.sessions:
        assert s.implicit_tls and s.starttls_state.name == "TLS_ESTABLISHED"
        assert not any(f.rule_id == "PROTO-001" for f in s.findings)


def test_tls13_certificates_not_claimed():
    """Regression: certificates were reported as extracted from TLS 1.3 sessions."""
    for name in ("smtp_starttls_tls13_secure", "layer_b_smtp_tls13_secure", "ipv6_smtp_tls13"):
        r = Orchestrator().analyze(str(_case(name)["pcap"]))
        s = r.sessions[0]
        assert s.tls_data.server_version == "TLSv1.3"
        assert s.tls_data.certificate_visibility == "encrypted_tls13"
        assert s.certificates == []
        assert r.posture.certificate_coverage_percent == 0.0  # reported as not observed, not "100% covered"


def test_no_email_traffic_is_unknown_not_excellent():
    r = Orchestrator().analyze(str(_case("unrelated_traffic")["pcap"]))
    assert r.email_session_count == 0 and r.reconstructed_stream_count == 3
    assert r.posture.overall_score is None and r.posture.status.value == "Unknown"


def test_chain_linkage_verified_cryptographically():
    r = Orchestrator().analyze(str(_case("smtp_starttls_tls12_chain")["pcap"]))
    s = r.sessions[0]
    assert s.chain["status"] == "linked"
    assert s.certificates[0].issued_by_next == "verified"
    assert s.certificates[0].is_self_signed is False
    assert all(c.trust_status == "unknown" for c in s.certificates)


def test_evidence_frames_point_into_capture():
    r = Orchestrator().analyze(str(_case("smtp_weak_deprecated")["pcap"]))
    total = r.packet_count
    for f in r.findings:
        assert f.evidence_frames and all(1 <= fr <= total for fr in f.evidence_frames)


def test_ml_flags_the_planted_outlier_only():
    r = Orchestrator().analyze(str(_case("ml_mixed_estate")["pcap"]))
    flagged = [a for a in r.anomalies if a.is_anomaly]
    assert len(r.anomalies) == 12
    assert [a.session_id for a in flagged] == [s.session_id for s in r.sessions if s.stream.client_ip == "10.10.9.9"]
    # ML is supplementary: scoring uses deterministic findings only
    assert r.posture.findings_count == len(r.findings)


def test_ml_is_reproducible_and_capture_local():
    orc = Orchestrator()
    a = orc.analyze(str(_case("ml_mixed_estate")["pcap"]))
    orc.analyze(str(_case("smtp_weak_deprecated")["pcap"]))  # must not leak model state
    b = orc.analyze(str(_case("ml_mixed_estate")["pcap"]))
    assert [(x.session_id, x.is_anomaly, x.anomaly_score) for x in a.anomalies] == \
           [(x.session_id, x.is_anomaly, x.anomaly_score) for x in b.anomalies]


def test_whole_analysis_deterministic():
    p = str(_case("implicit_tls_mixed")["pcap"])
    a, b = Orchestrator().analyze(p), Orchestrator().analyze(p)
    dump = lambda r: json.dumps([(f.finding_id, f.severity.value, f.evidence) for f in r.findings], default=str)
    assert dump(a) == dump(b) and a.posture.overall_score == b.posture.overall_score
