"""Behavioural tests of the posture outlier model (isolation-forest/2) and its evaluation."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from securemailscope.certificates.analyzer import CertificateDetails
from securemailscope.ml.anomaly_detector import AnomalyDetectionEngine
from securemailscope.ml.posture_model import key_security_bits, modulus_security_bits
from securemailscope.protocols.detector import EmailProtocol
from securemailscope.tls.ciphers import classify_cipher
from securemailscope.tls.parser import TLSSessionData

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SUITES = {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F, "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
          "TLS_AES_256_GCM_SHA384": 0x1302}


def cert(bits=2048, algo="RSA", expired=False, self_signed=False, days_left=200):
    return CertificateDetails(
        fingerprint_sha256="a" * 64, subject="CN=m", issuer="CN=ca", serial_number="1",
        not_before=NOW - timedelta(days=100), not_after=NOW + timedelta(days=-5 if expired else days_left),
        is_expired=expired, is_not_yet_valid=False, is_self_signed=self_signed, public_key_algorithm=algo,
        public_key_size_bits=bits, signature_algorithm="sha256WithRSAEncryption")


def row(i, version="TLSv1.2", suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", certs=None, group="x25519"):
    code = SUITES[suite]
    tls = TLSSessionData(server_version=version, cipher_suite_hex=code, cipher_suite_name=suite,
                         cipher=classify_cipher(code), key_exchange_group=group if "ECDHE" in suite or version == "TLSv1.3" else None)
    if certs is None:
        certs = [] if version == "TLSv1.3" else [cert()]
    return {"session_id": f"s{i}", "protocol": EmailProtocol.SMTP, "tls_data": tls, "certs": certs}


def flagged(rows):
    e = AnomalyDetectionEngine(min_training_sessions=5)
    assert e.train_on_sessions(rows, EmailProtocol.SMTP, reference_time=NOW)
    return {r.session_id: r for r in e.detect_anomalies(rows, reference_time=NOW)}


def test_security_bits_follow_nist_sp800_57():
    assert modulus_security_bits(1024) == 80 and modulus_security_bits(2048) == 112
    assert modulus_security_bits(3072) == 128 and modulus_security_bits(4096) == 128
    assert key_security_bits("EC (secp256r1)", 256) == 128 and key_security_bits("RSA", 0) is None


def test_healthy_minority_configurations_are_not_outliers():
    """v1 flagged ~98% of these (TLS 1.3 / stronger keys in a TLS 1.2 RSA-2048 fleet)."""
    rows = [row(i) for i in range(40)]
    rows += [row(40 + i, version="TLSv1.3", suite="TLS_AES_256_GCM_SHA384") for i in range(3)]
    rows += [row(50 + i, certs=[cert(4096)]) for i in range(3)]
    rows += [row(60 + i, certs=[cert(256, "EC (secp256r1)")]) for i in range(3)]
    res = flagged(rows)
    assert not any(r.is_anomaly for r in res.values())
    assert "not observable" in res["s40"].explanation  # TLS 1.3 certificate treated as neutral


def test_minority_weakness_is_flagged_and_explained():
    rows = [row(i) for i in range(40)] + [row(40, version="TLSv1.0", suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                                              certs=[cert(1024)])]
    res = flagged(rows)
    assert [s for s, r in res.items() if r.is_anomaly] == ["s40"]
    text = res["s40"].explanation
    assert "TLS version: TLS 1.0" in text and "Certificate key strength: 80-bit" in text


def test_minority_weak_certificate_in_mostly_tls13_capture_is_flagged():
    """Regression: the norm must not be defined by the few observable (weak) certificates."""
    rows = [row(i, version="TLSv1.3", suite="TLS_AES_256_GCM_SHA384") for i in range(30)]
    rows += [row(30 + i, certs=[cert(1024)]) for i in range(4)]
    res = flagged(rows)
    assert {s for s, r in res.items() if r.is_anomaly} == {f"s{30 + i}" for i in range(4)}


def test_stronger_than_norm_is_never_an_outlier_even_in_a_legacy_fleet():
    rows = [row(i, version="TLSv1.0", suite="TLS_RSA_WITH_AES_128_CBC_SHA", certs=[cert(1024)]) for i in range(30)]
    rows += [row(30 + i) for i in range(3)]  # modern servers in a legacy estate
    res = flagged(rows)
    assert not any(r.is_anomaly for r in res.values())
    assert all(res[f"s{30 + i}"].anomaly_score >= 0 for i in range(3))


def test_expired_and_self_signed_certificates_are_below_norm():
    rows = [row(i) for i in range(30)] + [row(30, certs=[cert(expired=True)]), row(31, certs=[cert(self_signed=True)])]
    res = flagged(rows)
    assert {s for s, r in res.items() if r.is_anomaly} == {"s30", "s31"}


def test_features_report_not_observable_as_null():
    rows = [row(i, version="TLSv1.3", suite="TLS_AES_256_GCM_SHA384") for i in range(6)]
    f = flagged(rows)["s0"].features
    assert f["certificate_key_security_bits"] is None and f["protocol_version"] == 5.0


POOL = Path(__file__).parent / "ml_eval" / "pool" / "pool_manifest.json"


@pytest.mark.skipif(not POOL.exists(), reason="labelled pool not generated")
def test_labelled_pool_evaluation_does_not_regress():
    """Guards the measured behaviour on real labelled lab sessions (see ML_DESIGN.md)."""
    from tests.ml_eval.evaluate import evaluate, load_pool
    pool, labels, ref = load_pool()
    factory = lambda: AnomalyDetectionEngine(min_training_sessions=5)  # noqa: E731
    for part, seed in (("A", 0), ("B", 100000)):
        r = evaluate(factory, pool, labels, ref, part, 60, seed)
        assert r["weak_recall"] >= 0.95, r
        assert r["precision"] >= 0.95, r
        assert r["false_positive_rate_minority_healthy"] <= 0.02, r
        assert r["clean_estates_with_any_flag"].startswith("0/"), r
    json.dumps(r)
