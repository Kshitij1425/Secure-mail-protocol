"""
M11 Tests: Feature Extraction and Anomaly Detection.

Validates feature extraction from TLS sessions and Isolation Forest anomaly detection.
"""
import pytest
import numpy as np
from datetime import datetime, timezone, timedelta

from securemailscope.ml.feature_extractor import (
    FeatureExtractor,
    SessionFeatures,
    TLSVersionOrdinal,
)
from securemailscope.ml.anomaly_detector import (
    AnomalyDetectionEngine,
    IsolationForestAnomalyDetector,
    AnomalyLevel,
)
from securemailscope.tls.parser import TLSSessionData
from securemailscope.certificates.analyzer import CertificateDetails
from securemailscope.protocols.detector import EmailProtocol


# ============================================================================
# Helper Functions
# ============================================================================

def _make_cert(**kwargs):
    """Helper to create a CertificateDetails with default fields."""
    defaults = {
        "fingerprint_sha256": "a" * 64,
        "subject": "CN=Test",
        "issuer": "CN=CA",
        "serial_number": "123",
        "not_before": datetime.now(timezone.utc) - timedelta(days=30),
        "not_after": datetime.now(timezone.utc) + timedelta(days=365),
        "is_expired": False,
        "is_not_yet_valid": False,
        "is_self_signed": False,
        "public_key_algorithm": "RSA",
        "public_key_size_bits": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "san_list": [],
        "weak_key": False,
        "weak_signature": False,
    }
    defaults.update(kwargs)
    return CertificateDetails(**defaults)


def create_mock_session_features(
    session_id: str,
    tls_version: float = 5.0,
    cipher_strength: float = 95.0,
    duration: float = 2.5,
    packet_count: float = 15.0,
    cert_age: float = 30.0,
    cert_validity: float = 365.0,
    key_size: float = 2048.0,
    has_pfs: float = 1.0,
    sig_strength: float = 95.0,
    chain_depth: float = 1.0,
) -> SessionFeatures:
    """Helper to create mock SessionFeatures with configurable parameters."""
    return SessionFeatures(
        session_id=session_id,
        protocol="SMTP",
        tls_version_ordinal=tls_version,
        cipher_strength=cipher_strength,
        certificate_key_size=key_size,
        certificate_age_days=cert_age,
        certificate_validity_days=cert_validity,
        session_duration_seconds=duration,
        packet_count=packet_count,
        has_forward_secrecy=has_pfs,
        signature_algorithm_strength=sig_strength,
        certificate_chain_depth=chain_depth,
    )


# ============================================================================
# Feature Extraction Tests
# ============================================================================

def test_extract_tls_version_ordinal():
    """Test TLS version to ordinal mapping."""
    assert FeatureExtractor.extract_tls_version_ordinal("TLS 1.3") == 5.0
    assert FeatureExtractor.extract_tls_version_ordinal("TLS 1.2") == 4.0
    assert FeatureExtractor.extract_tls_version_ordinal("TLS 1.0") == 2.0
    assert FeatureExtractor.extract_tls_version_ordinal("SSL 3.0") == 1.0
    assert FeatureExtractor.extract_tls_version_ordinal(None) == 0.0
    # Also accept TLSv1.x format used by TLSParser
    assert FeatureExtractor.extract_tls_version_ordinal("TLSv1.3") == 5.0
    assert FeatureExtractor.extract_tls_version_ordinal("TLSv1.2") == 4.0


def test_extract_cipher_strength():
    """Test cipher suite strength estimation."""
    # TLS 1.3 ciphers (should return 95.0)
    assert FeatureExtractor.extract_cipher_strength("TLS_AES_256_GCM_SHA384") == 95.0
    assert FeatureExtractor.extract_cipher_strength("TLS_CHACHA20_POLY1305_SHA256") == 95.0

    # Modern with PFS
    assert FeatureExtractor.extract_cipher_strength("ECDHE-RSA-AES256-GCM-SHA384") == 90.0
    assert FeatureExtractor.extract_cipher_strength("DHE-RSA-AES128-SHA") == 90.0

    # Legacy but acceptable (3DES)
    assert FeatureExtractor.extract_cipher_strength("DES-CBC3-SHA") == 50.0

    # Weak
    assert FeatureExtractor.extract_cipher_strength("RC4-SHA") == 25.0

    # Broken
    assert FeatureExtractor.extract_cipher_strength("EXP-DES-CBC-SHA") == 10.0
    assert FeatureExtractor.extract_cipher_strength("NULL-SHA256") == 10.0
    assert FeatureExtractor.extract_cipher_strength("TLS_RSA_WITH_AES_128_CBC_SHA") == 70.0


def test_extract_forward_secrecy():
    """Test forward secrecy detection."""
    assert FeatureExtractor.extract_forward_secrecy("ECDHE-RSA-AES256-GCM-SHA384") == 1.0
    assert FeatureExtractor.extract_forward_secrecy("DHE-RSA-AES128-SHA") == 1.0
    assert FeatureExtractor.extract_forward_secrecy("RSA-AES256-GCM-SHA384") == 0.0
    assert FeatureExtractor.extract_forward_secrecy(None) == 0.0


def test_extract_signature_strength():
    """Test signature algorithm strength estimation."""
    cert_sha256 = _make_cert(signature_algorithm="sha256WithRSAEncryption")
    assert FeatureExtractor.extract_signature_strength(cert_sha256) == 95.0

    cert_sha1 = _make_cert(signature_algorithm="sha1WithRSAEncryption")
    assert FeatureExtractor.extract_signature_strength(cert_sha1) == 40.0

    cert_md5 = _make_cert(signature_algorithm="md5WithRSAEncryption")
    assert FeatureExtractor.extract_signature_strength(cert_md5) == 10.0


def test_extract_certificate_age():
    """Test certificate age calculation from not_before."""
    issued_30_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    cert = _make_cert(not_before=issued_30_days_ago)
    age = FeatureExtractor.extract_certificate_age(cert)
    assert 29 <= age <= 31


def test_extract_certificate_validity():
    """Test certificate validity period calculation from not_after."""
    expires_in_365_days = datetime.now(timezone.utc) + timedelta(days=365)
    cert = _make_cert(not_after=expires_in_365_days)
    validity = FeatureExtractor.extract_certificate_validity(cert)
    assert 364 <= validity <= 366


def test_extract_from_tls_session_complete():
    """Test full feature extraction from a complete TLS session."""
    # Build TLSSessionData using actual dataclass fields
    session = TLSSessionData(
        client_version=None,
        server_version="TLSv1.3",
        cipher_suite_hex=None,
        cipher_suite_name="TLS_AES_256_GCM_SHA384",
        client_supported_ciphers=[],
        certificates=[],
        sni=None,
        handshake_complete=True,
        alerts=[],
        has_forward_secrecy=True,
    )

    cert = _make_cert(
        subject="CN=mail.example.com",
        serial_number="123456",
        signature_algorithm="sha256WithRSAEncryption",
        public_key_size_bits=2048,
    )

    features = FeatureExtractor.extract_from_tls_session(
        session_id="test_session_1",
        protocol=EmailProtocol.SMTP,
        tls_data=session,
        certs=[cert],
        packet_count=15,
        session_duration_seconds=2.5
    )

    assert features is not None
    assert features.session_id == "test_session_1"
    assert features.protocol == "SMTP"
    assert features.tls_version_ordinal == 5.0  # TLSv1.3
    assert features.cipher_strength == 95.0
    assert features.certificate_key_size == 2048.0
    assert features.packet_count == 15.0
    assert features.session_duration_seconds == 2.5
    assert features.has_forward_secrecy == 1.0  # TLS 1.3 has implicit FS
    assert features.signature_algorithm_strength == 95.0
    assert features.certificate_chain_depth == 1.0


def test_session_features_to_numpy():
    """Test converting SessionFeatures to numpy array."""
    features = SessionFeatures(
        session_id="test",
        protocol="SMTP",
        tls_version_ordinal=5.0,
        cipher_strength=95.0,
        certificate_key_size=2048.0,
        certificate_age_days=30.0,
        certificate_validity_days=365.0,
        session_duration_seconds=2.5,
        packet_count=15.0,
        has_forward_secrecy=1.0,
        signature_algorithm_strength=95.0,
        certificate_chain_depth=1.0,
    )

    arr = features.to_numpy_array()
    assert isinstance(arr, np.ndarray)
    assert arr.shape == (10,)
    assert arr[0] == 5.0  # tls_version_ordinal
    assert arr[1] == 95.0  # cipher_strength


def test_extract_from_tls_session_no_data():
    """Test that None tls_data returns None."""
    result = FeatureExtractor.extract_from_tls_session(
        session_id="test",
        protocol=EmailProtocol.SMTP,
        tls_data=None,
        certs=[],
    )
    assert result is None


# ============================================================================
# Anomaly Detection Tests
# ============================================================================

def test_isolation_forest_training():
    """Test training Isolation Forest with normal sessions."""
    detector = IsolationForestAnomalyDetector(contamination=0.1)

    normal_sessions = [
        create_mock_session_features(f"session_{i}", tls_version=5.0, cipher_strength=95.0)
        for i in range(10)
    ]

    success = detector.fit(normal_sessions)
    assert success is True
    assert detector.model is not None


def test_isolation_forest_insufficient_data():
    """Test that training fails with insufficient data."""
    detector = IsolationForestAnomalyDetector()

    sessions = [
        create_mock_session_features("s1"),
        create_mock_session_features("s2"),
    ]

    success = detector.fit(sessions)
    assert success is False
    assert detector.model is None


def test_anomaly_detection_normal_session():
    """Test that normal sessions are classified as normal."""
    detector = IsolationForestAnomalyDetector(contamination=0.1)

    normal_sessions = [
        create_mock_session_features(
            f"session_{i}",
            tls_version=5.0,
            cipher_strength=95.0,
            duration=2.0 + (i % 5) * 0.2,
            packet_count=10.0 + (i % 10),
            cert_age=20.0 + (i % 20),
            cert_validity=300.0 + (i % 50),
        )
        for i in range(50)
    ]
    detector.fit(normal_sessions)

    test_session = create_mock_session_features(
        "test_normal",
        tls_version=5.0,
        cipher_strength=95.0,
        duration=2.4,
        packet_count=14.0,
        cert_age=25.0,
        cert_validity=320.0,
    )
    result = detector.detect(test_session)

    assert result.is_anomaly is False
    assert result.anomaly_level == AnomalyLevel.NORMAL
    assert result.session_id == "test_normal"


def test_anomaly_detection_untrained_returns_normal():
    """Test that an untrained detector classifies everything as normal."""
    detector = IsolationForestAnomalyDetector()
    assert detector.model is None

    test_session = create_mock_session_features("test")
    result = detector.detect(test_session)

    assert result.is_anomaly is False
    assert result.anomaly_level == AnomalyLevel.NORMAL
    assert "untrained" in result.explanation.lower()


def test_anomaly_detection_outlier_session():
    """Test that outlier sessions are flagged as anomalies."""
    detector = IsolationForestAnomalyDetector(contamination=0.1)

    normal_sessions = [
        create_mock_session_features(
            f"session_{i}",
            tls_version=5.0,
            cipher_strength=95.0,
            duration=2.0 + (i % 5) * 0.2,
            packet_count=10.0 + (i % 10),
            cert_age=20.0 + (i % 20),
            cert_validity=300.0 + (i % 50),
        )
        for i in range(50)
    ]
    detector.fit(normal_sessions)

    # Create outlier: TLS 1.0 with weak cipher (very different from training)
    outlier_session = SessionFeatures(
        session_id="outlier",
        protocol="SMTP",
        tls_version_ordinal=2.0,  # TLS 1.0
        cipher_strength=25.0,     # Weak (RC4)
        certificate_key_size=1024.0,  # Weak key
        certificate_age_days=1000.0,  # Old cert
        certificate_validity_days=-30.0,  # Expired
        session_duration_seconds=10.0,
        packet_count=100.0,
        has_forward_secrecy=0.0,
        signature_algorithm_strength=40.0,  # SHA1
        certificate_chain_depth=1.0,
    )

    result = detector.detect(outlier_session)

    assert result.is_anomaly is True
    assert result.anomaly_level in [AnomalyLevel.MILD, AnomalyLevel.MODERATE, AnomalyLevel.SEVERE]
    assert result.session_id == "outlier"
    assert result.anomaly_score < 0.0


def test_anomaly_detection_engine_training():
    """Test AnomalyDetectionEngine training workflow."""
    engine = AnomalyDetectionEngine(contamination=0.1)

    sessions = []
    for i in range(15):
        tls_data = TLSSessionData(
            client_version=None,
            server_version="TLSv1.3",
            cipher_suite_hex=None,
            cipher_suite_name="TLS_AES_256_GCM_SHA384",
            client_supported_ciphers=[],
            certificates=[],
            sni=None,
            handshake_complete=True,
            alerts=[],
            has_forward_secrecy=True,
        )
        cert = _make_cert(
            subject=f"CN=mail{i}.example.com",
            serial_number=str(i),
        )
        sessions.append({
            "session_id": f"session_{i}",
            "tls_data": tls_data,
            "certs": [cert],
            "packet_count": 10,
            "duration": 2.0
        })

    success = engine.train_on_sessions(sessions, EmailProtocol.SMTP)
    assert success is True
    assert engine.trained_sessions_count == 15


def test_anomaly_detection_engine_detect():
    """Test AnomalyDetectionEngine detection workflow."""
    engine = AnomalyDetectionEngine(contamination=0.1)

    sessions = []
    for i in range(15):
        tls_data = TLSSessionData(
            client_version=None,
            server_version="TLSv1.3",
            cipher_suite_hex=None,
            cipher_suite_name="TLS_AES_256_GCM_SHA384",
            client_supported_ciphers=[],
            certificates=[],
            sni=None,
            handshake_complete=True,
            alerts=[],
            has_forward_secrecy=True,
        )
        cert = _make_cert(
            subject=f"CN=mail{i}.example.com",
            serial_number=str(i),
        )
        sessions.append({
            "session_id": f"session_{i}",
            "tls_data": tls_data,
            "certs": [cert],
            "packet_count": 10,
            "duration": 2.0
        })

    engine.train_on_sessions(sessions, EmailProtocol.SMTP)

    tls_data_test = TLSSessionData(
        client_version=None,
        server_version="TLSv1.3",
        cipher_suite_hex=None,
        cipher_suite_name="TLS_AES_128_GCM_SHA256",
        client_supported_ciphers=[],
        certificates=[],
        sni=None,
        handshake_complete=True,
        alerts=[],
        has_forward_secrecy=True,
    )
    cert_test = _make_cert(subject="CN=test.example.com", serial_number="999")

    result = engine.detect_anomaly(
        session_id="test_session",
        protocol=EmailProtocol.SMTP,
        tls_data=tls_data_test,
        certs=[cert_test],
        packet_count=12,
        duration=2.2
    )

    assert result is not None
    assert result.session_id == "test_session"
    assert result.is_anomaly is False


def test_anomaly_detection_engine_summary():
    """Test AnomalyDetectionEngine summary output."""
    engine = AnomalyDetectionEngine(contamination=0.15)

    summary = engine.get_summary()
    assert summary["engine"] == "IsolationForest"
    assert summary["trained"] is False
    assert summary["trained_sessions"] == 0
    assert summary["contamination"] == 0.15
    assert summary["feature_count"] == 10


def test_anomaly_result_fields():
    """Test AnomalyResult has all expected fields."""
    features = create_mock_session_features("test")
    result = IsolationForestAnomalyDetector().detect(features)

    assert result.session_id == "test"
    assert isinstance(result.is_anomaly, bool)
    assert isinstance(result.anomaly_score, float)
    assert isinstance(result.anomaly_level, AnomalyLevel)
    assert isinstance(result.features, dict)
    assert isinstance(result.explanation, str)


def test_anomaly_detection_batch():
    """Test batch anomaly detection."""
    detector = IsolationForestAnomalyDetector(contamination=0.1)

    normal_sessions = [
        create_mock_session_features(
            f"session_{i}",
            tls_version=5.0,
            cipher_strength=95.0,
            duration=2.0 + (i % 5) * 0.2,
            packet_count=10.0 + (i % 10),
            cert_age=20.0 + (i % 20),
            cert_validity=300.0 + (i % 50),
        )
        for i in range(50)
    ]
    detector.fit(normal_sessions)

    test_sessions = [
        create_mock_session_features(
            f"test_{i}",
            tls_version=5.0,
            cipher_strength=95.0,
            duration=2.1 + i * 0.1,
            packet_count=11.0 + i,
            cert_age=22.0 + i,
            cert_validity=310.0 + i,
        )
        for i in range(3)
    ]
    results = detector.detect_batch(test_sessions)

    assert len(results) == 3
    assert all(r.is_anomaly is False for r in results)
    assert all(r.anomaly_level == AnomalyLevel.NORMAL for r in results)


def test_anomaly_detection_unfitted_engine():
    """Test that AnomalyDetectionEngine returns normal when untrained."""
    engine = AnomalyDetectionEngine()
    assert not engine.detector.model

    result = engine.detect_anomaly(
        session_id="test",
        protocol=EmailProtocol.SMTP,
        tls_data=TLSSessionData(
            client_version=None,
            server_version="TLSv1.3",
            cipher_suite_hex=None,
            cipher_suite_name="TLS_AES_256_GCM_SHA384",
            client_supported_ciphers=[],
            certificates=[],
            sni=None,
            handshake_complete=True,
            alerts=[],
            has_forward_secrecy=True,
        ),
        certs=[],
    )

    # Without training, detector returns NORMAL for everything
    assert result is not None
    assert result.is_anomaly is False


def test_anomaly_level_classification():
    """Test that anomaly levels are correctly classified."""
    detector = IsolationForestAnomalyDetector(contamination=0.1)

    # Train on normal sessions
    normal_sessions = [
        create_mock_session_features(
            f"session_{i}",
            tls_version=5.0,
            cipher_strength=95.0,
            duration=2.0 + (i % 5) * 0.2,
            packet_count=10.0 + (i % 10),
            cert_age=20.0 + (i % 20),
            cert_validity=300.0 + (i % 50),
        )
        for i in range(50)
    ]
    detector.fit(normal_sessions)

    # Outlier anomaly: significantly different features
    outlier_anomaly = SessionFeatures(
        session_id="mild",
        protocol="SMTP",
        tls_version_ordinal=2.0,
        cipher_strength=25.0,
        certificate_key_size=1024.0,
        certificate_age_days=1000.0,
        certificate_validity_days=-30.0,
        session_duration_seconds=10.0,
        packet_count=100.0,
        has_forward_secrecy=0.0,
        signature_algorithm_strength=40.0,
        certificate_chain_depth=1.0,
    )
    result = detector.detect(outlier_anomaly)
    if result.is_anomaly:
        assert result.anomaly_level in [AnomalyLevel.MILD, AnomalyLevel.MODERATE, AnomalyLevel.SEVERE]

    # Normal session
    normal = create_mock_session_features(
        "normal",
        tls_version=5.0,
        cipher_strength=95.0,
        duration=2.3,
        packet_count=12.0,
        cert_age=24.0,
        cert_validity=315.0,
    )
    result = detector.detect(normal)
    assert result.is_anomaly is False


def test_cipher_strength_edge_cases():
    """Test cipher strength estimation edge cases."""
    # None cipher
    assert FeatureExtractor.extract_cipher_strength(None) == 50.0

    # Empty string
    assert FeatureExtractor.extract_cipher_strength("") == 50.0

    # Unknown cipher (falls through to default)
    assert FeatureExtractor.extract_cipher_strength("UNKNOWN_CIPHER") == 70.0

def test_batch_detection_matches_single_detection():
    """The batched scoring path used by the pipeline must equal per-session detect()."""
    detector = IsolationForestAnomalyDetector(contamination="auto")
    sessions = [create_mock_session_features(f"s{i}", tls_version=5.0 if i % 9 else 2.0,
                                             cipher_strength=95.0 if i % 9 else 25.0, packet_count=10.0 + i % 4)
                for i in range(40)]
    assert detector.fit(sessions)
    batch = detector.detect_batch(sessions)
    single = [detector.detect(s) for s in sessions]
    assert [(b.is_anomaly, round(b.anomaly_score, 9), b.anomaly_level) for b in batch] == \
           [(s.is_anomaly, round(s.anomaly_score, 9), s.anomaly_level) for s in single]
