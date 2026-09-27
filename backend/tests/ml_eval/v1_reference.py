"""Frozen copy of the v1 ML model (isolation-forest/1) for side-by-side evaluation. Do not edit."""
from securemailscope.tls.parser import TLSSessionData  # noqa: F401
from securemailscope.certificates.analyzer import CertificateDetails  # noqa: F401
from securemailscope.protocols.detector import EmailProtocol  # noqa: F401
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import numpy as np
from enum import Enum



class TLSVersionOrdinal(Enum):
    """Map TLS versions to ordinal values for feature extraction."""
    SSL_20 = 0
    SSL_30 = 1
    TLS_10 = 2
    TLS_11 = 3
    TLS_12 = 4
    TLS_13 = 5


@dataclass
class SessionFeatures:
    """Extracted numerical features from a single TLS session."""
    session_id: str
    protocol: str
    tls_version_ordinal: float
    cipher_strength: float
    certificate_key_size: float
    certificate_age_days: float
    certificate_validity_days: float
    session_duration_seconds: float
    packet_count: float
    has_forward_secrecy: float
    signature_algorithm_strength: float
    certificate_chain_depth: float

    def to_numpy_array(self) -> np.ndarray:
        """Convert to feature vector for ML models."""
        return np.array([
            self.tls_version_ordinal,
            self.cipher_strength,
            self.certificate_key_size,
            self.certificate_age_days,
            self.certificate_validity_days,
            self.session_duration_seconds,
            self.packet_count,
            self.has_forward_secrecy,
            self.signature_algorithm_strength,
            self.certificate_chain_depth,
        ], dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "tls_version_ordinal": float(self.tls_version_ordinal),
            "cipher_strength": float(self.cipher_strength),
            "certificate_key_size": float(self.certificate_key_size),
            "certificate_age_days": float(self.certificate_age_days),
            "certificate_validity_days": float(self.certificate_validity_days),
            "session_duration_seconds": float(self.session_duration_seconds),
            "packet_count": float(self.packet_count),
            "has_forward_secrecy": bool(self.has_forward_secrecy),
            "signature_algorithm_strength": float(self.signature_algorithm_strength),
            "certificate_chain_depth": float(self.certificate_chain_depth),
        }


class FeatureExtractor:
    """Extract ML features from TLS sessions."""

    @staticmethod
    def extract_tls_version_ordinal(tls_version: Optional[str]) -> float:
        """Convert TLS version string to ordinal value. Handles both TLS 1.3 and TLSv1.3 formats."""
        if not tls_version:
            return 0.0

        version_map = {
            "SSL 2.0": TLSVersionOrdinal.SSL_20.value,
            "SSL 3.0": TLSVersionOrdinal.SSL_30.value,
            "TLS 1.0": TLSVersionOrdinal.TLS_10.value,
            "TLS 1.1": TLSVersionOrdinal.TLS_11.value,
            "TLS 1.2": TLSVersionOrdinal.TLS_12.value,
            "TLS 1.3": TLSVersionOrdinal.TLS_13.value,
            "TLSv1.0": TLSVersionOrdinal.TLS_10.value,
            "TLSv1.1": TLSVersionOrdinal.TLS_11.value,
            "TLSv1.2": TLSVersionOrdinal.TLS_12.value,
            "TLSv1.3": TLSVersionOrdinal.TLS_13.value,
            "SSLv3": TLSVersionOrdinal.SSL_30.value,
        }
        return float(version_map.get(tls_version, 0.0))

    @staticmethod
    def extract_cipher_strength(cipher_suite: Optional[str]) -> float:
        """Estimate cipher suite strength from suite name. 0-100 scale."""
        if not cipher_suite:
            return 50.0

        suite_lower = cipher_suite.lower()

        # Check TLS 1.3 ciphers first (they contain "aes" or "chacha20" but
        # should return 95, not 70)
        if "tls_aes" in suite_lower or "chacha20" in suite_lower:
            return 95.0
        # Broken/export ciphers (must check DES before 3DES)
        if any(x in suite_lower for x in ["export", "null", "anon"]):
            return 10.0
        # DES-CBC3-SHA contains "des-cbc" but is actually 3DES (cbc3)
        if "des-cbc" in suite_lower and "cbc3" not in suite_lower and "3des" not in suite_lower:
            return 10.0
        # Weak (RC4, DSS variants)
        if "rc4" in suite_lower or "dss" in suite_lower:
            return 25.0
        # Legacy but acceptable (3DES / DES-CBC3 / Triple-DES / EDE)
        if "3des" in suite_lower or "cbc3" in suite_lower or "des3" in suite_lower or "ede" in suite_lower:
            return 50.0
        # Modern with forward secrecy (ECDHE, DHE)
        if any(x in suite_lower for x in ["ecdhe", "dhe"]):
            return 90.0
        # Modern AES without PFS
        if "aes" in suite_lower:
            return 70.0
        return 70.0

    @staticmethod
    def extract_key_size(cert: Optional[CertificateDetails]) -> float:
        """Extract RSA/ECDSA key size in bits."""
        if not cert or not hasattr(cert, 'public_key_size_bits'):
            return 0.0
        return float(cert.public_key_size_bits) if cert.public_key_size_bits else 0.0

    @staticmethod
    def extract_certificate_age(cert: Optional[CertificateDetails], reference_time=None) -> float:
        """Days since certificate issuance (from not_before) at ``reference_time`` (default: now)."""
        if not cert or not hasattr(cert, 'not_before') or not cert.not_before:
            return 0.0
        from datetime import datetime, timezone
        try:
            now = reference_time or datetime.now(timezone.utc)
            issued = cert.not_before
            if isinstance(issued, datetime):
                delta = now - issued
            else:
                delta = now - issued.replace(tzinfo=timezone.utc)
            return float(delta.days)
        except Exception:
            return 0.0

    @staticmethod
    def extract_certificate_validity(cert: Optional[CertificateDetails], reference_time=None) -> float:
        """Days until expiration (from not_after) at ``reference_time`` (default: now). Negative if expired."""
        if not cert or not hasattr(cert, 'not_after') or not cert.not_after:
            return 0.0
        from datetime import datetime, timezone
        try:
            now = reference_time or datetime.now(timezone.utc)
            expires = cert.not_after
            if isinstance(expires, datetime):
                delta = expires - now
            else:
                delta = expires.replace(tzinfo=timezone.utc) - now
            return float(delta.days)
        except Exception:
            return 0.0

    @staticmethod
    def extract_forward_secrecy(cipher_suite: Optional[str]) -> float:
        """Return 1.0 if cipher uses PFS (ECDHE, DHE, TLS 1.3 ciphers), 0.0 otherwise."""
        if not cipher_suite:
            return 0.0
        suite_lower = cipher_suite.lower()
        if any(x in suite_lower for x in ["ecdhe", "dhe", "tls_aes", "chacha20"]):
            return 1.0
        return 0.0

    @staticmethod
    def extract_signature_strength(cert: Optional[CertificateDetails]) -> float:
        """Estimate signature algorithm strength. 0-100 scale."""
        if not cert or not hasattr(cert, 'signature_algorithm') or not cert.signature_algorithm:
            return 50.0
        sig_algo_lower = cert.signature_algorithm.lower()
        if "md5" in sig_algo_lower or "md2" in sig_algo_lower:
            return 10.0
        if "sha1" in sig_algo_lower:
            return 40.0
        if any(x in sig_algo_lower for x in ["sha256", "sha384", "sha512"]):
            return 95.0
        if "ecdsa" in sig_algo_lower:
            return 90.0
        return 70.0

    @staticmethod
    def extract_certificate_chain_depth(certs: List[CertificateDetails]) -> float:
        """Return the depth of the certificate chain."""
        return float(len(certs)) if certs else 0.0

    @classmethod
    def extract_from_tls_session(
        cls,
        session_id: str,
        protocol: EmailProtocol,
        tls_data: Optional[TLSSessionData],
        certs: List[CertificateDetails],
        packet_count: int = 0,
        session_duration_seconds: float = 0.0,
        reference_time=None,
    ) -> Optional[SessionFeatures]:
        """
        Extract features from a complete TLS session.
        Returns None if insufficient data.

        ``reference_time`` anchors certificate age/validity (the capture time in the
        pipeline) so identical captures always yield identical features.
        """
        if not tls_data:
            return None

        tls_version_ord = cls.extract_tls_version_ordinal(tls_data.server_version)
        cipher_strength = cls.extract_cipher_strength(tls_data.cipher_suite_name)
        key_size = cls.extract_key_size(certs[0]) if certs else 0.0
        cert_age = cls.extract_certificate_age(certs[0], reference_time) if certs else 0.0
        cert_validity = cls.extract_certificate_validity(certs[0], reference_time) if certs else 0.0
        has_pfs = cls.extract_forward_secrecy(tls_data.cipher_suite_name)
        if tls_data.server_version == "TLSv1.3":
            has_pfs = 1.0
        sig_strength = cls.extract_signature_strength(certs[0]) if certs else 50.0
        chain_depth = cls.extract_certificate_chain_depth(certs)

        return SessionFeatures(
            session_id=session_id,
            protocol=protocol.name,
            tls_version_ordinal=tls_version_ord,
            cipher_strength=cipher_strength,
            certificate_key_size=key_size,
            certificate_age_days=cert_age,
            certificate_validity_days=cert_validity,
            session_duration_seconds=session_duration_seconds,
            packet_count=float(packet_count),
            has_forward_secrecy=has_pfs,
            signature_algorithm_strength=sig_strength,
            certificate_chain_depth=chain_depth,
        )

class AnomalyLevel(Enum):
    """Anomaly severity classification."""
    NORMAL = "normal"
    MILD = "mild"
    MODERATE = "moderate"
    SEVERE = "severe"


@dataclass
class AnomalyResult:
    """Result from anomaly detection on a single session."""
    session_id: str
    is_anomaly: bool
    anomaly_score: float  # -1.0 (very anomalous) to 1.0 (very normal)
    anomaly_level: AnomalyLevel
    features: Dict[str, float]
    explanation: str


class IsolationForestAnomalyDetector:
    """
    Unsupervised anomaly detection using Isolation Forest.

    Isolation Forest isolates anomalies by randomly selecting features and
    split values. Anomalies require fewer splits to isolate, resulting in
    shorter paths through the tree ensemble.

    NOT a replacement for M8 deterministic rules — purely supplementary.
    """

    MODEL_VERSION = "isolation-forest/1"

    def __init__(self, contamination=0.1, random_state: int = 42):
        try:
            from sklearn.ensemble import IsolationForest
            self.IsolationForest = IsolationForest
        except ImportError:
            raise ImportError(
                "scikit-learn is required for ML anomaly detection. "
                "Install with: pip install scikit-learn"
            )

        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self._baseline = None
        self.feature_names = [
            "tls_version_ordinal",
            "cipher_strength",
            "certificate_key_size",
            "certificate_age_days",
            "certificate_validity_days",
            "session_duration_seconds",
            "packet_count",
            "has_forward_secrecy",
            "signature_algorithm_strength",
            "certificate_chain_depth",
        ]

    def fit(self, session_features: List[SessionFeatures]) -> bool:
        """Train the anomaly detector on a set of sessions."""
        if not session_features or len(session_features) < 3:
            return False

        X = np.array([f.to_numpy_array() for f in session_features], dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1000.0, neginf=-1000.0)

        self.model = self.IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100
        )
        self.model.fit(X)
        # Per-feature value frequencies (values rounded to 6 decimals), computed once:
        # O(n) instead of scanning the baseline for every flagged session.
        self._baseline = []
        for i in range(X.shape[1]):
            vals, counts = np.unique(np.round(X[:, i].astype(np.float64), 6), return_counts=True)
            self._baseline.append((dict(zip(vals.tolist(), (counts / len(X)).tolist()))))
        return True

    def _rareness(self, features: SessionFeatures) -> str:
        """Name the features whose values are least common in the training baseline."""
        x = features.to_numpy_array()
        rare = []
        for i, name in enumerate(self.feature_names):
            share = self._baseline[i].get(round(float(x[i]), 6), 0.0)
            if share <= 0.2:
                rare.append((share, name, float(x[i])))
        rare.sort()
        if not rare:
            return "No single feature is rare; the combination is unusual."
        return "Rare in this capture: " + ", ".join(
            f"{n}={v:g} ({s * 100:.0f}% of sessions)" for s, n, v in rare[:3]) + "."

    def detect(self, features: SessionFeatures) -> AnomalyResult:
        """Detect anomalies in a single session."""
        if self.model is None:
            return AnomalyResult(
                session_id=features.session_id,
                is_anomaly=False,
                anomaly_score=1.0,
                anomaly_level=AnomalyLevel.NORMAL,
                features=features.to_dict(),
                explanation="No anomaly model available (untrained)."
            )

        X = features.to_numpy_array().reshape(1, -1)
        X = np.nan_to_num(X, nan=0.0, posinf=1000.0, neginf=-1000.0)

        prediction = self.model.predict(X)[0]
        is_anomaly = bool(prediction == -1)

        # decision_function: >0 inlier, <0 outlier (relative to the fitted threshold).
        decision = float(self.model.decision_function(X)[0])
        anomaly_score_normalized = float(np.clip(decision / 0.2, -1.0, 1.0))

        if not is_anomaly:
            level = AnomalyLevel.NORMAL
        elif anomaly_score_normalized < -0.75:
            level = AnomalyLevel.SEVERE
        elif anomaly_score_normalized < -0.25:
            level = AnomalyLevel.MODERATE
        else:
            level = AnomalyLevel.MILD

        explanation = self._generate_explanation(features, level)
        if is_anomaly and self._baseline is not None:
            explanation += " " + self._rareness(features)

        return AnomalyResult(
            session_id=features.session_id,
            is_anomaly=is_anomaly,
            anomaly_score=float(anomaly_score_normalized),
            anomaly_level=level,
            features=features.to_dict(),
            explanation=explanation
        )

    def detect_batch(self, session_features: List[SessionFeatures]) -> List[AnomalyResult]:
        """Score many sessions with one model call (identical results to ``detect``)."""
        if self.model is None or not session_features:
            return [self.detect(f) for f in session_features]
        X = np.nan_to_num(np.array([f.to_numpy_array() for f in session_features], dtype=np.float32),
                          nan=0.0, posinf=1000.0, neginf=-1000.0)
        decisions = self.model.decision_function(X)
        out = []
        for f, decision in zip(session_features, decisions):
            # predict() == -1 exactly when decision_function() < 0
            is_anomaly = bool(decision < 0)
            norm = float(np.clip(float(decision) / 0.2, -1.0, 1.0))
            if not is_anomaly:
                level = AnomalyLevel.NORMAL
            elif norm < -0.75:
                level = AnomalyLevel.SEVERE
            elif norm < -0.25:
                level = AnomalyLevel.MODERATE
            else:
                level = AnomalyLevel.MILD
            explanation = self._generate_explanation(f, level)
            if is_anomaly and self._baseline is not None:
                explanation += " " + self._rareness(f)
            out.append(AnomalyResult(session_id=f.session_id, is_anomaly=is_anomaly, anomaly_score=norm,
                                     anomaly_level=level, features=f.to_dict(), explanation=explanation))
        return out

    def _generate_explanation(self, features: SessionFeatures, level: AnomalyLevel) -> str:
        """Generate human-readable explanation for anomaly."""
        explanations = {
            AnomalyLevel.NORMAL: "Session exhibits normal TLS characteristics.",
            AnomalyLevel.MILD: (
                f"Mild anomaly: Session has unusual combination of "
                f"TLS {features.tls_version_ordinal:.0f}, "
                f"cipher strength {features.cipher_strength:.0f}%, "
                f"key size {features.certificate_key_size:.0f} bits."
            ),
            AnomalyLevel.MODERATE: (
                f"Moderate anomaly: Session significantly deviates from baseline. "
                f"Certificate validity in {features.certificate_validity_days:.0f} days, "
                f"chain depth {features.certificate_chain_depth:.0f}."
            ),
            AnomalyLevel.SEVERE: (
                f"Severe anomaly: Session is a strong outlier. "
                f"Highly unusual combination of protocol parameters: "
                f"version={features.tls_version_ordinal:.0f}, "
                f"key_size={features.certificate_key_size:.0f}, "
                f"age={features.certificate_age_days:.0f}d, "
                f"pfs={bool(features.has_forward_secrecy)}."
            ),
        }
        return explanations.get(level, "Unknown anomaly.")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize model metadata (not full model)."""
        return {
            "model_type": "IsolationForest",
            "model_version": self.MODEL_VERSION,
            "random_state": self.random_state,
            "contamination": self.contamination,
            "n_estimators": 100,
            "feature_names": self.feature_names,
            "is_trained": self.model is not None,
        }


class AnomalyDetectionEngine:
    """
    High-level anomaly detection orchestrator.

    Coordinates feature extraction and anomaly detection across the pipeline.
    Surfaces anomalies as supplementary insights without overriding M8 findings.
    """

    def __init__(self, contamination=0.1, min_training_sessions: int = 3):
        self.detector = IsolationForestAnomalyDetector(contamination=contamination)
        self.trained_sessions_count = 0
        self.min_training_sessions = min_training_sessions
        self.status = "not_trained"

    def train_on_sessions(
        self,
        sessions: List[Dict[str, Any]],
        protocol: EmailProtocol,
        reference_time=None,
    ) -> bool:
        """Train anomaly detector on a collection of sessions (unsupervised, per capture)."""
        features_list = []
        if len(sessions) < self.min_training_sessions:
            self.status = f"insufficient_sessions (<{self.min_training_sessions})"
            return False

        for i, session in enumerate(sessions):
            tls_data = session.get("tls_data")
            certs = session.get("certs", [])

            features = FeatureExtractor.extract_from_tls_session(
                session_id=session.get("session_id", f"session_{i}"),
                protocol=session.get("protocol", protocol),
                tls_data=tls_data,
                certs=certs,
                packet_count=session.get("packet_count", 0),
                session_duration_seconds=session.get("duration", 0.0),
                reference_time=reference_time,
            )

            if features:
                features_list.append(features)

        if features_list:
            success = self.detector.fit(features_list)
            if success:
                self.trained_sessions_count = len(features_list)
                self.status = "trained"
            return success

        return False

    def detect_anomaly(
        self,
        session_id: str,
        protocol: EmailProtocol,
        tls_data: Optional[TLSSessionData],
        certs: List[CertificateDetails],
        packet_count: int = 0,
        duration: float = 0.0,
        reference_time=None,
    ) -> Optional[AnomalyResult]:
        """Detect anomalies in a single session."""
        features = FeatureExtractor.extract_from_tls_session(
            session_id=session_id,
            protocol=protocol,
            tls_data=tls_data,
            certs=certs,
            packet_count=packet_count,
            session_duration_seconds=duration,
            reference_time=reference_time,
        )

        if not features:
            return None

        return self.detector.detect(features)

    def detect_anomalies(self, sessions: List[Dict[str, Any]], reference_time=None) -> List[AnomalyResult]:
        """Batch variant of ``detect_anomaly`` over the same row format as ``train_on_sessions``."""
        feats = []
        for row in sessions:
            f = FeatureExtractor.extract_from_tls_session(
                session_id=row["session_id"], protocol=row["protocol"], tls_data=row["tls_data"],
                certs=row["certs"], packet_count=row.get("packet_count", 0),
                session_duration_seconds=row.get("duration", 0.0), reference_time=reference_time)
            if f is not None:
                feats.append(f)
        return self.detector.detect_batch(feats)

    def get_summary(self) -> Dict[str, Any]:
        """Get anomaly detection engine summary."""
        return {
            "engine": "IsolationForest",
            "model_version": self.detector.MODEL_VERSION,
            "status": self.status,
            "trained": self.detector.model is not None,
            "trained_sessions": self.trained_sessions_count,
            "min_training_sessions": self.min_training_sessions,
            "contamination": self.detector.contamination,
            "random_state": self.detector.random_state,
            "feature_count": len(self.detector.feature_names),
            "training_scope": "unsupervised, fitted per capture on its own TLS sessions",
        }
