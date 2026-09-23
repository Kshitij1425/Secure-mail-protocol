"""
M11 Anomaly Detector: Unsupervised anomaly detection on TLS sessions.

Uses Isolation Forest to identify unusual TLS session patterns without
overriding deterministic security findings from M8.

Anomalies are surfaced as supplementary insights, not blocking findings.
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import numpy as np
from enum import Enum

from securemailscope.ml.feature_extractor import SessionFeatures, FeatureExtractor
from securemailscope.tls.parser import TLSSessionData
from securemailscope.certificates.analyzer import CertificateDetails
from securemailscope.protocols.detector import EmailProtocol


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

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        try:
            from sklearn.ensemble import IsolationForest
            self.IsolationForest = IsolationForest
        except ImportError:
            raise ImportError(
                "scikit-learn required for M11 anomaly detection. "
                "Install with: pip install scikit-learn"
            )

        self.contamination = contamination
        self.random_state = random_state
        self.model = None
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
        return True

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

        score = self.model.score_samples(X)[0]
        anomaly_score_normalized = float(np.clip(score / 0.2, -1.0, 1.0))

        if not is_anomaly:
            level = AnomalyLevel.NORMAL
        elif anomaly_score_normalized < -0.75:
            level = AnomalyLevel.SEVERE
        elif anomaly_score_normalized < -0.25:
            level = AnomalyLevel.MODERATE
        else:
            level = AnomalyLevel.MILD

        explanation = self._generate_explanation(features, level)

        return AnomalyResult(
            session_id=features.session_id,
            is_anomaly=is_anomaly,
            anomaly_score=float(anomaly_score_normalized),
            anomaly_level=level,
            features=features.to_dict(),
            explanation=explanation
        )

    def detect_batch(self, session_features: List[SessionFeatures]) -> List[AnomalyResult]:
        """Detect anomalies in multiple sessions."""
        return [self.detect(f) for f in session_features]

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

    def __init__(self, contamination: float = 0.1):
        self.detector = IsolationForestAnomalyDetector(contamination=contamination)
        self.trained_sessions_count = 0

    def train_on_sessions(
        self,
        sessions: List[Dict[str, Any]],
        protocol: EmailProtocol,
    ) -> bool:
        """Train anomaly detector on a collection of sessions."""
        features_list = []

        for i, session in enumerate(sessions):
            tls_data = session.get("tls_data")
            certs = session.get("certs", [])

            features = FeatureExtractor.extract_from_tls_session(
                session_id=session.get("session_id", f"session_{i}"),
                protocol=protocol,
                tls_data=tls_data,
                certs=certs,
                packet_count=session.get("packet_count", 0),
                session_duration_seconds=session.get("duration", 0.0)
            )

            if features:
                features_list.append(features)

        if features_list:
            success = self.detector.fit(features_list)
            if success:
                self.trained_sessions_count = len(features_list)
            return success

        return False

    def detect_anomaly(
        self,
        session_id: str,
        protocol: EmailProtocol,
        tls_data: Optional[TLSSessionData],
        certs: List[CertificateDetails],
        packet_count: int = 0,
        duration: float = 0.0
    ) -> Optional[AnomalyResult]:
        """Detect anomalies in a single session."""
        features = FeatureExtractor.extract_from_tls_session(
            session_id=session_id,
            protocol=protocol,
            tls_data=tls_data,
            certs=certs,
            packet_count=packet_count,
            session_duration_seconds=duration
        )

        if not features:
            return None

        return self.detector.detect(features)

    def get_summary(self) -> Dict[str, Any]:
        """Get anomaly detection engine summary."""
        return {
            "engine": "IsolationForest",
            "trained": self.detector.model is not None,
            "trained_sessions": self.trained_sessions_count,
            "contamination": self.detector.contamination,
            "feature_count": len(self.detector.feature_names),
        }
