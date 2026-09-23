"""
M11: ML Anomaly Detection

Unsupervised anomaly detection layer for identifying unusual TLS session patterns.
Built on Isolation Forest, non-blocking to deterministic M8 security rules.
"""
from securemailscope.ml.feature_extractor import (
    FeatureExtractor,
    SessionFeatures,
    TLSVersionOrdinal,
)
from securemailscope.ml.anomaly_detector import (
    AnomalyDetectionEngine,
    IsolationForestAnomalyDetector,
    AnomalyResult,
    AnomalyLevel,
)

__all__ = [
    "FeatureExtractor",
    "SessionFeatures",
    "TLSVersionOrdinal",
    "AnomalyDetectionEngine",
    "IsolationForestAnomalyDetector",
    "AnomalyResult",
    "AnomalyLevel",
]
