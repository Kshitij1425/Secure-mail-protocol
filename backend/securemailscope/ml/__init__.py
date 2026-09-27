"""
ML anomaly detection (supplementary)

Unsupervised anomaly detection layer for identifying unusual TLS session patterns.
Built on Isolation Forest, never changes the deterministic rule findings.
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
