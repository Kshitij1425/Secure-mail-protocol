"""
Scoring Configuration for M9: Cryptographic Security Posture Scoring.

This module defines the policy version, dimension weights, severity mappings,
and scoring bands used by the SecureMailScope scoring engine.
"""
from dataclasses import dataclass, field
from typing import Dict, List
from enum import Enum


class ScoreStatus(Enum):
    """Human-readable status mapped from numeric scores."""
    EXCELLENT = "Excellent"
    GOOD = "Good"
    NEEDS_IMPROVEMENT = "Needs Improvement"
    POOR = "Poor"
    CRITICAL = "Critical"
    UNKNOWN = "Unknown"


# Points removed from 100 for one root cause at minimal prevalence (before the
# prevalence multiplier, which ramps linearly up to x1.5 at 50% of sessions).
# These weights are a policy choice (see "Scoring" in ARCHITECTURE.md),
# not an empirically calibrated risk model: e.g. one CRITICAL root cause affecting
# every session costs 45 x 1.5 = 67.5 points and lands in the Critical band.
SEVERITY_IMPACT_MAP = {
    "CRITICAL": 45.0,
    "HIGH": 20.0,
    "MEDIUM": 12.0,
    "LOW": 5.0,
    "INFO": 1.0,
}

# Confidence weighting: high confidence findings count fully,
# lower confidence findings are proportionally reduced
CONFIDENCE_WEIGHT_MIN = 0.5
CONFIDENCE_WEIGHT_MAX = 1.0

# Score bands for status mapping
SCORE_BANDS = {
    (90, 100): ScoreStatus.EXCELLENT,
    (75, 89): ScoreStatus.GOOD,
    (60, 74): ScoreStatus.NEEDS_IMPROVEMENT,
    (40, 59): ScoreStatus.POOR,
    (0, 39): ScoreStatus.CRITICAL,
}


@dataclass
class DimensionConfig:
    """Configuration for a single scoring dimension."""
    name: str
    weight: float  # Weight relative to other dimensions (sum to ~1.0 or normalize)
    description: str
    rules: List[str] = field(default_factory=list)  # M8 rule IDs that belong to this dimension


# Scoring dimensions. Rule membership is derived from the rule catalogue so that
# every rule the engine can emit is attributed to exactly one dimension.
def _rules_for(dimension: str) -> List[str]:
    from securemailscope.rules.engine import RULE_CATALOGUE
    return [r.rule_id for r in RULE_CATALOGUE.values() if r.dimension == dimension]


DIMENSIONS = {
    "tls_protocol": DimensionConfig(
        name="TLS Protocol",
        weight=0.20,
        description="Negotiated TLS/SSL version and handshake outcome",
        rules=_rules_for("tls_protocol")
    ),
    "cryptography": DimensionConfig(
        name="Cryptographic Algorithms",
        weight=0.15,
        description="Cipher suites, key exchange, forward secrecy",
        rules=_rules_for("cryptography")
    ),
    "certificate": DimensionConfig(
        name="Certificate Security",
        weight=0.25,
        description="Certificate validity, key strength, signature, hostname and chain linkage",
        rules=_rules_for("certificate")
    ),
    "starttls": DimensionConfig(
        name="STARTTLS Security",
        weight=0.20,
        description="STARTTLS negotiation and upgrade behavior",
        rules=_rules_for("starttls")
    ),
    "protocol": DimensionConfig(
        name="Protocol Security",
        weight=0.20,
        description="Plaintext sessions and plaintext authentication",
        rules=_rules_for("protocol")
    ),
}


@dataclass
class ScoringPolicy:
    """Complete scoring policy configuration."""
    version: str = "2.0"
    dimensions: Dict[str, DimensionConfig] = field(default_factory=lambda: DIMENSIONS)
    severity_impact: Dict[str, float] = field(default_factory=lambda: SEVERITY_IMPACT_MAP)
    score_bands: Dict[tuple, ScoreStatus] = field(default_factory=lambda: SCORE_BANDS)
    confidence_weight_min: float = CONFIDENCE_WEIGHT_MIN
    confidence_weight_max: float = CONFIDENCE_WEIGHT_MAX
    # Prevalence threshold: when prevalence exceeds this, apply maximum prevalence penalty
    prevalence_threshold_high: float = 0.5  # 50%
    # Maximum penalty multiplier from high prevalence
    prevalence_max_multiplier: float = 1.5

    def get_dimension_by_rule(self, rule_id: str) -> str:
        """Map a rule ID to its scoring dimension."""
        for dim_name, dim_config in self.dimensions.items():
            if rule_id in dim_config.rules:
                return dim_name
        return "protocol"  # Default fallback

    def get_status(self, score) -> ScoreStatus:
        """Map a numeric score to a status.

        Bands are applied by lower bound so fractional scores (e.g. 89.5) never
        fall between bands. ``None`` means the posture could not be assessed.
        """
        if score is None or score < 0 or score > 100:
            return ScoreStatus.UNKNOWN
        for (min_score, _max_score), status in sorted(self.score_bands.items(), key=lambda kv: -kv[0][0]):
            if score >= min_score:
                return status
        return ScoreStatus.UNKNOWN


# Default global policy instance
DEFAULT_POLICY = ScoringPolicy()