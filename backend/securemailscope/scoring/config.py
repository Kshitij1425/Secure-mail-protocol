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


# Mapping from M8 Severity to numeric impact (0-100 scale for a single finding)
# CRITICAL findings have highest impact, INFO findings have minimal impact
# Values calibrated so a single CRITICAL finding at 100% prevalence drops
# the score into the Critical band (<40), satisfying test expectations
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


# Define scoring dimensions based on M8 rule categories
DIMENSIONS = {
    "tls_protocol": DimensionConfig(
        name="TLS Protocol",
        weight=0.20,
        description="TLS version security (deprecated TLS 1.0/1.1, SSL variants)",
        rules=["TLS-001"]
    ),
    "cryptography": DimensionConfig(
        name="Cryptographic Algorithms",
        weight=0.15,
        description="Cipher suites, key exchange, signature algorithms",
        rules=["TLS-003", "TLS-004"]
    ),
    "certificate": DimensionConfig(
        name="Certificate Security",
        weight=0.25,
        description="Certificate validity, key strength, chain trust",
        rules=["CERT-001", "CERT-003", "CERT-005"]
    ),
    "starttls": DimensionConfig(
        name="STARTTLS Security",
        weight=0.20,
        description="STARTTLS negotiation and upgrade behavior",
        rules=["STLS-001"]
    ),
    "protocol": DimensionConfig(
        name="Protocol Security",
        weight=0.20,
        description="General protocol security (plaintext, downgrade)",
        rules=["PROTO-001"]
    ),
}


@dataclass
class ScoringPolicy:
    """Complete scoring policy configuration."""
    version: str = "1.0"
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

    def get_status(self, score: float) -> ScoreStatus:
        """Map a numeric score to a status."""
        if score < 0 or score > 100:
            return ScoreStatus.UNKNOWN
        for (min_score, max_score), status in self.score_bands.items():
            if min_score <= score <= max_score:
                return status
        return ScoreStatus.UNKNOWN


# Default global policy instance
DEFAULT_POLICY = ScoringPolicy()