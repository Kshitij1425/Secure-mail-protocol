"""
Data models: Cryptographic Security Posture Scoring.

Defines the core data structures for scores, dimensions, and explanations.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

from securemailscope.scoring.config import ScoreStatus


class EvidenceQuality(Enum):
    """Quality/availability of evidence for assessment."""
    FULL = "full"           # Complete evidence available
    PARTIAL = "partial"     # Some evidence missing
    INSUFFICIENT = "insufficient"  # Not enough evidence
    NOT_OBSERVED = "not_observed"  # Property not present in capture
    UNKNOWN = "unknown"     # Cannot determine


@dataclass
class CoverageMetric:
    """Measures how much of the capture was assessable for a given dimension."""
    dimension: str
    total_sessions: int
    assessable_sessions: int
    quality: EvidenceQuality
    reason: str = ""

    @property
    def coverage_percent(self) -> float:
        if self.total_sessions == 0:
            return 100.0
        return (self.assessable_sessions / self.total_sessions) * 100.0


@dataclass
class ScoreContribution:
    """A single contributor to the overall score reduction."""
    root_issue: str
    severity: str
    affected_sessions: int
    total_sessions: int
    prevalence: float  # 0.0 to 1.0
    impact_points: float  # Points deducted
    explanation: str
    finding_ids: List[str] = field(default_factory=list)


@dataclass
class DimensionScore:
    """Score for a single security dimension."""
    dimension: str
    name: str
    score: Optional[float]  # 0-100, None when not assessable
    weight: float
    affected_sessions: int
    assessable_sessions: int
    findings_count: int
    coverage_percent: float
    evidence_quality: EvidenceQuality
    top_contributors: List[ScoreContribution] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "name": self.name,
            "score": round(self.score, 2) if self.score is not None else None,
            "weight": self.weight,
            "affected_sessions": self.affected_sessions,
            "assessable_sessions": self.assessable_sessions,
            "findings_count": self.findings_count,
            "coverage_percent": round(self.coverage_percent, 2),
            "evidence_quality": self.evidence_quality.value,
            "top_contributors": [
                {
                    "root_issue": c.root_issue,
                    "severity": c.severity,
                    "affected_sessions": c.affected_sessions,
                    "prevalence": round(c.prevalence, 4),
                    "impact_points": round(c.impact_points, 2),
                    "explanation": c.explanation
                }
                for c in self.top_contributors
            ]
        }


@dataclass
class PostureScore:
    """
    Complete security posture score for a capture.

    This is the main output of the scoring engine.
    """
    overall_score: Optional[float]  # 0-100; None = insufficient evidence
    status: ScoreStatus
    scoring_policy_version: str
    analyzed_at: datetime

    # Session counts
    total_sessions: int
    tls_sessions: int
    sessions_with_findings: int

    # Coverage metrics
    tls_coverage_percent: float
    certificate_coverage_percent: float

    # Dimension scores
    dimension_scores: List[DimensionScore] = field(default_factory=list)

    # Top contributors to score reduction
    top_contributors: List[ScoreContribution] = field(default_factory=list)

    # Additional metadata
    securemailscope_version: str = "0.1.0"
    findings_count: int = 0

    # Root-cause aggregation tracking
    root_cause_groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "overall_score": round(self.overall_score, 2) if self.overall_score is not None else None,
            "status": self.status.value,
            "scoring_policy_version": self.scoring_policy_version,
            "analyzed_at": self.analyzed_at.isoformat(),
            "metadata": {
                "total_sessions": self.total_sessions,
                "tls_sessions": self.tls_sessions,
                "sessions_with_findings": self.sessions_with_findings,
                "findings_count": self.findings_count,
                "tls_coverage_percent": round(self.tls_coverage_percent, 2),
                "certificate_coverage_percent": round(self.certificate_coverage_percent, 2),
                "securemailscope_version": self.securemailscope_version
            },
            "dimensions": [d.to_dict() for d in self.dimension_scores],
            "top_contributors": [
                {
                    "root_issue": c.root_issue,
                    "severity": c.severity,
                    "affected_sessions": c.affected_sessions,
                    "total_sessions": c.total_sessions,
                    "prevalence": round(c.prevalence, 4),
                    "impact_points": round(c.impact_points, 2),
                    "explanation": c.explanation,
                    "finding_ids": c.finding_ids[:5]  # Limit for display
                }
                for c in self.top_contributors
            ]
        }

    def get_summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            (f"Security Posture: {self.overall_score:.0f}/100 ({self.status.value})"
             if self.overall_score is not None else
             "Security Posture: not assessable (no email sessions with evidence)"),
            f"Sessions analyzed: {self.total_sessions}",
            f"TLS sessions: {self.tls_sessions}",
            f"Findings: {self.findings_count}",
            "",
            "Dimension Scores:"
        ]
        for d in self.dimension_scores:
            lines.append(f"  {d.name}: {d.score:.0f}/100" if d.score is not None else f"  {d.name}: n/a")

        if self.top_contributors:
            lines.append("")
            lines.append("Top Contributors:")
            for i, c in enumerate(self.top_contributors[:5], 1):
                lines.append(f"  {i}. {c.root_issue} ({c.severity}): {c.affected_sessions} sessions, {c.prevalence*100:.1f}% prevalence")

        return "\n".join(lines)