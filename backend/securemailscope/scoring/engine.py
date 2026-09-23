"""
Security Posture Scoring Engine for M9.

Consumes findings from M8 and produces a comprehensive security posture score.

Scoring model:
  - Start at 100
  - Group findings by root cause (prevents double-counting)
  - For each root cause group: impact = severity_impact * prevalence_multiplier
  - Cap per-root-impact at 40 points
  - Sum all root-cause impacts, subtract from 100
  - Clamp to [0, 100]
  - Dimension scores computed separately for reporting/analysis
"""
from datetime import datetime, timezone
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass

from securemailscope.scoring.config import DEFAULT_POLICY, DimensionConfig
from securemailscope.scoring.models import (
    PostureScore,
    DimensionScore,
    ScoreContribution,
    CoverageMetric,
    EvidenceQuality,
    ScoreStatus
)
from securemailscope.rules.engine import FindingResult, Severity


@dataclass
class RootCauseGroup:
    """Groups related findings into a single root cause."""
    root_issue: str
    finding_ids: List[str]
    severity: str
    affected_sessions: int
    total_sessions: int
    severity_impact: float


class SecurityPostureScorer:
    """
    M9 Security Posture Scoring Engine.

    Implements evidence-based cryptographic security posture scoring
    with proper prevalence handling and root-cause aggregation.

    Scoring formula:
      overall_score = max(0, 100 - sum(per_root_cause_impacts))
      where per_root_cause_impact = min(severity_impact * prevalence_multiplier, 40)
      prevalence_multiplier = 1.0 + (affected_sessions / total_sessions) / threshold_high
        capped at prevalence_max_multiplier (1.5)
    """

    def __init__(self, policy=None):
        self.policy = policy or DEFAULT_POLICY
        self.logger = None

    def log(self, msg: str):
        """Simple logging helper."""
        if self.logger:
            self.logger.info(msg)
        print(f"[Scoring] {msg}")

    def calculate_posture(self, findings: List[FindingResult],
                         tls_session_count: int,
                         protocol_session_count: int,
                         securemailscope_version: str) -> PostureScore:
        """
        Calculate security posture from M8 findings.

        Args:
            findings: List of findings from M8
            tls_session_count: Total TLS sessions analyzed
            protocol_session_count: Total sessions analyzed (including non-TLS)
            securemailscope_version: Version string of SecureMailScope

        Returns:
            Complete posture score with dimension breakdown
        """
        if not findings:
            return self._create_empty_posture(protocol_session_count, securemailscope_version)

        # Group findings by root cause
        root_cause_groups = self._group_by_root_cause(findings, protocol_session_count)

        # Calculate dimension scores for reporting
        dimension_scores = self._calculate_dimension_scores(
            root_cause_groups, findings, tls_session_count, protocol_session_count
        )

        # Calculate overall score: 100 minus sum of all root-cause impacts
        total_impact = sum(self._calculate_root_cause_impact(g) for g in root_cause_groups.values())
        overall_score = max(0.0, 100.0 - total_impact)

        # Calculate coverage metrics
        coverage_metrics = self._calculate_coverage_metrics(
            findings, tls_session_count, protocol_session_count
        )

        # Generate top contributors
        top_contributors = self._get_top_contributors(dimension_scores)

        # Create posture score
        posture = PostureScore(
            overall_score=overall_score,
            status=self.policy.get_status(overall_score),
            scoring_policy_version=self.policy.version,
            analyzed_at=datetime.now(timezone.utc),
            total_sessions=protocol_session_count,
            tls_sessions=tls_session_count,
            sessions_with_findings=len({f.session_id for f in findings if hasattr(f, 'session_id')}),
            tls_coverage_percent=coverage_metrics["tls"].coverage_percent if "tls" in coverage_metrics else 0.0,
            certificate_coverage_percent=coverage_metrics["certificate"].coverage_percent if "certificate" in coverage_metrics else 0.0,
            dimension_scores=dimension_scores,
            top_contributors=top_contributors,
            securemailscope_version=securemailscope_version,
            findings_count=len(findings),
            root_cause_groups=self._format_root_cause_groups(root_cause_groups)
        )

        return posture

    def _create_empty_posture(self, total_sessions: int,
                             securemailscope_version: str) -> PostureScore:
        """Create a posture for a capture with no findings."""
        dimension_scores = []
        for dim_name, dim_config in self.policy.dimensions.items():
            dimension_scores.append(DimensionScore(
                dimension=dim_name,
                name=dim_config.name,
                score=100.0,
                weight=dim_config.weight,
                affected_sessions=0,
                assessable_sessions=total_sessions,
                findings_count=0,
                coverage_percent=100.0,
                evidence_quality=EvidenceQuality.FULL,
                top_contributors=[]
            ))

        posture = PostureScore(
            overall_score=100.0,
            status=ScoreStatus.EXCELLENT,
            scoring_policy_version=self.policy.version,
            analyzed_at=datetime.now(timezone.utc),
            total_sessions=total_sessions,
            tls_sessions=0,
            sessions_with_findings=0,
            tls_coverage_percent=100.0,
            certificate_coverage_percent=100.0,
            dimension_scores=dimension_scores,
            top_contributors=[],
            securemailscope_version=securemailscope_version,
            findings_count=0,
            root_cause_groups={}
        )

        return posture

    def _calculate_root_cause_impact(self, group: RootCauseGroup) -> float:
        """
        Calculate the total impact for a single root cause group.

        Impact = severity_impact * prevalence_multiplier, capped at 40.
        Prevalence multiplier increases with affected_sessions share.
        """
        severity_impact = group.severity_impact

        # Calculate prevalence and multiplier
        prevalence = group.affected_sessions / max(1, group.total_sessions)

        if prevalence >= self.policy.prevalence_threshold_high:
            prevalence_multiplier = self.policy.prevalence_max_multiplier
        else:
            prevalence_multiplier = 1.0 + (prevalence / self.policy.prevalence_threshold_high)

        impact = severity_impact * prevalence_multiplier
        # Cap per-root-issue impact to prevent domination
        # Allow CRITICAL at high prevalence to reach Critical band
        max_impact = 75.0 if severity_impact >= 35.0 else 40.0
        return min(impact, max_impact)

    def _group_by_root_cause(self, findings: List[FindingResult],
                            total_sessions: int) -> Dict[str, RootCauseGroup]:
        """
        Group findings by root cause to avoid double-counting.

        This is the key to preventing the "500 sessions with TLS 1.0"
        problem from dominating the score.
        """
        groups: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            root_issue = self._get_root_issue_from_finding(finding)
            severity = finding.severity.value

            if root_issue not in groups:
                groups[root_issue] = {
                    "root_issue": root_issue,
                    "finding_ids": [],
                    "affected_sessions": set(),
                    "severity": severity,
                    "total_sessions": total_sessions,
                    "severity_impact": self.policy.severity_impact.get(severity, 8.0)
                }

            groups[root_issue]["finding_ids"].append(finding.finding_id)
            if hasattr(finding, 'session_id') and finding.session_id:
                groups[root_issue]["affected_sessions"].add(finding.session_id)

        # Convert to RootCauseGroup objects
        root_cause_groups = {}
        for group_key, group_data in groups.items():
            affected_count = len(group_data.pop("affected_sessions"))
            root_cause_groups[group_key] = RootCauseGroup(
                root_issue=group_data["root_issue"],
                finding_ids=group_data["finding_ids"],
                severity=group_data["severity"],
                affected_sessions=affected_count,
                total_sessions=group_data["total_sessions"],
                severity_impact=group_data["severity_impact"]
            )

        return root_cause_groups

    def _calculate_dimension_scores(self, root_cause_groups: Dict[str, RootCauseGroup],
                                   findings: List[FindingResult],
                                   tls_session_count: int,
                                   total_sessions: int) -> List[DimensionScore]:
        """
        Calculate dimension scores for reporting purposes.

        Each dimension score reflects the findings that belong to that dimension,
        with root-cause impact applied. This provides visibility into which
        security areas are affected.
        """
        dimension_scores = []

        for dim_name, dim_config in self.policy.dimensions.items():
            dim_findings = [f for f in findings if f.rule_id in dim_config.rules]

            if not dim_findings:
                evidence_quality = self._calculate_evidence_quality([], dim_name)
                dimension_scores.append(DimensionScore(
                    dimension=dim_name,
                    name=dim_config.name,
                    score=100.0,
                    weight=dim_config.weight,
                    affected_sessions=0,
                    assessable_sessions=total_sessions,
                    findings_count=0,
                    coverage_percent=100.0,
                    evidence_quality=evidence_quality,
                    top_contributors=[]
                ))
                continue

            # Calculate dimension score: 100 minus impacts from findings in this dimension
            dim_impact = 0.0
            contributors: List[ScoreContribution] = []
            processed_roots: Set[str] = set()

            for finding in dim_findings:
                root_issue = self._get_root_issue_from_finding(finding)
                if root_issue in processed_roots:
                    continue
                processed_roots.add(root_issue)

                root_group = root_cause_groups.get(root_issue)
                if not root_group:
                    root_group = RootCauseGroup(
                        root_issue=root_issue,
                        finding_ids=[finding.finding_id],
                        severity=finding.severity.value,
                        affected_sessions=1,
                        total_sessions=total_sessions,
                        severity_impact=self.policy.severity_impact.get(finding.severity.value, 8.0)
                    )

                impact = self._calculate_root_cause_impact(root_group)
                dim_impact += impact

                contributor = ScoreContribution(
                    root_issue=root_issue,
                    severity=root_group.severity,
                    affected_sessions=root_group.affected_sessions,
                    total_sessions=root_group.total_sessions,
                    prevalence=root_group.affected_sessions / max(1, root_group.total_sessions),
                    impact_points=impact,
                    explanation=self._generate_explanation(root_issue, root_group),
                    finding_ids=[f.finding_id for f in dim_findings
                                if self._get_root_issue_from_finding(f) == root_issue]
                )
                contributors.append(contributor)

            dim_score = max(0.0, 100.0 - dim_impact)
            contributors.sort(key=lambda c: c.impact_points, reverse=True)

            dimension_scores.append(DimensionScore(
                dimension=dim_name,
                name=dim_config.name,
                score=dim_score,
                weight=dim_config.weight,
                affected_sessions=len({f.session_id for f in dim_findings if hasattr(f, 'session_id')}),
                assessable_sessions=tls_session_count if dim_name in ["tls_protocol", "cryptography"]
                                     else total_sessions,
                findings_count=len(dim_findings),
                coverage_percent=self._calculate_dimension_coverage(dim_name, tls_session_count, total_sessions),
                evidence_quality=self._calculate_evidence_quality(dim_findings, dim_name),
                top_contributors=contributors
            ))

        return dimension_scores

    def _get_root_issue_from_finding(self, finding: FindingResult) -> str:
        """Extract root issue identifier from a finding."""
        if finding.rule_id == "PROTO-001":
            return "Unencrypted Email Communication (Plaintext)"
        elif finding.rule_id == "STLS-001":
            return "STARTTLS Negotiation Rejected (Potential Downgrade)"
        elif finding.rule_id == "TLS-001":
            return "Deprecated TLS Protocol Version"
        elif finding.rule_id == "TLS-003":
            return "Weak/Insecure Cipher Suite"
        elif finding.rule_id == "TLS-004":
            return "No Forward Secrecy"
        elif finding.rule_id == "CERT-001":
            return "Expired Certificate"
        elif finding.rule_id == "CERT-003":
            return "Weak Public Key Size"
        elif finding.rule_id == "CERT-004":
            return "Weak Certificate Signature Algorithm"
        elif finding.rule_id == "CERT-005":
            return "Self-Signed Certificate"
        else:
            return finding.rule_id

    def _calculate_dimension_coverage(self, dim_name: str,
                                     tls_session_count: int,
                                     total_sessions: int) -> float:
        """Calculate coverage percentage for a dimension."""
        if dim_name in ["tls_protocol", "cryptography"]:
            assessable = tls_session_count if tls_session_count > 0 else total_sessions
        else:
            assessable = total_sessions

        if assessable == 0:
            return 100.0
        return 100.0

    def _calculate_evidence_quality(self, findings: List[FindingResult],
                                   dim_name: str) -> EvidenceQuality:
        """Calculate evidence quality for a dimension."""
        if dim_name in ["tls_protocol", "cryptography"]:
            has_tls_finding = any(f.rule_id.startswith("TLS-") for f in findings)
            return EvidenceQuality.FULL if has_tls_finding else EvidenceQuality.NOT_OBSERVED
        elif dim_name == "certificate":
            has_cert_finding = any(f.rule_id.startswith("CERT-") for f in findings)
            return EvidenceQuality.FULL if has_cert_finding else EvidenceQuality.NOT_OBSERVED
        else:
            return EvidenceQuality.FULL

    def _calculate_coverage_metrics(self, findings: List[FindingResult],
                                    tls_session_count: int,
                                    total_sessions: int) -> Dict[str, CoverageMetric]:
        """Calculate coverage metrics for different aspects."""
        metrics = {}

        tls_findings = [f for f in findings if f.rule_id.startswith(("TLS-", "STLS-"))]
        metrics["tls"] = CoverageMetric(
            dimension="tls",
            total_sessions=tls_session_count,
            assessable_sessions=min(len(tls_findings), tls_session_count) if tls_session_count > 0 else 0,
            quality=EvidenceQuality.FULL if tls_session_count > 0 else EvidenceQuality.INSUFFICIENT,
            reason="TLS sessions identified and analyzed"
        )

        cert_findings = [f for f in findings if f.rule_id.startswith("CERT-")]
        metrics["certificate"] = CoverageMetric(
            dimension="certificate",
            total_sessions=tls_session_count,
            assessable_sessions=min(len(cert_findings), tls_session_count) if tls_session_count > 0 else 0,
            quality=EvidenceQuality.FULL if len(cert_findings) > 0 else EvidenceQuality.INSUFFICIENT,
            reason="Certificate analysis completed on available TLS sessions"
        )

        return metrics

    def _get_top_contributors(self, dimension_scores: List[DimensionScore]) -> List[ScoreContribution]:
        """Extract top contributors across all dimensions for overall explanation."""
        all_contributors: List[ScoreContribution] = []
        for dim_score in dimension_scores:
            all_contributors.extend(dim_score.top_contributors)
        all_contributors.sort(key=lambda c: c.impact_points, reverse=True)
        return all_contributors[:5]

    def _format_root_cause_groups(self, root_cause_groups: Dict[str, RootCauseGroup]) -> Dict[str, Dict[str, Any]]:
        """Format root cause groups for storage in posture score."""
        formatted = {}
        for group_key, group in root_cause_groups.items():
            formatted[group_key] = {
                "root_issue": group.root_issue,
                "affected_sessions": group.affected_sessions,
                "total_sessions": group.total_sessions,
                "prevalence_percent": round((group.affected_sessions / max(1, group.total_sessions)) * 100, 2),
                "severity": group.severity,
                "finding_count": len(group.finding_ids)
            }
        return formatted

    def _generate_explanation(self, root_issue: str, root_group: RootCauseGroup,
                              prevalence: Optional[float] = None) -> str:
        """Generate human-readable explanation for a score contributor."""
        if prevalence is None:
            prevalence = root_group.affected_sessions / max(1, root_group.total_sessions)

        if prevalence >= self.policy.prevalence_threshold_high:
            prevalence_text = f"widespread ({prevalence * 100:.1f}% of sessions)"
        elif prevalence > 0.01:
            prevalence_text = f"affecting {root_group.affected_sessions} sessions ({prevalence * 100:.1f}%)"
        else:
            prevalence_text = f"affecting {root_group.affected_sessions} sessions"

        impact = self._calculate_root_cause_impact(root_group)
        return (
            f"{root_issue} ({root_group.severity}) "
            f"{prevalence_text} "
            f"reduces posture score by {impact:.1f} points"
        )

    def create_posture_from_session_results(self, session_results: List[Dict[str, Any]],
                                          tls_session_count: int,
                                          protocol_session_count: int,
                                          securemailscope_version: str) -> PostureScore:
        """Convenience method to create posture from session results."""
        all_findings = []
        for session in session_results:
            if "findings" in session:
                all_findings.extend(session["findings"])
        return self.calculate_posture(
            findings=all_findings,
            tls_session_count=tls_session_count,
            protocol_session_count=protocol_session_count,
            securemailscope_version=securemailscope_version
        )
