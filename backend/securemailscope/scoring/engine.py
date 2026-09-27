"""
Security posture scoring engine.

Consumes deterministic rule findings and produces a comprehensive security posture score.

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
from securemailscope.rules.engine import FindingResult, Severity, RULE_CATALOGUE


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
    Security posture scoring engine.

    Implements evidence-based cryptographic security posture scoring
    with proper prevalence handling and root-cause aggregation.

    Scoring formula:
      overall_score = max(0, 100 - sum(per_root_cause_impacts))
      where per_root_cause_impact = min(severity_impact * prevalence_multiplier, 40)
      prevalence_multiplier = 1.0 + (max_multiplier - 1.0) * min(1, prevalence / threshold_high)
    """

    def __init__(self, policy=None):
        self.policy = policy or DEFAULT_POLICY
        self.logger = None

    def log(self, msg: str):
        """Simple logging helper."""
        if self.logger:
            self.logger.info(msg)

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def calculate_posture(self, findings: List[FindingResult],
                         tls_session_count: int,
                         protocol_session_count: int,
                         securemailscope_version: str,
                         coverage: Optional[Dict[str, int]] = None) -> PostureScore:
        """
        Calculate security posture from rule findings.

        Args:
            findings: List of rule findings
            tls_session_count: Total TLS sessions analyzed
            protocol_session_count: Total sessions analyzed (including non-TLS)
            securemailscope_version: Version string of SecureMailScope

        Returns:
            Complete posture score with dimension breakdown
        """
        # Without explicit coverage, fall back to the session counts we were given.
        self._coverage = coverage or {"email_sessions": protocol_session_count,
                                      "tls_observed": tls_session_count}
        if protocol_session_count <= 0:
            # Nothing was assessable: this is "unknown", not "excellent".
            return self._create_unknown_posture(securemailscope_version, len(findings))

        all_findings = findings
        # Findings that only record missing evidence are reported but not scored:
        # unknown is not automatically insecure.
        findings = [f for f in findings if getattr(f, "evidence_type", "OBSERVED") != "INSUFFICIENT_EVIDENCE"]
        if not findings:
            posture = self._create_empty_posture(protocol_session_count, securemailscope_version)
            posture.tls_sessions = tls_session_count
            posture.findings_count = len(all_findings)
            return posture

        # Group findings by root cause
        root_cause_groups = self._group_by_root_cause(findings, protocol_session_count)

        # Calculate dimension scores for reporting
        dimension_scores = self._calculate_dimension_scores(
            root_cause_groups, findings, tls_session_count, protocol_session_count
        )

        # Calculate overall score: 100 minus sum of all root-cause impacts
        total_impact = sum(self._calculate_root_cause_impact(g) for g in root_cause_groups.values())
        # Rounded once, here, so every layer (DB, API, reports, UI) carries the same value.
        overall_score = round(max(0.0, 100.0 - total_impact), 2)

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
            findings_count=len(all_findings),
            root_cause_groups=self._format_root_cause_groups(root_cause_groups)
        )

        return posture

    def _create_unknown_posture(self, securemailscope_version: str, findings_count: int = 0) -> PostureScore:
        """Posture for a capture with no assessable email sessions."""
        dimension_scores = [
            DimensionScore(dimension=dim_name, name=cfg.name, score=None, weight=cfg.weight,
                           affected_sessions=0, assessable_sessions=0, findings_count=0,
                           coverage_percent=0.0, evidence_quality=EvidenceQuality.INSUFFICIENT,
                           top_contributors=[])
            for dim_name, cfg in self.policy.dimensions.items()
        ]
        return PostureScore(
            overall_score=None, status=ScoreStatus.UNKNOWN,
            scoring_policy_version=self.policy.version, analyzed_at=datetime.now(timezone.utc),
            total_sessions=0, tls_sessions=0, sessions_with_findings=0,
            tls_coverage_percent=0.0, certificate_coverage_percent=0.0,
            dimension_scores=dimension_scores, top_contributors=[],
            securemailscope_version=securemailscope_version, findings_count=findings_count,
            root_cause_groups={},
        )

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
                coverage_percent=self._calculate_dimension_coverage(dim_name, 0, total_sessions),
                evidence_quality=self._calculate_evidence_quality([], dim_name),
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
            tls_coverage_percent=self._pct("tls_observed"),
            certificate_coverage_percent=self._pct("certificates_observed"),
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

        # Linear ramp from 1.0 (no prevalence) to the maximum at the threshold, flat after.
        # Monotone in prevalence: more affected sessions can never raise the score.
        # (Previously 1 + p/threshold below the threshold, which exceeded the cap, e.g.
        # 1.8 at 40% vs 1.5 at 50%, so adding an affected session improved the score.)
        ramp = min(1.0, prevalence / self.policy.prevalence_threshold_high)
        prevalence_multiplier = 1.0 + (self.policy.prevalence_max_multiplier - 1.0) * ramp

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

            if self.SEVERITY_ORDER.get(severity, 0) > self.SEVERITY_ORDER.get(groups[root_issue]["severity"], 0):
                groups[root_issue]["severity"] = severity
                groups[root_issue]["severity_impact"] = self.policy.severity_impact.get(severity, 8.0)
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
            dim_findings = [f for f in findings if self.policy.get_dimension_by_rule(f.rule_id) == dim_name]

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

            dim_score = round(max(0.0, 100.0 - dim_impact), 2)
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

    _LEGACY_ROOT_NAMES = {"PROTO-001", "STLS-001", "TLS-001", "TLS-003", "TLS-004",
                          "CERT-001", "CERT-003", "CERT-004", "CERT-005"}

    def _get_root_issue_from_finding(self, finding: FindingResult) -> str:
        """Extract root issue identifier from a finding."""
        rule = RULE_CATALOGUE.get(finding.rule_id)
        if finding.rule_id not in self._LEGACY_ROOT_NAMES and rule is not None:
            return rule.title
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

    # Coverage keys supplied by the orchestrator:
    #   email_sessions, tls_observed (sessions with a parsed ServerHello),
    #   certificates_observed (sessions with a parsed certificate),
    #   certificates_encrypted (TLS 1.3 sessions whose certificates are not observable)
    _DIM_COVERAGE_KEY = {"tls_protocol": "tls_observed", "cryptography": "tls_observed",
                         "certificate": "certificates_observed"}

    def _pct(self, key: str) -> float:
        cov = getattr(self, "_coverage", None) or {}
        if not cov or key not in cov:
            return 100.0
        total = cov.get("email_sessions", 0)
        if total <= 0:
            return 0.0
        return round(100.0 * cov.get(key, 0) / total, 2)

    def _calculate_dimension_coverage(self, dim_name: str,
                                     tls_session_count: int,
                                     total_sessions: int) -> float:
        """Share of email sessions in which this dimension could actually be assessed."""
        cov = getattr(self, "_coverage", None) or {}
        if not cov:
            return 100.0  # no coverage context supplied (unit-level use)
        key = self._DIM_COVERAGE_KEY.get(dim_name)
        if key is None:
            return 100.0 if cov.get("email_sessions", 0) > 0 else 0.0
        if key not in cov:
            return 100.0  # not measured
        return self._pct(key)

    def _calculate_evidence_quality(self, findings: List[FindingResult],
                                   dim_name: str) -> EvidenceQuality:
        """Evidence quality derives from what was observed, not from whether findings exist."""
        cov = getattr(self, "_coverage", None) or {}
        key = self._DIM_COVERAGE_KEY.get(dim_name)
        if not cov or (key is not None and key not in cov):
            # No observation counts available: fall back to the evidence carried by findings.
            if key is None:
                return EvidenceQuality.FULL
            prefix = "CERT-" if dim_name == "certificate" else "TLS-"
            return EvidenceQuality.FULL if any(f.rule_id.startswith(prefix) for f in findings)                 else EvidenceQuality.NOT_OBSERVED
        total = cov.get("email_sessions", 0)
        if total <= 0:
            return EvidenceQuality.INSUFFICIENT
        if key is None:
            return EvidenceQuality.FULL
        seen = cov.get(key, 0)
        if seen >= total:
            return EvidenceQuality.FULL
        if seen > 0:
            return EvidenceQuality.PARTIAL
        return EvidenceQuality.NOT_OBSERVED

    def _calculate_coverage_metrics(self, findings: List[FindingResult],
                                    tls_session_count: int,
                                    total_sessions: int) -> Dict[str, CoverageMetric]:
        """Calculate coverage metrics for different aspects."""
        metrics = {}

        cov = getattr(self, "_coverage", None) or {}
        if cov and "certificates_observed" in cov:
            total = cov.get("email_sessions", 0)
            metrics["tls"] = CoverageMetric(
                dimension="tls", total_sessions=total, assessable_sessions=cov.get("tls_observed", 0),
                quality=self._calculate_evidence_quality([], "tls_protocol"),
                reason="Email sessions whose TLS ServerHello was observed")
            metrics["certificate"] = CoverageMetric(
                dimension="certificate", total_sessions=total,
                assessable_sessions=cov.get("certificates_observed", 0),
                quality=self._calculate_evidence_quality([], "certificate"),
                reason=(f"Email sessions with an observable certificate; "
                        f"{cov.get('certificates_encrypted', 0)} TLS 1.3 session(s) encrypt certificates"))
        else:
            metrics["tls"] = CoverageMetric(
                dimension="tls", total_sessions=tls_session_count, assessable_sessions=tls_session_count,
                quality=EvidenceQuality.FULL if tls_session_count else EvidenceQuality.INSUFFICIENT,
                reason="No coverage context supplied")
            metrics["certificate"] = CoverageMetric(
                dimension="certificate", total_sessions=tls_session_count, assessable_sessions=tls_session_count,
                quality=EvidenceQuality.UNKNOWN, reason="No coverage context supplied")

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
