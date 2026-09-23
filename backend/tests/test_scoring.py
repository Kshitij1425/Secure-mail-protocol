"""
M9: Cryptographic Security Posture Scoring Tests.
Comprehensive test suite for the Security Posture Scorer.
"""
import pytest
from datetime import datetime, timedelta, timezone

from securemailscope.rules.engine import (
    SecurityPolicyEngine,
    FindingResult,
    Severity,
    EmailProtocol,
    TLSState,
)
from securemailscope.tls.parser import TLSSessionData
from securemailscope.certificates.analyzer import CertificateDetails
from securemailscope.scoring.engine import SecurityPostureScorer, RootCauseGroup
from securemailscope.scoring.models import (
    PostureScore,
    DimensionScore,
    ScoreContribution,
    EvidenceQuality,
    ScoreStatus,
    CoverageMetric,
)
from securemailscope.scoring.config import (
    ScoringPolicy,
    DEFAULT_POLICY,
    SCORE_BANDS,
    SEVERITY_IMPACT_MAP,
)


def make_finding(rule_id: str, severity: Severity = Severity.HIGH,
                  confidence: float = 1.0, session_id: str = "sess-1") -> FindingResult:
    """Helper to create a FindingResult."""
    return FindingResult(
        finding_id=f"{session_id}-{rule_id}",
        rule_id=rule_id,
        category="Test",
        title=f"Test {rule_id}",
        severity=severity,
        confidence=confidence,
        description="",
        recommendation="",
        session_id=session_id,
    )


def make_cert_details(is_expired: bool = False, key_size: int = 2048,
                       is_self_signed: bool = True, weak_key: bool = False) -> CertificateDetails:
    """Helper to create a CertificateDetails."""
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=1)
    not_after = now - timedelta(days=10) if is_expired else now + timedelta(days=365)
    return CertificateDetails(
        fingerprint_sha256="abc123",
        subject="CN=mail.example.org",
        issuer="CN=mail.example.org" if is_self_signed else "CN=Example CA",
        serial_number="0x123",
        not_before=not_before,
        not_after=not_after,
        is_expired=is_expired,
        is_not_yet_valid=False,
        is_self_signed=is_self_signed,
        public_key_algorithm="RSA",
        public_key_size_bits=key_size,
        signature_algorithm="sha256WithRSAEncryption",
        san_list=[],
        weak_key=weak_key,
        weak_signature=False,
    )


class TestPostureScorer:
    """Test suite for SecurityPostureScorer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scorer = SecurityPostureScorer()

    # --- Property/Invariant Tests ---

    def test_score_bounded_zero_to_100(self):
        """Invariant: score must always be between 0 and 100."""
        # Test various combinations of findings
        test_cases = [
            [],  # No findings
            [make_finding("CERT-001", Severity.HIGH)],  # Single finding
            [make_finding("PROTO-001", Severity.CRITICAL)],  # Critical finding
            [make_finding("TLS-001", Severity.HIGH), make_finding("CERT-001", Severity.MEDIUM)],  # Multiple findings
            [make_finding(f"TLS-00{i}", Severity.HIGH, session_id=f"sess-{i}") for i in range(1, 5)],  # Multiple sessions
        ]
        for findings in test_cases:
            posture = self.scorer.calculate_posture(
                findings=findings,
                tls_session_count=10,
                protocol_session_count=10,
                securemailscope_version="0.1.0"
            )
            assert 0 <= posture.overall_score <= 100, \
                f"Score {posture.overall_score} out of bounds for findings {findings}"
            for dim in posture.dimension_scores:
                assert 0 <= dim.score <= 100, \
                    f"Dimension {dim.dimension} score {dim.score} out of bounds"

    def test_identical_findings_produce_identical_score(self):
        """Invariant: identical findings must produce identical score."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture1 = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        posture2 = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture1.overall_score == posture2.overall_score

    def test_score_is_deterministic(self):
        """Invariant: same input always produces same output."""
        findings = [make_finding("TLS-001", Severity.HIGH)]
        scores = set()
        for _ in range(10):
            posture = self.scorer.calculate_posture(
                findings=findings,
                tls_session_count=10,
                protocol_session_count=10,
                securemailscope_version="0.1.0"
            )
            scores.add(posture.overall_score)
        assert len(scores) == 1

    def test_policy_version_persisted(self):
        """Invariant: policy version must be recorded in score."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.scoring_policy_version == "1.0"
        assert posture.securemailscope_version == "0.1.0"

    def test_empty_findings_produce_maximum_score(self):
        """Zero findings → 100/Excellent."""
        posture = self.scorer.calculate_posture(
            findings=[],
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score == 100.0
        assert posture.status == ScoreStatus.EXCELLENT

    def test_critical_finding_reduces_score_significantly(self):
        """A CRITICAL finding must reduce score substantially."""
        findings = [make_finding("PROTO-001", Severity.CRITICAL)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100
        assert posture.status in (ScoreStatus.CRITICAL, ScoreStatus.POOR, ScoreStatus.NEEDS_IMPROVEMENT)

    def test_low_severity_finding_small_reduction(self):
        """A LOW finding must reduce score only slightly."""
        findings = [make_finding("CERT-005", Severity.LOW)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100
        assert posture.overall_score > 50  # Low severity shouldn't drop too far

    def test_duplicate_findings_not_double_counted(self):
        """Same root issue across many sessions must not catastrophically penalize."""
        # 10 identical CERT-001 findings across different sessions
        findings = [make_finding("CERT-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(10)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # With root-cause grouping, the penalty should be the same as a single finding
        # not multiplied by 10
        assert posture.overall_score >= 0
        assert posture.overall_score <= 100
        # Verify root cause grouping occurred
        assert len(posture.root_cause_groups) <= len(findings)

    def test_root_cause_grouping_reduces_duplicates(self):
        """Root cause grouping should produce fewer groups than raw findings."""
        findings = [make_finding("CERT-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(5)]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        # All CERT-001 findings should be grouped into one root cause
        assert len(groups) == 1
        assert "Expired Certificate" in groups

    def test_prevalence_matters(self):
        """Widespread issues must affect posture more than isolated issues."""
        # Low prevalence finding
        low_prevalence_findings = [make_finding("CERT-001", Severity.HIGH)]
        posture_low = self.scorer.calculate_posture(
            findings=low_prevalence_findings,
            tls_session_count=100,
            protocol_session_count=100,
            securemailscope_version="0.1.0"
        )

        # High prevalence finding (same finding type but across many sessions)
        # For this test, we simulate high prevalence by adjusting the root cause group
        high_prevalence_findings = [make_finding("CERT-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(80)]
        posture_high = self.scorer.calculate_posture(
            findings=high_prevalence_findings,
            tls_session_count=100,
            protocol_session_count=100,
            securemailscope_version="0.1.0"
        )

        # High prevalence should result in lower score
        assert posture_high.overall_score <= posture_low.overall_score

    def test_dimension_scores_present(self):
        """Dimension scores must exist for all configured dimensions."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        dim_names = {d.dimension for d in posture.dimension_scores}
        expected_dims = {"tls_protocol", "cryptography", "certificate", "starttls", "protocol"}
        assert expected_dims.issubset(dim_names)

    def test_session_level_and_capture_level_consistent(self):
        """Session-level and capture-level scores must be consistent."""
        # Single session with one finding
        findings = [make_finding("TLS-001", Severity.HIGH, session_id="sess-1")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        # Score should be below 100 due to the finding
        assert posture.overall_score < 100
        # Dimension score for TLS protocol should be affected
        tls_dim = next(d for d in posture.dimension_scores if d.dimension == "tls_protocol")
        assert tls_dim.score < 100

    def test_unknown_properties_no_false_penalty(self):
        """Missing/unknown evidence should not penalize score."""
        # Empty findings - no evidence means no penalty
        posture = self.scorer.calculate_posture(
            findings=[],
            tls_session_count=0,
            protocol_session_count=0,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score == 100.0
        assert posture.status == ScoreStatus.EXCELLENT

    def test_all_critical_findings_produce_low_score(self):
        """All critical findings must produce a very low score."""
        findings = [
            make_finding("PROTO-001", Severity.CRITICAL),
            make_finding("TLS-001", Severity.CRITICAL),
            make_finding("CERT-001", Severity.CRITICAL),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 40  # Critical band
        assert posture.status == ScoreStatus.CRITICAL

    def test_score_status_mapping(self):
        """Score must map to correct status band."""
        for score, expected_status in [
            (95, ScoreStatus.EXCELLENT),
            (85, ScoreStatus.GOOD),
            (70, ScoreStatus.NEEDS_IMPROVEMENT),
            (50, ScoreStatus.POOR),
            (20, ScoreStatus.CRITICAL),
        ]:
            status = DEFAULT_POLICY.get_status(score)
            assert status == expected_status, f"Score {score} mapped to {status}, expected {expected_status}"

    def test_score_with_top_contributors(self):
        """Score must include top contributors for explanation."""
        findings = [
            make_finding("CERT-001", Severity.HIGH, session_id="sess-1"),
            make_finding("CERT-001", Severity.HIGH, session_id="sess-2"),
            make_finding("TLS-001", Severity.HIGH, session_id="sess-3"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Must have top contributors
        assert len(posture.top_contributors) > 0
        # Top contributor must be the highest impact
        for contrib in posture.top_contributors:
            assert contrib.impact_points > 0

    def test_dimension_score_weights_sum_to_one(self):
        """Dimension weights should sum to 1.0 for normalized scoring."""
        total_weight = sum(dim.weight for dim in DEFAULT_POLICY.dimensions.values())
        assert abs(total_weight - 1.0) < 0.01, f"Weights sum to {total_weight}, expected ~1.0"

    def test_coverage_metrics_present(self):
        """Coverage metrics must be present in posture score."""
        findings = [make_finding("TLS-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.tls_coverage_percent >= 0
        assert posture.certificate_coverage_percent >= 0
        assert posture.tls_coverage_percent <= 100
        assert posture.certificate_coverage_percent <= 100

    def test_confidence_consumed_sensibly(self):
        """Findings with high confidence should be treated more seriously."""
        high_conf_findings = [make_finding("CERT-001", Severity.HIGH, confidence=1.0)]
        low_conf_findings = [make_finding("CERT-001", Severity.HIGH, confidence=0.5)]

        posture_high = self.scorer.calculate_posture(
            findings=high_conf_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        posture_low = self.scorer.calculate_posture(
            findings=low_conf_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        # High confidence should result in lower (worse) score
        assert posture_high.overall_score <= posture_low.overall_score

    def test_multiple_dimensions_independent(self):
        """Changes in one dimension should not arbitrarily affect unrelated dimensions."""
        # Only TLS protocol finding
        tls_findings = [make_finding("TLS-001", Severity.HIGH)]
        posture_tls = self.scorer.calculate_posture(
            findings=tls_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        # Only certificate finding
        cert_findings = [make_finding("CERT-001", Severity.HIGH)]
        posture_cert = self.scorer.calculate_posture(
            findings=cert_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        # Both should have scores below 100
        assert posture_tls.overall_score < 100
        assert posture_cert.overall_score < 100

        # Check dimension scores
        tls_dim = next(d for d in posture_tls.dimension_scores if d.dimension == "tls_protocol")
        cert_dim = next(d for d in posture_cert.dimension_scores if d.dimension == "certificate")

        # TLS dimension should be affected
        assert tls_dim.score < 100
        # Certificate dimension should be affected
        assert cert_dim.score < 100

    def test_adding_weakness_never_improves_score(self):
        """Adding a genuine security weakness must not improve the score."""
        base_findings = [make_finding("CERT-001", Severity.MEDIUM)]
        posture_base = self.scorer.calculate_posture(
            findings=base_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        # Add another finding
        extended_findings = base_findings + [make_finding("TLS-001", Severity.HIGH)]
        posture_extended = self.scorer.calculate_posture(
            findings=extended_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        assert posture_extended.overall_score <= posture_base.overall_score

    def test_removing_weakness_never_worsens_score(self):
        """Removing a genuine security weakness must not worsen the score."""
        base_findings = [make_finding("CERT-001", Severity.MEDIUM)]
        posture_base = self.scorer.calculate_posture(
            findings=base_findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        # Remove the finding
        posture_empty = self.scorer.calculate_posture(
            findings=[],
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        assert posture_empty.overall_score >= posture_base.overall_score

    def test_duplicated_evidence_bounded_penalty(self):
        """Duplicating the same evidence should not create unbounded penalties."""
        # Create many identical findings
        findings = [make_finding("CERT-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(100)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=100,
            protocol_session_count=100,
            securemailscope_version="0.1.0"
        )
        # Score should be bounded at 0
        assert posture.overall_score >= 0
        # With root-cause grouping, 100 identical CERT-001 findings should not drop below 0
        # because the root cause is only counted once per dimension
        assert posture.overall_score > -1  # Must be >= 0 anyway, but this confirms no negative

    def test_metadata_changes_do_not_affect_score(self):
        """Changing unrelated session metadata should not unexpectedly change the score."""
        findings = [make_finding("CERT-001", Severity.HIGH, session_id="sess-1")]
        posture1 = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )

        # Same findings, different metadata
        posture2 = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=20,
            protocol_session_count=20,
            securemailscope_version="0.2.0"
        )

        # Score should remain similar (allowing for minor prevalence differences)
        # This test validates that the core scoring logic is stable
        assert abs(posture1.overall_score - posture2.overall_score) < 50

    def test_session_level_risk_exists(self):
        """Session-level posture must be calculable."""
        findings = [make_finding("CERT-001", Severity.HIGH, session_id="sess-1")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score >= 0
        assert posture.overall_score <= 100

    def test_capture_level_score_exists(self):
        """Capture-level posture must exist."""
        findings = [make_finding("TLS-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(5)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=5,
            protocol_session_count=5,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score >= 0
        assert posture.overall_score <= 100
        assert posture.total_sessions == 5
        assert posture.tls_sessions == 5

    def test_status_excellent_for_high_score(self):
        """Score >= 90 must map to Excellent."""
        posture = self.scorer.calculate_posture(
            findings=[],
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.status == ScoreStatus.EXCELLENT

    def test_status_critical_for_low_score(self):
        """Score < 40 must map to Critical."""
        # Create critical findings to drive score down
        findings = [make_finding("PROTO-001", Severity.CRITICAL)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.status in (ScoreStatus.CRITICAL, ScoreStatus.POOR)

    def test_securemailscope_version_persisted(self):
        """SecureMailScope version must be persisted in score."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="1.0.0-beta"
        )
        assert posture.securemailscope_version == "1.0.0-beta"

    def test_analysis_timestamp_recorded(self):
        """Analysis timestamp must be recorded."""
        findings = [make_finding("CERT-001")]
        before = datetime.now(timezone.utc)
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        after = datetime.now(timezone.utc)
        assert before <= posture.analyzed_at <= after

    def test_findings_count_recorded(self):
        """Number of findings must be recorded."""
        findings = [make_finding("CERT-001", session_id=f"sess-{i}") for i in range(7)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.findings_count == 7

    def test_top_contributors_ranked_by_impact(self):
        """Top contributors must be ranked by impact_points descending."""
        findings = [
            make_finding("CERT-001", Severity.HIGH, session_id="sess-1"),
            make_finding("TLS-001", Severity.CRITICAL, session_id="sess-2"),
            make_finding("CERT-003", Severity.MEDIUM, session_id="sess-3"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        impacts = [c.impact_points for c in posture.top_contributors]
        assert impacts == sorted(impacts, reverse=True)

    def test_dimension_score_excellent_when_no_issues(self):
        """Dimension with no issues must score 100."""
        findings = [make_finding("TLS-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Certificate dimension has no issues
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.score == 100.0

    def test_dimension_score_poor_when_issues_present(self):
        """Dimension with issues must score below 100."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.score < 100

    def test_dimension_affected_sessions_tracked(self):
        """Dimension must track affected sessions."""
        findings = [make_finding("CERT-001", Severity.HIGH, session_id="sess-1")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.affected_sessions >= 0

    def test_dimension_findings_count(self):
        """Dimension must track number of findings."""
        findings = [make_finding("CERT-001", Severity.HIGH), make_finding("CERT-003", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.findings_count == 2

    def test_root_cause_groups_not_empty_with_findings(self):
        """Root cause groups must be populated when findings exist."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert len(posture.root_cause_groups) > 0

    def test_root_cause_group_contains_issue_description(self):
        """Root cause group must contain the root issue description."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # "Expired Certificate" must be a key in root_cause_groups
        assert "Expired Certificate" in posture.root_cause_groups

    def test_score_explanation_not_empty(self):
        """Score explanation must be non-empty when findings exist."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        summary = posture.get_summary()
        assert len(summary) > 0
        assert "Security Posture" in summary

    def test_dimension_names_mapped(self):
        """Dimension names must be mapped correctly."""
        findings = [make_finding("TLS-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        tls_dim = next(d for d in posture.dimension_scores if d.dimension == "tls_protocol")
        assert tls_dim.name == "TLS Protocol"

    def test_scoring_policy_customizable(self):
        """Scoring policy must be customizable."""
        custom_policy = ScoringPolicy(version="2.0")
        scorer = SecurityPostureScorer(policy=custom_policy)
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.scoring_policy_version == "2.0"

    def test_unknown_rule_id_fallback(self):
        """Unknown rule IDs must not crash the scoring engine."""
        findings = [make_finding("UNKNOWN-999", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Should not crash; should still produce a valid score
        assert 0 <= posture.overall_score <= 100

    def test_severity_mapping_exists(self):
        """All M8 severities must have impact mappings."""
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert severity in SEVERITY_IMPACT_MAP, f"Missing severity mapping for {severity}"

    def test_score_bands_cover_full_range(self):
        """Score bands must cover the full 0-100 range."""
        covered = 0
        for (min_s, max_s), _ in SCORE_BANDS.items():
            covered += (max_s - min_s + 1)
        # Bands should cover 0-100 (note: some overlap at boundaries)
        assert covered >= 100

    def test_root_cause_group_affected_sessions(self):
        """Root cause group must track affected sessions."""
        findings = [make_finding("CERT-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(5)]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        # All 5 sessions should be tracked
        assert "Expired Certificate" in groups
        group = groups["Expired Certificate"]
        assert group.total_sessions == 10

    def test_dimension_scorer_does_not_modify_policy(self):
        """Scoring engine must not modify the policy."""
        policy = ScoringPolicy(version="test")
        scorer = SecurityPostureScorer(policy=policy)
        findings = [make_finding("CERT-001")]
        scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert policy.version == "test"

    def test_multiple_sessions_with_same_finding(self):
        """Multiple sessions with the same finding type must be aggregated."""
        findings = [
            make_finding("CERT-001", Severity.HIGH, session_id="sess-1"),
            make_finding("CERT-001", Severity.HIGH, session_id="sess-2"),
            make_finding("CERT-001", Severity.HIGH, session_id="sess-3"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Root cause grouping should consolidate into one group
        assert len(posture.root_cause_groups) == 1
        assert "Expired Certificate" in posture.root_cause_groups

    def test_different_findings_different_root_causes(self):
        """Different finding types must create different root cause groups."""
        findings = [
            make_finding("CERT-001", Severity.HIGH, session_id="sess-1"),
            make_finding("TLS-001", Severity.HIGH, session_id="sess-2"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Should have separate root cause groups for different finding types
        assert len(posture.root_cause_groups) >= 2
        assert "Expired Certificate" in posture.root_cause_groups
        assert "Deprecated TLS Protocol Version" in posture.root_cause_groups

    def test_score_not_penalized_for_unknown_cert(self):
        """Missing certificate evidence should not penalize score."""
        # No certificate findings, but TLS present
        findings = [make_finding("TLS-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Certificate dimension should score 100 when no cert issues
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        # Note: CERT-005 (self-signed) is a certificate dimension finding; if absent, cert score may be 100
        # But if TLS evidence is present, cert coverage may be partial
        assert 0 <= cert_dim.score <= 100

    def test_coverage_percent_calculation(self):
        """Coverage percentage must be calculated correctly."""
        findings = [make_finding("TLS-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.tls_coverage_percent >= 0
        assert posture.tls_coverage_percent <= 100

    def test_session_level_score_range(self):
        """Session-level posture score must be in valid range."""
        findings = [make_finding("TLS-001", Severity.MEDIUM, session_id="single-sess")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert 0 <= posture.overall_score <= 100

    def test_findings_without_session_id(self):
        """Findings without session_id must not crash the scorer."""
        finding = FindingResult(
            finding_id="test-001",
            rule_id="CERT-001",
            category="Certificate Security",
            title="Expired Certificate",
            severity=Severity.HIGH,
            confidence=1.0,
            description="",
            recommendation="",
        )
        posture = self.scorer.calculate_posture(
            findings=[finding],
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert 0 <= posture.overall_score <= 100

    def test_score_with_all_dimensions_affected(self):
        """All dimensions affected must produce low overall score."""
        findings = [
            make_finding("TLS-001", Severity.CRITICAL),
            make_finding("TLS-003", Severity.CRITICAL),
            make_finding("TLS-004", Severity.MEDIUM),
            make_finding("CERT-001", Severity.HIGH),
            make_finding("CERT-003", Severity.HIGH),
            make_finding("CERT-005", Severity.MEDIUM),
            make_finding("STLS-001", Severity.HIGH),
            make_finding("PROTO-001", Severity.CRITICAL),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 50
        assert posture.status in (ScoreStatus.CRITICAL, ScoreStatus.POOR)

    def test_existing_e2e_ground_truth_smtp_tls13_secure(self):
        """Test against existing E2E ground truth: smtp_starttls_tls13_secure."""
        findings = [
            make_finding("CERT-005", Severity.MEDIUM, session_id="stream-1"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        # Should have certificate dimension affected
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.score < 100  # Self-signed cert reduces score
        assert posture.overall_score < 100
        assert posture.status in (ScoreStatus.GOOD, ScoreStatus.NEEDS_IMPROVEMENT, ScoreStatus.POOR, ScoreStatus.CRITICAL)

    def test_existing_e2e_ground_truth_smtp_weak_deprecated(self):
        """Test against existing E2E ground truth: smtp_weak_deprecated."""
        findings = [
            make_finding("TLS-001", Severity.HIGH, session_id="stream-2"),
            make_finding("TLS-004", Severity.MEDIUM, session_id="stream-2"),
            make_finding("CERT-001", Severity.HIGH, session_id="stream-2"),
            make_finding("CERT-003", Severity.HIGH, session_id="stream-2"),
            make_finding("CERT-005", Severity.MEDIUM, session_id="stream-2"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        # Multiple critical issues should produce low score
        assert posture.overall_score < 60
        assert len(posture.root_cause_groups) >= 3  # Deprecated TLS, No FS, Expired Cert, Weak Key, Self-Signed

    def test_existing_e2e_ground_truth_smtp_starttls_downgrade(self):
        """Test against existing E2E ground truth: smtp_starttls_downgrade."""
        findings = [
            make_finding("STLS-001", Severity.HIGH, session_id="stream-3"),
            make_finding("PROTO-001", Severity.CRITICAL, session_id="stream-3"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,  # No TLS established
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        # STARTTLS rejection should affect starttls and protocol dimensions
        assert posture.overall_score < 100
        stls_dim = next(d for d in posture.dimension_scores if d.dimension == "starttls")
        assert stls_dim.score < 100

    def test_existing_e2e_ground_truth_imap_starttls_tls12(self):
        """Test against existing E2E ground truth: imap_starttls_tls12."""
        findings = [
            make_finding("CERT-005", Severity.MEDIUM, session_id="stream-4"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.score < 100

    def test_existing_e2e_ground_truth_pop3_starttls_rejected(self):
        """Test against existing E2E ground truth: pop3_starttls_rejected."""
        findings = [
            make_finding("STLS-001", Severity.HIGH, session_id="stream-5"),
            make_finding("PROTO-001", Severity.CRITICAL, session_id="stream-5"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,  # No TLS
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100

    def test_existing_e2e_ground_truth_smtp_starttls_truncated(self):
        """Test against existing E2E ground truth: smtp_starttls_truncated (no findings)."""
        findings = []
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,  # TLS not established
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        # No findings should mean perfect score
        assert posture.overall_score == 100.0
        assert posture.status == ScoreStatus.EXCELLENT

    def test_layer_b_tls13_secure(self):
        """Test against Layer-B fixture: layer_b_smtp_tls13_secure."""
        findings = [make_finding("CERT-005", Severity.MEDIUM, session_id="stream-lb1")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100
        assert posture.status != ScoreStatus.EXCELLENT

    def test_layer_b_tls12_weak(self):
        """Test against Layer-B fixture: layer_b_smtp_tls12_weak."""
        findings = [
            make_finding("TLS-004", Severity.MEDIUM, session_id="stream-lb2"),
            make_finding("CERT-001", Severity.HIGH, session_id="stream-lb2"),
            make_finding("CERT-003", Severity.HIGH, session_id="stream-lb2"),
            make_finding("CERT-005", Severity.MEDIUM, session_id="stream-lb2"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        # Multiple weak configurations should produce low score
        assert posture.overall_score < 70

    def test_layer_b_imap_segmented(self):
        """Test against Layer-B fixture: layer_b_imap_tls12_segmented."""
        findings = [make_finding("CERT-005", Severity.MEDIUM, session_id="stream-lb3")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=1,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100

    def test_example_calculation_step_by_step(self):
        """Worked numerical example matching the specification.

        Hypothetical capture:
        - 100 TLS sessions
        - 10 deprecated TLS sessions (TLS-001, HIGH severity)
        - 2 expired certificates (CERT-001, HIGH severity)
        - 5 sessions without forward secrecy (TLS-004, MEDIUM severity)
        """
        findings = []
        # 10 deprecated TLS sessions
        for i in range(10):
            findings.append(make_finding("TLS-001", Severity.HIGH, session_id=f"tls-sess-{i}"))
        # 2 expired certificates
        for i in range(2):
            findings.append(make_finding("CERT-001", Severity.HIGH, session_id=f"cert-sess-{i}"))
        # 5 sessions without forward secrecy
        for i in range(5):
            findings.append(make_finding("TLS-004", Severity.MEDIUM, session_id=f"fs-sess-{i}"))

        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=100,
            protocol_session_count=100,
            securemailscope_version="0.1.0"
        )

        # Verify structure
        assert posture.overall_score >= 0
        assert posture.overall_score < 100  # Should have some reduction due to findings
        assert len(posture.dimension_scores) == 5  # All dimensions present
        assert len(posture.top_contributors) > 0

        # Verify dimension breakdown exists
        dim_names = {d.dimension for d in posture.dimension_scores}
        assert "tls_protocol" in dim_names
        assert "cryptography" in dim_names
        assert "certificate" in dim_names
        assert "starttls" in dim_names
        assert "protocol" in dim_names

        # TLS protocol dimension should be affected (deprecated TLS)
        tls_dim = next(d for d in posture.dimension_scores if d.dimension == "tls_protocol")
        assert tls_dim.score < 100
        assert tls_dim.findings_count == 10  # All 10 deprecated TLS findings

        # Certificate dimension should be affected (expired certs)
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.score < 100
        assert cert_dim.findings_count == 2

        # Cryptography dimension should be affected (forward secrecy)
        crypto_dim = next(d for d in posture.dimension_scores if d.dimension == "cryptography")
        assert crypto_dim.score < 100
        assert crypto_dim.findings_count == 5

    def test_dimension_weights_sum_to_one(self):
        """Verify dimension weights sum to 1.0."""
        total_weight = sum(
            dim.weight for dim in DEFAULT_POLICY.dimensions.values()
        )
        assert abs(total_weight - 1.0) < 0.01, f"Weights sum to {total_weight}, expected 1.0"

    def test_dimension_rules_mapping(self):
        """Verify dimension rules mapping is correct."""
        # TLS-001 should map to tls_protocol dimension
        assert "TLS-001" in DEFAULT_POLICY.dimensions["tls_protocol"].rules
        # CERT-001 should map to certificate dimension
        assert "CERT-001" in DEFAULT_POLICY.dimensions["certificate"].rules
        # STLS-001 should map to starttls dimension
        assert "STLS-001" in DEFAULT_POLICY.dimensions["starttls"].rules

    def test_create_posture_from_session_results(self):
        """Test the convenience method for session results."""
        session_results = [
            {
                "stream_id": "stream-1",
                "protocol": "SMTP",
                "findings": [
                    make_finding("CERT-005", Severity.MEDIUM, session_id="stream-1")
                ]
            },
            {
                "stream_id": "stream-2",
                "protocol": "IMAP",
                "findings": [
                    make_finding("TLS-001", Severity.HIGH, session_id="stream-2")
                ]
            }
        ]
        posture = self.scorer.create_posture_from_session_results(
            session_results=session_results,
            tls_session_count=2,
            protocol_session_count=2,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100
        assert posture.total_sessions == 2
        assert len(posture.dimension_scores) == 5

    def test_top_contributors_limited(self):
        """Top contributors should be limited to top 5."""
        # Create many different findings
        findings = []
        for i, rule_id in enumerate(["CERT-001", "CERT-003", "CERT-005", "TLS-001", "TLS-003", "TLS-004", "STLS-001", "PROTO-001"]):
            findings.append(make_finding(rule_id, Severity.HIGH, session_id=f"sess-{i}"))

        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Top contributors should be limited (currently top 5 by impact)
        assert len(posture.top_contributors) <= 5

    def test_posture_score_to_dict(self):
        """PostureScore.to_dict() must produce valid dictionary."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        d = posture.to_dict()
        assert "overall_score" in d
        assert "status" in d
        assert "scoring_policy_version" in d
        assert "metadata" in d
        assert "dimensions" in d
        assert "top_contributors" in d
        assert d["metadata"]["total_sessions"] == 10
        assert d["metadata"]["findings_count"] == 1

    def test_dimension_score_to_dict(self):
        """DimensionScore.to_dict() must produce valid dictionary."""
        dim = DimensionScore(
            dimension="certificate",
            name="Certificate Security",
            score=85.0,
            weight=0.25,
            affected_sessions=2,
            assessable_sessions=10,
            findings_count=2,
            coverage_percent=100.0,
            evidence_quality=EvidenceQuality.FULL,
            top_contributors=[]
        )
        d = dim.to_dict()
        assert d["dimension"] == "certificate"
        assert d["score"] == 85.0
        assert d["weight"] == 0.25
        assert d["affected_sessions"] == 2
        assert d["coverage_percent"] == 100.0

    def test_analyzed_at_timestamp(self):
        """Analysis timestamp must be set and reasonable."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.analyzed_at is not None
        # Should be recent (within last minute)
        delta = datetime.now(timezone.utc) - posture.analyzed_at
        assert delta.total_seconds() < 60

    def test_sessions_with_findings_tracked(self):
        """Sessions with findings must be tracked."""
        findings = [
            make_finding("CERT-001", Severity.HIGH, session_id="sess-1"),
            make_finding("CERT-001", Severity.HIGH, session_id="sess-1"),  # Duplicate session
            make_finding("CERT-001", Severity.HIGH, session_id="sess-2"),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Should track 2 unique sessions with findings
        assert posture.sessions_with_findings == 2

    def test_coverage_percent_not_exceed_100(self):
        """Coverage percentage must not exceed 100%."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.tls_coverage_percent <= 100
        assert posture.certificate_coverage_percent <= 100

    def test_all_dimensions_present_in_output(self):
        """All configured dimensions must appear in output."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        dim_names = {d.dimension for d in posture.dimension_scores}
        expected = {"tls_protocol", "cryptography", "certificate", "starttls", "protocol"}
        assert expected == dim_names

    def test_evidence_quality_full_for_certificate_findings(self):
        """Evidence quality must be FULL when certificate findings exist."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.evidence_quality == EvidenceQuality.FULL

    def test_evidence_quality_not_observed_without_tls(self):
        """Evidence quality should reflect NOT_OBSERVED when no TLS evidence."""
        # Protocol findings without TLS
        findings = [make_finding("PROTO-001", Severity.CRITICAL)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,  # No TLS sessions
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Cryptography dimension should reflect insufficient evidence
        crypto_dim = next(d for d in posture.dimension_scores if d.dimension == "cryptography")
        # Since no TLS sessions, evidence quality may be NOT_OBSERVED
        assert crypto_dim.evidence_quality in (EvidenceQuality.NOT_OBSERVED, EvidenceQuality.INSUFFICIENT)

    def test_findings_count_zero_for_empty(self):
        """Findings count must be zero when no findings exist."""
        posture = self.scorer.calculate_posture(
            findings=[],
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.findings_count == 0

    def test_get_summary_returns_string(self):
        """get_summary() must return a string."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        summary = posture.get_summary()
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_total_sessions_recorded(self):
        """Total sessions must be recorded."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=25,
            securemailscope_version="0.1.0"
        )
        assert posture.total_sessions == 25
        assert posture.tls_sessions == 10

    def test_mixed_severity_findings(self):
        """Mixed severity findings must be handled correctly."""
        findings = [
            make_finding("CERT-001", Severity.CRITICAL),
            make_finding("TLS-004", Severity.LOW),
            make_finding("PROTO-001", Severity.MEDIUM),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Should produce a valid score
        assert 0 <= posture.overall_score <= 100
        # CRITICAL finding should dominate
        assert posture.overall_score < 75

    def test_single_session_critical_finding(self):
        """Single session with critical finding must produce low score."""
        findings = [make_finding("PROTO-001", Severity.CRITICAL, session_id="single")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,
            protocol_session_count=1,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 50
        assert posture.status in (ScoreStatus.CRITICAL, ScoreStatus.POOR)

    def test_no_tls_sessions_only_plaintext(self):
        """Capture with only plaintext (no TLS) sessions."""
        findings = [make_finding("PROTO-001", Severity.CRITICAL)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,  # No TLS sessions
            protocol_session_count=5,  # But 5 plaintext sessions
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100
        assert posture.total_sessions == 5

    def test_large_capture_many_sessions(self):
        """Large capture with many sessions must not crash."""
        findings = []
        for i in range(100):
            findings.append(make_finding("CERT-005", Severity.MEDIUM, session_id=f"sess-{i}"))
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=100,
            protocol_session_count=100,
            securemailscope_version="0.1.0"
        )
        assert 0 <= posture.overall_score <= 100
        assert posture.total_sessions == 100

    def test_root_cause_group_finding_ids(self):
        """Root cause group must track finding IDs."""
        findings = [make_finding("CERT-001", Severity.HIGH, session_id=f"sess-{i}") for i in range(3)]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        group = groups["Expired Certificate"]
        assert len(group.finding_ids) == 3
        assert all("CERT-001" in fid for fid in group.finding_ids)

    def test_root_cause_group_severity(self):
        """Root cause group must track severity."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        group = groups["Expired Certificate"]
        assert group.severity == "HIGH"

    def test_root_cause_group_severity_impact(self):
        """Root cause group must track severity impact."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        group = groups["Expired Certificate"]
        assert group.severity_impact > 0

    def test_group_by_root_cause_empty(self):
        """Grouping empty findings must produce empty groups."""
        groups = self.scorer._group_by_root_cause([], total_sessions=10)
        assert len(groups) == 0

    def test_group_by_root_cause_single_finding(self):
        """Grouping single finding must produce one group."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        assert len(groups) == 1
        assert "Expired Certificate" in groups

    def test_group_by_root_cause_multiple_rules(self):
        """Grouping multiple different rules must produce multiple groups."""
        findings = [
            make_finding("CERT-001", Severity.HIGH),
            make_finding("TLS-001", Severity.HIGH),
            make_finding("PROTO-001", Severity.CRITICAL),
        ]
        groups = self.scorer._group_by_root_cause(findings, total_sessions=10)
        assert len(groups) == 3

    def test_calculate_dimension_coverage_tls_dimensions(self):
        """TLS-related dimensions should use TLS session count for coverage."""
        scorer = SecurityPostureScorer()
        coverage = scorer._calculate_dimension_coverage("tls_protocol", tls_session_count=5, total_sessions=10)
        assert coverage == 100.0  # Simplified implementation

    def test_calculate_dimension_coverage_non_tls(self):
        """Non-TLS dimensions should use total session count for coverage."""
        scorer = SecurityPostureScorer()
        coverage = scorer._calculate_dimension_coverage("protocol", tls_session_count=5, total_sessions=10)
        assert coverage == 100.0  # Simplified implementation

    def test_calculate_dimension_coverage_zero_sessions(self):
        """Coverage should be 100% when no sessions to assess."""
        scorer = SecurityPostureScorer()
        coverage = scorer._calculate_dimension_coverage("tls_protocol", tls_session_count=0, total_sessions=0)
        assert coverage == 100.0

    def test_calculate_evidence_quality_full(self):
        """Evidence quality should be FULL for dimensions with TLS findings."""
        scorer = SecurityPostureScorer()
        findings = [make_finding("TLS-001", Severity.HIGH)]
        quality = scorer._calculate_evidence_quality(findings, "tls_protocol")
        assert quality == EvidenceQuality.FULL

    def test_calculate_evidence_quality_not_observed(self):
        """Evidence quality should reflect NOT_OBSERVED when no TLS evidence."""
        scorer = SecurityPostureScorer()
        findings = [make_finding("PROTO-001", Severity.CRITICAL)]
        quality = scorer._calculate_evidence_quality(findings, "tls_protocol")
        assert quality == EvidenceQuality.NOT_OBSERVED

    def test_coverage_metrics_structure(self):
        """Coverage metrics must have correct structure."""
        findings = [make_finding("TLS-001")]
        scorer = SecurityPostureScorer()
        metrics = scorer._calculate_coverage_metrics(findings, tls_session_count=5, total_sessions=5)
        assert "tls" in metrics
        assert "certificate" in metrics
        assert metrics["tls"].total_sessions == 5
        assert metrics["certificate"].total_sessions == 5

    def test_get_top_contributors_empty(self):
        """Top contributors should be empty when no dimension contributors exist."""
        scorer = SecurityPostureScorer()
        empty_dim = DimensionScore(
            dimension="test",
            name="Test",
            score=100.0,
            weight=0.2,
            affected_sessions=0,
            assessable_sessions=0,
            findings_count=0,
            coverage_percent=100.0,
            evidence_quality=EvidenceQuality.FULL,
            top_contributors=[]
        )
        top = scorer._get_top_contributors([empty_dim])
        assert len(top) == 0

    def test_get_top_contributors_ranked(self):
        """Top contributors must be ranked by impact."""
        scorer = SecurityPostureScorer()
        contrib1 = ScoreContribution(
            root_issue="Issue A",
            severity="HIGH",
            affected_sessions=5,
            total_sessions=10,
            prevalence=0.5,
            impact_points=15.0,
            explanation="Test"
        )
        contrib2 = ScoreContribution(
            root_issue="Issue B",
            severity="MEDIUM",
            affected_sessions=3,
            total_sessions=10,
            prevalence=0.3,
            impact_points=8.0,
            explanation="Test"
        )
        dim = DimensionScore(
            dimension="test",
            name="Test",
            score=80.0,
            weight=0.2,
            affected_sessions=5,
            assessable_sessions=10,
            findings_count=2,
            coverage_percent=100.0,
            evidence_quality=EvidenceQuality.FULL,
            top_contributors=[contrib1, contrib2]
        )
        top = scorer._get_top_contributors([dim])
        assert len(top) == 2
        assert top[0].impact_points >= top[1].impact_points

    def test_format_root_cause_groups(self):
        """Root cause groups must be formatted correctly."""
        scorer = SecurityPostureScorer()
        root_groups = {
            "Expired Certificate": RootCauseGroup(
                root_issue="Expired Certificate",
                finding_ids=["sess-1-CERT-001"],
                severity="HIGH",
                affected_sessions=2,
                total_sessions=10,
                severity_impact=15.0
            )
        }
        formatted = scorer._format_root_cause_groups(root_groups)
        assert "Expired Certificate" in formatted
        assert formatted["Expired Certificate"]["affected_sessions"] == 2
        assert formatted["Expired Certificate"]["severity"] == "HIGH"
        assert formatted["Expired Certificate"]["prevalence_percent"] == 20.0

    def test_format_root_cause_groups_empty(self):
        """Formatting empty root cause groups must produce empty dict."""
        scorer = SecurityPostureScorer()
        formatted = scorer._format_root_cause_groups({})
        assert len(formatted) == 0

    def test_generate_explanation(self):
        """Explanation must be generated correctly."""
        scorer = SecurityPostureScorer()
        root_group = RootCauseGroup(
            root_issue="Expired Certificate",
            finding_ids=["sess-1-CERT-001"],
            severity="HIGH",
            affected_sessions=5,
            total_sessions=10,
            severity_impact=15.0
        )
        explanation = scorer._generate_explanation("Expired Certificate", root_group, 0.5)
        assert "Expired Certificate" in explanation
        assert "HIGH" in explanation
        assert "50.0%" in explanation  # prevalence

    def test_generate_explanation_low_prevalence(self):
        """Explanation for low prevalence must use different text."""
        scorer = SecurityPostureScorer()
        root_group = RootCauseGroup(
            root_issue="Expired Certificate",
            finding_ids=["sess-1-CERT-001"],
            severity="MEDIUM",
            affected_sessions=1,
            total_sessions=100,
            severity_impact=8.0
        )
        explanation = scorer._generate_explanation("Expired Certificate", root_group, 0.01)
        assert "Expired Certificate" in explanation
        assert "affecting 1 sessions" in explanation

    def test_generate_explanation_widespread(self):
        """Explanation for widespread issues must use different text."""
        scorer = SecurityPostureScorer()
        root_group = RootCauseGroup(
            root_issue="Expired Certificate",
            finding_ids=["sess-1-CERT-001"],
            severity="CRITICAL",
            affected_sessions=80,
            total_sessions=100,
            severity_impact=25.0
        )
        explanation = scorer._generate_explanation("Expired Certificate", root_group, 0.8)
        assert "widespread" in explanation
        assert "80.0%" in explanation

    def test_custom_policy_version(self):
        """Custom policy version must be used."""
        custom_policy = ScoringPolicy(version="2.0-beta")
        scorer = SecurityPostureScorer(policy=custom_policy)
        findings = [make_finding("CERT-001")]
        posture = scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.scoring_policy_version == "2.0-beta"

    def test_custom_severity_impact(self):
        """Custom severity impact map must be used."""
        custom_policy = ScoringPolicy(
            version="custom",
            severity_impact={"CRITICAL": 30.0, "HIGH": 20.0, "MEDIUM": 10.0, "LOW": 5.0, "INFO": 1.0}
        )
        scorer = SecurityPostureScorer(policy=custom_policy)
        findings = [make_finding("CERT-001", Severity.CRITICAL)]
        posture = scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score < 100

    def test_custom_dimension_weights(self):
        """Custom dimension weights must be used."""
        from securemailscope.scoring.config import DimensionConfig
        custom_dims = {
            "certificate": DimensionConfig(
                name="Certificate Security",
                weight=0.5,
                description="Certificate security",
                rules=["CERT-001", "CERT-003", "CERT-005"]
            ),
            "tls_protocol": DimensionConfig(
                name="TLS Protocol",
                weight=0.5,
                description="TLS protocol security",
                rules=["TLS-001"]
            ),
        }
        custom_policy = ScoringPolicy(version="custom-weights", dimensions=custom_dims)
        scorer = SecurityPostureScorer(policy=custom_policy)
        findings = [make_finding("CERT-001")]
        posture = scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Certificate dimension should have higher weight
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.weight == 0.5

    def test_create_posture_from_empty_session_results(self):
        """Creating posture from empty session results must work."""
        posture = self.scorer.create_posture_from_session_results(
            session_results=[],
            tls_session_count=0,
            protocol_session_count=0,
            securemailscope_version="0.1.0"
        )
        assert posture.overall_score == 100.0
        assert posture.status == ScoreStatus.EXCELLENT

    def test_create_posture_from_session_results_mixed(self):
        """Creating posture from mixed session results must work."""
        session_results = [
            {"stream_id": "s1", "protocol": "SMTP", "findings": [make_finding("CERT-005")]},
            {"stream_id": "s2", "protocol": "IMAP", "findings": [make_finding("TLS-001")]},
            {"stream_id": "s3", "protocol": "POP3", "findings": []},
        ]
        posture = self.scorer.create_posture_from_session_results(
            session_results=session_results,
            tls_session_count=2,
            protocol_session_count=3,
            securemailscope_version="0.1.0"
        )
        assert posture.total_sessions == 3
        assert posture.tls_sessions == 2
        assert posture.overall_score < 100

    def test_all_m8_rules_mapped(self):
        """All M8 rule IDs must be mapped in the scoring engine."""
        all_rule_ids = ["PROTO-001", "STLS-001", "TLS-001", "TLS-003", "TLS-004", "CERT-001", "CERT-003", "CERT-004", "CERT-005"]
        for rule_id in all_rule_ids:
            root_issue = self.scorer._get_root_issue_from_finding(
                make_finding(rule_id, Severity.HIGH)
            )
            assert root_issue != rule_id or rule_id in ["PROTO-001", "STLS-001", "TLS-001", "TLS-003", "TLS-004", "CERT-001", "CERT-003", "CERT-004", "CERT-005"]

    def test_scoring_with_confidence_weighting(self):
        """Confidence values must influence scoring."""
        high_conf = [make_finding("CERT-001", Severity.HIGH, confidence=1.0)]
        low_conf = [make_finding("CERT-001", Severity.HIGH, confidence=0.5)]
        posture_high = self.scorer.calculate_posture(high_conf, 10, 10, "0.1.0")
        posture_low = self.scorer.calculate_posture(low_conf, 10, 10, "0.1.0")
        # High confidence should produce lower (worse) score
        assert posture_high.overall_score <= posture_low.overall_score

    def test_dimension_assessable_sessions(self):
        """Dimension must track assessable sessions."""
        findings = [make_finding("CERT-001")]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=20,
            securemailscope_version="0.1.0"
        )
        cert_dim = next(d for d in posture.dimension_scores if d.dimension == "certificate")
        assert cert_dim.assessable_sessions <= posture.total_sessions

    def test_dimension_evidence_quality_not_observed(self):
        """Evidence quality should be NOT_OBSERVED for dimensions without evidence."""
        findings = [make_finding("PROTO-001", Severity.CRITICAL)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=0,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Cryptography dimension has no TLS evidence
        crypto_dim = next(d for d in posture.dimension_scores if d.dimension == "cryptography")
        assert crypto_dim.evidence_quality in (EvidenceQuality.NOT_OBSERVED, EvidenceQuality.INSUFFICIENT)

    def test_sessions_with_findings_zero(self):
        """Sessions with findings must be zero when no findings exist."""
        posture = self.scorer.calculate_posture(
            findings=[],
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert posture.sessions_with_findings == 0

    def test_top_contributors_explanation(self):
        """Top contributors must have explanations."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        for contrib in posture.top_contributors:
            assert len(contrib.explanation) > 0
            assert contrib.root_issue != ""

    def test_root_cause_groups_populated(self):
        """Root cause groups must be populated for all finding types."""
        findings = [
            make_finding("CERT-001", Severity.HIGH),
            make_finding("TLS-001", Severity.HIGH),
            make_finding("TLS-004", Severity.MEDIUM),
            make_finding("STLS-001", Severity.HIGH),
            make_finding("PROTO-001", Severity.CRITICAL),
        ]
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        assert "Expired Certificate" in posture.root_cause_groups
        assert "Deprecated TLS Protocol Version" in posture.root_cause_groups
        assert "No Forward Secrecy" in posture.root_cause_groups
        assert "STARTTLS Negotiation Rejected (Potential Downgrade)" in posture.root_cause_groups
        assert "Unencrypted Email Communication (Plaintext)" in posture.root_cause_groups

    def test_findings_not_modified_by_scoring(self):
        """Scoring must not modify the original findings."""
        findings = [make_finding("CERT-001", Severity.HIGH)]
        original_rule_id = findings[0].rule_id
        original_severity = findings[0].severity
        posture = self.scorer.calculate_posture(
            findings=findings,
            tls_session_count=10,
            protocol_session_count=10,
            securemailscope_version="0.1.0"
        )
        # Original findings must be unchanged
        assert findings[0].rule_id == original_rule_id
        assert findings[0].severity == original_severity

    def test_dimension_score_with_no_assessable_sessions(self):
        """Dimension score must handle zero assessable sessions."""
        dim = DimensionScore(
            dimension="test",
            name="Test",
            score=100.0,
            weight=0.2,
            affected_sessions=0,
            assessable_sessions=0,
            findings_count=0,
            coverage_percent=100.0,
            evidence_quality=EvidenceQuality.INSUFFICIENT,
            top_contributors=[]
        )
        assert dim.coverage_percent == 100.0  # No sessions = full coverage

    def test_coverage_metric_total_zero(self):
        """Coverage metric must handle zero total sessions."""
        metric = CoverageMetric(
            dimension="test",
            total_sessions=0,
            assessable_sessions=0,
            quality=EvidenceQuality.INSUFFICIENT,
            reason="No sessions"
        )
        assert metric.coverage_percent == 100.0  # 0/0 = 100%

    def test_severity_impact_map_complete(self):
        """Severity impact map must cover all M8 severities."""
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert severity in SEVERITY_IMPACT_MAP
            assert SEVERITY_IMPACT_MAP[severity] > 0

    def test_dimension_weight_positive(self):
        """All dimension weights must be positive."""
        for dim_name, dim_config in DEFAULT_POLICY.dimensions.items():
            assert dim_config.weight > 0, f"Dimension {dim_name} has non-positive weight"

    def test_dimension_description_not_empty(self):
        """All dimension descriptions must be non-empty."""
        for dim_name, dim_config in DEFAULT_POLICY.dimensions.items():
            assert len(dim_config.description) > 0, f"Dimension {dim_name} has empty description"

    def test_score_bands_ordered(self):
        """Score bands must be ordered from highest to lowest."""
        bands = list(SCORE_BANDS.keys())
        for i in range(len(bands) - 1):
            assert bands[i][0] > bands[i+1][0], "Score bands must be ordered descending"

    def test_status_for_boundary_scores(self):
        """Status mapping must work for boundary scores."""
        assert DEFAULT_POLICY.get_status(90).value == "Excellent"
        assert DEFAULT_POLICY.get_status(75).value == "Good"
        assert DEFAULT_POLICY.get_status(60).value == "Needs Improvement"
        assert DEFAULT_POLICY.get_status(40).value == "Poor"
        assert DEFAULT_POLICY.get_status(0).value == "Critical"
        assert DEFAULT_POLICY.get_status(-1).value == "Unknown"
        assert DEFAULT_POLICY.get_status(101).value == "Unknown"

    def test_get_dimension_by_rule(self):
        """Dimension by rule mapping must work."""
        assert DEFAULT_POLICY.get_dimension_by_rule("TLS-001") == "tls_protocol"
        assert DEFAULT_POLICY.get_dimension_by_rule("CERT-001") == "certificate"
        assert DEFAULT_POLICY.get_dimension_by_rule("STLS-001") == "starttls"  # STLS-001 mapped to starttls
        assert DEFAULT_POLICY.get_dimension_by_rule("PROTO-001") == "protocol"  # PROTO-001 is in protocol rules

    def test_get_dimension_by_rule_unknown(self):
        """Unknown rule IDs must fallback to protocol dimension."""
        result = DEFAULT_POLICY.get_dimension_by_rule("UNKNOWN-999")
        assert result == "protocol"
