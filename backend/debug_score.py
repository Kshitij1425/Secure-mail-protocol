from securemailscope.scoring.engine import SecurityPostureScorer
from securemailscope.rules.engine import FindingResult, Severity

findings = [FindingResult(
    finding_id='sess-1-PROTO-001',
    rule_id='PROTO-001',
    category='Test',
    title='Test PROTO-001',
    severity=Severity.CRITICAL,
    confidence=1.0,
    description='',
    recommendation='',
    session_id='sess-1',
)]

scorer = SecurityPostureScorer()
posture = scorer.calculate_posture(findings=findings, tls_session_count=10, protocol_session_count=10, securemailscope_version='0.1.0')

print('Overall score:', posture.overall_score)
print('Status:', posture.status)
print('Root cause groups:', posture.root_cause_groups)
for key, group in posture.root_cause_groups.items():
    print('  Group:', group['root_issue'], 'Impact:', group['severity_impact'])