# Security Scoring (M9)

## Purpose

The M9 Security Posture Scoring System provides a transparent, evidence-based, and fully explainable cryptographic security posture score for SecureMailScope captures.

## Score Range

- **0–100**: Normalized security posture
- **100 = Excellent**
- **0 = Critical**

## Core Principle

Evidence → Findings → Severity → Impact → Aggregated Score

The scoring layer consumes validated M8 findings and never duplicates cryptographic detection logic.

## Dimensions

| Dimension | Weight | Rules | Description |
|-----------|--------|-------|-------------|
| TLS Protocol | 0.20 | TLS-001 | Deprecated TLS versions |
| Cryptography | 0.15 | TLS-003, TLS-004 | Cipher suites, key exchange |
| Certificate | 0.25 | CERT-001, CERT-003, CERT-005 | Cert validity, key strength |
| STARTTLS | 0.20 | STLS-001 | STARTTLS negotiation |
| Protocol | 0.20 | PROTO-001 | Plaintext/downgrade |

## Severity Mapping

| Severity | Impact (points) |
|----------|----------------|
| CRITICAL | 25.0 |
| HIGH | 15.0 |
| MEDIUM | 8.0 |
| LOW | 3.0 |
| INFO | 0.5 |

## Prevalence Treatment

- Same root issue across multiple sessions: **grouped by root cause**
- Widespread issues (prevalence > 50%): **higher multiplier (1.5x)**
- Per-root-issue impact **capped at 40 points** to prevent domination
- No catastrophic double-counting

## Score Formula (Documented)

For a capture with findings:

1. Group findings by root cause
2. For each dimension:
   - Apply severity-based impact
   - Apply prevalence multiplier
   - Cap at 40 points per root cause
   - Dimension score = 100 - sum(impacts)
3. Overall score = weighted average of dimensions

## Worked Example

Capture: 100 TLS sessions
- 10 deprecated TLS (TLS-001, HIGH): root cause grouped → ~15 impact
- 2 expired certs (CERT-001, HIGH): root cause grouped → ~15 impact
- 5 without FS (TLS-004, MEDIUM): root cause grouped → ~8 impact

Approximate dimension scores:
- TLS Protocol: ~85
- Cryptography: ~92
- Certificate: ~85
- STARTTLS: 100
- Protocol: 100

Overall (~weighted): ~89 (Good)

## Double-Counting Prevention

The root-cause grouping mechanism ensures:
- 500 TLS 1.0 sessions → single root cause group, not 500 penalties
- Expired cert + cert warning → grouped if same root
- Same session with multiple findings from same root → counted once

## Unknown / Insufficient Evidence

- Missing TLS evidence → score does NOT penalize
- Incomplete handshakes → documented as NOT_OBSERVED
- Coverage metrics reported separately

## Policy Versioning

- Version: `1.0`
- Every score records policy version and analysis timestamp
- Reproducible across versions

## Score Bands

| Range | Status |
|-------|--------|
| 90–100 | Excellent |
| 75–89 | Good |
| 60–74 | Needs Improvement |
| 40–59 | Poor |
| 0–39 | Critical |

## Testing

- 123 M9 tests covering invariants, dimensions, prevalence, root-cause grouping
- All 61 M1-M8 tests pass (no regression)
- Example calculations use real validated fixtures

## CLI / API Ready

```python
from securemailscope.scoring import SecurityPostureScorer
scorer = SecurityPostureScorer()
posture = scorer.calculate_posture(findings, tls_count, protocol_count, "0.1.0")
print(posture.get_summary())
```
