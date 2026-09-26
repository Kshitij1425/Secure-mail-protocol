# Final Security & Functional Audit - SecureMailScope (2026-09-26)

Scope: full takeover audit of the repository (baseline commit `1686dc2` + uncommitted work found
at takeover). Evidence standard: source code, executed tests, API responses, database contents,
real-capture analysis, browser behaviour, generated reports, measured benchmarks. Prior milestone
documents were not trusted (moved to `docs/history/`).

## Repository

| Item | Count |
|---|---|
| Files audited | all 144 tracked + 22 untracked at takeover |
| Backend modules audited | 40 Python files, 215 functions/methods |
| Frontend files audited | 20 TypeScript/TSX files (all components, pages, hooks, API client) |
| Test modules | 19 (13 pre-existing, reviewed and corrected; 6 new) |
| API endpoints | 24 routes, each exercised by tests |

## Functional status (M1-M15)

| Milestone | Status |
|---|---|
| M1 foundation | WORKING |
| M2 ingestion | WORKING |
| M3 TCP reconstruction | WORKING (rewritten) |
| M4 protocol detection | WORKING |
| M5 STARTTLS | WORKING (rewritten) |
| M6 TLS parsing | WORKING (rewritten) |
| M7 X.509 | WORKING; trust-anchor validation not performed (by design, reported as unknown) |
| M8 rules | WORKING (17 rules) |
| M9 scoring | WORKING (defects fixed; invariants property-tested) |
| M10 CLI + reports | WORKING (JSON/HTML/PDF from the real pipeline) |
| M11 ML | WORKING as supplementary unsupervised detection; no accuracy claim |
| M12 API | WORKING |
| M13 dashboard | WORKING (browser-verified) |
| M14 integration | WORKING (engine == DB == API == report == UI) |
| M15 hardening | WORKING, except Docker files (written, not built: no Docker in environment) |

Functionality items (FUNCTIONAL_REGRESSION_MATRIX.md): 31 - **29 fully working, 1 partial (trust
anchors), 0 broken, 1 unverified (Docker)**.

## SIH26159

Fully implemented: A, B, C, D, E, G, H, I, J, K, L, M, O, P, Q, R, S, T, U, V, W (21).
Partially implemented: F (certificate validation limited to what is observable; no trust anchors;
TLS 1.3 certificates encrypted), N (no supervised ML risk classifier - no labelled data; risk
classification is deterministic). Missing: none. Technically incorrect claims found and corrected:
TLS 1.3 certificate extraction, "chain validation", ML seed documentation, throughput figures.

## Security

| Severity | Discovered | Fixed | Remaining |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 5 (V-01..V-05) | 5 | 0 |
| Medium | 7 (V-06..V-12) | 7 | 0 |
| Low | 5 (V-13..V-17) | 5 | 0 |
| Info | 1 (V-18) | 1 | 0 |
| **Total** | **18** | **18** | **0** |

Accepted limitations: A-01 no API authentication (single local analyst; loopback binding enforced
by default; must not be exposed); A-02 `pip` 24.2 advisories in the audit machine's global
interpreter (tooling, not a dependency). Functional defects with security relevance for result
integrity (e.g. F-01 implicit TLS reported as plaintext, F-04 cipher false negatives/positives,
F-05 TLS 1.3 certificate claims, F-07 non-monotone score, F-30 unshippable package) are listed
in VULNERABILITY_REMEDIATION.md (30 functional defects, all fixed).

Tooling results: bandit 0 issues; `pip-audit -r requirements.lock` 0 known vulnerabilities;
`npm audit` 0 vulnerabilities; secret scan of tree and full git history: none found; no
`dangerouslySetInnerHTML`/`innerHTML`/`eval` in the frontend; no subprocess/shell in product code.

## Testing

| Metric | Value |
|---|---|
| Total tests | 329 |
| Passed / failed / skipped | 329 / 0 / 0 |
| Warnings | 2 (third-party deprecation notices in starlette/httpx test client) |
| Fuzz / property tests | 13 Hypothesis properties (150 examples each in CI; 3000 in the deep campaign, which found and fixed F-07) |
| Real-capture tests | 28 captures with per-session ground truth (TLS bytes from OpenSSL 3.0.13), + 8 cross-cutting real-capture tests |
| Browser E2E | 2 full walkthroughs (dev tree and clean environment), 30-step acceptance: all passed; 2 defects found and fixed (V-17 timezone, stale capture id) |
| Clean environment | fresh copy + venv from lock file: 329/329, 28/28, CLI reports, frontend build/lint |

## Performance (PERFORMANCE_REPORT.md)

Measured on an 8-thread AMD64 laptop, Windows 11, Python 3.12.5: 100k packets (19.9 MB, 4,513
sessions) analysed in 12.6 s (7.9k pkt/s), 21.9 s end-to-end incl. persistence and three
reports; largest tested capture 1,000,000 packets / 198.7 MB analysed in 214 s (4.7k pkt/s),
240 s with persistence, peak RSS 2.0 GB. Methodology: fixture traffic replicated with distinct
connections; single process. Limitations: ~45 connections per 1k packets (connection-heavy
workload); memory grows with the number of connections.

## ML (ML_DESIGN.md)

10 features; scikit-learn Isolation Forest (100 trees, `contamination="auto"`, seed 42); fitted
per capture on its own TLS sessions (>= 5 required); capture-time reference for time features;
batched scoring. Evaluation: no labelled dataset, so no accuracy is claimed. Measured: flags only
the planted outlier in `ml_mixed_estate` (1/12); ~30% of sessions on heterogeneous synthetic
estates (all deterministically weak sessions included). Never alters findings or scores.

## Integration

Direct engine, SQLite, API, JSON/HTML/PDF reports and dashboard were compared on 5 captures in
automated tests (packets, streams, email/TLS sessions, certificates, findings with severities,
anomalies, posture score/status, dimensions) and by hand in the browser: **they match.**

## Final status

**SECURITY HARDENING COMPLETE - NO KNOWN HIGH/CRITICAL ISSUES REMAIN**
(subject to the documented accepted limitation that the API is unauthenticated and must only be
run bound to localhost, as it is by default).

**FUNCTIONALLY VERIFIED** for M1-M14 and M15 hardening; the Docker packaging is written but
unverified, and trust-anchor certificate validation is intentionally out of scope.

This is not a claim that the software is vulnerability-free: it is the result of the audit and
testing documented here. The fixture corpus uses synthesised TCP framing around real TLS bytes;
validation on third-party real-world mail captures (gap G-6) is the most important next step.
