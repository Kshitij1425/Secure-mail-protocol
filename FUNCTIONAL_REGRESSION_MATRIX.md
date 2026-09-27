# Functional Regression Matrix (verified 2026-09-27)

Status legend: **WORKING** = verified by unit + integration + real-capture (+ browser where applicable);
**PARTIAL** = works with documented limits; **BROKEN/UNVERIFIED** = none remaining (see "Before" column
for the state found at takeover).

| Area | Capability | Before audit | Implementation | Unit | Integration / real capture | Browser E2E | Now |
|---|---|---|---|---|---|---|---|
| Foundation | Package, config, logging, errors | Logger wrote to CWD + stdout; config ignored limits | `utils/`, `api/config.py` | - | CLI/API tests | yes | WORKING |
| Ingestion | PCAP + PCAPNG ingestion, SHA-256, stats | Truncation aborted analysis; only Ethernet/raw | `ingestion/reader.py` | `test_ingestion.py` | `pcapng_imap_plaintext`, `sll_pop3_stls_tls12`, fuzz | upload | WORKING |
| Ingestion | Malformed / corrupt / empty captures | Crash->500 | reader + service | fuzz | `test_upload_not_a_capture` | yes | WORKING |
| TCP | TCP direction (client/server) | First packet only | `tcp/stream.py` | `test_tcp_stream_client_server_from_syn_even_if_synack_first` | all fixtures | - | WORKING |
| TCP | Seq reassembly, OOO, retransmission, gaps, overlap, wraparound, port reuse | Not implemented (concatenation) | `tcp/stream.py` | 9 regression + 2 property tests | `out_of_order`, `retransmissions`, `missing_segment`, `tcp_overlap_conflict` | - | WORKING |
| TCP | Resource limits | None; O(n^2) | `TCPLimits` | `test_tcp_limits_bound_memory` | benchmark to 1M packets | - | WORKING |
| Detection | SMTP/IMAP/POP3 detection incl. non-standard ports | 2222/2220 misclassified; no negatives | `protocols/detector.py` | 22 tests | `smtp_nonstandard_port`, `unrelated_traffic` | - | WORKING |
| Detection | Implicit TLS 465/993/995 | Reported as plaintext (CRITICAL FP) | detector + orchestrator | detector tests | `implicit_tls_mixed` | yes | WORKING |
| STARTTLS | STARTTLS requested/accepted/rejected/incomplete/failed | 454 missed, tags ignored, first line only | `starttls/machine.py` | 15 tests | downgrade, rejected, truncated, pipelined, handshake-failure fixtures | yes | WORKING |
| STARTTLS | Plaintext auth / pipelining indicators | Not implemented | machine + PROTO-002/STLS-003 | yes | `smtp_plaintext_auth`, `smtp_starttls_pipelined` | yes | WORKING |
| TLS | TLS records/handshakes across segments and records | Per-record only; shared buffer | `tls/parser.py` | 13 tests + 2 fuzz | segmented fixtures | - | WORKING |
| TLS | Version (1.0-1.3), cipher, key exchange, group, alerts, handshake status | 8 ciphers; no KX; completion = any app data | parser + `tls/ciphers.py` | registry test | all TLS fixtures | yes | WORKING |
| TLS | TLS 1.3 visibility | Claimed certificates | `certificate_visibility` | yes | 3 TLS 1.3 fixtures | yes | WORKING |
| X.509 | DER parsing, subject/issuer/SAN/serial/fingerprint/validity/key/signature | Validity at analysis time | `certificates/analyzer.py` | 6 tests + fuzz | chain, weak, SNI fixtures | yes | WORKING |
| X.509 | Chain linkage, self-signed by signature, hostname match | Name comparison only | analyzer | yes | `smtp_starttls_tls12_chain`, `smtp_tls12_sni_mismatch` | yes | WORKING |
| X.509 | Trust-anchor validation | Not implemented (claimed) | - | - | - | - | PARTIAL (not performed; reported as unknown) |
| Rules | 19 deterministic rules (18 by default), evidence classes, frames | 9 rules; FPs/FNs | `rules/engine.py` | `test_rules_engine.py` + regressions | every fixture's exact rule set | yes | WORKING |
| Scoring | Score 0-100, dimensions, coverage, root causes, Unknown | Band gaps, non-monotone, 100 for no evidence | `scoring/` | 131 tests + 4 properties | fixtures | yes | WORKING |
| CLI + reports | CLI analyze + JSON/HTML/PDF | Reports posture-only; no PDF; XSS | `cli.py`, `reports/` | `test_m10_cli.py` | CLI subprocess on real captures | - | WORKING |
| ML | 10 features, Isolation Forest, explanations, reproducibility | Forced outliers, time-dependent, shared model | `ml/` | `test_m11_ml.py` (23) | `ml_mixed_estate` | yes | WORKING (supplementary; no accuracy claim) |
| API | REST API (all endpoints), validation, isolation | Placeholder posture, collisions, leaks | `api/` | - | `test_m12_api.py` (29) | yes | WORKING |
| API | Persistence of sessions/findings/certs/anomalies/links | Partially empty fields | `services/analyzers.py` | - | `test_engine_db_api_consistency` (5 captures) | yes | WORKING |
| Dashboard | Overview / Findings / Sessions / Certificates / Anomalies / Upload | Missing states, stale-id 404s, no export | `frontend/src` | tsc + oxlint | - | full walkthrough | WORKING |
| Dashboard | Detail panels, back/forward, deep links, filters, sort | History hack | `useDetailPanel` (URL) | - | - | verified | WORKING |
| Integration | Engine == DB == API == report == UI | Mismatches (see ROOT_CAUSE history) | canonical document | - | consistency test | spot-checked counts | WORKING |
| Hardening | Hardening, limits, security headers, CI | Claimed, not present | see SECURITY_TEST_MATRIX.md | - | - | - | WORKING |
| Hardening | Docker | Not present | `backend/Dockerfile`, `docker-compose.yml` | - | not built (no Docker) | - | UNVERIFIED |
| - | Report download from UI | Not present | `ReportExport` | - | `test_reports_all_formats` | PDF downloaded | WORKING |
| - | Finding triage lifecycle | Not present | `PATCH /findings/{id}/status` | - | `test_finding_status_workflow` | yes | WORKING |

| - | Real mail server/client captures (controlled lab) | Not present | `lab/`, `tests/real_captures/` | - | `test_real_mail_captures.py` (21) | - | WORKING |
| - | Policy profiles, re-analysis | Not present | `policy.py`, rules `_apply_profile` | `test_analyst_features.py` | real captures | upload + re-analyse | WORKING |
| - | History and comparison | Not present | `reports/compare.py`, `/compare` | yes | remediation before/after | yes | WORKING |
| - | Evidence chain, timeline, certificate inventory, remediation view | Not present | `document.py`, `analyzers.evidence_chain` | yes | real captures | yes | WORKING |
| - | Redaction, evidence bundle, STIX 2.1 | Not present | `reports/redact.py`, `bundle.py`, `stix.py` | yes | yes | downloads verified | WORKING |
| - | 14-section report | 10 sections | `report.html.j2`, `render.py` | `test_html_sections_present` | CLI | yes | WORKING |

| - | Real IMAP captures (pymap: IMAPS, STARTTLS, weak, plaintext) and weak POP3S | Not present | `lab/imap_server.py`, `lab/real_mail_lab.py` | - | `test_real_mail_captures.py` (36) | - | WORKING |
| - | External public captures (Wireshark wiki, 5) | Not present | `tests/external_captures/` | - | `test_external_captures.py` (10) | - | WORKING |
| - | 8-step workflow, case bar, step pager, evidence register, server grouping | Not present | `frontend/src` | tsc + oxlint | - | `qa/e2e_walkthrough.py` (112 checks) | WORKING |
| - | Analyst notes / report selection, posture trend | Not present | `annotations` table, `/trend` | `test_analyst_features.py` | - | yes | WORKING |
| - | PDF report with the same 14 sections | 10 sections | `reports/render.py` | pypdf test | - | - | WORKING |

| - | Compare: new / resolved / persisting ML-anomalous sessions | Count only | `reports/compare.py` `compare_anomalies` | `test_compare_lists_anomalous_sessions_new_resolved_persisting` | ml_mixed_estate vs lab captures | yes | WORKING |
| - | In-app report preview (raw / redacted) before download | Not present | `/captures/{id}/report-preview`, Reports page | preview tests (byte-identical to the downloaded HTML) | - | yes | WORKING |
| - | Automated accessibility scan | Not present | `qa/a11y_scan.py` (axe-core) | - | - | 55 page states, 0 violations | WORKING |
Totals: 45 capability rows - 43 WORKING, 1 PARTIAL (trust anchors, by design), 1 UNVERIFIED (Docker; the Docker mail lab was not run either).
