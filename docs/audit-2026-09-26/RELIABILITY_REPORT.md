# Reliability Report

## 1. Test suite

Run from `backend/` with `python -m pytest -q` (see FINAL_SECURITY_AUDIT.md for the final
counts of the verification run). Suites:

| Suite | Scope |
|---|---|
| `test_tcp_stream.py`, `test_ingestion.py`, `test_protocol_detector.py`, `test_starttls_machine.py`, `test_tls_parser.py`, `test_certificate_analyzer.py`, `test_rules_engine.py`, `test_scoring.py`, `test_m11_ml.py` | Unit tests per stage |
| `test_core_regressions.py` | One test per defect fixed in the audit (TCP, detector, STARTTLS, TLS, ciphers, rules, scoring, certificates) |
| `test_real_pcap_validation.py` | 28 captures vs ground truth + cross-cutting checks (implicit TLS, TLS 1.3 visibility, Unknown posture, chain linkage, evidence frames, ML outlier, determinism) |
| `test_fuzz_properties.py` | 13 Hypothesis properties (capture, TCP, TLS, X.509, text layers, scoring invariants) |
| `test_m10_cli.py`, `test_m105_orchestrator.py` | CLI and reports on real captures |
| `test_m12_api.py` | API validation, persistence, isolation, engine==DB==API==report consistency, reports, triage, credentials |

## 2. Real-capture validation

`python -m tests.robustness.validate_fixtures` compares, per email session: protocol, STARTTLS
final state, negotiated TLS version, handshake status, certificate count, TCP reconstruction
quality, implicit-TLS flag and the exact set of rule IDs; plus stream counts, posture status,
certificate visibility, chain status and absence of credential strings. Result: **28/28 pass**.

| Scenario class | Captures |
|---|---|
| Plaintext / auth | `clean_baseline`, `smtp_plaintext_auth`, `pcapng_imap_plaintext` |
| STARTTLS success | `smtp_starttls_tls12_chain`, `smtp_starttls_tls13_secure`, `imap_starttls_tls12`, `layer_b_*`, `sll_pop3_stls_tls12`, `ipv6_smtp_tls13`, `smtp_nonstandard_port` |
| STARTTLS failure / anomaly | `smtp_starttls_downgrade` (454), `pop3_starttls_rejected`, `smtp_starttls_truncated`, `smtp_starttls_pipelined`, `smtp_tls_handshake_failure` |
| Implicit TLS | `implicit_tls_mixed` (993/995/465) |
| Weak crypto / certificates | `smtp_weak_deprecated`, `layer_b_smtp_tls12_weak`, `smtp_tls12_weak_dh`, `smtp_tls12_3des_synthetic`, `smtp_tls12_sni_mismatch` |
| TCP impairments | `out_of_order`, `retransmissions`, `missing_segment`, `tcp_overlap_conflict`, segmented TLS fixtures |
| Unrelated traffic | `unrelated_traffic` (HTTP, SSH on 2222, HTTPS) |
| Mixed estate / ML | `ml_mixed_estate` |

## 3. Browser end-to-end (Playwright, Chromium)

Backend on 127.0.0.1:8000 with a fresh database; frontend dev server on :5173.

| Step | Observed |
|---|---|
| Empty state | "No capture selected" with Upload link |
| Upload invalid file (`fake.pcap`, text) | Rejected: "File is not a PCAP or PCAPNG capture"; nothing stored |
| Upload `ml_mixed_estate.pcap` | Redirect to Overview; 275 packets, 12 streams, 12 email sessions, 12 TLS, 23 certificates, 1 ML anomaly, 2 High + 2 Medium, score 25 Critical, dimension table, remediation plan (4 items), top findings - identical to CLI/API values |
| Capture time | Initially rendered 04:30Z instead of 10:00Z -> **defect V-17 found and fixed** (UTC column type), re-verified |
| Stale stored capture id | Requests for a capture from a previous database -> **defect found and fixed** (context validates stored id) |
| Findings -> detail | Evidence JSON, frame 10, recommendation, references, triage select |
| Finding -> session link -> Session detail | TLSv1.0, TLS_RSA_WITH_AES_128_CBC_SHA, RSA KX, no PFS, SNI, 5 linked findings, certificate chain |
| Session -> certificate link -> Certificate detail | Validity at capture time "Expired at capture", RSA 1024 (weak), self-signed (verified), trust unknown, seen in 1 session |
| Browser Back x2 | Returns to session detail, then finding detail (URL state) |
| Close button | Detail closed, `?id` removed |
| Switch capture (top bar) | Pages show only the selected capture's data |
| Anomalies -> detail | Planted TLS 1.0 outlier "severe"; 10-feature vector; rareness explanation; supplementary disclaimer |
| Overview -> Export PDF | `POST /captures/{id}/reports?format=pdf` 200, download `ml_mixed_estate_report.pdf` |

## 4. Robustness

* Deep fuzz campaign (3000 examples per property): 12 of 13 properties passed; the scoring
  monotonicity property found defect F-07, which was fixed and re-verified at 3000 examples.
* Reproducibility: identical capture -> identical findings, scores and ML scores
  (`test_whole_analysis_deterministic`, `test_repeat_analysis_is_reproducible`).
* Failure handling: invalid captures -> 422 and capture row marked `failed` with a
  client-safe reason; limits -> 413; concurrency -> 503.

## 5. Known reliability limits

See LIMITATIONS.md: synchronous analysis, SQLite, per-stage limits instead of a global watchdog.

## 6. Clean-environment acceptance (2026-09-26)

The files git would ship (tracked + new, minus ignored; 194 files) were copied to an empty
directory; a new virtual environment was created from `requirements.lock`; `npm ci` was run for
the frontend. The first attempt failed on import (`securemailscope.reports.document` missing):
the `.gitignore` excluded the reports source package (defect F-30). After anchoring the ignore
patterns the run passed:

| Step | Result |
|---|---|
| `pytest` | 329 passed, 0 failed, 0 skipped |
| `validate_fixtures` | 28/28 |
| `securemailscope analyze ... --json --html --pdf` | 3 reports written |
| `npm ci`, `npm run build`, `npm run lint` | pass, 0 lint findings |
| Browser (clean servers, fresh DB): stale stored capture id | no requests for it, 0 console errors |
| Upload invalid file / real capture | rejected / analysed (22 packets, 1 stream, SMTP, TLS 1.0, 1 cert, 3 High + 2 Medium, score 0 Critical, capture time 10:00:00Z) |
| Finding / Session / Certificate detail (deep links), Anomalies page | render real data; honest "too few TLS sessions" ML state |
| JSON / HTML / PDF generation and download | 200 |
| Report vs dashboard (packets, findings, score) and SHA-256 | equal |
| Malformed capture, wrong extension | 422, no internals leaked |
| Second capture (`ml_mixed_estate`) | 12 sessions, 1 anomaly |
| Capture isolation | no shared finding ids; filters return only own records |
| Repeat analysis of the same capture | identical documents (except ids and timestamps) |
