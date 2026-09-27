# Threat Model

SecureMailScope is a security product whose primary input, a packet capture, is
**attacker-controlled**: anyone who can put traffic on the monitored network (or
hand an analyst a file) controls every byte the analyzer parses.

## Assets

| Asset | Why it matters |
|---|---|
| Analysis integrity (findings, score, evidence) | Wrong results lead to wrong security decisions |
| Evidence integrity (capture SHA-256, frame references) | Forensic defensibility |
| Captured content (mail metadata, possibly credentials in plaintext sessions) | Confidentiality of monitored users |
| Host running the analyzer | Code execution / resource exhaustion |
| Analyst's browser | Rendering of attacker-controlled strings |

## Trust boundaries

1. **Capture file -> parser** (ingestion, TCP, SMTP/IMAP/POP3, TLS, X.509): hostile bytes.
2. **HTTP client -> API**: uploads, filenames, query/path parameters. The API has **no
   authentication**; it is designed for a single analyst on the local machine and binds to
   127.0.0.1 by default.
3. **Stored analysis -> browser / reports**: every string that originated in a capture
   (certificate subject/SAN, SNI, banners, server responses, filenames) is untrusted.

## Threats and controls

| # | Threat (STRIDE) | Control | Verified by |
|---|---|---|---|
| T1 | Parser crash / exception on malformed PCAP, TCP, TLS, DER (DoS) | Bounds-checked parsing; per-direction abandonment; exceptions contained per session; corrupt capture -> clean 422 | Hypothesis fuzzing (13 properties, 3000-example deep run), `test_core_regressions.py` |
| T2 | Memory exhaustion via huge streams, out-of-order floods, stream explosion (DoS) | `TCPLimits`: 256 KiB retained per direction, 512 MiB global, 4096 pending segments / 4 MiB per direction, 100k streams; TLS record <= 18 KiB + 5, handshake <= 256 KiB, <= 20 certs; STARTTLS line <= 8 KiB, <= 5000 lines | `test_tcp_limits_bound_memory`, `test_non_tls_or_oversized_input_is_abandoned_not_buffered`, `test_hostile_lines_bounded` |
| T3 | CPU exhaustion (ReDoS, pathological captures) | Detector inspects <= 2 KiB with anchored, bounded regexes; ingestion packet limit (5M) and time budget (600 s); max 2 concurrent analyses (503 otherwise) | `test_detector_bounded_on_hostile_banner`, `test_cli_exit_codes` (limit) |
| T4 | TCP evasion (overlap with different bytes) to hide/alter content (Tampering) | First-wins reassembly, conflicting overlaps counted, stream marked `inconsistent` | `test_tcp_conflicting_overlap_first_wins_and_flags`, `tcp_overlap_conflict` fixture |
| T5 | Oversized upload / disk fill | Streaming ASGI body limit (Content-Length and chunked), streamed write with cap, rejected files deleted | `test_upload_too_large` |
| T6 | Path traversal / ADS / reserved names via upload filename | Stored name is `<uuid>.<format>`; client name kept only as sanitised display text | `test_upload_filename_cannot_escape` (8 variants) |
| T7 | Report download path escape | Report path resolved and required to be inside `reports_dir`; ids are UUIDs | `AnalysisService.report_path` |
| T8 | XSS in dashboard via certificate/SNI/banner strings | React text rendering only (no `dangerouslySetInnerHTML`), no attacker-controlled URLs rendered as links | grep audit; E2E |
| T9 | XSS / injection in HTML/PDF reports | Jinja2 autoescape + CSP `default-src 'none'`; ReportLab text XML-escaped; downloads are attachments with `sandbox` CSP | `test_html_escapes_untrusted_values`, `test_pdf_report_generated_and_escaped` |
| T10 | Information disclosure in errors (paths, stack traces) | Uniform error envelope; generic 500; validation errors name fields only | `test_errors_do_not_leak_internal_paths` |
| T11 | Credential disclosure (plaintext AUTH captured) | Only mechanism names stored; no payloads logged | `test_credentials_never_persisted`, fixture `forbidden_strings_in_outputs` |
| T12 | Cross-capture data leakage | Globally unique ids, capture-scoped queries, FK constraints | `test_capture_isolation` |
| T13 | Cross-origin abuse of the API from other sites | CORS allow-list (no `*`, no credentials); no cookies/auth exist | `test_cors_policy` |
| T14 | Misleading conclusions (e.g. "downgrade attack detected", "certificate trusted", TLS 1.3 certificates) | Evidence classes; explicit NOT_OBSERVED / UNKNOWN; trust never asserted | `test_tls13_certificates_not_claimed`, `test_no_email_traffic_is_unknown_not_excellent` |
| T15 | SQL injection | ORM only; no string-built SQL (one static `SELECT 1`) | bandit, code review |
| T16 | Command execution | No subprocess/shell in the product code | bandit, grep |
| T17 | Identity disclosure through "redacted" outputs (report, bundle, STIX, download file name) | Pseudonyms applied to the whole document; download names of redacted outputs use `capture_<sha256 prefix>`, never the original file name | `test_redacted_outputs_hide_identities_keep_crypto`, `test_redacted_stix_export_is_valid_and_leaks_no_addresses`, `test_redacted_download_names_do_not_reveal_capture_filename`, Playwright scan of redacted downloads for private IPs |
| T18 | Tampering with evidence bundles | Deterministic ZIP with per-file SHA-256 manifest and `manifest.sha256` | `test_analyst_features.py` bundle test |
| T19 | Re-analysis of a substituted file | Stored file hash re-verified before re-analysis | `test_analyst_features.py` reanalyze test |
| T20 | Invalid ids / policies on new endpoints (compare, chain, timeline, bundle, stix, reanalyze) | Typed parameters, 404 for unknown ids, 422 for unknown policy / equal compare ids / non-boolean `redact` | API tests; manual probes with traversal-style ids |
| T22 | Stored XSS / injection via analyst notes (free text) | React text rendering; Jinja2 autoescape in HTML reports; ReportLab escaping in PDF; 4000-character limit; notes must target an item of the same analysis | `test_hostile_note_text_is_escaped_in_reports`, `test_annotations_validate_targets_and_persist` |
| T23 | Identifying data in notes leaking through redacted reports | Notes are redacted with the rest of the document (addresses, host names, e-mail); other free text is documented as not redacted; only notes selected for the report are included | `test_selected_annotations_appear_in_reports_and_are_redacted` |
| T24 | Blocked or broken methods through a wrong CORS policy | Allow-list origins; every method the dashboard uses is allowed, foreign origins receive no CORS grant | `test_cors_preflight_allows_every_method_the_dashboard_uses` |
| T21 | Overstated conclusions in exports (STIX indicators, "malicious", "AI detected") | STIX contains observed-data and notes only; ML wording "requires investigation" | `test_stix_export_is_valid_observation_only`, UI wording check |

## Residual risks (accepted, documented)

* **No authentication/authorization** on the API. Mitigation: loopback binding; do not
  expose it. Multi-user deployment requires adding authentication first.
* Analysis runs in the API process; a parser bug that loops could hold a worker until the
  time budget check (checked every 5,000 packets during ingestion only; later stages are
  bounded by input size limits, not by a wall-clock timer).
* SQLite concurrency is adequate for a single analyst, not for many concurrent writers.
* IP fragments are not reassembled (TCP inside fragmented IP packets is ignored).
