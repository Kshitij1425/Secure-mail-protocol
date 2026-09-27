# Security Test Matrix

All tests are in `backend/tests/` and run in CI (`.github/workflows/ci.yml`). "Fuzz" tests
use Hypothesis: 150 examples per property in CI, 3000 in the deep campaign (`HYPOTHESIS_PROFILE=deep`).

| Area | Attack / hostile input | Test(s) | Result |
|---|---|---|---|
| PCAP | Random bytes with/without valid global header | `test_random_bytes_as_capture` (fuzz) | Clean `ValueError` or partial analysis; no crash |
| PCAP | Bit flips / truncation of all 28 real fixtures | `test_mutated_captures_never_crash` (fuzz) | No crash; score bounded |
| PCAP | Truncated tail, corrupt record | reader recovery (`truncated` flag) | Partial analysis, reported |
| PCAP | Packet-count limit | `test_cli_exit_codes` (`--max-packets`) | Aborts with exit 4 / HTTP 413 |
| TCP | Arbitrary seq/flags/payload sequences (both directions) | `test_arbitrary_segments_never_crash` (fuzz) | No crash; retention bounded |
| TCP | Reordering + duplication of a real stream | `test_reassembly_recovers_exact_bytes` (property) | Byte-exact reassembly |
| TCP | Conflicting overlap (evasion) | `test_tcp_conflicting_overlap_first_wins_and_flags`, fixture `tcp_overlap_conflict` | First wins; stream `inconsistent` |
| TCP | Sequence wraparound | `test_tcp_sequence_wraparound` | Correct |
| TCP | Out-of-order flood, huge streams, stream explosion | `test_tcp_limits_bound_memory` | Bounded (pending segments, bytes, streams) |
| SMTP/IMAP/POP3 | Arbitrary text chunks per direction | `test_starttls_machine_arbitrary_text` (fuzz) | No crash |
| SMTP/IMAP/POP3 | 1 MB line, 100k empty lines | `test_hostile_lines_bounded` | Line <= 8 KiB, <= 5000 lines |
| SMTP/IMAP/POP3 | Command split across segments; wrong IMAP tag; 454; pipelining | STARTTLS regression tests | Correct states |
| Detection | 200 KB banner (ReDoS) | `test_detector_bounded_on_hostile_banner` | < 0.5 s |
| Detection | Arbitrary bytes on any port | `test_detector_arbitrary_bytes` (fuzz) | Confidence in [0,1] |
| Detection | SSH/HTTP/TLS on mail and non-mail ports | `test_detector_rejects_non_email` | Not classified as email |
| TLS | Arbitrary bytes at random split points; crafted lengths | `test_tls_parser_arbitrary_bytes` (fuzz + explicit examples) | No crash; buffer <= one record |
| TLS | Mutated real OpenSSL handshakes (both directions) | `test_tls_parser_mutated_real_handshakes` (fuzz) | No crash |
| TLS | Oversized record / non-TLS after STARTTLS | `test_non_tls_or_oversized_input_is_abandoned_not_buffered` | Direction abandoned |
| TLS | Cleartext Certificate after TLS 1.3 ServerHello | `test_tls13_plaintext_certificate_is_not_trusted_evidence` | Ignored; protocol violation recorded |
| TLS | Hostile SNI (`<script>`) | `test_sni_is_neutralised` | Neutralised |
| X.509 | Mutated DER, truncated, 70 KB blob | `test_mutated_certificates_never_raise` (fuzz), `test_malformed_der_returns_none` | `None`, never raises |
| Scoring | Arbitrary finding sets | 4 property tests (bounded, deterministic, monotone add/remove, duplicate-invariant) | Hold (deep run found and fixed F-07) |
| API | Oversized upload (Content-Length and body) | `test_upload_too_large` | 413, nothing left on disk |
| API | Non-capture file with `.pcap` name; empty file; wrong extension | `test_upload_not_a_capture`, `test_upload_empty`, `test_upload_invalid_extension` | 422/400/422, cleaned up |
| API | Traversal / UNC / absolute / NUL / ADS / 400-char filenames | `test_upload_filename_cannot_escape` (8 cases) | Stored as `<uuid>.pcap` |
| API | Error information disclosure | `test_errors_do_not_leak_internal_paths` | Generic messages |
| API | Cross-capture access | `test_capture_isolation` | Isolated |
| API | Foreign origin | `test_cors_policy` | No CORS grant |
| API | Credential persistence | `test_credentials_never_persisted` (full DB dump) | Not stored |
| Reports | `<script>`, `<img onerror>` in filename/description | `test_html_escapes_untrusted_values` | Escaped + CSP |
| Reports | ReportLab markup injection | `test_pdf_report_generated_and_escaped` | Escaped |
| Reports | Report filename derivation from hostile names | `test_safe_report_basename` (6 cases) | Safe stems |
| Exports | Redacted report / bundle / STIX leak addresses or file name | `test_redacted_outputs_hide_identities_keep_crypto`, `test_redacted_stix_export_is_valid_and_leaks_no_addresses`, `test_redacted_download_names_do_not_reveal_capture_filename` | No addresses, host names or file name |
| Exports | Bundle integrity | bundle test in `test_analyst_features.py` | Byte-identical rebuild; hashes verify |
| Exports | STIX validity / overstated claims | `test_stix_export_is_valid_observation_only` (stix2 parser) | Valid; no indicator/malware objects |
| API | Unknown policy, equal compare ids, bad `redact`, traversal-style ids on new endpoints | `test_analyst_features.py`, manual probes | 422 / 404 |
| API | Analyst notes: unknown target, other capture's target, empty, over-long, hostile HTML | `test_annotations_validate_targets_and_persist`, `test_hostile_note_text_is_escaped_in_reports` | 422 / escaped |
| API | CORS preflight for GET/POST/PATCH/DELETE; foreign origin | `test_cors_preflight_allows_every_method_the_dashboard_uses` | Allowed for the dashboard origin only |
| Captures | Plaintext credentials in real SMTP AUTH and IMAP LOGIN captures | `test_real_plaintext_credentials_not_persisted` (DB, document, bundle, STIX, JSON/HTML reports) | Never stored or output |
| Captures | External captures | `test_external_captures.py` (pinned SHA-256; mismatching files deleted by the fetcher) | Verified before use |
| Frontend | Report preview (untrusted capture strings in HTML) | sandboxed iframe without scripts + report CSP; escaping tests above | No script execution |
| Frontend | Unsafe HTML/URL sinks | grep for `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `javascript:` | None; all values rendered as text |
| Dependencies | Known CVEs | `pip-audit -r requirements.lock`, `npm audit` | 0 / 0 |
| Static analysis | Python SAST | `bandit -r securemailscope` | 0 issues |
| Secrets | Keys/tokens/passwords in tree and full git history | regex scan (`git grep` over `git rev-list --all`) | None found |
