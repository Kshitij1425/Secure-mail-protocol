# SIH26159 Compliance Matrix (verified 2026-09-27)

Status: **FULL** = implemented and verified end-to-end on captures; **PARTIAL** = implemented
with a documented limit; **LIMITED BY PASSIVITY** = cannot be fully established from a capture.
"Evidence" cites tests in `backend/tests/` and fixtures in `backend/tests/robustness/fixtures/`.

| Req | Requirement | Status | Implementation | Evidence |
|---|---|---|---|---|
| A | Passive analysis of SMTP/IMAP/POP3 from PCAP | FULL | `ingestion`, whole pipeline; no network access | 28 fixture captures, `test_real_pcap_validation.py`, 9 real server/client lab captures (`test_real_mail_captures.py`; no IMAP server in the lab) |
| B | Automatic protocol identification | FULL | `protocols/detector.py`: banner + commands + port; non-standard ports by banner; implicit TLS by port; non-email rejected | `smtp_nonstandard_port`, `unrelated_traffic`, `test_detector_*` |
| C | STARTTLS negotiation / upgrade detection and validation | FULL | `starttls/machine.py` + TLS parser confirmation; requested/accepted/rejected (SMTP 4xx/5xx, IMAP tagged, POP3 -ERR), advertised, repeated, pipelined, plaintext after rejection; "requested" never equated with "established" | `smtp_starttls_downgrade`, `pop3_starttls_rejected`, `smtp_starttls_truncated`, `smtp_starttls_pipelined`, STARTTLS regression tests |
| D | Complete TCP stream reconstruction | FULL (IPv4/IPv6; no IP-fragment reassembly) | `tcp/stream.py`: per-direction seq reassembly, OOO, retransmission, overlap conflicts, gaps, wraparound, port reuse, limits | `out_of_order`, `retransmissions`, `missing_segment`, `tcp_overlap_conflict`, property test `test_reassembly_recovers_exact_bytes` |
| E | TLS handshake parsing/reconstruction | FULL for cleartext messages | `tls/parser.py`: records across TCP chunks, handshake across records, ClientHello/ServerHello/HRR/Certificate/ServerKeyExchange/alerts/CCS; SSLv2 ClientHello | segmented fixtures, TLS regression + fuzz tests |
| F | X.509 extraction and validation to the extent observable | PARTIAL - LIMITED BY PASSIVITY | Extraction (TLS <= 1.2), parsing, validity at capture time, key/signature, SAN/CN vs SNI, chain linkage by signature. Trust-anchor validation not performed; TLS 1.3 certs not observable | `smtp_starttls_tls12_chain` (linked), `smtp_tls12_sni_mismatch`, `test_chain_linkage_verified_cryptographically` |
| G | Negotiated TLS version | FULL | ServerHello + supported_versions (TLS 1.3) | all TLS fixtures (1.0, 1.2, 1.3) |
| H | Cipher suite identification | FULL | IANA registry (287 suites), GREASE/SCSV handling | `test_cipher_classification_covers_registry` |
| I | Key exchange mechanism | FULL | From suite (RSA/DHE/ECDHE/PSK/...) + group (ServerKeyExchange curve / DH prime bits; TLS 1.3 key_share) | `smtp_tls12_weak_dh` (DH-1024), x25519 in ECDHE fixtures |
| J | Deprecated protocol detection | FULL | TLS-001 (SSLv2/3 CRITICAL, TLS 1.0/1.1 HIGH) | `smtp_weak_deprecated`, `ml_mixed_estate` |
| K | Weak algorithms / cipher suites | FULL (negotiated); client offers as LOW | TLS-003, TLS-004, TLS-005, TLS-006 | `smtp_tls12_3des_synthetic`, `layer_b_smtp_tls12_weak`, `smtp_tls12_weak_dh` |
| L | Certificate vulnerabilities | FULL for observable certs | CERT-001..007 | fixtures above; certificate regression tests |
| M | Cryptographic feature extraction | FULL | 10 features (`ml/feature_extractor.py`) + TLS/cert evidence in session documents | `test_m11_ml.py` |
| N | AI/ML cryptographic risk classification | PARTIAL | No supervised risk classifier (no labelled data exists). Risk classification is deterministic (rules + severity); ML provides unsupervised outlier ranking only | ML_DESIGN.md |
| O | AI/ML anomalous TLS session detection | FULL (unsupervised, per capture, supplementary) | Isolation Forest, seed 42, capture-time features, rareness explanations | `test_ml_flags_the_planted_outlier_only`, `test_ml_is_reproducible_and_capture_local` |
| P | Security posture scoring | FULL | `scoring/`: 0-100, 5 dimensions, coverage, evidence quality, Unknown when no evidence; invariants property-tested | `test_scoring.py`, property tests |
| Q | Threat / risk prioritisation | FULL | Findings ordered by severity/confidence; `priority`; root-cause impact (`risk_contribution`); remediation plan ordered by severity, prevalence, impact | `test_json_report_carries_real_evidence` |
| R | Mitigation recommendations | FULL | Per rule recommendation + references (RFC/NIST); remediation plan | reports, UI |
| S | Comprehensive posture assessment | FULL within passive limits | Canonical document combining all of the above | `test_engine_db_api_consistency` |
| T | JSON report | FULL | `reports/document.py` | `test_reports_all_formats`, CLI tests |
| U | HTML report | FULL | Jinja2 template, escaped, CSP | same |
| V | PDF report | FULL | ReportLab (dependency declared) | same; browser E2E download |
| W | Interactive dashboard | FULL | React investigation workflow: Captures (history, re-analysis, compare), Overview, Findings (evidence chain, remediation), Sessions (timeline), Certificates (inventory), Timeline, Anomalies, Reports/export (raw or redacted; bundle; STIX) | scripted Playwright walkthrough (45 checks, 0 console errors) |

Technically incorrect claims found in earlier documentation and corrected: TLS 1.3
certificate extraction, "chain validation" (only leaf parsing existed), "AI-based" posture
(ML never influenced the score, correctly), ML seed "not fixed" (it was 42), throughput figures
measured on 3-30 packet files.
