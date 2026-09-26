# SecureMailScope Architecture

SecureMailScope analyses a stored packet capture (PCAP/PCAPNG) and reports the
cryptographic posture of the SMTP, IMAP and POP3 traffic it contains. It is
strictly passive: it never contacts a mail server and never decrypts traffic.

```
            upload / CLI                      React dashboard (Vite, TypeScript)
                 |                                     ^
                 v                                     | JSON (REST)
   +-----------------------------+      +--------------------------------+
   | FastAPI  api/main.py        |----->| SQLite (SQLAlchemy ORM)        |
   |  upload intake (streamed,   |      |  captures / sessions / findings|
   |  size-capped, magic-checked)|      |  certificates / anomalies /    |
   |  AnalysisService            |      |  reports + canonical document  |
   +--------------+--------------+      +--------------------------------+
                  | Orchestrator.analyze(capture)
                  v
  ingestion -> tcp reassembly -> protocol detection -> STARTTLS state machine
     |                                    |                      |
     |                                    v                      v
     |                           TLS record/handshake parser -> X.509 analyzer
     |                                    |                      |
     +------------------------------------+----------+-----------+
                                                     v
                         deterministic rules (rule catalogue) -> findings
                                                     |
                               +---------------------+-----------------+
                               v                                       v
                   posture scoring (findings only)        ML anomaly detection
                                                           (supplementary; never
                                                            changes findings/score)
                               |
                               v
             canonical analysis document -> JSON / HTML / PDF reports, API, UI
```

## Modules (backend/securemailscope)

| Module | Responsibility | Key properties |
|---|---|---|
| `ingestion/reader.py` | Read PCAP/PCAPNG with dpkt; decode link layer by declared DLT (Ethernet incl. VLAN, Linux SLL/SLL2, raw IP, loopback); SHA-256 of file | Magic check before parsing; malformed frames counted; truncated tail tolerated and reported; packet/time budgets |
| `tcp/stream.py` | Per-connection, per-direction reassembly by sequence number | 32-bit wraparound; out-of-order buffering; duplicate/retransmission suppression; first-wins overlap policy with conflict detection; gap recording; bounded buffers (`TCPLimits`) |
| `protocols/detector.py` | SMTP/IMAP/POP3 identification from server greeting, client commands, port; implicit TLS on 465/993/995 | Bounded inspection window, anchored regexes; rejects SSH/HTTP/Telnet/VNC greetings and TLS on non-mail ports |
| `starttls/machine.py` | STARTTLS/STLS state (requested, accepted, rejected incl. SMTP 4xx, IMAP tag matching), capability advertisement, plaintext AUTH/LOGIN/USER-PASS (mechanism names only), pipelining after STARTTLS | Line-oriented with partial-line carry-over; line count/length caps |
| `tls/parser.py`, `tls/ciphers.py`, `tls/cipher_registry.py` | TLS record + handshake parsing per direction; ClientHello/ServerHello/Certificate/ServerKeyExchange/alerts; IANA registry (287 suites) + classification | Handshake reassembly across records; oversized/invalid data abandons the direction instead of buffering; TLS 1.3 certificates are reported as `encrypted_tls13` |
| `certificates/analyzer.py` | X.509 parsing, validity at capture time, key/signature strength, SAN/CN, hostname match, chain linkage by signature | Trust is never claimed (no trust anchors); self-signed = self-signature verifies |
| `rules/engine.py` | Rule catalogue (17 rules) + evaluation | Findings carry evidence class and capture frame numbers; no rule fires on unknown values |
| `scoring/` | Posture score 0-100 per capture and per dimension | Root-cause grouping, monotone prevalence ramp, INSUFFICIENT_EVIDENCE not scored, no sessions -> `Unknown` |
| `ml/` | 10 features per TLS session, Isolation Forest fitted per capture | Fixed seed, capture-time reference, >= 5 sessions, `auto` threshold, batched scoring |
| `core/orchestrator.py` | Runs the pipeline; builds fresh state per analysis | Session ids can be capture-prefixed for global uniqueness |
| `reports/` | Canonical document + JSON/HTML (Jinja2 autoescape, CSP) / PDF (ReportLab, escaped) | Same document for CLI, API and reports |
| `api/` | REST API, persistence, report generation | See SECURITY_POLICY.md |
| `cli.py` | `securemailscope analyze` | Same pipeline + reports as the API |

## Identifiers

* `session_id` = `<capture_id>~tcp-<client>_<cport>-<server>_<sport>[-n]` (API) or the stream id (CLI)
* `finding_id` = `<session_id>:<RULE>[:<chain position>]`
* `certificate_id` = `<session_id>~c<position>`

## Scoring

`score = 100 - sum(root-cause impacts)`, clamped to [0, 100] and rounded to 2 decimals.
Each root cause (one per rule) contributes `severity_impact x prevalence_multiplier`,
capped at 75 (CRITICAL) or 40 (others). Severity impacts: CRITICAL 45, HIGH 20,
MEDIUM 12, LOW 5, INFO 1. The prevalence multiplier ramps linearly from 1.0 to 1.5
between 0% and 50% of email sessions affected. Findings with evidence class
`INSUFFICIENT_EVIDENCE` are reported but not scored. A capture with no email session
has score `null` and status `Unknown`. Bands: >=90 Excellent, >=75 Good, >=60 Needs
Improvement, >=40 Poor, else Critical. These weights are a documented policy choice,
not an empirically calibrated risk model. Properties (bounded, deterministic,
monotone, duplicate-invariant) are enforced by property-based tests.

## Data flow guarantees (tested)

* Direct engine, database, API, JSON report and dashboard show the same counts,
  findings, scores and certificates (`tests/test_m12_api.py::test_engine_db_api_consistency`).
* No data of capture A is returned for capture B (`test_capture_isolation`).
* Credentials seen in plaintext AUTH are never stored (`test_credentials_never_persisted`).
