# SecureMailScope

**Passive cryptographic posture assessment of email traffic (SMTP / IMAP / POP3) from packet captures.**
Smart India Hackathon 2026 - problem statement SIH26159.

SecureMailScope reads a PCAP/PCAPNG capture, reassembles the TCP connections, identifies
mail protocols, follows STARTTLS/STLS upgrades, parses the TLS handshakes, analyses the
observable X.509 certificates, applies deterministic security rules, computes a posture
score, flags statistical outliers with an unsupervised model, and produces JSON / HTML /
PDF reports and an interactive dashboard. It never contacts a mail server and never
decrypts traffic.

## What it reports

* **Sessions** - protocol (by banner/commands/port, incl. non-standard ports and implicit TLS
  on 465/993/995), STARTTLS state (advertised / requested / accepted / rejected, SMTP 4xx
  included), negotiated TLS version, cipher suite (full IANA registry), key exchange and group
  (incl. DH prime size), forward secrecy, SNI, ALPN, handshake status and alerts, TCP
  reassembly quality.
* **Certificates** - observed only where the protocol exposes them (TLS <= 1.2). Validity at
  capture time, key and signature strength, SAN, hostname vs SNI, chain linkage verified by
  signature. Trust is **not** asserted (no trust anchors are used). TLS 1.3 certificates are
  reported as encrypted / not observed.
* **17 deterministic rules + 1 optional** (`backend/securemailscope/rules/engine.py`; TLS-007
  non-AEAD suite is enabled only by the strict profile): plaintext sessions,
  plaintext credentials, STARTTLS rejection / missing TLS / pipelining, deprecated protocol
  versions, handshake failure, insecure/weak suites, no forward secrecy, weak DH/curves,
  insecure client offers, expired / not-yet-valid / weak-key / weak-signature / self-signed /
  hostname-mismatch certificates, inconsistent chains. Each finding carries an evidence class
  (OBSERVED, INFERRED, POTENTIAL_INDICATOR, INSUFFICIENT_EVIDENCE), capture frame numbers,
  a recommendation and standards references.
* **Posture score** 0-100 with five dimensions, coverage and evidence quality, root-cause
  grouping and a prioritised remediation plan. No email sessions -> `Unknown`, not 100.
* **ML anomalies** (supplementary) - Isolation Forest fitted per capture that reports sessions
  cryptographically weaker than the capture's own norm and rare in it; never changes findings or
  the score. Evaluated on 80 labelled real lab sessions (v1 vs v2 in [ML_DESIGN.md](ML_DESIGN.md)).

## Analyst workflow

The dashboard is an investigation workstation with an eight-step workflow: **1 Capture -> 2 Analyze
-> 3 Posture -> 4 Findings -> 5 Sessions -> 6 Certificates -> 7 Evidence -> 8 Report**, plus
supporting views (ML anomalies, Compare and trend, About and limitations). Every analysis page
shows the record under investigation (file, SHA-256, capture time, policy, posture) and links to
the previous and next step. A finding leads to its session, TLS parameters, certificate,
evidence frames and recommendation ("Why am I seeing this?"); a session leads back to its
findings, certificates, timeline and evidence; a certificate leads to its sessions and findings.

* **Policy profiles** - `balanced` (default, identical to earlier releases), `strict`
  (RSA/DH >= 3072, TLS 1.0/1.1 CRITICAL, optional TLS-007) and `legacy_audit` (lower severities
  for legacy estates). Chosen at upload or by re-analysing a stored capture; the profile is
  recorded in every report.
* **Analysis history and comparison** - every analysis is kept; two analyses can be compared
  (new / resolved / persisting findings, matched by rule + protocol + server address:port),
  e.g. before and after remediation.
* **Evidence chain** per finding - capture -> frames -> session -> protocol -> TLS ->
  certificate -> rule -> finding, each step labelled OBSERVED / INFERRED / NOT OBSERVED /
  NOT OBSERVABLE.
* **Timeline** - capture-time events (TCP open, STARTTLS, ClientHello/ServerHello, alerts,
  findings at their evidence frame) with frame numbers; ML assessments are listed at analysis time.
* **Certificate inventory** - distinct certificates with extraction, chain linkage and trust
  reported separately (trust is never asserted).
* **Remediation view** - why each finding matters and the expected effect of the fix.
* **Exports** - 14-section JSON/HTML/PDF report, deterministic evidence bundle (ZIP + SHA-256
  manifest, no payloads) and STIX 2.1 observations (no indicators). Each can be **raw** or
  **redacted** (consistent pseudonyms for IPs, host names, organisations, e-mail addresses and
  the file name; cryptographic evidence kept).
* **Evidence register** - one numbered entry per finding with its capture frame, capture time and
  evidence class, next to the full capture timeline.
* **Analyst notes and report selection** - notes on a capture, finding, session or certificate;
  items marked "include in investigation report" appear in Appendix A of the report. Notes never
  change evidence, findings or the score.
* **Posture trend** - score, findings and critical/high findings over capture time for analyses
  that share a mail server with the selected one (association by address, not identity).
* **Server grouping** - sessions grouped by protocol, address and port with TLS versions, suites
  and server certificates.
* Accessibility: skip link, text size (A / A+ / A++), high-contrast mode, keyboard-operable
  tabs and drawers (focus on open, Esc to close), no horizontal scroll at 390 px.
  Design rationale: [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md).

The visual design is original. It follows public GIGW 3.0 accessibility conventions; it uses
no government emblem, seal, logo or branding, and SecureMailScope is **not** affiliated with,
endorsed by or a product of NTRO or the Government of India.

## Quick start (Windows)

```powershell
cd backend
pip install -r requirements.lock
pip install -e . --no-deps
cd ..\frontend
npm ci
cd ..
.\start_demo.ps1        # API on http://127.0.0.1:8000, dashboard on http://localhost:5173
```

Upload any capture from `backend/tests/robustness/fixtures/pcaps/` in the dashboard's
Upload page (e.g. `ml_mixed_estate.pcap`). Full walkthrough: [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md).

### CLI

```powershell
securemailscope analyze capture.pcap --output-dir reports --json --html --pdf
```

Exit codes: 0 ok, 2 file missing, 3 not a capture, 4 resource limit, 5 report format unavailable.

### API (selection)

`GET /policies` · `POST /analyze` (multipart `file`, optional `policy`) · `POST /captures/{id}/reanalyze?policy=` · `GET /captures[/{id}]` · `GET /captures/{id}/{sessions|findings|certificates|anomalies|posture|document}` ·
`POST /captures/{id}/reports?format=json|html|pdf` · `GET /reports/{id}/download` ·
`GET /sessions/{id}` · `GET /findings/{id}` · `GET /findings/{id}/chain` · `PATCH /findings/{id}/status` · `GET /certificates/{id}` · `GET /anomalies/{id}` ·
`GET /captures/{id}/{timeline|certificate-inventory}` · `GET /captures/{id}/{bundle|stix|document}?redact=true|false` ·
`GET /compare?a=&b=` · `GET /captures/{id}/trend` · `GET|POST /captures/{id}/annotations` · `PATCH|DELETE /annotations/{id}`.
Reports accept `redact=true`.
Interactive docs at `/docs`.

## Testing

```powershell
cd backend
python -m tests.external_captures.fetch              # optional: download the 5 public validation captures
python -m pytest -q                                  # 411 tests incl. fuzz/property tests (external ones skip if not downloaded)
python -m tests.robustness.validate_fixtures         # 28 captures vs ground truth
$env:HYPOTHESIS_PROFILE="deep"; python -m pytest tests/test_fuzz_properties.py   # long fuzz run
python -m tests.performance.benchmark --sizes 1000 10000 100000
```

The fixture corpus (`backend/tests/robustness/fixture_factory.py`) uses real OpenSSL TLS
handshakes wrapped in synthesised TCP framing. In addition, `backend/tests/real_captures/`
holds 15 captures of **real mail server/client sessions generated in a controlled test
environment** covering SMTP, IMAP and POP3, healthy and weak (Mailpit 1.31.2, aiosmtpd and the
pymap IMAP server with Python smtplib/poplib/imaplib clients, recorded by a TCP relay:
application bytes are real, TCP/IP headers are reconstructed). Five independently produced
public captures (Wireshark wiki) form an external validation layer (`tests/test_external_captures.py`). Provenance and
intended conditions are in `manifest.json`; `tests/test_real_mail_captures.py` checks them.
Reproduce with `python lab/real_mail_lab.py` (see [lab/README.md](lab/README.md)). A Docker
lab with Postfix, Dovecot and tcpdump is provided in `lab/docker/` but was not run here.
See [LIMITATIONS.md](LIMITATIONS.md).

## Documentation

| Document | Content |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline, modules, identifiers, scoring formula |
| [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) | Interface research, tokens, components, wording rules |
| [lab/README.md](lab/README.md) | Real capture lab (SMTP / IMAP / POP3), provenance, external captures |
| [LIMITATIONS.md](LIMITATIONS.md) | What is not observable / not implemented |
| [SECURITY_POLICY.md](SECURITY_POLICY.md), [THREAT_MODEL.md](THREAT_MODEL.md) | Deployment and security model |
| [FINAL_SECURITY_AUDIT.md](FINAL_SECURITY_AUDIT.md) | Audit results and final status |
| [FUNCTIONAL_REGRESSION_MATRIX.md](FUNCTIONAL_REGRESSION_MATRIX.md) | Capability-by-capability verification |
| [SIH26159_COMPLIANCE_MATRIX.md](SIH26159_COMPLIANCE_MATRIX.md), [SIH26159_GAP_ANALYSIS.md](SIH26159_GAP_ANALYSIS.md) | Requirement coverage |
| [PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md) | Measured throughput and memory |
| [ML_DESIGN.md](ML_DESIGN.md) | Model, features, measured behaviour |
| `docs/history/` | Superseded milestone documents (unverified claims; kept for traceability) |

## Security notes

The API is unauthenticated and binds to 127.0.0.1; do not expose it. Captures are treated as
hostile input. See [SECURITY_POLICY.md](SECURITY_POLICY.md).

## License

No license file is present in this repository yet; choose and add one before publishing.
