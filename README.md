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
* **17 deterministic rules** (`backend/securemailscope/rules/engine.py`): plaintext sessions,
  plaintext credentials, STARTTLS rejection / missing TLS / pipelining, deprecated protocol
  versions, handshake failure, insecure/weak suites, no forward secrecy, weak DH/curves,
  insecure client offers, expired / not-yet-valid / weak-key / weak-signature / self-signed /
  hostname-mismatch certificates, inconsistent chains. Each finding carries an evidence class
  (OBSERVED, INFERRED, POTENTIAL_INDICATOR, INSUFFICIENT_EVIDENCE), capture frame numbers,
  a recommendation and standards references.
* **Posture score** 0-100 with five dimensions, coverage and evidence quality, root-cause
  grouping and a prioritised remediation plan. No email sessions -> `Unknown`, not 100.
* **ML anomalies** (supplementary) - Isolation Forest fitted per capture; never changes findings
  or the score. See [ML_DESIGN.md](ML_DESIGN.md).

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

`POST /analyze` (multipart `file`) · `GET /captures[/{id}]` · `GET /captures/{id}/{sessions|findings|certificates|anomalies|posture|document}` ·
`POST /captures/{id}/reports?format=json|html|pdf` · `GET /reports/{id}/download` ·
`GET /sessions/{id}` · `GET /findings/{id}` · `PATCH /findings/{id}/status` · `GET /certificates/{id}` · `GET /anomalies/{id}`.
Interactive docs at `/docs`.

## Testing

```powershell
cd backend
python -m pytest -q                                  # 329 tests incl. fuzz/property tests
python -m tests.robustness.validate_fixtures         # 28 captures vs ground truth
$env:HYPOTHESIS_PROFILE="deep"; python -m pytest tests/test_fuzz_properties.py   # long fuzz run
python -m tests.performance.benchmark --sizes 1000 10000 100000
```

The fixture corpus (`backend/tests/robustness/fixture_factory.py`) uses real OpenSSL TLS
handshakes wrapped in synthesised TCP framing; see [LIMITATIONS.md](LIMITATIONS.md).

## Documentation

| Document | Content |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline, modules, identifiers, scoring formula |
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
