# Security Policy

## Supported deployment

SecureMailScope is a **single-analyst, local** tool. The API has no authentication and
binds to `127.0.0.1:8000`. Do not expose it on a network interface or the internet
without first adding authentication, TLS termination and per-user authorization.

## Handling of evidence

* Uploaded captures are stored as `uploads/<capture_id>.<pcap|pcapng>`; the file's
  SHA-256 is recorded before analysis and included in every report.
* Captures may contain personal data or credentials. Store the `uploads/`, `reports/` and
  database files on encrypted storage and delete them per your retention policy.
* SecureMailScope never stores credential values from plaintext authentication; it records
  the mechanism name only.
* Logs contain identifiers, counts and hashes, never payload bytes.

## Configuration (environment variables, prefix `SECUREMAILSCOPE_`)

| Variable | Default | Purpose |
|---|---|---|
| `MAX_UPLOAD_SIZE_MB` | 100 | Upload cap (enforced while streaming) |
| `MAX_PACKETS` | 5000000 | Abort analysis above this many frames |
| `ANALYSIS_TIME_BUDGET_SECONDS` | 600 | Ingestion wall-clock budget |
| `MAX_CONCURRENT_ANALYSES` | 2 | Further uploads get HTTP 503 |
| `CORS_ORIGINS` | `["http://localhost:5173","http://127.0.0.1:5173"]` | Browser origins allowed |
| `DATABASE_URL`, `UPLOAD_DIR`, `REPORTS_DIR` | local paths | Storage locations |

`SMS_LOG_LEVEL` and `SMS_LOG_FILE` control logging.

## Security checks in CI

`pytest` (incl. fuzz/property tests), `bandit`, `pip-audit -r requirements.lock`,
`npm audit --audit-level=high`, `oxlint`, TypeScript build.

## Reporting a vulnerability

Report privately to the maintainers (do not open a public issue) with a minimal capture or
request that reproduces the problem. Crashes found by fuzzing are added as permanent
regression examples in `backend/tests/test_fuzz_properties.py`.
