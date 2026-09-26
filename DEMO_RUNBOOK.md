# Demo Runbook

Verified end-to-end in a browser on 2026-09-26 (Windows 11, Python 3.12.5, Node 24).

## 1. Start

```powershell
.\start_demo.ps1
```
Opens two windows: API on `http://127.0.0.1:8000` (docs at `/docs`) and dashboard on
`http://localhost:5173`. First start creates `backend/securemailscope.db`; a database from an
older schema is moved aside to `securemailscope.db.schema-v1-<timestamp>.bak`.

## 2. Suggested captures (`backend/tests/robustness/fixtures/pcaps/`)

| Capture | What it shows |
|---|---|
| `ml_mixed_estate.pcap` | 12 SMTP STARTTLS sessions; one legacy server (TLS 1.0, RSA-1024, no PFS) flagged by rules and by ML |
| `implicit_tls_mixed.pcap` | IMAPS 993 (TLS 1.2), POP3S 995 (TLS 1.3), SMTPS 465 - no plaintext false positives; TLS 1.3 certificate "encrypted" |
| `smtp_weak_deprecated.pcap` | TLS 1.0, static RSA, expired self-signed RSA-1024 certificate |
| `smtp_plaintext_auth.pcap` | AUTH LOGIN in cleartext: PROTO-001 + PROTO-002, credential values not stored |
| `smtp_starttls_downgrade.pcap` | 454 STARTTLS rejection then plaintext MAIL FROM |
| `smtp_tls12_weak_dh.pcap` | DHE with 1024-bit group (TLS-005) |
| `smtp_tls12_sni_mismatch.pcap` | Certificate does not cover the SNI hostname (CERT-006) |
| `unrelated_traffic.pcap` | HTTP, SSH, HTTPS only: posture `Unknown`, not "Excellent" |

## 3. Walkthrough

1. **Upload** -> choose a capture -> *Run analysis*. Invalid files are rejected with a message.
2. **Overview**: score ring, packets/streams/sessions/TLS/certificates/ML counts, severity
   counts, posture by dimension (coverage + evidence quality), prioritised remediation, top
   findings. *Export* JSON / HTML / PDF downloads the report.
3. **Findings**: search, severity filter, sort; click a finding -> evidence, frame numbers,
   recommendation, references, triage status. Click the session link.
4. **Sessions**: protocol filter; click a session -> TLS details, STARTTLS state, reassembly
   quality, linked findings, certificate chain, ML assessment.
5. **Certificates**: click -> validity at capture time, key/signature, SAN, chain linkage,
   trust = unknown (not evaluated), sessions where seen.
6. **Anomalies**: flagged outliers (toggle to show all evaluated sessions); click -> feature
   vector and rareness explanation. Labelled as supplementary.
7. Browser *Back* returns to the previous detail view; *Esc* or the close button closes it;
   refreshing keeps the selection (it is in the URL).
8. Switch captures in the top bar: every page shows only the selected capture's data.

## 4. CLI alternative

```powershell
cd backend
securemailscope analyze tests\robustness\fixtures\pcaps\ml_mixed_estate.pcap --output-dir ..\demo_reports --json --html --pdf
```
