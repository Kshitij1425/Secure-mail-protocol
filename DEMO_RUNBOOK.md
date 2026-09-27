# Demo Runbook

Verified end-to-end in a browser on 2026-09-27 (Windows 11, Python 3.12.5, Node 24; scripted Playwright walkthrough, 45 checks).

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

1. **Analyse a capture** (Tools) -> choose a file -> choose a policy profile -> *Run analysis*.
   Invalid files are rejected with a message.
2. **1 Captures**: history of every analysis (policy, score, severity counts). *Open* selects
   an analysis; *Re-analyse* runs the same stored file under another profile (SHA-256 checked).
3. **2 Overview**: score, counts, severity distribution, posture by dimension, remediation plan.
4. **3 Findings**: search, severity filter, sort; click a finding -> remediation view (why it
   matters, expected effect), evidence chain with OBSERVED / INFERRED / NOT OBSERVED labels,
   frames, triage status.
5. **4 Sessions**: filter, search, sort; click a session -> TLS details, STARTTLS state,
   linked findings, certificate chain, ML assessment and the session timeline.
6. **5 Certificates**: inventory of distinct certificates; filter; click -> extraction,
   chain linkage and trust (not evaluated) shown separately; sessions where seen.
7. **6 Timeline**: capture-time events with frame numbers; filter by session and event type.
8. **7 Anomalies**: outliers "require investigation"; toggle to show all evaluated sessions.
9. **8 Reports and export**: Raw or Redacted; PDF / HTML / JSON report, evidence bundle,
   STIX 2.1; list of generated reports.
10. Browser *Back* returns to the previous detail view; refreshing keeps the selection (URL).
11. Utility strip: A / A+ / A++ text size and high contrast (remembered per browser).

### Remediation story (real captures)

Upload `backend/tests/real_captures/real_remediation_before.pcap` and
`real_remediation_after.pcap`, tick both in **Captures**, *Compare selected*: the TLS 1.0 and
expired RSA-1024 self-signed certificate findings on 10.77.0.50:587 appear as resolved.

### Policy story

Upload `real_smtp_tls10_legacy.pcap` with **Strict**, then *Re-analyse* it with **Legacy
audit** and compare the two: the same observations produce different severities.

## 4. CLI alternative

```powershell
cd backend
securemailscope analyze tests\robustness\fixtures\pcaps\ml_mixed_estate.pcap --output-dir ..\demo_reports --json --html --pdf
```
