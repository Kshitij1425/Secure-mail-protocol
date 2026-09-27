# Demo Runbook

Verified end-to-end in a browser on 2026-09-27 (Windows 11, Python 3.12.5, Node 24; scripted Playwright walkthrough, 80 checks).

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

## 3. Walkthrough (8-step workflow)

1. **Capture**: history of every analysis (policy, score, severity counts). *Open* an analysis;
   *Re-analyse* the same stored file under another profile (SHA-256 checked); tick two to compare.
2. **Analyze**: choose a file and a policy profile, *Run analysis* (upload bar, then server analysis).
3. **Posture**: score, severity distribution, dimensions, top issues, ML summary, capture notes.
   The case bar above every analysis page names the capture, SHA-256, policy and posture.
4. **Findings**: register-numbered list; open one -> *Why am I seeing this?* (what was observed,
   how it was established, evidence frame, affected session, TLS, certificate, why it matters,
   recommendation, expected effect), the evidence chain, analyst notes, triage.
5. **Sessions**: list with filters, or *Grouped by server*; open a session -> TLS, STARTTLS,
   findings, certificate chain, ML assessment, session timeline, notes.
6. **Certificates**: inventory; open one -> extraction / linkage / trust (not evaluated), sessions,
   certificate findings on those sessions, notes.
7. **Evidence**: numbered evidence register (frame, capture time, evidence class) and the full
   capture timeline (arrow keys switch tabs).
8. **Report**: raw or redacted PDF / HTML / JSON (14 sections; Appendix A lists items you selected),
   evidence bundle, STIX 2.1.

Supporting views: **ML anomalies** (deterministic vs ML explained, limitations), **Compare and
trend**, **About and limitations**. Each step page links to the previous and next step; Esc
closes a detail drawer; refresh keeps the selection (URL).

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
