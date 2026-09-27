# SIH26159 Gap Analysis

| Gap | Requirement | Why | What would close it | Priority |
|---|---|---|---|---|
| G-1 | F (certificates) | Trust-anchor validation (path building to a root store, revocation) is not performed; passive captures often omit roots and never contain OCSP answers for SMTP | Optional offline trust store (e.g. Mozilla CA bundle) + path validation, reported separately from "observed"; never default "trusted" | Medium |
| G-2 | F (TLS 1.3) | Certificates are encrypted in TLS 1.3 | Optional SSLKEYLOGFILE import for captures where the analyst owns the endpoint; mark results as "decrypted with provided keys" | Medium |
| G-3 | N (ML risk classification) | No labelled corpus of mail-server captures | Collect/label real captures; evaluate a supervised classifier against deterministic rules on an independent test set before claiming accuracy | Low (deterministic rules already classify risk) |
| G-4 | O (ML) | Per-capture fitting: outliers are relative to the capture. Addressed: v1 false flags on healthy diversity (98%) removed in v2; not-observable values are neutral. Open: evaluated on lab data only; fleet-wide weakness is not an outlier | Real labelled captures; persisted organisational baseline | Low |
| G-5 | D | IP fragment reassembly not implemented | dpkt-based fragment reassembly with limits | Low (rare for TCP mail) |
| G-6 | A-W validation | No third-party real-world captures were available. Partly addressed: 9 real server/client sessions (Mailpit, aiosmtpd) recorded via a TCP relay; no IMAP server; Postfix/Dovecot Docker lab not run | Run `lab/docker` (tcpdump on real interfaces); captures from production-like MTAs (Postfix, Exchange) | High (for field claims) |
| G-7 | P | Score weights are policy, not calibrated; a single legacy session can place a capture in "Critical" | Partly addressed: strict / balanced / legacy_audit profiles implemented (not stakeholder-reviewed); per-server posture still open | Medium |
| G-8 | Deployment | No authentication; synchronous analysis | Add auth + job queue before any multi-user deployment | High (for deployment beyond a single analyst) |

## Product enhancements considered (Phase 16)

| Enhancement | Classification | Decision |
|---|---|---|
| Finding lifecycle (open/ack/in progress/resolved/false positive) | High value / low risk | **Implemented** (`PATCH /findings/{id}/status`, UI triage; does not alter score) |
| Prioritised remediation plan | High value / low risk | **Implemented** (reports, API posture, Overview) |
| ClientHello vs ServerHello comparison | High value / low risk | **Implemented** as data (client max/offered versions, offered insecure suites TLS-006, session detail) |
| Certificate intelligence (reuse across sessions, SAN/SNI) | High value / low risk | **Implemented** (`seen_in_sessions`, CERT-006) |
| ML explanation by feature rareness | High value / low risk | **Implemented** |
| Infrastructure inventory / capture comparison / trend | Medium | **Implemented**: history, comparison, certificate inventory (trend charts not built) |
| Remediation simulator | Medium | Deferred |
| Configurable policy profiles | Medium | **Implemented** (3 profiles) |
| Privacy/pseudonymisation mode | Medium | **Implemented** (redacted outputs) |
| Forensic evidence bundles / STIX export | Medium / high risk of scope creep | **Implemented**, observations only (no indicators) |
