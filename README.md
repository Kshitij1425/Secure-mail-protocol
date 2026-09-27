# SecureMailScope

**Passive cryptographic security posture assessment of email traffic (SMTP, IMAP, POP3) from packet captures.**
Independent academic project for Smart India Hackathon 2026, problem statement SIH26159.

## 1. The problem

Mail servers still negotiate obsolete TLS versions, weak cipher suites and expired or
self-signed certificates; STARTTLS can be refused or stripped so that mail and passwords travel
in plaintext. Analysts who hold a capture of that traffic need an assessment they can act on and
defend: which sessions are weak, why, how sure we are, where in the capture it shows, and what to
fix first.

SecureMailScope reads a PCAP/PCAPNG capture, reassembles the TCP connections, identifies SMTP,
IMAP and POP3 (including STARTTLS/STLS and implicit TLS), parses the TLS handshakes and the
observable X.509 certificates, applies deterministic security rules, scores the posture and
produces an evidence-linked forensic report. It **never contacts a mail server and never
decrypts traffic**.

## 2. Why it exists alongside Wireshark, Zeek and Suricata

| Tool | What it does well | What it does not do for this problem |
|---|---|---|
| Wireshark | Decodes every packet for manual inspection | No automatic judgement of email cryptographic posture |
| Zeek | Logs connections, TLS and certificates; scriptable | Posture assessment needs custom scripts; no evidence-linked findings or reports |
| Suricata | Signature-based IDS with TLS metadata logging | Alerts on patterns; no per-session posture, scoring or remediation plan |
| testssl.sh, SSL Labs | Grade the TLS configuration of a live server | Must connect to the server; cannot analyse a stored capture (SSL Labs: public HTTPS only) |

SecureMailScope combines the passive, capture-based view of the first group with the posture
judgement of the second, and ties every finding to the capture frames that evidence it. It
complements these tools; it does not replace them.

## 3. Workflow

The dashboard is an investigation workstation with eight connected steps:
**1 Capture, 2 Analyze, 3 Posture, 4 Findings, 5 Sessions, 6 Certificates, 7 Evidence, 8 Report**,
plus ML anomalies, Compare and trend, and About and limitations.

* **Analyze** a capture under a policy profile: `balanced` (default), `strict` or `legacy_audit`.
* **Findings**: 19 deterministic rules (18 on by default). Each finding answers *Why am I seeing
  this?*: what was observed, how it was established (OBSERVED / INFERRED / POTENTIAL_INDICATOR),
  the capture frame, affected session, TLS parameters, certificate, recommendation and expected effect,
  plus the full evidence chain from capture to finding.
* **Sessions** (also grouped by server), **Certificates** (inventory; extraction, chain linkage and
  trust reported separately), **Evidence** (numbered register and capture timeline).
* **Report**: choose raw or redacted, **preview** the real report in the app, then download the
  14-section JSON / HTML / PDF report, a deterministic evidence bundle (ZIP with SHA-256 manifest,
  no payloads) or STIX 2.1 observations (no indicators).
* **Compare and trend**: new / resolved / persisting findings and ML-anomalous sessions between two
  analyses (for example before and after remediation), and the posture trend of servers over time.
* Analyst notes and "include in investigation report" selections on any capture, finding, session
  or certificate (report Appendix A).

## 4. Architecture

```
PCAP/PCAPNG -> TCP reassembly -> SMTP/IMAP/POP3 identification -> STARTTLS state machine
            -> TLS handshake parser -> X.509 analyser -> rule engine (19 rules) -> posture scoring
            -> ML ranking (Isolation Forest, supplementary)
            -> canonical evidence document -> SQLite -> FastAPI -> React dashboard, reports, bundle, STIX
```

Backend: Python 3.12, FastAPI, SQLAlchemy/SQLite, dpkt, cryptography, scikit-learn, Jinja2,
ReportLab. Frontend: React, TypeScript, Vite, Tailwind. Details: [ARCHITECTURE.md](ARCHITECTURE.md),
[DESIGN_SYSTEM.md](DESIGN_SYSTEM.md).

## 5. Installation

Requirements: Python 3.12, Node.js 20.19+ or 22.12+ (required by Vite 8).

```powershell
cd backend
python -m venv .venv; .\.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.lock
pip install -e . --no-deps
cd ..\frontend
npm ci
```

## 6. Running and demo

Windows: `.\start_demo.ps1` opens the API (http://127.0.0.1:8000, docs at `/docs`) and the
dashboard (http://localhost:5173). Any platform, in two terminals:

```
cd backend  && python -m uvicorn securemailscope.api.main:app --host 127.0.0.1 --port 8000
cd frontend && npm run dev -- --host 127.0.0.1 --port 5173
```

Demo: in the dashboard, *Analyze* `backend/tests/robustness/fixtures/pcaps/ml_mixed_estate.pcap`,
then follow the steps. Before/after story: analyse `backend/tests/real_captures/real_remediation_before.pcap`
and `real_remediation_after.pcap` and compare them. Full script: [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md).

Command line: `securemailscope analyze capture.pcap --output-dir reports --json --html --pdf`
(exit codes: 0 ok, 2 file missing, 3 not a capture, 4 resource limit, 5 report format unavailable).

## 7. Dataset and PCAP methodology

No enterprise or operational mail traffic was used. Three validation layers:

1. **Fixture corpus** (28 captures, `backend/tests/robustness/`): real OpenSSL TLS handshakes in
   synthesised TCP framing, each with ground truth.
2. **Real lab captures** (15, `backend/tests/real_captures/`): real email server/client
   application interactions generated in a controlled local environment (Mailpit and aiosmtpd for
   SMTP/POP3, the pymap IMAP server; Python smtplib, poplib and imaplib clients), covering SMTP,
   IMAP and POP3, healthy and weak. They were recorded by a TCP relay: **application bytes and
   timing are real, TCP/IP headers are reconstructed**, because no raw capture driver was
   available. They are not untouched network-interface captures. Provenance, configuration and
   ground truth: `manifest.json` and [lab/README.md](lab/README.md).
3. **External public captures** (5, Wireshark wiki; IMAP/POP3 against Dovecot, SMTP STARTTLS,
   plaintext SMTP): downloaded at test time with pinned SHA-256 (GPL, not redistributed).

A Docker lab with Postfix, Dovecot and tcpdump is provided in `lab/docker/` but was not run.

## 8. ML limitations

The ML stage is an **unsupervised Isolation Forest that ranks sessions weaker than the capture's
norm; evaluated on labelled lab sessions; supplementary to deterministic rules.** It is
evaluated only on 80 lab-generated labelled sessions, so no real-world accuracy is claimed; on
that data it performs the same as the rule "below the capture norm on any feature" and adds a
ranking. A weakness shared by most of a capture is not an ML anomaly (the rules still report it).
ML never changes findings or the score, and the dashboard never presents it as attack detection.
Details: [ML_DESIGN.md](ML_DESIGN.md).

## 9. Passive-analysis limitations

* Certificates in TLS 1.3 are encrypted by the protocol: reported as **NOT OBSERVABLE**.
* Certificate trust is **NOT EVALUATED** (no trust store, CRL or OCSP); chain linkage is verified by signature.
* Only what the capture shows: server capabilities that were not exercised, anything inside TLS,
  DANE / MTA-STS / DNSSEC policy are not assessed.
* A STARTTLS rejection is a potential indicator; the capture cannot tell an attack from a misconfiguration.
* Scoring weights and policy profiles are documented policy choices, not calibrated risk models.

Full list: [LIMITATIONS.md](LIMITATIONS.md).

## 10. Security limitations

* The API has **no authentication** and binds to 127.0.0.1; run it for a single analyst on a
  trusted machine and do not expose it.
* Captures are treated as hostile input (bounded parsers, resource limits, fuzz-tested), and
  plaintext credentials seen in captures are never stored.
* Analysis runs inside the API process; very large captures hold the upload request open.
* Redaction pseudonymises addresses, host names, organisations, e-mail addresses and the file name;
  certificate fingerprints stay and can be looked up in public Certificate Transparency logs.

See [SECURITY_POLICY.md](SECURITY_POLICY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Testing

```powershell
cd backend
python -m tests.external_captures.fetch              # download the 5 public validation captures
python -m pytest -q                                  # full suite (unit, fuzz/property, API, reports, real captures)
python -m tests.robustness.validate_fixtures         # 28 fixture captures vs ground truth
python -m tests.ml_eval.evaluate --estates 300       # ML v1 vs v2 on the labelled lab pool
```

Browser QA against a running API and dashboard (Python Playwright + Chromium): see [qa/README.md](qa/README.md).

## Documentation

| Document | Content |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline, modules, identifiers, scoring formula |
| [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) | Interface research, tokens, components, wording rules |
| [lab/README.md](lab/README.md) | Real capture lab, provenance, external captures |
| [LIMITATIONS.md](LIMITATIONS.md) | What is not observable or not implemented |
| [ML_DESIGN.md](ML_DESIGN.md) | ML model, features, evaluation |
| [SECURITY_POLICY.md](SECURITY_POLICY.md), [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY_TEST_MATRIX.md](SECURITY_TEST_MATRIX.md) | Security model and tests |
| [FUNCTIONAL_REGRESSION_MATRIX.md](FUNCTIONAL_REGRESSION_MATRIX.md) | Capability-by-capability verification |
| [SIH26159_COMPLIANCE_MATRIX.md](SIH26159_COMPLIANCE_MATRIX.md), [SIH26159_GAP_ANALYSIS.md](SIH26159_GAP_ANALYSIS.md) | Requirement coverage and readiness check |
| [PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md) | Measured throughput and memory |
| [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) | Demo walkthrough |
| [docs/audit-2026-09-26](docs/audit-2026-09-26/README.md), [docs/history](docs/history/README.md) | Dated audit record; superseded development documents |

## Independence and license

SecureMailScope is an independent academic project. It is not affiliated with, endorsed by or a
product of NTRO or any government agency, and uses no government emblem, seal or branding.

No license file is present yet; choose and add one before publishing the code for reuse.
