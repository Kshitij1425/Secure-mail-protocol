# SecureMailScope

**Passive Email TLS Security Forensics Platform**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Node.js 18+](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org/)
[![Tests: 219 Passing](https://img.shields.io/badge/tests-219%20passing-brightgreen.svg)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Deterministic, explainable, traceable security analysis of email traffic from PCAP captures.**

SecureMailScope analyzes network packet captures (PCAP/PCAPNG) to assess the cryptographic security posture of email infrastructure—without requiring live access to mail servers or private keys.

**🎯 Smart India Hackathon 2026 | Problem Statement: Email Security Forensics**

---

## Quick Demo (< 2 minutes)

```powershell
# Windows (PowerShell)
.\start_demo.ps1

# Manual startup
.\start_backend.ps1   # Terminal 1: http://localhost:8000
.\start_frontend.ps1  # Terminal 2: http://localhost:5173

# Open browser to http://localhost:5173
# Upload: backend/tests/robustness/fixtures/pcaps/smtp_starttls_tls13_secure.pcap
# View: Security posture, findings, sessions, certificates, anomalies
```

**Demo complete in ~10 seconds.** See [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) for full walkthrough.

---

## What SecureMailScope Does

✅ **Passive Analysis** — Analyzes stored PCAP files; never modifies or intercepts live traffic  
✅ **Protocol Detection** — Identifies SMTP, IMAP, POP3 automatically  
✅ **TCP Reconstruction** — Reassembles fragmented email sessions  
✅ **STARTTLS Analysis** — Tracks encryption upgrade negotiations  
✅ **TLS Parsing** — Extracts versions, cipher suites, key exchange methods  
✅ **Certificate Extraction** — Analyzes X.509 certificates (validity, key strength, signatures)  
✅ **Deterministic Rules** — 8+ security policy checks (NIST SP 800-52 Rev 2)  
✅ **Posture Scoring** — 0-100 cryptographic security score (M9)  
✅ **Forensic Reports** — JSON/HTML/PDF with full evidence traceability  
✅ **ML Anomaly Detection** — Supplementary IsolationForest outlier detection (M11)  
✅ **Interactive Dashboard** — React UI for analysts (Overview, Findings, Sessions, Certificates)  

---

## Architecture (5-Minute Overview)

```
┌─────────────────────────────────────────────────────────────┐
│                    React Dashboard (M13)                    │
│  Overview │ Findings │ Sessions │ Certificates │ Anomalies  │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP/REST
┌─────────────────────▼───────────────────────────────────────┐
│                  FastAPI Backend (M12)                      │
│  13 REST endpoints │ SQLite persistence │ Background jobs   │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Analysis Orchestrator (M1-M11)                 │
├─────────────────────────────────────────────────────────────┤
│ M1: PCAP Ingestion          │ M7: Certificate Analysis      │
│ M2: Packet Parsing          │ M8: Security Policy Engine    │
│ M3: TCP Reconstruction      │ M9: Posture Scoring           │
│ M4: Protocol Detection      │ M10: Report Generation        │
│ M5: STARTTLS State Machine  │ M11: ML Anomaly Detection     │
│ M6: TLS Parser              │                               │
└─────────────────────────────────────────────────────────────┘
```

**Data Flow:** PCAP Upload → M1-M11 Pipeline → SQLite → API → Dashboard

---

## Key Features

### 🔍 Deterministic Security Findings

- **Plaintext Email Detection** — Unencrypted SMTP/IMAP/POP3
- **STARTTLS Failures** — Rejected or missing encryption upgrades
- **Deprecated TLS Versions** — TLS 1.0, TLS 1.1, SSLv3
- **Weak Cipher Suites** — RC4, 3DES, export-grade ciphers
- **No Forward Secrecy** — Static RSA key exchange
- **Certificate Issues** — Expired, self-signed, weak keys (< 2048-bit RSA)
- **Weak Signature Algorithms** — MD5, SHA-1

### 📊 Security Posture Scoring (M9)

- **0-100 Score** — Weighted dimension model (encryption, forward secrecy, certificates)
- **Status Bands** — EXCELLENT (90+), GOOD (75-89), MODERATE (50-74), POOR (25-49), CRITICAL (<25)
- **Top Contributors** — Ranked by impact with affected session counts
- **Root-Cause Grouping** — Deduplicates identical findings across sessions

### 🤖 ML Anomaly Detection (M11)

- **Unsupervised Learning** — IsolationForest on 10-dimensional feature space
- **Supplementary Only** — Never overrides deterministic findings
- **Feature Extraction** — TLS version, cipher strength, forward secrecy, certificate age, packet counts, session duration
- **Clear UI Labeling** — "ML anomaly detection outputs are purely supplementary diagnostic insights"

### 📈 Interactive Dashboard

- **Overview** — Posture score, KPI metrics, top findings preview
- **Findings** — Filterable list with detail drawer (explanation, evidence, recommendation)
- **Sessions** — Reconstructed TCP streams with TLS properties
- **Certificates** — X.509 inventory with validity, key size, signatures
- **Anomalies** — ML-detected outliers with feature breakdown
- **Upload** — Drag-and-drop PCAP ingestion

---

## Installation

### Prerequisites

- **Python 3.12+** ([Download](https://www.python.org/downloads/))
- **Node.js 18+** ([Download](https://nodejs.org/))
- **Git** (for cloning)

### Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

---

## Usage

### Option 1: One-Command Startup (Windows)

```powershell
.\start_demo.ps1
```

Opens two PowerShell windows:
- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`

### Option 2: Manual Startup

**Terminal 1 (Backend):**
```bash
cd backend
python -m uvicorn securemailscope.api.main:app --host 0.0.0.0 --port 8000
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

**Browser:** Open `http://localhost:5173`

### Option 3: CLI (Command-Line Interface)

```bash
cd backend
python -m securemailscope.cli analyze path/to/capture.pcap --output report.json --format json
```

**Output formats:** `json`, `html`, `pdf` (requires WeasyPrint)

---

## Demo Workflow

1. **Upload PCAP** — Drag-and-drop `smtp_starttls_tls13_secure.pcap` into dashboard
2. **Processing** — Watch analysis complete (~0.5s for 13 packets)
3. **Overview** — View posture score (e.g., 68/100 MODERATE)
4. **Findings** — Click a finding → see explanation, evidence, recommendation
5. **Sessions** — Inspect reconstructed TCP stream → TLS version, cipher, PFS
6. **Certificates** — View X.509 details → validity, key size, signature algorithm
7. **Anomalies** — See ML-detected outliers → 10D feature vector + explanation
8. **Reports** — Download JSON/HTML/PDF forensic report

**Complete demo:** [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md)

---

## Testing

### Run Backend Tests

```bash
cd backend
pytest tests/ --verbose
```

**Result:** 219/219 tests passing ✓

### Run Frontend Build

```bash
cd frontend
npm run build
```

**Result:** 0 errors ✓

### Test Coverage

- **M1-M8:** Protocol detection, TCP reconstruction, TLS parsing, certificate analysis, security rules
- **M9:** Posture scoring (100+ test cases)
- **M10:** CLI and report generation
- **M11:** ML feature extraction and anomaly detection
- **M12:** API endpoints (15 tests)
- **M13:** Frontend build validation

---

## Supported Protocols

| Protocol | Ports | STARTTLS | Implicit TLS |
|---|---|---|---|
| **SMTP** | 25, 587 | ✅ | ✅ (465) |
| **IMAP** | 143 | ✅ | ✅ (993) |
| **POP3** | 110 | ✅ | ✅ (995) |

**TLS Versions:** 1.0, 1.1, 1.2, 1.3

---

## Project Structure

```
SecureMailScope/
├── backend/
│   ├── securemailscope/
│   │   ├── ingestion/        # M1-M2: PCAP ingestion
│   │   ├── tcp/              # M3: TCP stream reconstruction
│   │   ├── protocols/        # M4: Email protocol detection
│   │   ├── starttls/         # M5: STARTTLS state machine
│   │   ├── tls/              # M6: TLS handshake parsing
│   │   ├── certificates/     # M7: X.509 certificate analysis
│   │   ├── rules/            # M8: Security policy engine
│   │   ├── scoring/          # M9: Posture scoring
│   │   ├── reports/          # M10: JSON/HTML/PDF generation
│   │   ├── ml/               # M11: ML anomaly detection
│   │   ├── api/              # M12: FastAPI REST backend
│   │   └── core/             # Orchestrator
│   └── tests/                # 219 automated tests
├── frontend/
│   └── src/
│       ├── pages/            # React dashboard pages
│       ├── components/       # Reusable UI components
│       ├── lib/              # API client
│       └── types/            # TypeScript interfaces
├── start_demo.ps1            # One-command startup
├── DEMO_RUNBOOK.md           # Complete demo walkthrough
├── LIMITATIONS.md            # Honest technical constraints
├── PERFORMANCE_REPORT.md     # Measured benchmarks
└── README.md                 # This file
```

---

## Documentation

- **[DEMO_RUNBOOK.md](DEMO_RUNBOOK.md)** — 10-minute SIH demonstration script
- **[INTEGRATION.md](INTEGRATION.md)** — M14 E2E validation report
- **[VALIDATION_REPORT.md](VALIDATION_REPORT.md)** — M14 complete system validation
- **[LIMITATIONS.md](LIMITATIONS.md)** — Known constraints and honest scope
- **[PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md)** — Measured benchmarks
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design and data flow (TBD)
- **[ML_DESIGN.md](ML_DESIGN.md)** — M11 Isolation Forest design (TBD)

---

## Performance

**Measured on development workstation (Windows 11, Python 3.12.5):**

| Capture Size | Packets | Analysis Time | Throughput |
|---|---|---|---|
| 419 bytes | 3 | ~0.3s | ~15 pkt/s |
| 1.8 KB | 13 | ~0.5s | ~26 pkt/s |
| 1.9 KB | 30 | ~0.9s | ~33 pkt/s |

**Suitable for:** Forensic investigation, incident response, compliance auditing  
**Not suitable for:** Real-time high-throughput stream processing (without architecture changes)

See [PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md) for full analysis.

---

## Security

SecureMailScope treats PCAP content as **untrusted, attacker-controlled input.**

**Hardening measures:**
- ✅ Upload filename sanitization
- ✅ File size limits (100 MB configurable)
- ✅ Extension validation (`.pcap`, `.pcapng` only)
- ✅ SQLAlchemy ORM (no raw SQL injection)
- ✅ React JSX escaping (no `dangerouslySetInnerHTML`)
- ✅ CORS restricted to `localhost:3000`, `localhost:5173`
- ✅ Path traversal prevention
- ✅ PCAP parser error handling (corrupt/malformed files)

**What to audit before production:**
- Multi-user authentication/authorization (not implemented)
- Role-based access control (not implemented)
- Audit logging (not implemented)
- Rate limiting (not implemented)
- Third-party security audit (not performed)

---

## Limitations (Honest Scope)

### What SecureMailScope **Cannot** Do

❌ Decrypt TLS traffic (no private keys)  
❌ Determine server config not exercised in capture  
❌ Analyze email content encryption (S/MIME, PGP)  
❌ Validate certificate trust chains in real time  
❌ Detect zero-day vulnerabilities  
❌ Analyze encrypted tunnels (VPN/SSH)  
❌ Replace compliance audits  

### Current Scale Limits

- Tested on captures < 2 KB, < 30 packets
- Single-threaded Python processing
- SQLite (not distributed database)
- No streaming/chunked processing for large files

See [LIMITATIONS.md](LIMITATIONS.md) for complete constraints.

---

## Roadmap (Post-SIH)

- [ ] Docker containerization
- [ ] PostgreSQL support
- [ ] Distributed job queue (Celery/RQ)
- [ ] Multi-user authentication
- [ ] Historical trending
- [ ] Capture comparison/diffing
- [ ] Excel/CSV export
- [ ] Scheduled report delivery
- [ ] CI/CD pipeline
- [ ] Cross-platform testing (Linux, macOS)

---

## Contributing

SecureMailScope is a Smart India Hackathon 2026 project. Contributions welcome after SIH judging.

**Development workflow:**
1. Fork repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Run tests (`pytest tests/`)
4. Commit changes (`git commit -m 'Add AmazingFeature'`)
5. Push to branch (`git push origin feature/AmazingFeature`)
6. Open Pull Request

**Testing requirement:** All tests must pass. No regressions.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Authors

**Team SecureMailScope**  
Smart India Hackathon 2026

---

## Acknowledgments

- **NIST SP 800-52 Rev 2** — TLS security guidelines
- **dpkt** — Python packet parsing library
- **FastAPI** — Modern Python web framework
- **React** — UI library
- **scikit-learn** — Isolation Forest implementation
- **Tailwind CSS** — Dashboard styling

---

## FAQ

**Q: Can SecureMailScope analyze live traffic?**  
A: SecureMailScope processes stored PCAP files. Capture live traffic with Wireshark/tcpdump, then upload.

**Q: Does it decrypt TLS?**  
A: No. Analysis is passive; no decryption or private keys required.

**Q: How accurate is the ML anomaly detection?**  
A: M11 is unsupervised and supplementary. No accuracy claims without labeled evaluation dataset. Use for diagnostic investigation, not autonomous decisions.

**Q: What PCAPs should I upload?**  
A: Lab network captures with email traffic (SMTP/IMAP/POP3). Anonymize production data before upload.

**Q: Is this production-ready?**  
A: M15 is a working prototype suitable for demonstration, proof-of-concept, and internal security tooling. Not production SaaS without hardening (auth, RBAC, audit logging, scale testing).

**Q: How do I integrate with my SIEM?**  
A: Use the REST API (`/captures`, `/findings`, `/posture`) or export JSON reports for ingestion.

---

## Contact

For SIH 2026 inquiries: [Contact team through SIH portal]

**Project Repository:** [GitHub link TBD after SIH]

---

**SecureMailScope — Deterministic, Explainable, Traceable Email Security Forensics**
