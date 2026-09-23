# SecureMailScope — Known Limitations

**Version:** M15 (2026-09-16)  
**Purpose:** Honest technical constraints for judges, stakeholders, and future developers

---

## 1. Passive Analysis Constraints

### What SecureMailScope **Cannot** Determine from PCAP

❌ **Server configuration not exercised in the capture**  
Example: Server supports TLS 1.3, but client in capture negotiated TLS 1.2. SecureMailScope only sees TLS 1.2.

❌ **Private keys**  
Cannot decrypt TLS traffic. Cannot verify server-side key storage practices.

❌ **Server-side policy enforcement**  
Cannot determine if server would reject weak ciphers if offered—only what was actually negotiated.

❌ **Email content security**  
Cannot analyze email body encryption (S/MIME, PGP) or DLP policies.

❌ **Authentication strength**  
Cannot determine password policies, MFA configuration, or account security.

❌ **Trust chain validation**  
Cannot query CRLs/OCSP in real time. Cannot verify certificate trust against user's actual trust store.

❌ **Network topology**  
Cannot determine firewalls, proxies, or network segmentation from PCAP alone.

❌ **Traffic not in the capture**  
If STARTTLS negotiation happens outside capture window, SecureMailScope cannot detect it.

---

## 2. Protocol Support

### Supported
✅ SMTP (port 25, 587)  
✅ IMAP (port 143, 993)  
✅ POP3 (port 110, 995)  
✅ STARTTLS upgrade detection  
✅ TLS 1.0, 1.1, 1.2, 1.3  
✅ X.509 certificate extraction  

### Not Supported
❌ Exchange Web Services (EWS)  
❌ MAPI/RPC  
❌ Proprietary email protocols  
❌ DANE/DNSSEC validation  
❌ SMTP STS policy verification  
❌ MTA-STS  

---

## 3. Capture Requirements

SecureMailScope requires:
- Complete TCP streams (SYN → FIN or RST)
- Unencrypted STARTTLS negotiation visible
- TLS handshake present in capture
- Certificate messages not truncated

### Limitations
- **Fragmented streams:** Partial reconstruction may yield incomplete findings
- **Out-of-order packets:** TCP reconstructor handles some reordering; extreme fragmentation may fail
- **Encrypted tunnels:** Cannot analyze email inside VPN/SSH tunnels
- **Implicit TLS (SMTPS/IMAPS/POP3S):** Cannot observe pre-TLS negotiation if connection starts encrypted

---

## 4. ML Anomaly Detection (M11)

### What M11 **Is**
- Unsupervised outlier detection (Isolation Forest)
- 10-dimensional feature extraction from TLS session statistics
- **Supplementary diagnostic tool**

### What M11 **Is NOT**
❌ Ground-truth vulnerability detection  
❌ Signature-based threat detection  
❌ Adversarial attack detection  
❌ Zero-day discovery  
❌ Replacement for M8 deterministic rules  

### Limitations
- Requires ≥3 TLS sessions per capture to train
- No cross-capture learning (each analysis is independent)
- High false-positive rate expected (unsupervised)
- Feature engineering is heuristic, not proven optimal
- No labeled evaluation dataset → **no accuracy claims**

**M11 results NEVER override M8 findings or M9 posture score.**

---

## 5. Forensic Traceability

### What is Traceable
✅ Finding → Session → TCP Stream → TLS Handshake → Certificate → Rule  
✅ Posture score → Dimension scores → Top contributors → Affected sessions  

### What is NOT Traceable
❌ Individual packet-level attribution for every finding  
❌ Exact cipher suite negotiation order (only final result)  
❌ Server certificate chain beyond what was sent in handshake  

---

## 6. Scalability

### Current Tested Limits
- **Packet count:** Up to ~30 packets per test fixture
- **File size:** Up to ~2 KB PCAP files
- **Concurrent uploads:** Not stress-tested beyond 2 simultaneous
- **Database:** SQLite (single-file, not distributed)

### Known Bottlenecks
- Single-threaded Python analysis
- No streaming/chunked PCAP processing
- In-memory TCP stream reconstruction
- No distributed job queue

### Realistic Use Cases (Current Architecture)
✅ Forensic investigation (1-100 captures/hour)  
✅ Incident response (single-file upload)  
✅ Compliance audit (batch processing overnight)  

❌ Real-time high-throughput email gateway monitoring  
❌ Petabyte-scale capture analysis  
❌ Multi-tenant SaaS without architecture changes  

---

## 7. Security Posture Scoring (M9)

### Transparency
- M9 uses a weighted-dimension model (encryption, forward secrecy, certificates, STARTTLS)
- Scoring policy: NIST SP 800-52 Rev 2 + industry best practices
- Root-cause deduplication prevents double-counting

### Limitations
❌ **Not a compliance certification tool**  
SecureMailScope findings assist compliance—they do not replace audits.

❌ **Scoring policy is opinionated**  
Different organizations may weight risks differently.

❌ **Captures are snapshots**  
Posture score reflects only what was in the capture, not ongoing server configuration.

---

## 8. Report Generation (M10)

### Supported Formats
✅ JSON (machine-readable)  
✅ HTML (human-readable)  
✅ PDF (WeasyPrint, if dependencies installed)  

### Limitations
❌ No Excel/CSV export (can be added)  
❌ No custom report templates (fixed structure)  
❌ No scheduled/automated report delivery  

---

## 9. User Interface (M13)

### Current State
✅ React single-page app  
✅ Overview, Findings, Sessions, Certificates, Anomalies, Upload pages  
✅ Real-time API integration  

### Limitations
❌ No multi-user authentication/authorization  
❌ No role-based access control  
❌ No audit logging for UI actions  
❌ No capture comparison/diffing  
❌ No historical trending  

**Prototype UI, not production multi-tenant SaaS.**

---

## 10. Testing & Validation

### What Was Tested
✅ 219+ automated unit/integration tests  
✅ Real PCAP validation (13 fixtures)  
✅ E2E browser workflow  
✅ Edge cases (empty, corrupt, oversized files)  

### What Was NOT Tested
❌ Load testing (1000+ concurrent users)  
❌ Long-running stability (24+ hour uptime)  
❌ Adversarial PCAP fuzzing  
❌ Cross-platform compatibility (tested on Windows only)  
❌ Independent third-party security audit  

---

## 11. Deployment

### Current State
- Development-ready
- SQLite database (single file)
- Manual startup scripts
- No containerization (Docker)
- No CI/CD pipeline

### Production Readiness
SecureMailScope M15 is a **working prototype** suitable for:
- Academic demonstration
- Proof-of-concept deployment
- Internal security team tooling (with supervision)

**Not production-ready for:**
- Public SaaS
- Mission-critical compliance enforcement
- Unattended automated processing at scale

---

## 12. Known Issues (Non-Blocking)

1. **Deprecation warnings:** Pydantic v2, SQLAlchemy 2.0, FastAPI lifespan (logged, not breaking)
2. **ML model persistence:** IsolationForest trains per-capture; no shared baseline
3. **Certificate chain validation:** Only analyzes leaf cert; no chain validation
4. **IPv6:** Not explicitly tested
5. **Non-English UI:** Dashboard is English-only

---

## Summary

SecureMailScope delivers **deterministic, explainable, traceable** passive email TLS forensics for captured network traffic. It is honest about what passive PCAP analysis can and cannot determine. It clearly separates deterministic findings (M8) from supplementary ML insights (M11). It is suitable for forensic investigation, compliance assistance, and security posture assessment **where the limitations are understood and accepted.**

**Use SecureMailScope as a forensic assistant, not an autonomous security oracle.**
