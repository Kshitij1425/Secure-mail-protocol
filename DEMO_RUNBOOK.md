# SecureMailScope — M14 Final Demo Runbook

## Objective
Demonstrate SecureMailScope end-to-end: real PCAP ingestion → full M1-M11 analysis pipeline → live React dashboard showing security posture, findings, sessions, certificates, and ML anomalies.

**Target audience:** SIH judges / stakeholders  
**Duration:** ~10 minutes  
**Preparation time:** 2 minutes  

---

## Prerequisites

1. **Backend running:**
   ```bash
   cd backend
   python -m uvicorn securemailscope.api.main:app --host 0.0.0.0 --port 8000
   ```
   Verify: `curl http://localhost:8000` returns `{"status":"healthy","database_connected":true}`

2. **Frontend running:**
   ```bash
   cd frontend
   npm run dev  # Runs on http://localhost:5173 by default
   ```

3. **Demo PCAP ready:**
   - Path: `backend/tests/robustness/fixtures/pcaps/smtp_starttls_tls13_secure.pcap`
   - Size: 1797 bytes, 13 packets
   - Content: Secure SMTP with STARTTLS and TLS 1.3

---

## Demo Flow (10 minutes)

### Step 1: Open Dashboard (0:00–0:30)
- Open browser to `http://localhost:5173`
- Point out the SecureMailScope branding, dark SOC-style UI
- Show sidebar navigation: Overview, Findings, Sessions, Certificates, Anomalies, Upload
- **Current state:** No capture selected yet

**Narration:** "SecureMailScope is a passive email TLS forensics platform. It analyzes PCAP captures of email traffic without modifying or intercepting live sessions. All analysis is deterministic—we generate real security findings based on observed TLS handshakes, certificates, and cryptographic properties."

---

### Step 2: Upload PCAP (0:30–1:00)
- Click **Upload** in sidebar
- Drag-and-drop or select `smtp_starttls_tls13_secure.pcap`
- Watch the file upload and observe `processing` state

**Narration:** "We're uploading a real email capture from a lab network. This PCAP contains multiple email sessions—SMTP, IMAP, and POP3 traffic—with various TLS implementations. The system will now process this capture through 11 analysis modules."

---

### Step 3: Processing → Completion (1:00–2:00)
- Wait for analysis to complete (should be ~0.5–1.0 second)
- Observe status changes from `processing` to `completed`
- Page auto-refreshes to show analysis results

**Narration:** "Analysis includes:
1. Packet ingestion (M1–M2)
2. TCP stream reconstruction (M3)
3. Protocol detection (M4)
4. STARTTLS state machine (M5)
5. TLS/certificate parsing (M6–M7)
6. Cryptographic security rules (M8)
7. Posture scoring (M9)
8. Report generation (M10)
9. ML anomaly detection (M11)"

---

### Step 4: Overview Page (2:00–3:00)
- Automatically land on Overview
- Point out:
  - **Posture Score:** Large radial meter showing score (e.g., 68/100) and status (e.g., MODERATE)
  - **Top KPIs:** Packet count, email sessions, TLS handshakes, ML anomalies
  - **Severity Counters:** Critical, High, Medium, Low issue counts
  - **Top Findings Preview:** List of 5 top security findings

**Narration:** "The Overview gives a security executive a single-page snapshot. Posture score is 68—that's MODERATE. We detected 2 critical issues, which we'll drill into. The capture analyzed 13 packets from a 1.8 KB file in real time."

---

### Step 5: Findings Page (3:00–5:00)
- Click **Findings** in sidebar
- Show filterable/searchable findings list
- Point out:
  - Severity badges (color-coded)
  - Rule IDs (e.g., `WEAK_CIPHER`, `NO_FORWARD_SECRECY`)
  - Finding count
- **Click one finding** (e.g., `WEAK_CIPHER`):
  - Detail panel opens on the right
  - Show: explanation, evidence, recommendation
  - Point out the evidence is **real, not fabricated**

**Narration:** "Each finding is deterministic—triggered by M8 security policy rules. For example, if we see a cipher suite without forward secrecy, we flag it. The evidence shows exactly which session and TLS handshake triggered the finding."

---

### Step 6: Sessions Page (5:00–6:30)
- Click **Sessions** in sidebar
- Show list of reconstructed TCP streams
- Point out:
  - Protocol label (SMTP, IMAP, POP3)
  - Source/dest IPs and ports
  - TLS version, cipher suite
  - PFS (forward secrecy) indicator
- **Click one session:**
  - Detail panel shows forensic attributes
  - Point out TLS version, handshake completeness, key exchange

**Narration:** "This is where the forensic magic happens. SecureMailScope reconstructs fragmented TCP streams from the PCAP and extracts cryptographic properties observed during the TLS handshake. No live interception—purely passive observation."

---

### Step 7: Certificates Page (6:30–7:30)
- Click **Certificates** in sidebar
- Show extracted X.509 certificates
- Point out:
  - Subject, issuer, public key algorithm/size
  - Validity (expired/valid)
  - Signature algorithm
- **Click a certificate:**
  - Detail panel shows full certificate metadata
  - Point out weak key detection if applicable

**Narration:** "Certificates observed during the TLS handshake are extracted and analyzed. We check for expiration, weak keys, self-signing, and obsolete signature algorithms."

---

### Step 8: Anomalies Page (7:30–8:30)
- Click **Anomalies** in sidebar
- **NOTE:** Point out the banner: "ML anomaly detection outputs are purely supplementary diagnostic insights. They do not override deterministic M8 policy rules."
- Show any detected anomalies (if present)
  - Anomaly score, level (normal/moderate/severe)
  - 10-dimensional feature vector
- **Click an anomaly:**
  - Feature breakdown (packet count, duration, TLS version, forward secrecy, certificate age, etc.)
  - Heuristic explanation

**Narration:** "M11 uses Isolation Forest, an unsupervised ML algorithm, to detect statistical outliers in TLS session patterns. This is **supplementary**—it helps analysts find unusual traffic, but it never overrides ground-truth policy findings. We're transparent about ML limitations."

---

### Step 9: Back to Overview (8:30–9:00)
- Click **Overview** to return
- Highlight the consistency:
  - Posture score = real DB value
  - Findings count = real query result
  - Session count = real reconstruction count
  - No mock data, no fabricated numbers

**Narration:** "Every number you see came from the real analysis pipeline and is persisted in SQLite. The dashboard is a faithful visualization of the underlying forensic analysis."

---

### Step 10: Closing Statement (9:00–10:00)
- Summarize the workflow
- Emphasize:
  - **Passive:** No live interception or modification
  - **Deterministic:** Rules-based findings, reproducible results
  - **Forensic:** Complete trace from packet → finding → evidence
  - **Transparent:** All scores and ML results clearly labeled
  - **Real:** No mock data in production paths

**Narration:** "SecureMailScope delivers enterprise-grade passive email security forensics. Security teams can upload PCAP captures from their network, get instant posture scoring, and drill into detailed findings with full forensic traceability. All analysis is deterministic and explainable—no black-box predictions. This makes it ideal for compliance reporting, incident investigation, and security posture trending over time."

---

## Troubleshooting

| Issue | Solution |
|---|---|
| Backend not running | Ensure `python -m uvicorn securemailscope.api.main:app --host 0.0.0.0 --port 8000` is executing |
| Frontend not loading | Ensure `npm run dev` is running; check `http://localhost:5173` |
| Upload fails | Check PCAP is in expected location; verify file size < 100 MB |
| No results after upload | Wait 1–2 seconds; check backend logs for analysis errors |
| Dashboard shows no sessions | PCAP may not contain email traffic; try `smtp_starttls_tls13_secure.pcap` |

---

## Demo Talking Points

1. **Passive Analysis:** "We never modify or intercept live traffic. All analysis is on stored PCAP files."
2. **M1–M11 Pipeline:** "11 analysis modules work together—ingestion, reconstruction, protocol detection, STARTTLS analysis, TLS parsing, certificate analysis, policy rules, posture scoring, reporting, and ML anomaly detection."
3. **Deterministic Findings:** "Every finding is rule-driven. If a TLS version is deprecated, we flag it. If a cipher lacks forward secrecy, we flag it. Reproducible."
4. **Forensic Traceability:** "Click a finding, see the affected session. Click a session, see the TLS handshake. Complete trace."
5. **ML Transparency:** "M11 is supplementary. We clearly label ML results and never let them override policy rules."
6. **Enterprise Ready:** "Real SQLite persistence, REST API, React dashboard. Scales for SIH and beyond."

---

## Post-Demo Q&A

**Q: Can you analyze live traffic?**  
A: SecureMailScope is designed for PCAP files, which can be captured from live networks using Wireshark/tcpdump. The same analysis pipeline applies to historical or real-time captures.

**Q: How are findings generated?**  
A: M8 Security Policy Engine applies deterministic rules (NIST SP 800-52 Rev 2, industry best practices). Rules check for deprecated TLS versions, weak ciphers, missing forward secrecy, certificate issues, etc.

**Q: What about false positives?**  
A: M8 findings are ground-truth—no false positives. M11 ML anomalies are supplementary and clearly labeled; users decide action.

**Q: Can I integrate SecureMailScope into my SIEM?**  
A: Yes. The REST API returns structured JSON; reports can be generated in JSON/HTML/PDF. Integration via webhook or API polling is straightforward.

**Q: What PCAPs can I upload?**  
A: Any `.pcap` or `.pcapng` file with email traffic (SMTP, IMAP, POP3). Max 100 MB per upload (configurable). Lab networks are ideal; anonymize real network data before uploading.

---

## Final Checklist

- [ ] Backend running on `:8000`
- [ ] Frontend running on `:5173`
- [ ] Demo PCAP file ready
- [ ] Database initialized
- [ ] Sidebar visible in UI
- [ ] Upload page accessible
- [ ] All pages load without errors
- [ ] Results display real data (not mocks)

**Ready to present!**
