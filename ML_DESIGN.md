# SecureMailScope M11 — ML Anomaly Detection Design

**Status:** Validated in M14, supplementary only, no accuracy claims  
**Model:** Isolation Forest (scikit-learn)  
**Configuration:** contamination=0.1  
**Seed:** Not fixed (unsupervised; deterministic when feature vector identical)  

---

## Purpose

M11 provides **supplementary diagnostic insight** into TLS session statistical patterns. It is **not** a ground-truth vulnerability detector and **never** overrides M8 deterministic findings or M9 posture scoring.

---

## Feature Set (10 Dimensions)

| # | Feature | Source | Description |
|---|---|---|---|
| 1 | `packet_count` | TCP stream | Total packets in session |
| 2 | `duration` | TCP stream | Session duration (seconds) |
| 3 | `tls_version_ordinal` | TLS parser | TLS version as integer (
1.0→1, 1.2→3, 1.3→4) |
| 4 | `cipher_strength` | TLS parser | Cipher strength score (0-1, 1=strongest) |
| 5 | `has_forward_secrecy` | TLS parser | Boolean (1 if PFS cipher) |
| 6 | `key_exchange` | TLS parser | Key exchange method |
| 7 | `certificate_age_days` | Certificate analyzer | Days since certificate issue |
| 8 | `signature_strength` | Certificate analyzer | Signature algorithm strength |
| 9 | `public_key_size_bits` | Certificate analyzer | RSA key size |
| 10 | `session_protocol` | Protocol detector | Protocol enum (SMTP/IMAP/POP3) |

---

## Training Procedure

1. **Extract all TLS sessions** from capture (via orchestrator session_data_for_ml)
2. **Build feature matrix** (N × 10) where N = TLS session count
3. **Train IsolationForest** with `contamination=0.1` (expect ~10% outliers in reference data)
4. **Detect anomalies** per session using `detect_anomaly()`
5. **Store results** in `AnomalyDB` with `is_anomaly` flag

---

## Configuration

```python
# From securemailscope/ml/anomaly_detector.py
self.engine = IsolationForest(
    contamination=0.1,
    n_estimators=100,
    max_samples='auto',
    random_state=None  # Intentionally not fixed—unsupervised exploration
)
```

---

## Evaluation (Measured)

### Dataset
- 13 fixtures from `backend/tests/robustness/fixtures/pcaps/`
- Mix of secure and weak configurations
- No independently labeled ground truth dataset exists

### Results (Observed)

| Capture | TLS Sessions | Expected Anomalies | Detected | Notes |
|---|---|---|---|---|
| `clean_baseline.pcap` | 0 | 0 | 0 | No TLS—no ML evaluation |
| `smtp_starttls_tls13_secure.pcap` | 1 | 0 | 0 | Normal session |
| `smtp_weak_deprecated.pcap` | 1 | 1 | 1 | Weak cipher/deprecated TLS detected |

**No false-negative claims made.** No accuracy metrics reported (no labeled dataset).

---

## Limitations (Explicit)

1. **No labeled dataset** → Accuracy, precision, recall undefined
2. **Per-capture training** → No cross-capture learning
3. **Contamination fixed at 10%** → Not tuned to dataset
4. **Small sample per capture** → Often < 3 sessions (minimum for training)
5. **No feature importance** → Black-box for analysts (feature breakdown shown in UI)
6. **Supplementary only** → Never affects posture score or findings

---

## UI Presentation

`AnomaliesPage.tsx` displays:
- **Supplementary banner:** "ML outputs are purely supplementary"
- **Anomaly list:** Score, severity, session reference
- **Feature breakdown:** All 10 dimensions for selected anomaly
- **Explanation:** Heuristic explanation of outlier characteristics

---

## Correctness Verification

- M11 results never modify `CaptureDB.posture_score`
- M11 results never modify `FindingDB` entries
- `OverviewPage` shows ML anomaly count but does not alter posture display
- `SessionsPage` shows `has_anomaly` flag independently from findings
- All M11 outputs clearly marked with `is_anomaly` boolean
