# ML Anomaly Detection - Design and Measured Behaviour

**Role:** supplementary. The ML stage never creates, removes or changes a deterministic
finding and never affects the posture score (enforced in `core/orchestrator.py`: scoring
consumes `all_findings` only; covered by `test_ml_flags_the_planted_outlier_only`).

## Model

| Item | Value |
|---|---|
| Algorithm | scikit-learn `IsolationForest`, 100 trees |
| Training | **Unsupervised, fitted per capture** on that capture's own TLS sessions. No external baseline, no labels, no persisted model. |
| Eligible sessions | Email sessions whose TLS ServerHello was observed (negotiated version known) |
| Minimum sessions | 5 (`MIN_ML_SESSIONS`). Below that the stage reports `insufficient_sessions (<5)` and produces no results. |
| Threshold | `contamination="auto"` (score-based threshold, no forced outlier quota) |
| Seed | `random_state=42` (fixed) |
| Time reference | Capture start time (certificate age/validity features), so results do not change with the analysis date |
| Model version string | `isolation-forest/1` (stored with every anomaly row) |
| Scoring path | Batched `decision_function` (identical to per-session scoring; `test_batch_detection_matches_single_detection`) |

## Features (10, `ml/feature_extractor.py`)

| # | Feature | Source | Missing-data handling |
|---|---|---|---|
| 1 | `tls_version_ordinal` (SSLv2=0 ... TLS1.3=5) | ServerHello / supported_versions | Not applicable: only sessions with a negotiated version are evaluated |
| 2 | `cipher_strength` (0-100 heuristic from suite name) | ServerHello | 50 if unknown |
| 3 | `certificate_key_size` (bits) | Leaf certificate | 0 if no certificate observed (e.g. TLS 1.3) |
| 4 | `certificate_age_days` at capture time | Leaf certificate | 0 if none |
| 5 | `certificate_validity_days` remaining at capture time | Leaf certificate | 0 if none |
| 6 | `session_duration_seconds` | TCP stream | - |
| 7 | `packet_count` | TCP stream | - |
| 8 | `has_forward_secrecy` (0/1) | Cipher classification / TLS 1.3 | 0 if unknown |
| 9 | `signature_algorithm_strength` (0-100) | Leaf certificate | 50 if none |
| 10 | `certificate_chain_depth` | Certificate message | 0 if none |

Known weakness: "no certificate observed" (TLS 1.3) is encoded as zeros, so TLS 1.3
sessions look unusual next to TLS 1.2 sessions in a mixed capture.

## Explanations

Each flagged session gets a level (mild / moderate / severe from the normalised decision
score) and a *rareness* explanation naming the features whose values occur in <= 20% of
the capture's sessions (e.g. `certificate_key_size=1024 (8% of sessions)`).

## Measured results (not accuracy claims)

There is **no independent labelled dataset**, so no precision/recall/accuracy is claimed.
The following are observations on the repository's synthetic-framing / real-OpenSSL fixtures:

| Capture | TLS sessions evaluated | Flagged | Notes |
|---|---|---|---|
| `ml_mixed_estate.pcap` (11 TLS 1.2 ECDHE + 1 TLS 1.0 RSA-1024) | 12 | 1 | The single flagged session is the planted TLS 1.0 outlier |
| Benchmark estate, 2,000 packets | 79 | 24 (30%) | All 5 deterministically weak sessions flagged; 19 other flags are minority configurations (TLS 1.3, implicit TLS) |
| Benchmark estate, 10,000 packets | 383 | 119 (31%) | All 24 weak sessions flagged; 95 other flags |

Interpretation: on heterogeneous captures the detector highlights *minority
configurations*, which is useful for triage ("which endpoints behave differently?") but it
is **not** a vulnerability detector, and its flag rate on mixed estates is high. Repeat
analysis of the same capture produced identical scores in every run.

## What would be needed for stronger claims

* A labelled corpus of real mail-server captures (independent of the fixtures) to measure
  precision/recall.
* A persisted baseline model per organisation instead of per-capture fitting.
* Encoding "not observable" explicitly (indicator features) instead of zeros.
