> **HISTORICAL DOCUMENT - SUPERSEDED (audit of 2026-09-26).** Written during earlier development
> milestones. Its claims were NOT verified and several are known to be wrong (see
> `FINAL_SECURITY_AUDIT.md`, `FUNCTIONAL_REGRESSION_MATRIX.md`). Kept for traceability only.

# SecureMailScope Integration Root-Cause Report

**Audit date:** 2026-09-26  
**Scope:** Diagnose the discrepancy between the Overview page and the Sessions, Certificates, and Anomalies pages.  
**Constraint:** No application code, scoring logic, UI behavior, or tests were modified during this audit.

## 1. Executive conclusion

The uploaded PCAP is valid and the core orchestrator is not losing the observed email/TLS data.

For the uploaded capture `securemailscope_demo_rich_valid.pcap`, direct execution of the same orchestrator produced:

| Stage | Actual count |
|---|---:|
| Packets read and yielded | 175 |
| TCP streams reconstructed | 27 |
| Email protocol sessions detected | 7 |
| TLS sessions established | 3 |
| Certificates parsed | 3 |
| Raw rule-engine findings | 11 |
| ML sessions before M11 | 3 |
| ML anomaly results from a current direct run | 1 |

The API/database state for the uploaded capture was instead:

| Persisted/API value | Actual value |
|---|---:|
| `captures.packet_count` | 0 |
| `captures.stream_count` | 27 |
| `captures.email_session_count` | 0 |
| `captures.tls_session_count` | 0 |
| `captures.posture_score` | 0.0 |
| `sessions` rows | 0 |
| `certificates` rows | 0 |
| `findings` rows | 5 |
| `anomalies` rows | 0 |

**Primary root cause:** the API service does not persist sessions, certificates, or anomalies. Both `_store_certificates` and `_store_anomalies` are placeholder methods containing only `pass`, and no session-storage method is called at all.

**Secondary root cause:** `_process_analysis_results` reads `packet_count`, `email_session_count`, and `tls_session_count` from metadata, but the orchestrator returns `total_packets`, `reconstructed_streams`, and only ML metadata. Missing keys default to zero.

**Why five findings still appear:** `_store_findings` does not persist the raw per-session findings. It persists only `posture_score.top_contributors`, which contained five aggregated root-cause contributors. These records have `session_id = NULL`, so they are not traceable to the sessions and certificates that generated the underlying findings.

The issue is therefore primarily **API persistence/integration**, with a separate metadata-contract mismatch. It is not primarily a PCAP, TLS parser, frontend rendering, or ML-generation problem.

## 2. Reproduction

The already-uploaded UI capture was identified in the live API:

```text
capture_id = ab7434b2-90ca-4476-8b7b-2b49cbfa4d34
filename   = securemailscope_demo_rich_valid.pcap
sha256     = 61d94e69d18140c9acc7a402cec04ddc5ef6e4ab6a2c71fbf320c7bc883075a6
```

The same PCAP was uploaded again through `POST /analyze` to verify the behavior was reproducible:

```text
new capture_id = 71b6106b-87c2-4bb5-b772-93b561df7102
HTTP status    = 200
status         = completed
```

The fresh upload produced the same persisted contradiction:

```text
captures row: packet_count=0, stream_count=27, email_session_count=0,
              tls_session_count=0, posture_score=0.0, posture_status=Critical
child rows:   sessions=0, certificates=0, findings=5, anomalies=0
```

The original capture showed the same values through the UI/API:

```text
Security posture: 0/100
TLS handshakes:   0
ML anomalies:     0
Findings:         5
Sessions page:    []
Certificates:     []
Anomalies:        []
```

## 3. Direct orchestrator trace

The direct run used the real [Orchestrator](../../backend/securemailscope/core/orchestrator.py), bypassing FastAPI and SQLite.

### Ingestion and reconstruction

The [PcapIngestor](../../backend/securemailscope/ingestion/reader.py) reported:

```text
total_packets     = 175
valid_packets     = 175
malformed_packets = 0
ignored_non_ip    = 0
```

The [TCPReconstructor](../../backend/securemailscope/tcp/stream.py) produced 27 streams.

### Protocol and TLS analysis

Seven streams were recognized as email protocols:

- SMTP: 3 streams
- IMAP: 2 streams
- POP3: 2 streams

Three streams established TLS and yielded certificates:

| Protocol/port | TLS state | TLS version | Cipher | Certificates | Findings |
|---|---|---|---|---:|---|
| SMTP/587 | `TLS_ESTABLISHED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1 | `CERT-005` |
| SMTP/25 | `TLS_ESTABLISHED` | TLS 1.2 | `UNKNOWN_CIPHER_0x000A` | 1 | `TLS-004`, `CERT-001`, `CERT-003`, `CERT-005` |
| SMTP/2525 | `TLS_ESTABLISHED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1 | `CERT-005` |

The remaining four recognized email streams were plaintext or rejected STARTTLS:

- IMAP/993: plaintext
- POP3/995: plaintext
- POP3/110: `STARTTLS_REJECTED`
- IMAP/993: plaintext

Their findings were:

```text
PROTO-001, PROTO-001, PROTO-001,
PROTO-001 + STLS-001
```

The direct raw rule-engine total was therefore 11 findings.

### Orchestrator return shape

The orchestrator returned a `PostureScore` containing:

```text
total_sessions   = 7
tls_sessions     = 3
findings_count   = 11
overall_score    = 0.0
status           = Critical
```

It returned metadata containing:

```text
total_packets
valid_packets
reconstructed_streams
ml_anomalies_detected
ml_engine_summary
```

It did **not** return metadata keys named:

```text
packet_count
email_session_count
tls_session_count
```

This is the direct cause of the three zero capture counters in the API.

## 4. M11 behavior

The rich capture had three TLS sessions before M11. The [orchestrator](../../backend/securemailscope/core/orchestrator.py) only enters M11 when at least three TLS session records are available.

A traced direct run showed:

```text
M11 train input = 3 sessions
training result = True
trained_sessions = 3
current direct run anomaly results = 1
```

The original API capture still has zero persisted anomalies because [AnalysisService._store_anomalies](../../backend/securemailscope/api/services/analyzers.py) is an empty placeholder. The same persistence result was reproduced for the fresh upload.

Therefore:

- `0` anomalies in the API/UI is not evidence that the PCAP had no TLS sessions.
- The current direct orchestrator can train M11 on the rich capture.
- The API cannot expose any M11 result because it never stores one.
- Existing one-TLS-session fixtures correctly do not train M11 because the minimum of three sessions is not met.

## 5. SQLite evidence

For the original capture ID `ab7434b2-90ca-4476-8b7b-2b49cbfa4d34`, direct SQLite inspection of `backend/securemailscope.db` showed:

```text
captures       = 1
sessions       = 0
certificates   = 0
findings       = 5
anomalies      = 0
session_findings = 0
```

The capture row was:

```text
packet_count          = 0
stream_count          = 27
email_session_count   = 0
tls_session_count     = 0
posture_score         = 0.0
posture_status        = Critical
ml_anomalies_detected = 0
```

All five persisted findings had:

```text
capture_id = ab7434b2-90ca-4476-8b7b-2b49cbfa4d34
session_id = NULL
```

Their evidence strings were aggregate text such as `Detected in 4 sessions` or `Detected in 0 sessions`; they did not contain a persisted session foreign-key relationship.

The finding rows were:

1. Unencrypted Email Communication (Plaintext) — CRITICAL
2. Expired Certificate — HIGH
3. Weak Public Key Size — HIGH
4. STARTTLS Negotiation Rejected (Potential Downgrade) — HIGH
5. No Forward Secrecy — MEDIUM

The five rows are aggregate top contributors, not the 11 raw per-session findings returned by the rule engine.

## 6. API responses

For the original capture ID, the live API returned:

```http
GET /captures/{id}
200
```

The response included:

```json
{
  "packet_count": 0,
  "stream_count": 27,
  "email_session_count": 0,
  "tls_session_count": 0,
  "posture_score": 0.0,
  "findings_count": 5,
  "sessions_count": 0,
  "certificates_count": 0,
  "ml_anomalies_detected": 0
}
```

```http
GET /captures/{id}/sessions
200
[]
```

```http
GET /sessions?capture_id={id}
200
[]
```

```http
GET /findings?capture_id={id}
200
```

Returned the five aggregate finding records listed above, all with `session_id: null`.

```http
GET /anomalies?capture_id={id}
200
[]
```

```http
GET /certificates?capture_id={id}
200
[]
```

```http
GET /captures/{id}/posture
500
Internal Server Error
```

The posture route returns only a small subset of the fields required by the `PostureResponse` schema, so response validation fails. The frontend currently does not use this route; it reads posture from `GET /captures/{id}`.

The requested `/api/v1/...` paths are not mounted in the current application. For example:

```http
GET /api/v1/captures/{id}
404
```

The actual routes are rooted at `/captures`, `/sessions`, `/findings`, `/certificates`, and `/anomalies`.

## 7. Frontend request trace

The frontend receives empty arrays from the API; it is not discarding populated records.

| Page | Source call | Request filter | Actual response | Rendering result |
|---|---|---|---|---|
| Overview | `getCapture(id)` | capture ID in path | capture with zero counters and score 0 | Displays zeros |
| Overview | `getFindings({capture_id:id})` | `capture_id` query parameter | five finding rows | Displays five findings |
| Overview | `getAnomalies({capture_id:id})` | `capture_id` query parameter | `[]` | Displays anomaly count 0 |
| Sessions | `getCaptureSessions(id)` | capture ID in path | `[]` | “No sessions detected in capture.” |
| Certificates | `getCertificates({capture_id:id})` | `capture_id` query parameter | `[]` | “No certificates observed in capture.” |
| Anomalies | `getAnomalies({capture_id:id})` | `capture_id` query parameter | `[]` | “No ML anomalies flagged in this capture.” |

Relevant frontend files:

- [frontend/src/pages/OverviewPage.tsx](../../frontend/src/pages/OverviewPage.tsx)
- [frontend/src/pages/SessionsPage.tsx](../../frontend/src/pages/SessionsPage.tsx)
- [frontend/src/pages/CertificatesPage.tsx](../../frontend/src/pages/CertificatesPage.tsx)
- [frontend/src/pages/AnomaliesPage.tsx](../../frontend/src/pages/AnomaliesPage.tsx)
- [frontend/src/lib/api.ts](../../frontend/src/lib/api.ts)

The frontend state and filtering logic are consistent with the API responses. The data has already been lost before rendering.

## 8. Exact data-loss points

### Point 1: capture counter metadata contract mismatch

In [AnalysisService._process_analysis_results](../../backend/securemailscope/api/services/analyzers.py), the service assigns:

```python
capture.packet_count = metadata.get("packet_count", 0)
capture.email_session_count = metadata.get("email_session_count", 0)
capture.tls_session_count = metadata.get("tls_session_count", 0)
```

The orchestrator does not provide those keys. It provides `total_packets`, `reconstructed_streams`, and posture totals. Consequently:

```text
packet_count        becomes 0
email_session_count becomes 0
tls_session_count   becomes 0
```

`stream_count` is nonzero because `reconstructed_streams` is explicitly added and read separately.

### Point 2: no session persistence

The analysis service has no implementation that converts reconstructed streams into `SessionDB` rows. The database model exists, and the API query routes exist, but no rows are inserted.

### Point 3: no certificate persistence

[AnalysisService._store_certificates](../../backend/securemailscope/api/services/analyzers.py) contains only a comment and `pass`. The three certificates extracted by the orchestrator are not persisted.

### Point 4: no anomaly persistence

[AnalysisService._store_anomalies](../../backend/securemailscope/api/services/analyzers.py) contains only a comment and `pass`. M11 output cannot reach the `anomalies` table.

### Point 5: findings are detached aggregate projections

[_store_findings](../../backend/securemailscope/api/services/analyzers.py) iterates over `posture_score.top_contributors`, rather than the raw `FindingResult` objects. It creates five aggregate rows with `session_id=None`. This is why findings appear while the evidence-bearing session and certificate inventories are empty.

## 9. Finding/session consistency

The consistency requirement is not satisfied in the persisted/API representation.

Examples:

- **Expired Certificate** is displayed as a finding, but has `session_id: null` and there are zero certificate rows.
- **Weak Public Key Size** is displayed as a finding, but has no persisted certificate or TLS session reference.
- **No Forward Secrecy** is displayed as a finding, but has no persisted session reference.
- **STARTTLS Negotiation Rejected** is displayed as a finding, but has no persisted session reference.

The direct rule engine did have session-scoped evidence before persistence. The inconsistency is introduced by the API service's aggregate-only finding persistence.

## 10. PCAP validity and parser assessment

Independent command-line tools such as `tshark`, `capinfos`, `dumpcap`, and Wireshark were not installed in the environment.

The repository's independent `dpkt` ingestion path successfully parsed the uploaded capture:

```text
175 total packets
175 valid IP packets
0 malformed packets
0 ignored non-IP packets
27 TCP streams
```

The same parser and orchestrator successfully handled the repository's validated fixtures:

| Fixture | Direct protocol sessions | Direct TLS sessions | Direct certificates | Direct findings |
|---|---:|---:|---:|---:|
| `smtp_starttls_tls13_secure.pcap` | 1 | 1 | 1 | 1 |
| `smtp_weak_deprecated.pcap` | 1 | 1 | 1 | 5 |
| `smtp_starttls_downgrade.pcap` | 1 | 0 | 0 | 2 |
| `imap_starttls_tls12.pcap` | 1 | 1 | 1 | 1 |
| `pop3_starttls_rejected.pcap` | 1 | 0 | 0 | 2 |
| `layer_b_smtp_tls12_weak.pcap` | 1 | 1 | 1 | 4 |
| `layer_b_smtp_tls13_secure.pcap` | 1 | 1 | 1 | 1 |
| `layer_b_imap_tls12_segmented.pcap` | 1 | 1 | 1 | 1 |

These results show that the parser and direct analysis path are capable of producing the expected session/certificate evidence. API uploads of the known fixtures also persisted zero sessions, zero certificates, and zero anomalies while persisting their findings, confirming an application integration defect independent of the rich PCAP.

## 11. Why the Overview shows 0/100

The direct orchestrator also calculated a posture score of `0.0 / 100` for the rich capture from 11 actual findings across seven email sessions. The score is therefore not caused by the API's zero session counters.

The API persisted that score correctly:

```text
posture_score = 0.0
posture_status = Critical
```

The five UI findings are an incomplete aggregate projection of the 11 raw findings. The zero score is consistent with the scoring engine's severity impacts for the rich capture, while the zero TLS/session/certificate counters are incorrect persisted metadata/inventory values.

So the contradiction is a combination of:

1. **Legitimate score:** calculated from real direct findings.
2. **Incorrect capture counters:** caused by metadata key mismatch.
3. **Empty inventory pages:** caused by unimplemented persistence.
4. **Five instead of 11 findings:** caused by storing only top contributors.
5. **Zero API anomalies:** caused by unimplemented anomaly persistence; a current direct run can train M11 on the three TLS sessions.

## 12. Classification

| Area | Classification | Evidence |
|---|---|---|
| PCAP | Not the primary fault | 175/175 packets parsed; direct analysis produces sessions/TLS/certificates |
| Ingestion | Working for this capture | `dpkt` reports no malformed or ignored packets |
| TCP reconstruction | Working for this capture | 27 streams reconstructed |
| Protocol detector | Working for recognized streams | 7 email protocol sessions detected |
| TLS parser | Working for three TLS streams | ClientHello/ServerHello/cipher/certificate data observed |
| Orchestrator | Produces the evidence but exposes limited metadata | Direct run returns posture totals and reconstructed stream count; no persisted session collection |
| Database schema | Tables/models exist | `sessions`, `certificates`, and `anomalies` tables are present |
| Persistence service | Primary defect | Sessions are never inserted; certificate/anomaly methods are `pass`; findings are aggregate-only |
| API query routes | Query the correct capture IDs | Empty arrays reflect empty tables; findings correctly filter by capture ID |
| API posture route | Separate defect | Returns 500 because response fields do not satisfy `PostureResponse` |
| Frontend | Downstream symptom, not data-loss point | Pages display the API's actual empty arrays |
| ML | Downstream persistence symptom | Three TLS sessions are available directly; API stores no anomaly rows |
| Scoring | Score itself is explainable | Direct and persisted score are 0 for the rich capture's real findings |

## 13. Recommended fix (not implemented)

No fix was applied during this audit. The implementation work should be treated as a separate, explicitly approved task.

The required repair sequence is:

1. Define a typed result contract from the orchestrator that includes reconstructed session records, TLS data, certificates, raw findings, and anomaly results, not only posture and generic metadata.
2. Persist one `SessionDB` row per recognized email stream with the same `capture_id`.
3. Persist certificates with the originating `capture_id` and `session_id`.
4. Persist raw findings with valid session IDs and create `SessionFindingDB` relationships.
5. Persist all M11 results with the same `capture_id` and session ID.
6. Map `total_packets`, protocol-session count, and TLS-session count to the capture counters explicitly rather than relying on missing metadata keys.
7. Decide whether the API should expose raw findings or intentionally documented aggregate findings; do not silently replace one with the other.
8. Correct the posture response contract so `/captures/{id}/posture` either returns the complete schema or uses a smaller matching schema.
9. Add integration assertions that compare direct orchestrator counts with persisted/API counts for secure, weak, STARTTLS-rejected, IMAP, POP3, and multi-session captures.

## Final answer to the priority question

SecureMailScope can show five findings alongside zero TLS handshakes, zero sessions, zero certificates, and zero ML anomalies because the current API service persists only aggregate top-contributor findings and capture posture. It does not persist the underlying sessions, certificates, or M11 results, and it reads nonexistent metadata keys for the capture counters. The direct orchestrator has already detected the underlying evidence; the evidence is lost at the API persistence/metadata-mapping boundary.
