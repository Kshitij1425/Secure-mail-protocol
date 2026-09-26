> **HISTORICAL DOCUMENT - SUPERSEDED (audit of 2026-09-26).** Written during earlier development
> milestones. Its claims were NOT verified and several are known to be wrong (see
> `FINAL_SECURITY_AUDIT.md`, `FUNCTIONAL_REGRESSION_MATRIX.md`). Kept for traceability only.

# Integration Fix Report

## Root cause

The orchestrator returned a posture summary and metadata tuple, while the API
service persisted only aggregate posture contributors. It did not receive or
persist reconstructed email sessions, TLS data, certificates, raw findings, or
M11 results. In addition, capture counters were read using metadata keys that
the orchestrator did not produce. This left the database and API with zero
sessions, TLS sessions, certificates, and anomalies while findings remained.

## Files changed

- `backend/securemailscope/core/orchestrator.py`
  - Added the typed `OrchestratorResult` and session result contract while
    preserving legacy tuple unpacking.
- `backend/securemailscope/api/services/analyzers.py`
  - Persists sessions, TLS relationships, certificates, raw findings,
    session/finding links, anomalies, and typed capture counts.
  - Converts reconstructed packet IP bytes to API-safe address strings.
- `backend/securemailscope/api/main.py`
  - Returns a schema-complete posture response.
- `backend/tests/test_m12_api.py`
  - Added a real rich-PCAP upload/orchestrator/SQLite/API consistency test.
- `backend/tests/robustness/fixtures/pcaps/securemailscope_demo_rich_valid.pcap`
  - Repository fixture for the validated rich capture.

## Before and after counts

| Measure | Before | After |
|---|---:|---:|
| Packets | 0 | 175 |
| TCP streams | 27 | 27 |
| Email sessions | 0 | 7 |
| TLS sessions | 0 | 3 |
| Certificates | 0 | 3 |
| Raw findings | 5 aggregate contributors | 11 |
| M11 anomalies | 0 | 1 anomalous result |
| Posture score | 0.0 (persisted without underlying records) | Actual orchestrator score |

The integration test compares the direct orchestrator result with SQLite rows
and API responses for the same capture ID, including session IDs, certificate
fingerprints, finding links, and anomaly counts.

## Tests added

`test_api_rich_pcap_persists_pipeline_results_and_posture_schema` uploads the
real rich PCAP, runs the real M1-M11 pipeline, checks the API endpoints, and
checks the persisted SQLite rows. It asserts the validated counts:

- 175 packets
- 7 email sessions
- 3 TLS sessions
- 3 certificates
- 11 raw findings
- 1 anomaly

## Validation

- Targeted API/orchestrator suites: **19 passed**
- Full backend regression suite (`pytest tests/ -q`): **220 passed**
- Frontend behavior is unchanged; it now receives the persisted records through
  the existing capture-scoped endpoints.
