> **HISTORICAL DOCUMENT - SUPERSEDED (audit of 2026-09-26).** Written during earlier development
> milestones. Its claims were NOT verified and several are known to be wrong (see
> `FINAL_SECURITY_AUDIT.md`, `FUNCTIONAL_REGRESSION_MATRIX.md`). Kept for traceability only.

# Frontend functionality audit

## Findings

- Removed visible internal milestone labels from the sidebar, anomaly view, findings copy, and upload progress state.
- Mounted the existing capture header so capture selection and refresh controls are available.
- Finding, session, certificate, and anomaly rows now expose real API-backed detail panels as keyboard-accessible buttons.
- Detail panels support an accessible close button, Escape to close, and browser Back to close without leaving the current page.
- The upload drop zone now supports keyboard activation.
- Fixed unencoded finding/session/certificate IDs in detail API requests.
- Removed visible placeholder loopback addresses and stray literal newline text.
- Added actual available IDs, relationships, timing, transport, certificate, and ML metadata to detail panels.

## Validation

- [x] `npm run lint` (run from `frontend`; two pre-existing `CaptureContext.tsx` warnings)
- [x] `npm run build` (run from `frontend`)
- [x] Manual API-backed checks with the rich capture loaded: finding, session, and certificate rows opened; finding Escape close verified.

## Final audit

- Dead/broken interactions found: 2 primary classes (row detail handlers and unencoded detail IDs), plus visible internal labels.
- Fixed: all identified classes.
- Routes verified: `/`, `/findings`, `/sessions`, `/certificates`, `/anomalies`, `/upload`.
- Detail views verified: findings, sessions, certificates; anomaly implementation is API-backed and uses the same open/close/Escape mechanism.
- Frontend tests: no test script is defined in `frontend/package.json`.
- Backend regression: 220 tests passed.
- Build: passed.
