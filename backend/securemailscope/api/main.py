"""
FastAPI application for SecureMailScope.

All handlers are synchronous (``def``) so FastAPI runs them in its worker thread
pool: CPU-bound analysis never blocks the event loop.
"""
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from securemailscope import __version__
from securemailscope.api.config import get_settings
from securemailscope.api.database import (AnnotationDB, AnomalyDB, CaptureDB, CertificateDB, FindingDB, ReportDB, SessionDB,
                                          SessionFindingDB, get_db, init_db)
from securemailscope.api.schemas import (AnalysisResponse, AnomalyDetail, AnomalySummary, CaptureDetail,
                                         CaptureSummary, CertificateDetail, CertificateSummary, FindingDetail,
                                         FindingStatusUpdate, FindingSummary, HealthResponse, PostureResponse,
                                         ReportSummary, SessionDetail, SessionSummary)
from securemailscope.api.services.analyzers import (AnalysisService, ServiceError, annotation_target_label,
                                                     evidence_chain)
from securemailscope.api.schemas import AnnotationCreate, AnnotationOut, AnnotationUpdate, TrendPoint
from securemailscope.policy import PROFILES
from securemailscope.reports.render import safe_report_basename
from securemailscope.rules.engine import RULE_GUIDANCE

logger = logging.getLogger("securemailscope.api")
FINDING_STATUSES = {"open", "acknowledged", "in_progress", "resolved", "false_positive"}
MAX_PAGE = 5000


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    os.makedirs(settings.upload_dir, exist_ok=True)
    os.makedirs(settings.reports_dir, exist_ok=True)
    init_db()
    yield


app = FastAPI(title="SecureMailScope API", description="Passive email TLS posture analysis of PCAP captures",
              version=__version__, lifespan=lifespan)


class BodySizeLimitMiddleware:
    """Reject request bodies above the upload cap while they stream in, before the
    multipart parser spools them to disk (covers chunked uploads without Content-Length)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        limit = get_settings().max_upload_size_bytes + 64 * 1024  # multipart framing overhead
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        return await _too_large(send)
                except ValueError:
                    return await _too_large(send)
        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _too_large(send)


class _BodyTooLarge(Exception):
    pass


async def _too_large(send):
    body = json.dumps({"error": {"code": "FILE_TOO_LARGE", "message": "File too large"},
                       "detail": "File too large"}).encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    if not request.url.path.startswith(("/docs", "/redoc")):
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return response


app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "Accept"])
app.add_middleware(BodySizeLimitMiddleware)

service = AnalysisService()
analysis_service = service  # backwards-compatible name


# -------------------------------------------------------------- error envelope
_CODES = {400: "BAD_REQUEST", 404: "NOT_FOUND", 409: "CONFLICT", 413: "FILE_TOO_LARGE", 422: "VALIDATION_ERROR",
          500: "INTERNAL_ERROR", 501: "NOT_IMPLEMENTED", 503: "SERVICE_UNAVAILABLE"}


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": _CODES.get(status, "ERROR"), "message": message},
                                                     "detail": message})


@app.exception_handler(StarletteHTTPException)
async def http_error(_request, exc: StarletteHTTPException):
    return _error(exc.status_code, str(exc.detail) if exc.detail else "Error")


@app.exception_handler(RequestValidationError)
async def validation_error(_request, exc: RequestValidationError):
    fields = sorted({".".join(str(p) for p in e.get("loc", [])[1:]) or "request" for e in exc.errors()})
    return _error(422, f"Invalid request parameter(s): {', '.join(fields)[:200]}")


@app.exception_handler(Exception)
async def unhandled_error(_request, exc: Exception):
    logger.exception("Unhandled API error")
    return _error(500, "Internal server error")


def _svc(e: ServiceError):
    raise HTTPException(status_code=e.status, detail=e.message)


# ---------------------------------------------------------------------- health
@app.get("/", response_model=HealthResponse)
@app.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        ok = True
    except Exception:
        ok = False
    return HealthResponse(status="healthy" if ok else "degraded", version=__version__, database_connected=ok)


# --------------------------------------------------------------------- analyze
@app.get("/policies")
def list_policies():
    """Available policy profiles with their thresholds and documented rationale."""
    return [p.to_dict() for p in PROFILES.values()]


def _check_policy(policy: str) -> str:
    if policy not in PROFILES:
        raise HTTPException(status_code=422, detail=f"Unknown policy profile. Available: {', '.join(PROFILES)}")
    return policy


@app.post("/analyze", response_model=AnalysisResponse)
def analyze_capture(file: UploadFile = File(...), policy: str = Form("balanced"), db: Session = Depends(get_db)):
    """Upload a PCAP/PCAPNG capture and run the full analysis pipeline synchronously."""
    _check_policy(policy)
    try:
        tmp, sha, size, fmt, display = service.receive_upload(file.file, file.filename)
        capture = service.create_capture(tmp, sha, size, fmt, display, db, policy_profile=policy)
        service.run_analysis(capture, db)
    except ServiceError as e:
        _svc(e)
    return AnalysisResponse(capture_id=capture.capture_id, status=capture.analysis_status, message="Analysis completed")


# -------------------------------------------------------------------- captures
def _capture_or_404(db: Session, capture_id: str) -> CaptureDB:
    c = db.query(CaptureDB).filter(CaptureDB.capture_id == capture_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Capture not found")
    return c


def _severity_counts(db, capture_id) -> dict:
    return {sev: n for sev, n in db.query(FindingDB.severity, func.count(FindingDB.id))
            .filter(FindingDB.capture_id == capture_id).group_by(FindingDB.severity)}


def _count(db, model, capture_id, *filters) -> int:
    return db.query(func.count(model.id)).filter(model.capture_id == capture_id, *filters).scalar() or 0


@app.get("/captures", response_model=List[CaptureSummary])
def list_captures(db: Session = Depends(get_db), status: Optional[str] = None,
                  limit: int = Query(500, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    q = db.query(CaptureDB)
    if status:
        q = q.filter(CaptureDB.analysis_status == status)
    out = []
    for c in q.order_by(CaptureDB.upload_timestamp.desc(), CaptureDB.id.desc()).offset(offset).limit(limit):
        s = CaptureSummary.model_validate(c)
        s.findings_count = _count(db, FindingDB, c.capture_id)
        s.anomalies_count = _count(db, AnomalyDB, c.capture_id, AnomalyDB.is_anomaly.is_(True))
        s.severity_counts = _severity_counts(db, c.capture_id)
        out.append(s)
    return out


@app.get("/captures/{capture_id}", response_model=CaptureDetail)
def get_capture(capture_id: str, db: Session = Depends(get_db)):
    c = _capture_or_404(db, capture_id)
    d = CaptureDetail.model_validate(c)
    d.findings_count = _count(db, FindingDB, capture_id)
    d.anomalies_count = _count(db, AnomalyDB, capture_id, AnomalyDB.is_anomaly.is_(True))
    d.sessions_count = _count(db, SessionDB, capture_id)
    d.certificates_count = _count(db, CertificateDB, capture_id)
    d.reports_count = _count(db, ReportDB, capture_id)
    d.severity_counts = _severity_counts(db, capture_id)
    meta = json.loads(c.metadata_json) if c.metadata_json else {}
    d.coverage = meta.get("coverage", {})
    d.ingestion = {k: meta.get(k) for k in ("total_packets", "valid_packets", "malformed_packets", "ignored_non_ip",
                                            "truncated", "truncation_reason", "link_type", "format")}
    return d


@app.get("/captures/{capture_id}/sessions", response_model=List[SessionSummary])
def list_capture_sessions(capture_id: str, db: Session = Depends(get_db),
                          limit: int = Query(MAX_PAGE, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    _capture_or_404(db, capture_id)
    return (db.query(SessionDB).filter(SessionDB.capture_id == capture_id)
            .order_by(SessionDB.start_timestamp, SessionDB.id).offset(offset).limit(limit).all())


@app.get("/captures/{capture_id}/findings", response_model=List[FindingSummary])
def list_capture_findings(capture_id: str, db: Session = Depends(get_db),
                          limit: int = Query(MAX_PAGE, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    _capture_or_404(db, capture_id)
    return (db.query(FindingDB).filter(FindingDB.capture_id == capture_id)
            .order_by(FindingDB.priority, FindingDB.id).offset(offset).limit(limit).all())


@app.get("/captures/{capture_id}/certificates", response_model=List[CertificateSummary])
def list_capture_certificates(capture_id: str, db: Session = Depends(get_db)):
    _capture_or_404(db, capture_id)
    return (db.query(CertificateDB).filter(CertificateDB.capture_id == capture_id)
            .order_by(CertificateDB.session_id, CertificateDB.chain_position).limit(MAX_PAGE).all())


@app.get("/captures/{capture_id}/anomalies", response_model=List[AnomalySummary])
def list_capture_anomalies(capture_id: str, db: Session = Depends(get_db)):
    _capture_or_404(db, capture_id)
    return (db.query(AnomalyDB).filter(AnomalyDB.capture_id == capture_id)
            .order_by(AnomalyDB.anomaly_score, AnomalyDB.id).limit(MAX_PAGE).all())


@app.get("/captures/{capture_id}/posture", response_model=PostureResponse)
def get_capture_posture(capture_id: str, db: Session = Depends(get_db)):
    """The posture computed by the scoring engine at analysis time (not re-derived)."""
    c = _capture_or_404(db, capture_id)
    if c.analysis_status != "completed" or not c.posture_json:
        raise HTTPException(status_code=404, detail="Posture not yet computed")
    p = json.loads(c.posture_json)
    doc = json.loads(c.document_json) if c.document_json else {}
    meta = p.get("metadata", {})
    cov = p.get("coverage", {})
    total = meta.get("total_sessions", 0)
    return PostureResponse(
        capture_id=capture_id, overall_score=p.get("overall_score"), status=p.get("status", "Unknown"),
        scoring_policy_version=p.get("scoring_policy_version", "unknown"), analysis_timestamp=c.analysis_timestamp,
        total_sessions=total, tls_sessions=meta.get("tls_sessions", 0),
        sessions_with_findings=meta.get("sessions_with_findings", 0), findings_count=meta.get("findings_count", 0),
        tls_coverage_percent=meta.get("tls_coverage_percent", 0.0),
        certificate_coverage_percent=meta.get("certificate_coverage_percent", 0.0),
        coverage_percent=round(100.0 * cov.get("tls_observed", 0) / total, 2) if total else 0.0,
        dimension_scores=p.get("dimensions", []), top_contributors=p.get("top_contributors", []),
        root_cause_groups=list((p.get("root_cause_groups") or {}).values()),
        remediation_plan=doc.get("remediation_plan", []),
    )


@app.get("/captures/{capture_id}/document")
def get_capture_document(capture_id: str, redact: bool = False, db: Session = Depends(get_db)):
    """The canonical analysis document, labelled RAW or REDACTED (identical to the JSON report)."""
    c = _capture_or_404(db, capture_id)
    if not c.document_json:
        raise HTTPException(status_code=404, detail="Analysis not available")
    return JSONResponse(service.document(c, redact))


@app.post("/captures/{capture_id}/reports", response_model=ReportSummary)
def create_report(capture_id: str, format: str = Query(..., pattern="^(json|html|pdf)$"), redact: bool = False,
                  db: Session = Depends(get_db)):
    c = _capture_or_404(db, capture_id)
    try:
        return service.generate_report(c, format, db, redact=redact)
    except ServiceError as e:
        _svc(e)


@app.post("/captures/{capture_id}/reanalyze", response_model=AnalysisResponse)
def reanalyze_capture(capture_id: str, policy: str = Query("balanced"), db: Session = Depends(get_db)):
    """Analyse the same stored capture again (e.g. under another policy profile) as a new analysis."""
    _check_policy(policy)
    src = _capture_or_404(db, capture_id)
    try:
        c = service.reanalyze(src, policy, db)
    except ServiceError as e:
        _svc(e)
    return AnalysisResponse(capture_id=c.capture_id, status=c.analysis_status, message=f"Re-analysed with policy {policy}")


def _doc(db, capture_id, redact=False):
    try:
        return service.document(_capture_or_404(db, capture_id), redact)
    except ServiceError as e:
        _svc(e)


@app.get("/captures/{capture_id}/timeline")
def get_timeline(capture_id: str, session_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Capture-time events (TCP, protocol, STARTTLS, TLS, certificate, findings) plus analysis-phase ML events."""
    tl = _doc(db, capture_id).get("timeline", [])
    return [e for e in tl if session_id is None or e.get("session_id") == session_id]


@app.get("/captures/{capture_id}/certificate-inventory")
def get_certificate_inventory(capture_id: str, db: Session = Depends(get_db)):
    return _doc(db, capture_id).get("certificate_inventory", [])


@app.get("/captures/{capture_id}/bundle")
def get_evidence_bundle(capture_id: str, redact: bool = False, db: Session = Depends(get_db)):
    """Deterministic ZIP evidence bundle (JSON + SHA-256 manifest). No packet payloads."""
    from securemailscope.reports.bundle import build_bundle
    c = _capture_or_404(db, capture_id)
    data = build_bundle(_raw_doc(c), redact=redact)
    name = f"{_download_stem(c, redact)}_evidence_{'redacted' if redact else 'raw'}.zip"
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/captures/{capture_id}/stix")
def get_stix(capture_id: str, redact: bool = False, db: Session = Depends(get_db)):
    """STIX 2.1 bundle of observations (no indicators; findings as notes)."""
    from securemailscope.reports.stix import build_stix_bundle
    c = _capture_or_404(db, capture_id)
    data = json.dumps(build_stix_bundle(_doc(db, capture_id, redact)), indent=2).encode()
    name = f"{_download_stem(c, redact)}_stix_{'redacted' if redact else 'raw'}.json"
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _download_stem(c, redact: bool) -> str:
    """Download file-name stem. Redacted outputs must not reveal the original file name."""
    if c is None:
        return "capture"
    if redact:
        return f"capture_{(c.file_hash or 'unknown')[:12]}"
    return safe_report_basename(c.filename)


# ------------------------------------------------------------------ analyst annotations
@app.get("/captures/{capture_id}/annotations", response_model=List[AnnotationOut])
def list_annotations(capture_id: str, target_type: Optional[str] = None, target_id: Optional[str] = None,
                     db: Session = Depends(get_db)):
    _capture_or_404(db, capture_id)
    q = db.query(AnnotationDB).filter(AnnotationDB.capture_id == capture_id)
    if target_type:
        q = q.filter(AnnotationDB.target_type == target_type)
    if target_id:
        q = q.filter(AnnotationDB.target_id == target_id)
    return q.order_by(AnnotationDB.created_at, AnnotationDB.id).limit(MAX_PAGE).all()


@app.post("/captures/{capture_id}/annotations", response_model=AnnotationOut, status_code=201)
def create_annotation(capture_id: str, body: AnnotationCreate, db: Session = Depends(get_db)):
    """Attach an analyst note / report selection. The target must exist in this analysis."""
    c = _capture_or_404(db, capture_id)
    doc = _raw_doc(c)
    if annotation_target_label(doc, body.target_type, body.target_id) is None:
        raise HTTPException(status_code=422, detail=f"{body.target_type} not found in this analysis")
    if not body.text.strip() and not body.include_in_report:
        raise HTTPException(status_code=422, detail="Provide a note or select the item for the report")
    row = AnnotationDB(capture_id=capture_id, target_type=body.target_type, target_id=body.target_id,
                       text=body.text.strip(), include_in_report=body.include_in_report)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _annotation_or_404(db: Session, annotation_id: int) -> AnnotationDB:
    a = db.get(AnnotationDB, annotation_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Annotation not found")
    return a


@app.patch("/annotations/{annotation_id}", response_model=AnnotationOut)
def update_annotation(annotation_id: int, body: AnnotationUpdate, db: Session = Depends(get_db)):
    a = _annotation_or_404(db, annotation_id)
    if body.text is not None:
        a.text = body.text.strip()
    if body.include_in_report is not None:
        a.include_in_report = body.include_in_report
    db.commit()
    db.refresh(a)
    return a


@app.delete("/annotations/{annotation_id}", status_code=204)
def delete_annotation(annotation_id: int, db: Session = Depends(get_db)):
    db.delete(_annotation_or_404(db, annotation_id))
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ posture trend
@app.get("/captures/{capture_id}/trend", response_model=List[TrendPoint])
def get_trend(capture_id: str, db: Session = Depends(get_db)):
    """Completed analyses that share at least one mail server (protocol, address, port) with this one,
    ordered by capture time. Association by shared server address only; not an identity claim."""
    _capture_or_404(db, capture_id)
    servers = {(s.protocol, s.dest_ip, s.dest_port) for s in
               db.query(SessionDB.protocol, SessionDB.dest_ip, SessionDB.dest_port).filter(SessionDB.capture_id == capture_id)}
    if not servers:
        return []
    rows = (db.query(SessionDB.capture_id, SessionDB.protocol, SessionDB.dest_ip, SessionDB.dest_port)
            .filter(SessionDB.dest_ip.in_({ip for _, ip, _ in servers})).distinct().all())
    shared = {}
    for cid, proto, ip, port in rows:
        if (proto, ip, port) in servers:
            shared.setdefault(cid, set()).add(f"{proto} {ip}:{port}")
    out = []
    for c in db.query(CaptureDB).filter(CaptureDB.capture_id.in_(shared), CaptureDB.analysis_status == "completed"):
        counts = _severity_counts(db, c.capture_id)
        out.append(TrendPoint(
            capture_id=c.capture_id, filename=c.filename, file_hash=c.file_hash, policy_profile=c.policy_profile,
            capture_start=c.capture_start.isoformat() if c.capture_start else None, analysis_timestamp=c.analysis_timestamp,
            posture_score=c.posture_score, posture_status=c.posture_status, findings_count=sum(counts.values()),
            severe_findings_count=counts.get("CRITICAL", 0) + counts.get("HIGH", 0),
            shared_servers=sorted(shared[c.capture_id]), is_selected=c.capture_id == capture_id))
    out.sort(key=lambda t: (t.capture_start or "", t.analysis_timestamp.isoformat() if t.analysis_timestamp else ""))
    return out


def _raw_doc(c):
    if c.analysis_status != "completed" or not c.document_json:
        raise HTTPException(status_code=409, detail="Analysis is not complete for this capture")
    return json.loads(c.document_json)


@app.get("/compare")
def compare_captures(a: str, b: str, db: Session = Depends(get_db)):
    """Differences between two stored analyses (A = baseline, B = later)."""
    from securemailscope.reports.compare import compare_documents
    if a == b:
        raise HTTPException(status_code=422, detail="Choose two different analyses to compare")
    return compare_documents(_raw_doc(_capture_or_404(db, a)), _raw_doc(_capture_or_404(db, b)))


# -------------------------------------------------------------------- sessions
@app.get("/sessions", response_model=List[SessionSummary])
def list_sessions(db: Session = Depends(get_db), capture_id: Optional[str] = None, protocol: Optional[str] = None,
                  limit: int = Query(1000, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    q = db.query(SessionDB)
    if capture_id:
        q = q.filter(SessionDB.capture_id == capture_id)
    if protocol:
        q = q.filter(SessionDB.protocol == protocol.upper())
    return q.order_by(SessionDB.start_timestamp.desc(), SessionDB.id).offset(offset).limit(limit).all()


@app.get("/sessions/{session_id}", response_model=SessionDetail)
def get_session(session_id: str, db: Session = Depends(get_db)):
    s = db.query(SessionDB).filter(SessionDB.session_id == session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    d = SessionDetail.model_validate(s)
    d.findings = [f for (f,) in db.query(SessionFindingDB.finding_id).filter(SessionFindingDB.session_id == session_id)]
    d.certificates = [c for (c,) in db.query(CertificateDB.certificate_id).filter(CertificateDB.session_id == session_id)
                      .order_by(CertificateDB.chain_position)]
    a = db.query(AnomalyDB.id).filter(AnomalyDB.session_id == session_id).first()
    d.anomaly_id = a[0] if a else None
    d.detail = json.loads(s.detail_json) if s.detail_json else {}
    return d


# -------------------------------------------------------------------- findings
@app.get("/findings", response_model=List[FindingSummary])
def list_findings(db: Session = Depends(get_db), capture_id: Optional[str] = None, severity: Optional[str] = None,
                  rule_id: Optional[str] = None, session_id: Optional[str] = None,
                  limit: int = Query(1000, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    q = db.query(FindingDB)
    if capture_id:
        q = q.filter(FindingDB.capture_id == capture_id)
    if severity:
        q = q.filter(FindingDB.severity == severity.upper())
    if rule_id:
        q = q.filter(FindingDB.rule_id == rule_id)
    if session_id:
        q = q.filter(FindingDB.session_id == session_id)
    return q.order_by(FindingDB.capture_id, FindingDB.priority, FindingDB.id).offset(offset).limit(limit).all()


def _finding_detail(db: Session, f: FindingDB) -> FindingDetail:
    d = FindingDetail.model_validate({**{k: getattr(f, k) for k in FindingSummary.model_fields},
                                      "explanation": f.explanation, "recommendation": f.recommendation,
                                      "references": f.references, "timestamp": f.timestamp})
    d.evidence = json.loads(f.evidence) if f.evidence else {}
    d.evidence_frames = json.loads(f.evidence_frames) if f.evidence_frames else []
    d.affected_sessions = [s for (s,) in db.query(SessionFindingDB.session_id)
                           .filter(SessionFindingDB.finding_id == f.finding_id)]
    d.why_it_matters = RULE_GUIDANCE.get(f.rule_id, {}).get("why")
    d.expected_effect = RULE_GUIDANCE.get(f.rule_id, {}).get("effect")
    return d


@app.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(FindingDB).filter(FindingDB.finding_id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_detail(db, f)


@app.get("/findings/{finding_id}/chain")
def get_finding_chain(finding_id: str, db: Session = Depends(get_db)):
    """Evidence chain: finding -> session -> TCP stream -> TLS -> certificate -> evidence -> recommendation."""
    f = db.query(FindingDB).filter(FindingDB.finding_id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    chain = evidence_chain(_raw_doc(_capture_or_404(db, f.capture_id)), finding_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="Finding not found in the stored analysis")
    chain["capture_id"] = f.capture_id
    chain["status"] = f.status
    return chain


@app.patch("/findings/{finding_id}/status", response_model=FindingDetail)
def update_finding_status(finding_id: str, body: FindingStatusUpdate, db: Session = Depends(get_db)):
    """Analyst triage state. Does not alter the finding's evidence, severity or the posture score."""
    if body.status not in FINDING_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(FINDING_STATUSES)}")
    f = db.query(FindingDB).filter(FindingDB.finding_id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = body.status
    db.commit()
    db.refresh(f)
    return _finding_detail(db, f)


# ------------------------------------------------------------------- anomalies
@app.get("/anomalies", response_model=List[AnomalySummary])
def list_anomalies(db: Session = Depends(get_db), capture_id: Optional[str] = None, is_anomaly: Optional[bool] = None,
                   limit: int = Query(1000, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    q = db.query(AnomalyDB)
    if capture_id:
        q = q.filter(AnomalyDB.capture_id == capture_id)
    if is_anomaly is not None:
        q = q.filter(AnomalyDB.is_anomaly.is_(is_anomaly))
    return q.order_by(AnomalyDB.capture_id, AnomalyDB.anomaly_score, AnomalyDB.id).offset(offset).limit(limit).all()


@app.get("/anomalies/{anomaly_id}", response_model=AnomalyDetail)
def get_anomaly(anomaly_id: int, db: Session = Depends(get_db)):
    a = db.query(AnomalyDB).filter(AnomalyDB.id == anomaly_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    d = AnomalyDetail.model_validate(a)
    try:
        d.features = json.loads(a.features_json) if a.features_json else {}
    except ValueError:
        d.features = {}
    return d


# ---------------------------------------------------------------- certificates
@app.get("/certificates", response_model=List[CertificateSummary])
def list_certificates(db: Session = Depends(get_db), capture_id: Optional[str] = None, session_id: Optional[str] = None,
                      limit: int = Query(1000, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0)):
    q = db.query(CertificateDB)
    if capture_id:
        q = q.filter(CertificateDB.capture_id == capture_id)
    if session_id:
        q = q.filter(CertificateDB.session_id == session_id)
    return q.order_by(CertificateDB.capture_id, CertificateDB.session_id, CertificateDB.chain_position) \
        .offset(offset).limit(limit).all()


@app.get("/certificates/{certificate_id}", response_model=CertificateDetail)
def get_certificate(certificate_id: str, db: Session = Depends(get_db)):
    c = db.query(CertificateDB).filter(CertificateDB.certificate_id == certificate_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Certificate not found")
    d = CertificateDetail.model_validate({**{k: getattr(c, k) for k in CertificateDetail.model_fields
                                            if k not in ("san_list", "seen_in_sessions")}})
    d.san_list = json.loads(c.san_list) if c.san_list else []
    d.seen_in_sessions = [s for (s,) in db.query(CertificateDB.session_id).filter(
        CertificateDB.capture_id == c.capture_id, CertificateDB.fingerprint_sha256 == c.fingerprint_sha256)]
    return d


# --------------------------------------------------------------------- reports
@app.get("/reports", response_model=List[ReportSummary])
def list_reports(db: Session = Depends(get_db), capture_id: Optional[str] = None):
    q = db.query(ReportDB)
    if capture_id:
        q = q.filter(ReportDB.capture_id == capture_id)
    return q.order_by(ReportDB.created_at.desc()).limit(MAX_PAGE).all()


@app.get("/reports/{report_id}", response_model=ReportSummary)
def get_report(report_id: str, db: Session = Depends(get_db)):
    r = db.query(ReportDB).filter(ReportDB.report_id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return r


@app.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    r = db.query(ReportDB).filter(ReportDB.report_id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    path = service.report_path(r)
    if path is None:
        raise HTTPException(status_code=404, detail="Report file not found")
    c = db.query(CaptureDB).filter(CaptureDB.capture_id == r.capture_id).first()
    name = f"{_download_stem(c, bool(r.redacted))}_report{'_redacted' if r.redacted else ''}.{r.report_type}"
    # Always download (attachment), never render in the API origin.
    media = {"json": "application/json", "html": "text/html", "pdf": "application/pdf"}.get(r.report_type,
                                                                                          "application/octet-stream")
    return FileResponse(path=str(path), filename=name, media_type=media,
                        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"})


if __name__ == "__main__":
    import uvicorn

    s = get_settings()
    uvicorn.run("securemailscope.api.main:app", host=s.host, port=s.port, reload=False)
