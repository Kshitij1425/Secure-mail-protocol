"""
FastAPI application for SecureMailScope API.
Main entry point for the REST API server.
"""
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional, List
import logging
import os

from securemailscope.api.config import get_settings, Settings
from securemailscope.api.database import get_db, init_db, CaptureDB, SessionDB, FindingDB, CertificateDB, AnomalyDB, ReportDB
from securemailscope.api.schemas import (
    AnalyzeUploadRequest,
    CaptureSummary,
    CaptureDetail,
    SessionSummary,
    SessionDetail,
    FindingSummary,
    FindingDetail,
    CertificateSummary,
    CertificateDetail,
    AnomalySummary,
    AnomalyDetail,
    PostureResponse,
    ReportSummary,
    AnalysisResponse,
    AnalysisJobStatus,
    HealthResponse,
    ErrorResponse,
    ErrorDetail
)
from securemailscope.api.services.analyzers import AnalysisService
import orjson

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="SecureMailScope API",
    description="REST API for SecureMailScope TLS security analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global service instance
analysis_service = AnalysisService()


@app.on_event("startup")
def startup_event():
    """Initialize database and create necessary directories on startup."""
    init_db()
    settings = get_settings()

    # Create directories
    os.makedirs(settings.upload_dir, exist_ok=True)
    os.makedirs(settings.reports_dir, exist_ok=True)


@app.get("/", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    settings = get_settings()

    # Check database connection
    try:
        db = next(get_db())
        db.execute(text("SELECT 1"))
        database_connected = True
    except:
        database_connected = False

    return HealthResponse(
        status="healthy",
        version=settings.api_version,
        database_connected=database_connected
    )


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_capture(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Analyze a PCAP/PCAPNG file.

    Accepts a PCAP file and submits it for analysis.
    Runs synchronously for small files, asynchronously for large files.
    """
    # Validate file type
    settings = get_settings()
    allowed_extensions = {ext.lower() for ext in settings.allowed_extensions}
    file_extension = file.filename.lower().split('.')[-1] if '.' in file.filename else ''

    if not file_extension or f".{file_extension}" not in allowed_extensions:
        raise HTTPException(
            status_code=422,
            detail=f"File type {file_extension} not allowed. "
                   f"Allowed types: {', '.join(settings.allowed_extensions)}"
        )

    # Validate file size (peek without draining stream)
    # Using SpooledTemporaryFile to get file size, or read completely then reset
    # We must read completely to know the true size if it's spooled.
    content = await file.read()
    file_size = len(content)
    await file.seek(0)

    if file_size > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.max_upload_size_mb} MB"
        )

    # Save file and create capture record
    if file_size == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty"
        )

    # Save capture and start analysis
    try:
        capture, file_path = analysis_service.save_capture(file, db)

        # Re-check actual file size after save for background-task threshold
        file_size = file_path.stat().st_size
        if file_size > 50 * 1024 * 1024:  # 50MB
            background_tasks.add_task(
                analysis_service.run_analysis,
                capture,
                file_path,
                db
            )
            status = "processing"
            message = "Analysis started in background"
        else:
            # Run synchronously for small files
            capture = analysis_service.run_analysis(capture, file_path, db)
            status = "completed"
            message = "Analysis completed"

        return AnalysisResponse(
            capture_id=capture.capture_id,
            status=status,
            message=message
        )

    except Exception as e:
        logger.error(f"Error processing capture: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/captures", response_model=List[CaptureSummary])
async def list_captures(
    db: Session = Depends(get_db),
    status: Optional[str] = None
):
    """
    List all captures.

    Can optionally filter by analysis status.
    """
    query = db.query(CaptureDB)

    if status:
        query = query.filter(CaptureDB.analysis_status == status)

    captures = query.order_by(CaptureDB.upload_timestamp.desc()).all()

    # Convert to summary models
    summaries = []
    for capture in captures:
        summary = CaptureSummary(
            capture_id=capture.capture_id,
            filename=capture.filename,
            file_hash=capture.file_hash,
            upload_timestamp=capture.upload_timestamp,
            analysis_status=capture.analysis_status,
            packet_count=capture.packet_count,
            stream_count=capture.stream_count,
            email_session_count=capture.email_session_count,
            tls_session_count=capture.tls_session_count,
            posture_score=capture.posture_score,
            posture_status=capture.posture_status,
            findings_count=db.query(FindingDB).filter(FindingDB.capture_id == capture.capture_id).count(),
            anomalies_count=db.query(AnomalyDB).filter(AnomalyDB.capture_id == capture.capture_id).count()
        )
        summaries.append(summary)

    return summaries


@app.get("/captures/{capture_id}", response_model=CaptureDetail)
async def get_capture(
    capture_id: str,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific capture."""
    capture = db.query(CaptureDB).filter(CaptureDB.capture_id == capture_id).first()

    if not capture:
        raise HTTPException(
            status_code=404,
            detail="Capture not found"
        )

    return CaptureDetail(
        capture_id=capture.capture_id,
        filename=capture.filename,
        file_hash=capture.file_hash,
        file_size=capture.file_size,
        upload_timestamp=capture.upload_timestamp,
        analysis_status=capture.analysis_status,
        analysis_timestamp=capture.analysis_timestamp,
        packet_count=capture.packet_count,
        stream_count=capture.stream_count,
        email_session_count=capture.email_session_count,
        tls_session_count=capture.tls_session_count,
        posture_score=capture.posture_score,
        posture_status=capture.posture_status,
        scoring_policy_version=capture.scoring_policy_version,
        ml_engine_version=capture.ml_engine_version,
        ml_anomalies_detected=capture.ml_anomalies_detected,
        findings_count=db.query(FindingDB).filter(FindingDB.capture_id == capture.capture_id).count(),
        sessions_count=db.query(SessionDB).filter(SessionDB.capture_id == capture.capture_id).count(),
        certificates_count=db.query(CertificateDB).filter(CertificateDB.capture_id == capture.capture_id).count()
    )


@app.get("/captures/{capture_id}/sessions", response_model=List[SessionSummary])
async def list_capture_sessions(
    capture_id: str,
    db: Session = Depends(get_db)
):
    """List all sessions for a capture."""
    sessions = db.query(SessionDB).filter(SessionDB.capture_id == capture_id).all()

    return sessions


@app.get("/captures/{capture_id}/findings", response_model=List[FindingSummary])
async def list_capture_findings(
    capture_id: str,
    db: Session = Depends(get_db)
):
    """List all findings for a capture."""
    findings = db.query(FindingDB).filter(FindingDB.capture_id == capture_id).all()

    return findings


@app.get("/captures/{capture_id}/anomalies", response_model=List[AnomalySummary])
async def list_capture_anomalies(
    capture_id: str,
    db: Session = Depends(get_db)
):
    """List all anomalies for a capture."""
    anomalies = db.query(AnomalyDB).filter(AnomalyDB.capture_id == capture_id).all()

    return anomalies


@app.get("/captures/{capture_id}/posture", response_model=PostureResponse)
async def get_capture_posture(
    capture_id: str,
    db: Session = Depends(get_db)
):
    """Get posture analysis for a capture from persisted analysis."""
    capture = db.query(CaptureDB).filter(CaptureDB.capture_id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    if capture.posture_score is None:
        raise HTTPException(status_code=404, detail="Posture not yet computed")
    return PostureResponse(
        capture_id=capture_id,
        posture_score=capture.posture_score,
        posture_status=capture.posture_status,
        scoring_policy_version=capture.scoring_policy_version,
        analysis_timestamp=capture.analysis_timestamp
    )


@app.get("/sessions", response_model=List[SessionSummary])
async def list_sessions(
    db: Session = Depends(get_db),
    capture_id: Optional[str] = None,
    protocol: Optional[str] = None
):
    """List all sessions with optional filtering."""
    query = db.query(SessionDB)

    if capture_id:
        query = query.filter(SessionDB.capture_id == capture_id)

    if protocol:
        query = query.filter(SessionDB.protocol == protocol)

    sessions = query.order_by(SessionDB.start_timestamp.desc()).all()

    return sessions


@app.get("/sessions/{session_id}", response_model=SessionDetail)
async def get_session(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific session."""
    session = db.query(SessionDB).filter(SessionDB.session_id == session_id).first()

    if not session:
        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )

    return SessionDetail(
        session_id=session.session_id,
        protocol=session.protocol,
        source_ip=session.source_ip,
        source_port=session.source_port,
        dest_ip=session.dest_ip,
        dest_port=session.dest_port,
        start_timestamp=session.start_timestamp,
        end_timestamp=session.end_timestamp,
        packet_count=session.packet_count,
        byte_count=session.byte_count,
        starttls_state=session.starttls_state,
        tls_version=session.tls_version,
        cipher_suite=session.cipher_suite,
        key_exchange=session.key_exchange,
        has_forward_secrecy=session.has_forward_secrecy,
        handshake_complete=session.handshake_complete,
        has_findings=session.has_findings,
        has_anomaly=session.has_anomaly,
        anomaly_score=session.anomaly_score,
        anomaly_level=session.anomaly_level
    )


@app.get("/findings", response_model=List[FindingSummary])
async def list_findings(
    db: Session = Depends(get_db),
    capture_id: Optional[str] = None,
    severity: Optional[str] = None
):
    """List all findings with optional filtering."""
    query = db.query(FindingDB)

    if capture_id:
        query = query.filter(FindingDB.capture_id == capture_id)

    if severity:
        query = query.filter(FindingDB.severity == severity)

    findings = query.order_by(FindingDB.timestamp.desc()).all()

    return findings


@app.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: str,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific finding."""
    finding = db.query(FindingDB).filter(FindingDB.finding_id == finding_id).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return FindingDetail(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        session_id=finding.session_id,
        confidence=finding.confidence,
        risk_contribution=finding.risk_contribution,
        explanation=finding.explanation,
        recommendation=finding.recommendation,
        evidence=finding.evidence,
        timestamp=finding.timestamp,
        affected_sessions=[]  # Would need to join with session_findings table
    )


@app.get("/anomalies", response_model=List[AnomalySummary])
async def list_anomalies(
    db: Session = Depends(get_db),
    capture_id: Optional[str] = None,
    is_anomaly: Optional[bool] = None
):
    """List all anomalies with optional filtering."""
    query = db.query(AnomalyDB)

    if capture_id:
        query = query.filter(AnomalyDB.capture_id == capture_id)

    if is_anomaly is not None:
        query = query.filter(AnomalyDB.is_anomaly == is_anomaly)

    anomalies = query.order_by(AnomalyDB.timestamp.desc()).all()

    return anomalies


@app.get("/anomalies/{anomaly_id}", response_model=AnomalyDetail)
async def get_anomaly(
    anomaly_id: int,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific anomaly."""
    anomaly = db.query(AnomalyDB).filter(AnomalyDB.id == anomaly_id).first()

    if not anomaly:
        raise HTTPException(
            status_code=404,
            detail="Anomaly not found"
        )

    # Parse features_json if present
    features = {}
    if anomaly.features_json:
        try:
            features = orjson.loads(anomaly.features_json)
        except:
            pass

    return AnomalyDetail(
        id=anomaly.id,
        capture_id=anomaly.capture_id,
        session_id=anomaly.session_id,
        is_anomaly=anomaly.is_anomaly,
        anomaly_score=anomaly.anomaly_score,
        anomaly_level=anomaly.anomaly_level,
        model_version=anomaly.model_version,
        explanation=anomaly.explanation,
        features=features,
        timestamp=anomaly.timestamp
    )


@app.get("/certificates", response_model=List[CertificateSummary])
async def list_certificates(
    db: Session = Depends(get_db),
    capture_id: Optional[str] = None,
    session_id: Optional[str] = None
):
    """List all certificates with optional filtering."""
    query = db.query(CertificateDB)

    if capture_id:
        query = query.filter(CertificateDB.capture_id == capture_id)

    if session_id:
        query = query.filter(CertificateDB.session_id == session_id)

    certificates = query.order_by(CertificateDB.not_after.desc()).all()

    return certificates


@app.get("/certificates/{fingerprint}", response_model=CertificateDetail)
async def get_certificate(
    fingerprint: str,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific certificate."""
    certificate = db.query(CertificateDB).filter(CertificateDB.fingerprint_sha256 == fingerprint).first()

    if not certificate:
        raise HTTPException(
            status_code=404,
            detail="Certificate not found"
        )

    return CertificateDetail(
        fingerprint_sha256=certificate.fingerprint_sha256,
        subject=certificate.subject,
        issuer=certificate.issuer,
        serial_number=certificate.serial_number,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        is_expired=certificate.is_expired,
        is_self_signed=certificate.is_self_signed,
        public_key_algorithm=certificate.public_key_algorithm,
        public_key_size_bits=certificate.public_key_size_bits,
        signature_algorithm=certificate.signature_algorithm,
        san_list=orjson.loads(certificate.san_list) if certificate.san_list else [],
        weak_key=certificate.weak_key,
        weak_signature=certificate.weak_signature,
        session_id=certificate.session_id
    )


@app.get("/reports", response_model=List[ReportSummary])
async def list_reports(
    db: Session = Depends(get_db),
    capture_id: Optional[str] = None
):
    """List all generated reports."""
    query = db.query(ReportDB)

    if capture_id:
        query = query.filter(ReportDB.capture_id == capture_id)

    reports = query.order_by(ReportDB.created_at.desc()).all()

    return reports


@app.get("/reports/{report_id}", response_model=ReportSummary)
async def get_report(
    report_id: str,
    db: Session = Depends(get_db)
):
    """Get report metadata."""
    report = db.query(ReportDB).filter(ReportDB.report_id == report_id).first()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    return ReportSummary(
        report_id=report.report_id,
        capture_id=report.capture_id,
        report_type=report.report_type,
        file_size=report.file_size,
        created_at=report.created_at
    )


@app.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    db: Session = Depends(get_db)
):
    """Download a generated report file."""
    report = db.query(ReportDB).filter(ReportDB.report_id == report_id).first()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    if not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=404,
            detail="Report file not found"
        )

    return FileResponse(
        path=report.file_path,
        filename=os.path.basename(report.file_path),
        media_type="application/octet-stream"
    )


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content=ErrorResponse(
            error=ErrorDetail(
                code="NOT_FOUND",
                message="Resource not found"
            )
        ).dict()
    )


@app.exception_handler(422)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error=ErrorDetail(
                code="VALIDATION_ERROR",
                message="Request validation failed"
            )
        ).dict()
    )


@app.exception_handler(413)
async def file_too_large_handler(request, exc):
    return JSONResponse(
        status_code=413,
        content=ErrorResponse(
            error=ErrorDetail(
                code="FILE_TOO_LARGE",
                message="File too large"
            )
        ).dict()
    )


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()

    uvicorn.run(
        "securemailscope.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=True
    )
