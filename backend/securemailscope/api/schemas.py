"""
Pydantic schemas for API request/response models.
Separation between internal models and API-exposed models.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# Enums
class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class PostureStatus(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnomalyLevel(str, Enum):
    NORMAL = "normal"
    MILD = "mild"
    MODERATE = "moderate"
    SEVERE = "severe"


# Request Models
class AnalyzeUploadRequest(BaseModel):
    """Request model for PCAP upload."""
    pass  # File upload handled separately


# Response Models - Base
class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""
    created_at: Optional[datetime] = None
    upload_timestamp: Optional[datetime] = None
    analysis_timestamp: Optional[datetime] = None
    timestamp: Optional[datetime] = None


# Response Models - Capture
class CaptureSummary(BaseModel):
    """Summary of a capture for listing."""
    capture_id: str
    filename: str
    file_hash: str
    upload_timestamp: datetime
    analysis_status: str
    packet_count: int
    stream_count: int
    email_session_count: int
    tls_session_count: int
    posture_score: Optional[float]
    posture_status: Optional[str]
    findings_count: int = 0
    anomalies_count: int = 0


class CaptureDetail(BaseModel):
    """Detailed capture information."""
    capture_id: str
    filename: str
    file_hash: str
    file_size: int
    upload_timestamp: datetime
    analysis_status: str
    analysis_timestamp: Optional[datetime]
    packet_count: int
    stream_count: int
    email_session_count: int
    tls_session_count: int
    posture_score: Optional[float]
    posture_status: Optional[str]
    scoring_policy_version: Optional[str]
    ml_engine_version: Optional[str]
    ml_anomalies_detected: int
    findings_count: int = 0
    sessions_count: int = 0
    certificates_count: int = 0


# Response Models - Session
class SessionSummary(BaseModel):
    """Summary of a TLS session."""
    session_id: str
    protocol: str
    source_ip: Optional[str]
    source_port: Optional[int]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    start_timestamp: Optional[datetime]
    end_timestamp: Optional[datetime]
    packet_count: int
    byte_count: int
    starttls_state: Optional[str]
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    has_forward_secrecy: bool
    has_findings: bool
    has_anomaly: bool
    anomaly_level: Optional[str]


class SessionDetail(SessionSummary):
    """Detailed session information."""
    key_exchange: Optional[str]
    handshake_complete: bool
    anomaly_score: Optional[float]
    findings: List[str] = []  # Finding IDs
    certificates: List[str] = []  # Certificate fingerprints


# Response Models - Finding
class FindingSummary(BaseModel):
    """Summary of a security finding."""
    finding_id: str
    rule_id: str
    title: str
    severity: str
    category: str
    session_id: Optional[str]
    confidence: float


class FindingDetail(FindingSummary):
    """Detailed finding information."""
    risk_contribution: float
    explanation: Optional[str]
    recommendation: Optional[str]
    evidence: Optional[str]
    timestamp: datetime
    affected_sessions: List[str] = []


# Response Models - Certificate
class CertificateSummary(BaseModel):
    """Summary of a certificate."""
    fingerprint_sha256: str
    subject: str
    issuer: str
    is_expired: bool
    is_self_signed: bool
    public_key_algorithm: str
    public_key_size_bits: Optional[int]


class CertificateDetail(CertificateSummary):
    """Detailed certificate information."""
    serial_number: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    signature_algorithm: Optional[str]
    san_list: List[str] = []
    weak_key: bool
    weak_signature: bool
    session_id: Optional[str]


# Response Models - Anomaly
class AnomalySummary(BaseModel):
    """Summary of an anomaly."""
    id: int
    session_id: str
    is_anomaly: bool
    anomaly_score: Optional[float]
    anomaly_level: str
    model_version: Optional[str]


class AnomalyDetail(AnomalySummary):
    """Detailed anomaly information."""
    capture_id: str
    explanation: Optional[str]
    features: Dict[str, float] = {}
    timestamp: datetime


# Response Models - Posture
class DimensionScore(BaseModel):
    """Score for a single dimension."""
    dimension: str
    score: float
    status: str
    coverage_percent: float
    evidence_quality: str
    sessions_affected: int
    findings_count: int


class TopContributor(BaseModel):
    """Top contributing finding."""
    rule_id: str
    title: str
    severity: str
    sessions_affected: int
    impact: float


class RootCauseGroup(BaseModel):
    """Root cause grouping of findings."""
    root_cause: str
    severity: str
    sessions_affected: int
    findings_count: int
    rule_ids: List[str]


class PostureResponse(BaseModel):
    """Posture score response."""
    overall_score: float
    status: str
    dimension_scores: List[DimensionScore]
    top_contributors: List[TopContributor]
    root_cause_groups: List[RootCauseGroup]
    scoring_policy_version: str
    analysis_timestamp: datetime
    total_sessions: int
    sessions_with_findings: int
    findings_count: int
    coverage_percent: float


# Response Models - Report
class ReportSummary(BaseModel):
    """Summary of a generated report."""
    report_id: str
    capture_id: str
    report_type: str
    file_size: int
    created_at: datetime


class ReportDetail(ReportSummary):
    """Detailed report information."""
    download_url: str


# Response Models - Analysis
class AnalysisResponse(BaseModel):
    """Response for analysis submission."""
    capture_id: str
    status: str
    message: str


class AnalysisJobStatus(BaseModel):
    """Status of an analysis job."""
    capture_id: str
    status: str
    posture_score: Optional[float]
    posture_status: Optional[str]
    progress_percent: int = 0


# Response Models - Health
class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    database_connected: bool


# Error Response
class ErrorDetail(BaseModel):
    """Detailed error information."""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: ErrorDetail