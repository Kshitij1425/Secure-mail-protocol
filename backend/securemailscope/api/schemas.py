"""
Pydantic response models. Every endpoint's response is validated against these,
so the documented schema and the actual payload cannot drift apart.
"""
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class HealthResponse(BaseModel):
    status: str
    version: str
    database_connected: bool


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
    detail: Optional[str] = None


class AnalysisResponse(BaseModel):
    capture_id: str
    status: str
    message: str


# ------------------------------------------------------------------ captures
class CaptureSummary(_ORM):
    capture_id: str
    filename: str
    file_hash: str
    upload_timestamp: Optional[datetime]
    analysis_status: str
    analysis_error: Optional[str] = None
    packet_count: int
    stream_count: int
    email_session_count: int
    tls_session_count: int
    posture_score: Optional[float]
    posture_status: Optional[str]
    policy_profile: Optional[str] = "balanced"
    capture_start: Optional[datetime] = None
    analysis_timestamp: Optional[datetime] = None
    findings_count: int = 0
    anomalies_count: int = 0
    severity_counts: Dict[str, int] = {}


class CaptureDetail(CaptureSummary):
    file_size: int
    file_format: Optional[str]
    analysis_duration_seconds: Optional[float]
    capture_end: Optional[datetime]
    scoring_policy_version: Optional[str]
    rule_policy_version: Optional[str]
    ml_engine_version: Optional[str]
    ml_status: Optional[str]
    ml_anomalies_detected: int
    sessions_count: int = 0
    certificates_count: int = 0
    reports_count: int = 0
    coverage: Dict[str, Any] = {}
    ingestion: Dict[str, Any] = {}


# ------------------------------------------------------------------ sessions
class SessionSummary(_ORM):
    session_id: str
    capture_id: str
    stream_id: str
    protocol: str
    source_ip: Optional[str]
    source_port: Optional[int]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    start_timestamp: Optional[datetime]
    end_timestamp: Optional[datetime]
    packet_count: int
    byte_count: int
    detection_method: Optional[str]
    implicit_tls: bool
    starttls_state: Optional[str]
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    has_forward_secrecy: Optional[bool]
    handshake_status: Optional[str]
    certificate_visibility: Optional[str]
    reconstruction_quality: Optional[str]
    has_findings: bool
    has_anomaly: bool
    anomaly_level: Optional[str]


class SessionDetail(SessionSummary):
    key_exchange: Optional[str]
    key_exchange_group: Optional[str]
    sni: Optional[str]
    client_hello_version: Optional[str]
    starttls_advertised: Optional[bool]
    handshake_complete: bool
    anomaly_score: Optional[float]
    first_frame: Optional[int]
    last_frame: Optional[int]
    findings: List[str] = []
    certificates: List[str] = []
    anomaly_id: Optional[int] = None
    detail: Dict[str, Any] = {}


# ------------------------------------------------------------------ findings
class FindingSummary(_ORM):
    finding_id: str
    capture_id: str
    rule_id: str
    title: str
    severity: str
    category: str
    dimension: Optional[str]
    evidence_type: Optional[str]
    session_id: Optional[str]
    confidence: float
    risk_contribution: float
    priority: Optional[int]
    status: str


class FindingDetail(FindingSummary):
    explanation: Optional[str]
    recommendation: Optional[str]
    references: Optional[str]
    evidence: Dict[str, Any] = {}
    evidence_frames: List[int] = []
    timestamp: Optional[datetime]
    affected_sessions: List[str] = []
    why_it_matters: Optional[str] = None
    expected_effect: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: str


# -------------------------------------------------------------- certificates
class CertificateSummary(_ORM):
    certificate_id: str
    capture_id: str
    session_id: str
    chain_position: int
    fingerprint_sha256: str
    subject: Optional[str]
    issuer: Optional[str]
    common_name: Optional[str]
    not_after: Optional[datetime]
    is_expired: bool
    is_not_yet_valid: bool
    is_self_signed: bool
    public_key_algorithm: Optional[str]
    public_key_size_bits: Optional[int]
    trust_status: str


class CertificateDetail(CertificateSummary):
    serial_number: Optional[str]
    not_before: Optional[datetime]
    validity_reference: Optional[str]
    is_ca: Optional[bool]
    signature_algorithm: Optional[str]
    san_list: List[str] = []
    weak_key: bool
    weak_signature: bool
    issued_by_next: Optional[str]
    seen_in_sessions: List[str] = []


# ----------------------------------------------------------------- anomalies
class AnomalySummary(_ORM):
    id: int
    capture_id: str
    session_id: str
    is_anomaly: bool
    anomaly_score: Optional[float]
    anomaly_level: Optional[str]
    model_version: Optional[str]


class AnomalyDetail(AnomalySummary):
    explanation: Optional[str]
    features: Dict[str, Any] = {}
    timestamp: Optional[datetime]
    classification: str = "ML_ANOMALY (statistical outlier; not a confirmed vulnerability)"


# ------------------------------------------------------------------- posture
class ContributorModel(BaseModel):
    root_issue: str
    severity: str
    affected_sessions: int
    total_sessions: Optional[int] = None
    prevalence: float
    impact_points: float
    explanation: str
    finding_ids: List[str] = []


class DimensionScoreModel(BaseModel):
    dimension: str
    name: str
    score: Optional[float]
    weight: float
    affected_sessions: int
    assessable_sessions: int
    findings_count: int
    coverage_percent: float
    evidence_quality: str
    top_contributors: List[ContributorModel] = []


class RootCauseGroupModel(BaseModel):
    root_issue: str
    severity: str
    affected_sessions: int
    total_sessions: int
    prevalence_percent: float
    finding_count: int


class PostureResponse(BaseModel):
    capture_id: str
    overall_score: Optional[float]
    status: str
    scoring_policy_version: str
    analysis_timestamp: Optional[datetime]
    total_sessions: int
    tls_sessions: int
    sessions_with_findings: int
    findings_count: int
    tls_coverage_percent: float
    certificate_coverage_percent: float
    coverage_percent: float
    dimension_scores: List[DimensionScoreModel]
    top_contributors: List[ContributorModel]
    root_cause_groups: List[RootCauseGroupModel]
    remediation_plan: List[Dict[str, Any]] = []


# ------------------------------------------------------------------- reports
class ReportSummary(_ORM):
    report_id: str
    capture_id: str
    report_type: str
    file_size: int
    sha256: Optional[str]
    redacted: bool = False
    created_at: Optional[datetime]


class AnnotationCreate(BaseModel):
    target_type: Literal["capture", "finding", "session", "certificate"]
    target_id: str = Field(min_length=1, max_length=260)
    text: str = Field(default="", max_length=4000)
    include_in_report: bool = False


class AnnotationUpdate(BaseModel):
    text: Optional[str] = Field(default=None, max_length=4000)
    include_in_report: Optional[bool] = None


class AnnotationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    capture_id: str
    target_type: str
    target_id: str
    text: str
    include_in_report: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TrendPoint(BaseModel):
    capture_id: str
    filename: str
    file_hash: str
    policy_profile: Optional[str] = None
    capture_start: Optional[str] = None
    analysis_timestamp: Optional[datetime] = None
    posture_score: Optional[float] = None
    posture_status: Optional[str] = None
    findings_count: int
    severe_findings_count: int
    shared_servers: List[str]
    is_selected: bool
