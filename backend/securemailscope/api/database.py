"""
Database models for persistence.
SQLite-based storage for analysis results.
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import uuid

from securemailscope.api.config import get_settings

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


class CaptureDB(Base):
    """Capture metadata and analysis results."""
    __tablename__ = "captures"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), unique=True, default=generate_uuid, index=True)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)
    analysis_status = Column(String(20), default="pending")  # pending, processing, completed, failed
    analysis_timestamp = Column(DateTime, nullable=True)
    packet_count = Column(Integer, default=0)
    stream_count = Column(Integer, default=0)
    email_session_count = Column(Integer, default=0)
    tls_session_count = Column(Integer, default=0)
    posture_score = Column(Float, nullable=True)
    posture_status = Column(String(20), nullable=True)
    scoring_policy_version = Column(String(50), nullable=True)
    ml_engine_version = Column(String(50), nullable=True)
    ml_anomalies_detected = Column(Integer, default=0)

    sessions = relationship("SessionDB", back_populates="capture", cascade="all, delete-orphan")
    findings = relationship("FindingDB", back_populates="capture", cascade="all, delete-orphan")
    certificates = relationship("CertificateDB", back_populates="capture", cascade="all, delete-orphan")
    anomalies = relationship("AnomalyDB", back_populates="capture", cascade="all, delete-orphan")
    reports = relationship("ReportDB", back_populates="capture", cascade="all, delete-orphan")


class SessionDB(Base):
    """TLS session metadata."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id"), nullable=False)
    session_id = Column(String(100), nullable=False, index=True)
    protocol = Column(String(20), nullable=False)
    source_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_ip = Column(String(45), nullable=True)
    dest_port = Column(Integer, nullable=True)
    start_timestamp = Column(DateTime, nullable=True)
    end_timestamp = Column(DateTime, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    starttls_state = Column(String(30), nullable=True)
    tls_version = Column(String(20), nullable=True)
    cipher_suite = Column(String(100), nullable=True)
    key_exchange = Column(String(50), nullable=True)
    has_forward_secrecy = Column(Boolean, default=False)
    handshake_complete = Column(Boolean, default=False)
    has_findings = Column(Boolean, default=False)
    has_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    anomaly_level = Column(String(20), nullable=True)

    capture = relationship("CaptureDB", back_populates="sessions")
    session_findings = relationship("SessionFindingDB", back_populates="session")


class FindingDB(Base):
    """Security finding details."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id"), nullable=False)
    finding_id = Column(String(50), nullable=False, index=True)
    session_id = Column(String(100), nullable=True, index=True)
    rule_id = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    category = Column(String(50), nullable=False)
    confidence = Column(Float, default=1.0)
    risk_contribution = Column(Float, default=0.0)
    explanation = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    capture = relationship("CaptureDB", back_populates="findings")
    session_findings = relationship("SessionFindingDB", back_populates="finding")


class SessionFindingDB(Base):
    """Many-to-many relationship between sessions and findings."""
    __tablename__ = "session_findings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), ForeignKey("sessions.session_id"), nullable=False)
    finding_id = Column(String(50), ForeignKey("findings.finding_id"), nullable=False)

    session = relationship("SessionDB", back_populates="session_findings")
    finding = relationship("FindingDB", back_populates="session_findings")


class CertificateDB(Base):
    """Certificate details."""
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id"), nullable=False)
    session_id = Column(String(100), nullable=True, index=True)
    fingerprint_sha256 = Column(String(64), nullable=False, index=True)
    subject = Column(String(255), nullable=True)
    issuer = Column(String(255), nullable=True)
    serial_number = Column(String(100), nullable=True)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    is_expired = Column(Boolean, default=False)
    is_self_signed = Column(Boolean, default=False)
    public_key_algorithm = Column(String(50), nullable=True)
    public_key_size_bits = Column(Integer, nullable=True)
    signature_algorithm = Column(String(50), nullable=True)
    san_list = Column(Text, nullable=True)
    weak_key = Column(Boolean, default=False)
    weak_signature = Column(Boolean, default=False)

    capture = relationship("CaptureDB", back_populates="certificates")


class AnomalyDB(Base):
    """ML anomaly detection results."""
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id"), nullable=False)
    session_id = Column(String(100), nullable=False, index=True)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    anomaly_level = Column(String(20), nullable=True)
    explanation = Column(Text, nullable=True)
    features_json = Column(Text, nullable=True)
    model_version = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    capture = relationship("CaptureDB", back_populates="anomalies")


class ReportDB(Base):
    """Generated report metadata."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id"), nullable=False)
    report_id = Column(String(36), unique=True, default=generate_uuid, index=True)
    report_type = Column(String(20), nullable=False)  # json, html, pdf
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    capture = relationship("CaptureDB", back_populates="reports")


# Database engine and session
_engine = None
_SessionLocal = None


def get_engine():
    """Get or create database engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url.replace("sqlite:///", "sqlite:///"),
            connect_args={"check_same_thread": False}
        )
    return _engine


def get_session_local():
    """Get session local."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=get_engine())


def get_db():
    """Get database session."""
    SessionLocal = get_session_local()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()