"""
Persistence layer (SQLite via SQLAlchemy ORM).

Identifiers are globally unique so records from different captures can never
collide or leak into each other:

* session_id     = "<capture_id>~<stream_id>"
* finding_id     = "<session_id>:<rule_id>[:<chain position>]"
* certificate_id = "<session_id>~c<chain position>"

Every child row carries capture_id; foreign keys are enforced (SQLite PRAGMA).
"""
from datetime import datetime, timezone
import logging
import os
import uuid

from sqlalchemy import (Boolean, Column, DateTime as _SADateTime, Float, ForeignKey, Integer, String, Text,
                        TypeDecorator, UniqueConstraint, create_engine, event, inspect)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from securemailscope.api.config import get_settings

logger = logging.getLogger("securemailscope.api.database")
Base = declarative_base()

SCHEMA_VERSION = "3"


class UTCDateTime(TypeDecorator):
    """Stores UTC (SQLite has no timezone support) and always returns aware UTC datetimes,
    so the API never emits naive timestamps that browsers would read as local time."""
    impl = _SADateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=timezone.utc) if value is not None else None


def DateTime(timezone=True):  # noqa: N802 - column factory used below
    return UTCDateTime()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SchemaInfo(Base):
    __tablename__ = "schema_info"
    key = Column(String(32), primary_key=True)
    value = Column(String(64), nullable=False)


class CaptureDB(Base):
    """Capture metadata and analysis results."""
    __tablename__ = "captures"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), unique=True, default=generate_uuid, index=True, nullable=False)
    filename = Column(String(255), nullable=False)          # display name (sanitised client name)
    stored_filename = Column(String(64), nullable=True)     # server-generated, never client controlled
    file_hash = Column(String(64), nullable=False, index=True)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_format = Column(String(16), nullable=True)
    upload_timestamp = Column(DateTime(timezone=True), default=get_utc_now)
    analysis_status = Column(String(20), default="pending")  # pending, processing, completed, failed
    analysis_error = Column(String(255), nullable=True)
    analysis_timestamp = Column(DateTime(timezone=True), nullable=True)
    analysis_duration_seconds = Column(Float, nullable=True)
    capture_start = Column(DateTime(timezone=True), nullable=True)
    capture_end = Column(DateTime(timezone=True), nullable=True)
    packet_count = Column(Integer, default=0)
    stream_count = Column(Integer, default=0)
    email_session_count = Column(Integer, default=0)
    tls_session_count = Column(Integer, default=0)
    posture_score = Column(Float, nullable=True)
    posture_status = Column(String(32), nullable=True)
    scoring_policy_version = Column(String(50), nullable=True)
    rule_policy_version = Column(String(50), nullable=True)
    policy_profile = Column(String(32), default="balanced")
    ml_engine_version = Column(String(50), nullable=True)
    ml_status = Column(String(64), nullable=True)
    ml_anomalies_detected = Column(Integer, default=0)
    posture_json = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    document_json = Column(Text, nullable=True)   # canonical analysis document

    sessions = relationship("SessionDB", back_populates="capture", cascade="all, delete-orphan")
    findings = relationship("FindingDB", back_populates="capture", cascade="all, delete-orphan")
    certificates = relationship("CertificateDB", back_populates="capture", cascade="all, delete-orphan")
    anomalies = relationship("AnomalyDB", back_populates="capture", cascade="all, delete-orphan")
    reports = relationship("ReportDB", back_populates="capture", cascade="all, delete-orphan")
    annotations = relationship("AnnotationDB", back_populates="capture", cascade="all, delete-orphan")


class SessionDB(Base):
    """One recognised email session (TCP connection)."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(200), nullable=False, unique=True, index=True)
    stream_id = Column(String(160), nullable=False)
    protocol = Column(String(20), nullable=False)
    source_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_ip = Column(String(45), nullable=True)
    dest_port = Column(Integer, nullable=True)
    start_timestamp = Column(DateTime(timezone=True), nullable=True)
    end_timestamp = Column(DateTime(timezone=True), nullable=True)
    first_frame = Column(Integer, nullable=True)
    last_frame = Column(Integer, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    detection_method = Column(String(32), nullable=True)
    implicit_tls = Column(Boolean, default=False)
    starttls_state = Column(String(30), nullable=True)
    starttls_advertised = Column(Boolean, nullable=True)
    tls_version = Column(String(20), nullable=True)
    client_hello_version = Column(String(20), nullable=True)
    cipher_suite = Column(String(100), nullable=True)
    key_exchange = Column(String(50), nullable=True)
    key_exchange_group = Column(String(50), nullable=True)
    sni = Column(String(255), nullable=True)
    has_forward_secrecy = Column(Boolean, nullable=True)
    handshake_complete = Column(Boolean, default=False)
    handshake_status = Column(String(20), nullable=True)
    certificate_visibility = Column(String(32), nullable=True)
    reconstruction_quality = Column(String(20), nullable=True)
    has_findings = Column(Boolean, default=False)
    has_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    anomaly_level = Column(String(20), nullable=True)
    detail_json = Column(Text, nullable=True)   # canonical session document

    capture = relationship("CaptureDB", back_populates="sessions")
    session_findings = relationship("SessionFindingDB", back_populates="session", cascade="all, delete-orphan")


class FindingDB(Base):
    """Deterministic security finding."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(260), nullable=False, unique=True, index=True)
    session_id = Column(String(200), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=True, index=True)
    rule_id = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    category = Column(String(50), nullable=False)
    dimension = Column(String(32), nullable=True)
    evidence_type = Column(String(32), nullable=True)
    confidence = Column(Float, default=1.0)
    risk_contribution = Column(Float, default=0.0)
    priority = Column(Integer, nullable=True)
    explanation = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    references = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    evidence_frames = Column(Text, nullable=True)
    status = Column(String(20), default="open")   # open, acknowledged, in_progress, resolved, false_positive
    timestamp = Column(DateTime(timezone=True), default=get_utc_now)

    capture = relationship("CaptureDB", back_populates="findings")
    session_findings = relationship("SessionFindingDB", back_populates="finding", cascade="all, delete-orphan")


class SessionFindingDB(Base):
    """Session <-> finding association."""
    __tablename__ = "session_findings"
    __table_args__ = (UniqueConstraint("session_id", "finding_id"),)

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(200), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False)
    finding_id = Column(String(260), ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False)

    session = relationship("SessionDB", back_populates="session_findings")
    finding = relationship("FindingDB", back_populates="session_findings")


class CertificateDB(Base):
    """A certificate as observed in one session (same cert in two sessions = two rows)."""
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    certificate_id = Column(String(210), nullable=False, unique=True, index=True)
    session_id = Column(String(200), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False, index=True)
    chain_position = Column(Integer, default=0)
    fingerprint_sha256 = Column(String(64), nullable=False, index=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    common_name = Column(String(255), nullable=True)
    serial_number = Column(String(100), nullable=True)
    not_before = Column(DateTime(timezone=True), nullable=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    validity_reference = Column(String(32), nullable=True)
    is_expired = Column(Boolean, default=False)
    is_not_yet_valid = Column(Boolean, default=False)
    is_self_signed = Column(Boolean, default=False)
    is_ca = Column(Boolean, nullable=True)
    public_key_algorithm = Column(String(50), nullable=True)
    public_key_size_bits = Column(Integer, nullable=True)
    signature_algorithm = Column(String(80), nullable=True)
    san_list = Column(Text, nullable=True)
    weak_key = Column(Boolean, default=False)
    weak_signature = Column(Boolean, default=False)
    issued_by_next = Column(String(32), nullable=True)
    trust_status = Column(String(20), default="unknown")

    capture = relationship("CaptureDB", back_populates="certificates")


class AnomalyDB(Base):
    """Supplementary ML anomaly detection result (one per ML-evaluated session)."""
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(200), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False, index=True)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    anomaly_level = Column(String(20), nullable=True)
    explanation = Column(Text, nullable=True)
    features_json = Column(Text, nullable=True)
    model_version = Column(String(50), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=get_utc_now)

    capture = relationship("CaptureDB", back_populates="anomalies")


class ReportDB(Base):
    """Generated report file."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    report_id = Column(String(36), unique=True, default=generate_uuid, index=True)
    report_type = Column(String(20), nullable=False)  # json, html, pdf
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=True)
    redacted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now)

    capture = relationship("CaptureDB", back_populates="reports")


class AnnotationDB(Base):
    """Analyst note / report selection attached to a capture, finding, session or certificate.

    Analyst metadata only: never changes evidence, findings, severity or the score. Added as a
    new table (created by ``create_all`` on existing databases; no schema reset needed)."""
    __tablename__ = "annotations"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    target_type = Column(String(20), nullable=False)       # capture | finding | session | certificate
    target_id = Column(String(260), nullable=False, index=True)
    text = Column(Text, nullable=False, default="")
    include_in_report = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now)

    capture = relationship("CaptureDB", back_populates="annotations")


_engine = None
_SessionLocal = None


def _enable_sqlite_fk(dbapi_connection, _record):
    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


def get_engine():
    global _engine
    if _engine is None:
        url = get_settings().database_url
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        _engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(_engine, "connect", _enable_sqlite_fk)
    return _engine


def reset_engine() -> None:
    """Drop cached engine/session factory (tests, settings changes)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def get_session_local():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal


def init_db():
    """Create tables. An existing database with an older schema is preserved as a
    backup file and a fresh one is created (analysis data is re-derivable from the
    stored captures); nothing is deleted."""
    engine = get_engine()
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    outdated = bool(tables) and "schema_info" not in tables
    if not outdated and "schema_info" in tables:
        with engine.connect() as conn:
            row = conn.exec_driver_sql("SELECT value FROM schema_info WHERE key='version'").fetchone()
            outdated = row is None or row[0] != SCHEMA_VERSION
    if outdated:
        url = get_settings().database_url
        if url.startswith("sqlite:///"):
            path = url[len("sqlite:///"):]
            engine.dispose()
            if os.path.exists(path):
                backup = f"{path}.schema-old-{datetime.now().strftime('%Y%m%d%H%M%S')}.bak"
                os.replace(path, backup)
                logger.warning(f"Old database schema detected; preserved as {os.path.basename(backup)}")
            reset_engine()
            engine = get_engine()
        else:
            raise RuntimeError("Database schema is outdated; migrate or point SECUREMAILSCOPE_DATABASE_URL elsewhere.")
    Base.metadata.create_all(bind=engine)
    with get_session_local()() as db:
        if db.get(SchemaInfo, "version") is None:
            db.add(SchemaInfo(key="version", value=SCHEMA_VERSION))
            db.commit()


def get_db():
    SessionLocal = get_session_local()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
