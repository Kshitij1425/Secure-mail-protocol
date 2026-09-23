"""
Analysis service layer for SecureMailScope.
Coordinates the actual analysis pipeline without duplicating logic.
"""
import hashlib
import tempfile
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

import orjson
from fastapi import UploadFile, HTTPException
from sqlalchemy.orm import Session

from securemailscope.api.database import (
    get_session_local,
    CaptureDB,
    SessionDB,
    FindingDB,
    CertificateDB,
    AnomalyDB,
    ReportDB,
    SessionFindingDB
)
from securemailscope.core.orchestrator import Orchestrator
from securemailscope.api.config import get_settings

logger = logging.getLogger(__name__)


class AnalysisService:
    """Service for coordinating analysis pipelines."""

    def __init__(self):
        self.settings = get_settings()
        self.orchestrator = Orchestrator()

    def save_capture(self, file: UploadFile, db: Session) -> Tuple[CaptureDB, Path]:
        """Save uploaded capture file and create database record."""
        # Generate unique IDs and file paths
        capture_id = str(uuid.uuid4())
        file_hash = hashlib.sha256()

        # Create upload directory if not exists
        upload_dir = Path(self.settings.upload_dir)
        upload_dir.mkdir(exist_ok=True)

        # Generate safe filename
        original_filename = Path(file.filename)
        safe_filename = f"{capture_id}_{original_filename.name}"
        file_path = upload_dir / safe_filename

        # Read file in chunks and hash
        with open(file_path, "wb") as buffer:
            while chunk := file.file.read(8192):
                file_hash.update(chunk)
                buffer.write(chunk)

        file_hash_hex = file_hash.hexdigest()
        file_size = file_path.stat().st_size

        # Validate file extension
        allowed_extensions = {ext.lower() for ext in self.settings.allowed_extensions}
        if original_filename.suffix.lower() not in allowed_extensions:
            raise HTTPException(
                status_code=422,
                detail=f"File type {original_filename.suffix} not allowed. "
                       f"Allowed types: {', '.join(self.settings.allowed_extensions)}"
            )

        # Create database record
        capture = CaptureDB(
            capture_id=capture_id,
            filename=original_filename.name,
            file_hash=file_hash_hex,
            file_path=str(file_path),
            file_size=file_size,
            analysis_status="pending"
        )

        db.add(capture)
        db.commit()
        db.refresh(capture)

        logger.info(f"Saved capture {capture_id}: {original_filename.name} ({file_size} bytes)")

        return capture, file_path

    def run_analysis(self, capture: CaptureDB, file_path: Path, db: Session) -> CaptureDB:
        """Run the actual M1-M11 analysis pipeline."""
        try:
            # Update status to processing
            capture.analysis_status = "processing"
            db.commit()

            logger.info(f"Starting analysis for capture {capture.capture_id}")

            # Run the orchestrator (M1-M11 pipeline)
            posture_score, metadata = self.orchestrator.analyze(str(file_path))

            # Extract results from metadata and posture score
            self._process_analysis_results(capture, metadata, posture_score, db)

            # Update capture status
            capture.analysis_status = "completed"
            capture.analysis_timestamp = datetime.utcnow()

            db.commit()
            db.refresh(capture)

            logger.info(f"Analysis completed for capture {capture.capture_id}")

            return capture

        except Exception as e:
            logger.error(f"Analysis failed for capture {capture.capture_id}: {e}")

            # Update status to failed
            capture.analysis_status = "failed"
            capture.analysis_timestamp = datetime.utcnow()

            db.commit()
            db.refresh(capture)

            raise

    def _process_analysis_results(self, capture: CaptureDB, metadata: Dict[str, Any],
                                  posture_score, db: Session):
        """Process and store analysis results in database."""
        # Process sessions from metadata
        if "reconstructed_streams" in metadata:
            capture.stream_count = metadata.get("reconstructed_streams", 0)

        capture.packet_count = metadata.get("packet_count", 0)
        capture.email_session_count = metadata.get("email_session_count", 0)
        capture.tls_session_count = metadata.get("tls_session_count", 0)

        # Process findings from posture score
        self._store_findings(capture, posture_score, db)

        # Process certificates from posture score
        self._store_certificates(capture, posture_score, db)

        # Process anomalies from posture score
        self._store_anomalies(capture, posture_score, db)

        # Store posture score information
        capture.posture_score = posture_score.overall_score
        capture.posture_status = posture_score.status.value if hasattr(posture_score.status, 'value') else str(posture_score.status)
        capture.scoring_policy_version = posture_score.scoring_policy_version

        # ML engine version from posture score if available
        if hasattr(posture_score, 'ml_engine_version'):
            capture.ml_engine_version = posture_score.ml_engine_version

    def _store_findings(self, capture: CaptureDB, posture_score, db: Session):
        """Store findings from posture score in database."""
        # Extract findings from posture score top contributors
        for contributor in posture_score.top_contributors:
            finding = FindingDB(
                capture_id=capture.capture_id,
                finding_id=f"{contributor.root_issue}_{capture.capture_id}",
                session_id=None,  # Could be extracted from posture score
                rule_id=contributor.root_issue,
                title=contributor.root_issue.replace("_", " ").title(),
                severity=contributor.severity,
                category=self._map_category(contributor.root_issue),
                confidence=0.95,  # Default confidence
                risk_contribution=contributor.impact_points,
                explanation=contributor.explanation,
                recommendation=f"Apply remediation for {contributor.root_issue}",
                evidence=f"Detected in {contributor.affected_sessions} sessions"
            )

            db.add(finding)
            db.flush()

            # Create session-finding relationship if session_id available
            # This would require session extraction from posture score

    def _store_certificates(self, capture: CaptureDB, posture_score, db: Session):
        """Store certificate information."""
        # Extract certificates from posture score or engine
        # This would require certificate extraction from the analysis pipeline
        pass

    def _store_anomalies(self, capture: CaptureDB, posture_score, db: Session):
        """Store anomaly detection results."""
        # Extract anomalies from posture score or engine
        # This would require anomaly extraction from the analysis pipeline
        pass

    def _map_category(self, rule_id: str) -> str:
        """Map rule ID to category."""
        category_map = {
            "STARTTLS_REJECTED": "encryption",
            "WEAK_CIPHER": "encryption",
            "NO_FORWARD_SECRECY": "forward_secrecy",
            "EXPIRED_CERT": "certificates",
            "WEAK_RSA_KEY": "certificates",
            "SELF_SIGNED_CERT": "certificates",
        }

        return category_map.get(rule_id, "other")