"""
Analysis service: upload intake, pipeline execution, persistence and reports.

Security properties:
* uploads are streamed to disk under a hard size cap and validated by magic bytes;
* the stored file name is server generated (``<capture_id>.<format>``); the client
  file name is kept only as a sanitised display string;
* persistence of one analysis is a single transaction (all-or-nothing);
* error messages returned to clients never contain paths or exception text.
"""
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Tuple

from sqlalchemy import insert
from sqlalchemy.orm import Session

from securemailscope import __version__
from securemailscope.api.config import get_settings
from securemailscope.api.database import (AnomalyDB, CaptureDB, CertificateDB, FindingDB, ReportDB, SessionDB,
                                          SessionFindingDB, get_utc_now)
from securemailscope.core.orchestrator import Orchestrator, OrchestratorResult
from securemailscope.ingestion.reader import AnalysisLimitExceeded, detect_capture_format
from securemailscope.reports.document import document_from_result
from securemailscope.reports.render import RENDERERS, ReportUnavailable

logger = logging.getLogger("securemailscope.api.service")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class ServiceError(Exception):
    """Client-safe error with an HTTP status."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def sanitize_display_name(name: Optional[str]) -> str:
    """Display-only name: last path component, NFC, no control chars, bounded."""
    raw = (name or "capture").replace("\\", "/").split("/")[-1]
    raw = unicodedata.normalize("NFC", raw)
    raw = _CTRL.sub("", raw).strip().strip(".") or "capture"
    stem, ext = os.path.splitext(raw)
    ext = ext[:10]
    return stem[:200 - len(ext)] + ext


def _dt(ts) -> Optional[datetime]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _j(v) -> str:
    return json.dumps(v, default=str, separators=(",", ":"))


class AnalysisService:
    """Coordinates intake, analysis, persistence and reporting."""

    def __init__(self):
        self._slots = threading.BoundedSemaphore(get_settings().max_concurrent_analyses)

    # ------------------------------------------------------------- intake
    def receive_upload(self, stream: BinaryIO, filename: Optional[str]) -> Tuple[Path, str, int, str, str]:
        """Stream an upload to a temp file. Returns (path, sha256, size, format, display_name)."""
        settings = get_settings()
        display = sanitize_display_name(filename)
        ext = os.path.splitext(display)[1].lower()
        if ext not in {e.lower() for e in settings.allowed_extensions}:
            raise ServiceError(422, f"Unsupported file type. Allowed: {', '.join(sorted(settings.allowed_extensions))}")
        upload_dir = Path(settings.upload_dir)
        upload_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="incoming-", suffix=".part", dir=upload_dir)
        tmp = Path(tmp_name)
        h, size, limit = hashlib.sha256(), 0, settings.max_upload_size_bytes
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := stream.read(1 << 20):
                    size += len(chunk)
                    if size > limit:
                        raise ServiceError(413, f"File too large. Maximum size is {settings.max_upload_size_mb} MB")
                    h.update(chunk)
                    out.write(chunk)
            if size == 0:
                raise ServiceError(400, "Uploaded file is empty")
            fmt = detect_capture_format(str(tmp))
            if fmt is None:
                raise ServiceError(422, "File is not a PCAP or PCAPNG capture")
            return tmp, h.hexdigest(), size, fmt, display
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def create_capture(self, tmp: Path, sha: str, size: int, fmt: str, display: str, db: Session,
                       policy_profile: str = "balanced") -> CaptureDB:
        capture_id = str(uuid.uuid4())
        stored = f"{capture_id}.{fmt}"
        final = Path(get_settings().upload_dir) / stored
        os.replace(tmp, final)
        capture = CaptureDB(capture_id=capture_id, filename=display, stored_filename=stored, file_hash=sha,
                            policy_profile=policy_profile,
                            file_path=str(final), file_size=size, file_format=fmt, analysis_status="pending")
        db.add(capture)
        db.commit()
        db.refresh(capture)
        logger.info(f"Capture {capture_id} stored ({size} bytes, sha256 {sha[:12]})")
        return capture

    # ----------------------------------------------------------- analysis
    def run_analysis(self, capture: CaptureDB, db: Session) -> CaptureDB:
        settings = get_settings()
        if not self._slots.acquire(blocking=False):
            capture.analysis_status = "failed"
            capture.analysis_error = "Server busy: too many concurrent analyses"
            db.commit()
            raise ServiceError(503, "Server busy: too many concurrent analyses; retry shortly")
        started = time.perf_counter()
        try:
            capture.analysis_status = "processing"
            db.commit()
            orchestrator = Orchestrator(securemailscope_version=__version__, max_packets=settings.max_packets,
                                        policy_profile=capture.policy_profile or "balanced",
                                        time_budget_seconds=settings.analysis_time_budget_seconds)
            result = orchestrator.analyze(capture.file_path, session_prefix=f"{capture.capture_id}~")
            self._persist(capture, result, db, time.perf_counter() - started)
            return capture
        except (ValueError, AnalysisLimitExceeded) as e:
            db.rollback()
            msg = str(e) if isinstance(e, AnalysisLimitExceeded) else "Invalid or unreadable capture"
            self._mark_failed(capture, db, msg)
            raise ServiceError(422 if isinstance(e, ValueError) else 413, msg)
        except ServiceError:
            raise
        except Exception:
            db.rollback()
            logger.exception(f"Analysis failed for capture {capture.capture_id}")
            self._mark_failed(capture, db, "Internal analysis error")
            raise ServiceError(500, "Analysis failed due to an internal error")
        finally:
            self._slots.release()

    @staticmethod
    def _mark_failed(capture: CaptureDB, db: Session, message: str) -> None:
        capture.analysis_status = "failed"
        capture.analysis_error = message[:255]
        capture.analysis_timestamp = get_utc_now()
        db.commit()

    def _persist(self, capture: CaptureDB, result: OrchestratorResult, db: Session, duration: float) -> None:
        """Write every artefact of one analysis in a single transaction."""
        cid = capture.capture_id
        doc = document_from_result(result, capture_id=cid, filename=capture.filename)
        meta = result.metadata
        posture = result.posture

        sess_docs = {s["session_id"]: s for s in doc["sessions"]}

        def bulk(model, rows):
            # Core executemany in chunks: bounded memory, same transaction as the capture update.
            for i in range(0, len(rows), 2000):
                db.execute(insert(model), rows[i:i + 2000])

        def session_rows():
            for s in result.sessions:
                t, stream, a = s.tls_data, s.stream, s.anomaly
                yield dict(
                    capture_id=cid, session_id=s.session_id, stream_id=stream.stream_id, protocol=s.protocol.name,
                    source_ip=stream.client_ip, source_port=stream.src_port, dest_ip=stream.server_ip,
                    dest_port=stream.dst_port, start_timestamp=_dt(stream.start_time),
                    end_timestamp=_dt(stream.end_time), first_frame=stream.first_frame, last_frame=stream.last_frame,
                    packet_count=stream.packets_analyzed, byte_count=stream.payload_bytes,
                    detection_method=s.detection.detection_method if s.detection else None,
                    implicit_tls=s.implicit_tls, starttls_state=s.starttls_state.name,
                    starttls_advertised=s.starttls.starttls_advertised if s.starttls else None,
                    tls_version=t.server_version if t else None, client_hello_version=t.client_version if t else None,
                    cipher_suite=t.cipher_suite_name if t else None, key_exchange=t.key_exchange if t else None,
                    key_exchange_group=t.key_exchange_group if t else None, sni=t.sni if t else None,
                    has_forward_secrecy=(t.has_forward_secrecy if t and t.server_version else None),
                    handshake_complete=bool(t and t.handshake_complete),
                    handshake_status=t.handshake_status if t else None,
                    certificate_visibility=t.certificate_visibility if t else None,
                    reconstruction_quality=stream.reconstruction_quality, has_findings=bool(s.findings),
                    has_anomaly=bool(a and a.is_anomaly), anomaly_score=a.anomaly_score if a else None,
                    anomaly_level=a.anomaly_level.value if a else None, detail_json=_j(sess_docs[s.session_id]),
                )

        bulk(SessionDB, list(session_rows()))

        bulk(FindingDB, [dict(
            capture_id=cid, finding_id=f["finding_id"], session_id=f["session_id"], rule_id=f["rule_id"],
            title=f["title"][:255], severity=f["severity"], category=f["category"], dimension=f["dimension"],
            evidence_type=f["evidence_type"], confidence=f["confidence"], risk_contribution=f["risk_contribution"],
            priority=i, explanation=f["description"], recommendation=f["recommendation"], references=f["references"],
            evidence=_j(f["evidence"]), evidence_frames=_j(f["evidence_frames"]), status="open",
            timestamp=get_utc_now()) for i, f in enumerate(doc["findings"], 1)])
        bulk(SessionFindingDB, [dict(capture_id=cid, session_id=f["session_id"], finding_id=f["finding_id"])
                                for f in doc["findings"] if f["session_id"]])

        bulk(CertificateDB, [dict(
            capture_id=cid, certificate_id=c["certificate_id"], session_id=c["session_id"],
            chain_position=c["chain_position"], fingerprint_sha256=c["fingerprint_sha256"], subject=c["subject"],
            issuer=c["issuer"], common_name=c["common_name"], serial_number=c["serial_number"],
            not_before=datetime.fromisoformat(c["not_before"]) if c["not_before"] else None,
            not_after=datetime.fromisoformat(c["not_after"]) if c["not_after"] else None,
            validity_reference=c["validity_reference"], is_expired=c["is_expired"],
            is_not_yet_valid=c["is_not_yet_valid"], is_self_signed=c["is_self_signed"], is_ca=c["is_ca"],
            public_key_algorithm=c["public_key_algorithm"], public_key_size_bits=c["public_key_size_bits"],
            signature_algorithm=c["signature_algorithm"], san_list=_j(c["san_list"]), weak_key=c["weak_key"],
            weak_signature=c["weak_signature"], issued_by_next=c["issued_by_next"], trust_status=c["trust_status"],
        ) for c in doc["certificates"]])

        model_version = (meta.get("ml_engine_summary") or {}).get("model_version")
        bulk(AnomalyDB, [dict(capture_id=cid, session_id=a["session_id"], is_anomaly=a["is_anomaly"],
                              anomaly_score=a["anomaly_score"], anomaly_level=a["anomaly_level"],
                              explanation=a["explanation"], features_json=_j(a["features"]),
                              model_version=model_version, timestamp=get_utc_now()) for a in doc["anomalies"]])

        capture.packet_count = result.packet_count
        capture.stream_count = result.reconstructed_stream_count
        capture.email_session_count = result.email_session_count
        capture.tls_session_count = result.tls_session_count
        capture.capture_start = _dt(meta.get("start_time"))
        capture.capture_end = _dt(meta.get("end_time"))
        capture.posture_score = posture.overall_score
        capture.posture_status = posture.status.value
        capture.scoring_policy_version = posture.scoring_policy_version
        capture.rule_policy_version = meta.get("rule_policy_version")
        capture.policy_profile = meta.get("policy_profile", capture.policy_profile)
        capture.ml_engine_version = model_version
        capture.ml_status = (meta.get("ml_engine_summary") or {}).get("status")
        capture.ml_anomalies_detected = meta.get("ml_anomalies_detected", 0)
        capture.posture_json = _j(doc["posture"])
        capture.metadata_json = _j({k: v for k, v in meta.items() if k not in ("filepath",)})
        capture.document_json = _j(doc)
        capture.analysis_status = "completed"
        capture.analysis_error = None
        capture.analysis_timestamp = get_utc_now()
        capture.analysis_duration_seconds = round(duration, 4)
        db.commit()
        db.refresh(capture)
        logger.info(f"Analysis completed for capture {cid}: {result.email_session_count} email sessions, "
                    f"{len(result.findings)} findings")

    # ------------------------------------------------------------ reports
    def reanalyze(self, source: CaptureDB, policy_profile: str, db: Session) -> CaptureDB:
        """Analyse the same stored capture again (e.g. under another policy profile) as a new analysis.
        The evidence file is copied so every analysis owns an immutable file."""
        import shutil
        src = Path(source.file_path)
        if not src.is_file():
            raise ServiceError(404, "Stored capture file is no longer available")
        fd, tmp_name = tempfile.mkstemp(prefix="incoming-", suffix=".part", dir=Path(get_settings().upload_dir))
        os.close(fd)
        shutil.copyfile(src, tmp_name)
        tmp = Path(tmp_name)
        if hashlib.sha256(tmp.read_bytes()).hexdigest() != source.file_hash:
            tmp.unlink(missing_ok=True)
            raise ServiceError(409, "Stored capture no longer matches its recorded SHA-256")
        capture = self.create_capture(tmp, source.file_hash, source.file_size, source.file_format or "pcap",
                                      source.filename, db, policy_profile=policy_profile)
        return self.run_analysis(capture, db)

    @staticmethod
    def document(capture: CaptureDB, redact: bool = False) -> Dict[str, Any]:
        from securemailscope.reports.redact import raw_label, redact_document
        if capture.analysis_status != "completed" or not capture.document_json:
            raise ServiceError(409, "Analysis is not complete for this capture")
        doc = json.loads(capture.document_json)
        return redact_document(doc) if redact else raw_label(doc)

    def generate_report(self, capture: CaptureDB, fmt: str, db: Session, redact: bool = False) -> ReportDB:
        if fmt not in RENDERERS:
            raise ServiceError(422, "Unsupported report format (json, html, pdf)")
        if capture.analysis_status != "completed" or not capture.document_json:
            raise ServiceError(409, "Analysis is not complete for this capture")
        render, _ = RENDERERS[fmt]
        doc = self.document(capture, redact)
        try:
            data = render(doc)
        except ReportUnavailable as e:
            raise ServiceError(501, str(e))
        report_id = str(uuid.uuid4())
        out_dir = Path(get_settings().reports_dir) / capture.capture_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{report_id}.{fmt}"
        path.write_bytes(data)
        row = ReportDB(capture_id=capture.capture_id, report_id=report_id, report_type=fmt, file_path=str(path),
                       file_size=len(data), sha256=hashlib.sha256(data).hexdigest(), redacted=redact)
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    @staticmethod
    def report_path(row: ReportDB) -> Optional[Path]:
        """Resolve a report path and refuse anything outside the reports directory."""
        base = Path(get_settings().reports_dir).resolve()
        p = Path(row.file_path).resolve()
        try:
            p.relative_to(base)
        except ValueError:
            return None
        return p if p.is_file() else None


def evidence_chain(doc: Dict[str, Any], finding_id: str) -> Optional[Dict[str, Any]]:
    """Assemble finding -> session -> TCP stream -> TLS -> certificate -> evidence -> recommendation
    from one stored analysis document. Every link states whether it was observed."""
    f = next((x for x in doc.get("findings", []) if x["finding_id"] == finding_id), None)
    if f is None:
        return None
    sess = next((s for s in doc.get("sessions", []) if s["session_id"] == f["session_id"]), None)
    certs = [c for c in doc.get("certificates", []) if sess and c["session_id"] == sess["session_id"]]
    pos = f["evidence"].get("chain_position")
    related_cert = next((c for c in certs if c["chain_position"] == pos), None) if pos is not None else \
        next((c for c in certs if c["chain_position"] == 0), None)
    tls = (sess or {}).get("tls")
    frames = set(f["evidence_frames"])
    events = [e for e in (sess or {}).get("timeline", []) if e.get("frame") in frames or e.get("finding_id") == finding_id]
    if tls is None:
        tls_link = {"status": "NOT_OBSERVED", "reason": "No TLS handshake was observed in this session."}
    else:
        tls_link = {"status": "OBSERVED" if tls.get("negotiated_version") else "PARTIAL",
                    "negotiated_version": tls.get("negotiated_version"), "cipher_suite": tls.get("cipher_suite"),
                    "key_exchange": tls.get("key_exchange"), "key_exchange_group": tls.get("key_exchange_group"),
                    "forward_secrecy": tls.get("forward_secrecy"), "sni": tls.get("sni"),
                    "handshake_status": tls.get("handshake_status"),
                    "certificate_visibility": tls.get("certificate_visibility")}
    if related_cert:
        cert_link = {"status": "OBSERVED", "certificate_id": related_cert["certificate_id"],
                     "subject": related_cert["subject"], "issuer": related_cert["issuer"],
                     "serial_number": related_cert["serial_number"],
                     "fingerprint_sha256": related_cert["fingerprint_sha256"],
                     "not_before": related_cert["not_before"], "not_after": related_cert["not_after"],
                     "is_expired": related_cert["is_expired"], "chain_position": related_cert["chain_position"],
                     "trust": "NOT_EVALUATED (no trust anchors)"}
    elif tls and tls.get("certificate_visibility") == "encrypted_tls13":
        cert_link = {"status": "NOT_OBSERVABLE", "reason": "TLS 1.3 encrypts the server certificate."}
    else:
        cert_link = {"status": "NOT_OBSERVED", "reason": "No certificate was observed in this session."}
    return {
        "finding": {k: f[k] for k in ("finding_id", "rule_id", "title", "severity", "confidence", "evidence_type",
                                      "dimension", "description", "risk_contribution")},
        "session": None if sess is None else {
            "session_id": sess["session_id"], "protocol": sess["protocol"], "implicit_tls": sess["implicit_tls"],
            "client": sess["client"], "server": sess["server"], "start_time": sess["start_time"],
            "starttls_state": sess["starttls"]["final_state"], "detection": sess["detection"]},
        "tcp_stream": None if sess is None else {"stream_id": sess["stream_id"], "first_frame": sess["first_frame"],
                                                  "last_frame": sess["last_frame"],
                                                  "quality": sess["reconstruction"]["quality"]},
        "tls": tls_link,
        "certificate": cert_link,
        "evidence": {"class": f["evidence_type"], "values": f["evidence"], "frames": f["evidence_frames"],
                     "events": events},
        "recommendation": {"action": f["recommendation"], "why_it_matters": f.get("why_it_matters"),
                           "expected_effect": f.get("expected_effect"), "references": f["references"]},
        "policy_profile": doc.get("analysis", {}).get("policy_profile"),
    }
