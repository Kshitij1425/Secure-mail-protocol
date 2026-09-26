"""
SecureMailScope Core Orchestrator.

Runs the complete analysis pipeline on one capture file:

  ingest (PCAP/PCAPNG) -> TCP reassembly -> protocol detection -> STARTTLS state
  -> TLS handshake parsing -> X.509 analysis -> deterministic rules -> posture
  scoring -> supplementary ML anomaly detection

Every call builds fresh, capture-local state; nothing (including the ML model)
is shared between analyses.
"""
from typing import List, Dict, Any, Iterator, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
import time

from securemailscope.ingestion.reader import PcapIngestor
from securemailscope.tcp.stream import TCPReconstructor, TCPLimits, CLIENT_TO_SERVER, TCPStream
from securemailscope.protocols.detector import ProtocolDetector, EmailProtocol, ProtocolDetection, looks_like_tls_record
from securemailscope.starttls.machine import StartTLSMachine, TLSState
from securemailscope.tls.parser import TLSParser, TLSSessionData
from securemailscope.certificates.analyzer import CertificateAnalyzer, CertificateDetails
from securemailscope.rules.engine import SecurityPolicyEngine, FindingResult, POLICY_VERSION
from securemailscope.scoring.engine import SecurityPostureScorer
from securemailscope.scoring.models import PostureScore
from securemailscope.ml.anomaly_detector import AnomalyDetectionEngine, AnomalyResult
from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.core.orchestrator")

# Isolation Forest on a handful of points is not meaningful; below this the
# ML stage reports "insufficient sessions" instead of forcing outliers.
MIN_ML_SESSIONS = 5


@dataclass
class EmailSessionResult:
    """Persistable result for one recognised email TCP session."""
    session_id: str
    protocol: EmailProtocol
    stream: Any
    starttls_state: TLSState
    tls_data: Any = None
    certificates: List[Any] = field(default_factory=list)
    findings: List[FindingResult] = field(default_factory=list)
    anomaly: Any = None
    detection: Optional[ProtocolDetection] = None
    implicit_tls: bool = False
    starttls: Any = None
    chain: Dict[str, Any] = field(default_factory=dict)
    evidence_frames: Dict[str, int] = field(default_factory=dict)

    @property
    def tls_observed(self) -> bool:
        return bool(self.tls_data and self.tls_data.observed)


@dataclass
class OrchestratorResult:
    """Complete, typed output of the analysis pipeline."""
    posture: PostureScore
    metadata: Dict[str, Any]
    sessions: List[EmailSessionResult] = field(default_factory=list)
    findings: List[FindingResult] = field(default_factory=list)
    anomalies: List[AnomalyResult] = field(default_factory=list)

    @property
    def posture_score(self) -> PostureScore:
        return self.posture

    @property
    def finding_results(self) -> List[FindingResult]:
        return self.findings

    @property
    def anomaly_results(self) -> List[AnomalyResult]:
        return self.anomalies

    @property
    def packet_count(self) -> int:
        return int(self.metadata["total_packets"])

    @property
    def reconstructed_stream_count(self) -> int:
        return int(self.metadata["reconstructed_streams"])

    @property
    def email_session_count(self) -> int:
        return len(self.sessions)

    @property
    def tls_session_count(self) -> int:
        return sum(1 for s in self.sessions if s.tls_observed)

    # Keep the historical ``posture, metadata = analyze(...)`` API working.
    def __iter__(self) -> Iterator[Any]:
        yield self.posture
        yield self.metadata


class Orchestrator:
    """End-to-End Analysis Orchestrator."""

    def __init__(self, securemailscope_version: str = "0.2.0", max_packets: int = 0,
                 time_budget_seconds: float = 0.0, tcp_limits: Optional[TCPLimits] = None):
        self.version = securemailscope_version
        self.scorer = SecurityPostureScorer()
        self.max_packets = max_packets
        self.time_budget_seconds = time_budget_seconds
        self.tcp_limits = tcp_limits or TCPLimits()
        # Retained for callers that inspect it; a fresh engine is built per analysis.
        self.anomaly_engine = AnomalyDetectionEngine(contamination="auto", min_training_sessions=MIN_ML_SESSIONS)

    def analyze(self, filepath: str, session_prefix: str = "") -> OrchestratorResult:
        """Analyze one capture. ``session_prefix`` (e.g. "<capture_id>~") makes session,
        finding and certificate identifiers globally unique."""
        started = time.perf_counter()
        ingestor = PcapIngestor(filepath, max_packets=self.max_packets,
                                time_budget_seconds=self.time_budget_seconds)
        tcp_recon = TCPReconstructor(limits=self.tcp_limits)

        # Phase 1: ingestion + TCP reassembly. Format errors propagate as ValueError;
        # resource-limit violations propagate as AnalysisLimitExceeded.
        for ts, ip_pkt, frame in ingestor.read_packets():
            tcp_recon.process_packet(ip_pkt, ts, frame)
        t_ingest = time.perf_counter()

        streams = tcp_recon.get_streams()
        capture_time = self._capture_time(ingestor)
        detector = ProtocolDetector()
        email_sessions: List[EmailSessionResult] = []
        all_findings: List[FindingResult] = []
        skipped_no_payload = 0

        # Phase 2: per-stream application analysis.
        for stream in streams:
            if not stream.chunks:
                if stream.dst_port in (25, 110, 143, 465, 587, 993, 995, 2525):
                    skipped_no_payload += 1
                continue
            session = self._analyze_stream(stream, detector, capture_time, session_prefix)
            if session is None:
                continue
            email_sessions.append(session)
            all_findings.extend(session.findings)

        # Phase 3: supplementary ML (never alters findings or score).
        anomaly_results, ml_summary = self._run_ml(email_sessions, capture_time)
        for s in email_sessions:
            s.anomaly = next((a for a in anomaly_results if a.session_id == s.session_id), None)

        # Phase 4: posture scoring from deterministic findings only.
        tls_observed = sum(1 for s in email_sessions if s.tls_data and s.tls_data.server_version)
        coverage = {
            "email_sessions": len(email_sessions),
            "tls_observed": tls_observed,
            "certificates_observed": sum(1 for s in email_sessions if s.certificates),
            "certificates_encrypted": sum(1 for s in email_sessions
                                          if s.tls_data and s.tls_data.certificate_visibility == "encrypted_tls13"),
        }
        posture = self.scorer.calculate_posture(
            findings=all_findings,
            tls_session_count=sum(1 for s in email_sessions if s.tls_observed),
            protocol_session_count=len(email_sessions),
            securemailscope_version=self.version,
            coverage=coverage,
        )

        metadata = ingestor.get_metadata()
        tcp_stats = tcp_recon.get_statistics()
        metadata.update({
            "reconstructed_streams": len(streams),
            "packet_count": metadata.get("total_packets", 0),
            "email_session_count": len(email_sessions),
            "tls_session_count": sum(1 for s in email_sessions if s.tls_observed),
            "email_port_connections_without_payload": skipped_no_payload,
            "coverage": coverage,
            "tcp": tcp_stats,
            "ml_anomalies_detected": sum(1 for a in anomaly_results if a.is_anomaly),
            "ml_engine_summary": ml_summary,
            "rule_policy_version": POLICY_VERSION,
            "scoring_policy_version": posture.scoring_policy_version,
            "tool_version": self.version,
            "capture_start": capture_time.isoformat() if capture_time else None,
            "certificate_validity_reference": "capture_time" if capture_time else "analysis_time",
            "timings_seconds": {
                "ingest_and_reassembly": round(t_ingest - started, 4),
                "analysis_total": round(time.perf_counter() - started, 4),
            },
        })

        return OrchestratorResult(posture=posture, metadata=metadata, sessions=email_sessions,
                                  findings=all_findings, anomalies=anomaly_results)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _capture_time(ingestor: PcapIngestor) -> Optional[datetime]:
        ts = ingestor.stats.get("start_time")
        if ts is None:
            return None
        try:
            return datetime.fromtimestamp(float(ts), timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    def _analyze_stream(self, stream: TCPStream, detector: ProtocolDetector,
                        capture_time: Optional[datetime], session_prefix: str = "") -> Optional[EmailSessionResult]:
        server_bytes = stream.direction_payload("s2c")
        client_bytes = stream.direction_payload("c2s")
        det = detector.detect(server_bytes, port=stream.dst_port, client_payload=client_bytes)
        if det.protocol == EmailProtocol.UNKNOWN:
            return None

        machine = StartTLSMachine(det.protocol)
        parser = TLSParser()
        frames: Dict[str, int] = {}
        in_tls = False
        if det.implicit_tls:
            machine.mark_implicit_tls()
            in_tls = True

        for chunk in stream.chunks:
            is_client = chunk.direction == CLIENT_TO_SERVER
            direction = "c2s" if is_client else "s2c"
            if not in_tls and looks_like_tls_record(chunk.data):
                # TLS bytes without an observed STARTTLS acceptance (capture started late,
                # or the response was lost): parse them, and let the machine flag it.
                machine.process_binary(chunk.data)
                in_tls = True
            if in_tls:
                if machine.state.current_state == TLSState.STARTTLS_ACCEPTED:
                    machine.process_binary(chunk.data)
                parser.process_payload(chunk.data, direction=direction, frame=chunk.frame)
                continue
            frames.setdefault("first_plaintext", chunk.frame)
            state = machine.process_payload(chunk.data.decode("latin-1"), is_client, frame=chunk.frame)
            if state == TLSState.STARTTLS_ACCEPTED:
                in_tls = True

        machine.flush()
        tls_data: Optional[TLSSessionData] = parser.session if parser.session.observed else None
        final_state = machine.finalize(tls_data.handshake_status if tls_data else None)
        if tls_data and tls_data.app_data_seen.get("s2c") and final_state == TLSState.TLS_HANDSHAKE_STARTED \
                and tls_data.handshake_status == "complete":
            final_state = TLSState.TLS_ESTABLISHED

        ref_time = capture_time or datetime.fromtimestamp(stream.start_time, timezone.utc)
        certs: List[CertificateDetails] = []
        if tls_data:
            for pc in tls_data.certificates:
                d = CertificateAnalyzer.analyze_der(pc.raw_der, reference_time=ref_time,
                                                    reference_label="capture_time", position=pc.position)
                if d is not None:
                    certs.append(d)
        chain = CertificateAnalyzer.analyze_chain(certs) if certs else {}

        st = machine.state
        frames.update(st.evidence_frames)
        ctx = {
            "evidence_frames": frames,
            "starttls_advertised": st.starttls_advertised,
            "starttls_response": st.starttls_response,
            "starttls_attempts": st.starttls_attempts,
            "pipelined_after_starttls": st.pipelined_after_starttls,
            "plaintext_auth_mechanisms": list(st.plaintext_auth_mechanisms),
            "plaintext_mail_transaction": st.plaintext_mail_transaction,
            "plaintext_after_rejection": st.plaintext_after_rejection,
            "chain": chain,
        }
        session_id = f"{session_prefix}{stream.stream_id}"
        findings = SecurityPolicyEngine.evaluate_session(
            session_id=session_id, protocol=det.protocol, starttls_state=final_state,
            tls_data=tls_data, certs=certs, session_context=ctx)
        for f in findings:
            f.session_id = f.session_id or session_id

        return EmailSessionResult(
            session_id=session_id, protocol=det.protocol, stream=stream, starttls_state=final_state,
            tls_data=tls_data, certificates=certs, findings=findings, detection=det,
            implicit_tls=det.implicit_tls, starttls=st, chain=chain, evidence_frames=frames)

    def _run_ml(self, sessions: List[EmailSessionResult], capture_time: Optional[datetime]):
        engine = AnomalyDetectionEngine(contamination="auto", min_training_sessions=MIN_ML_SESSIONS)
        self.anomaly_engine = engine
        candidates = [s for s in sessions if s.tls_data and s.tls_data.server_version]
        rows = [{
            "session_id": s.session_id,
            "protocol": s.protocol,
            "tls_data": s.tls_data,
            "certs": s.certificates,
            "packet_count": s.stream.packets_analyzed,
            "duration": max(0.0, s.stream.end_time - s.stream.start_time),
        } for s in candidates]
        results: List[AnomalyResult] = []
        if engine.train_on_sessions(rows, EmailProtocol.SMTP, reference_time=capture_time):
            results = engine.detect_anomalies(rows, reference_time=capture_time)
        summary = engine.get_summary()
        summary["candidate_sessions"] = len(rows)
        return results, summary
