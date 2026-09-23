"""
SecureMailScope Core Orchestrator.
Orchestrates the entire M1-M11 pipeline, consuming a PCAP and yielding a PostureScore with ML anomalies.
"""
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import datetime
import traceback

from securemailscope.ingestion.reader import PcapIngestor
from securemailscope.tcp.stream import TCPReconstructor
from securemailscope.protocols.detector import ProtocolDetector, EmailProtocol
from securemailscope.starttls.machine import StartTLSMachine, TLSState
from securemailscope.tls.parser import TLSParser
from securemailscope.certificates.analyzer import CertificateAnalyzer
from securemailscope.rules.engine import SecurityPolicyEngine, FindingResult
from securemailscope.scoring.engine import SecurityPostureScorer
from securemailscope.scoring.models import PostureScore
from securemailscope.ml.feature_extractor import FeatureExtractor
from securemailscope.ml.anomaly_detector import AnomalyDetectionEngine


class Orchestrator:
    """End-to-End Analysis Orchestrator."""

    def __init__(self, securemailscope_version: str = "0.1.0"):
        self.version = securemailscope_version
        self.scorer = SecurityPostureScorer()
        self.anomaly_engine = AnomalyDetectionEngine(contamination=0.1)

    def analyze(self, filepath: str) -> Tuple[PostureScore, Dict[str, Any]]:
        """
        Runs the full M1-M11 pipeline against a PCAP file.

        Returns:
            Tuple of (PostureScore, metadata)
        """
        ingestor = PcapIngestor(filepath)
        tcp_recon = TCPReconstructor()

        # Phase 1: Ingestion & TCP Stream Assembly
        try:
            for ts, ip_pkt, _ in ingestor.read_packets():
                tcp_recon.process_packet(ip_pkt, ts)
        except Exception as e:
            # Handle corrupt PCAPs
            raise ValueError(f"Failed to ingest capture: {str(e)}")

        streams = tcp_recon.get_streams()
        proto_detector = ProtocolDetector()

        all_findings: List[FindingResult] = []
        tls_session_count = 0
        protocol_session_count = 0
        session_data_for_ml = []
        anomaly_results = []

        # Phase 2: Per-stream analysis
        for stream in streams:
            sorted_pkts = sorted(stream.packets, key=lambda p: p.timestamp)

            client_to_server_payload = b""
            server_to_client_payload = b""

            for pkt in sorted_pkts:
                if pkt.src_port == stream.src_port and pkt.dst_port == stream.dst_port:
                    client_to_server_payload += pkt.payload
                elif pkt.src_port == stream.dst_port and pkt.dst_port == stream.src_port:
                    server_to_client_payload += pkt.payload
                else:
                    if pkt.src_port == stream.src_port:
                        client_to_server_payload += pkt.payload
                    else:
                        server_to_client_payload += pkt.payload

            full_initial_payload = server_to_client_payload + client_to_server_payload

            # Protocol Detection
            proto_det = proto_detector.detect(full_initial_payload, port=stream.dst_port)
            if proto_det.protocol == EmailProtocol.UNKNOWN:
                continue

            protocol_session_count += 1

            # Engine & State Machine
            tls_machine = StartTLSMachine(proto_det.protocol)
            tls_parser = TLSParser()
            tls_data = None
            certs = []

            is_currently_tls = False

            for pkt in sorted_pkts:
                if not pkt.payload:
                    continue

                is_from_client = (pkt.src_port == stream.src_port)

                if not is_currently_tls:
                    try:
                        text = pkt.payload.decode('latin-1')
                        state = tls_machine.process_payload(text, is_from_client)
                        if state == TLSState.STARTTLS_ACCEPTED:
                            is_currently_tls = True
                    except UnicodeDecodeError:
                        pass
                else:
                    state = tls_machine.process_binary(pkt.payload)
                    parsed_tls = tls_parser.process_payload(pkt.payload)
                    # For simplicity, if we get any TLS data, we keep the latest or merge it.
                    # TLSParser currently merges state into the returned object or returns the accumulated state.
                    if parsed_tls:
                        tls_data = parsed_tls

            # Check if this stream ever established TLS
            if is_currently_tls or (tls_data and tls_data.tls_version):
                tls_session_count += 1

            # Certificate Analysis
            if tls_data:
                for raw_cert in tls_data.certificates:
                    cert_details = CertificateAnalyzer.analyze_der(raw_cert.raw_der)
                    if cert_details:
                        certs.append(cert_details)

            # Store session data for ML training/detection
            if tls_data:
                session_duration = (sorted_pkts[-1].timestamp - sorted_pkts[0].timestamp) if sorted_pkts else 0.0
                session_data_for_ml.append({
                    "session_id": stream.stream_id,
                    "tls_data": tls_data,
                    "certs": certs,
                    "packet_count": len(sorted_pkts),
                    "duration": session_duration
                })

            # Rule Engine
            findings = SecurityPolicyEngine.evaluate_session(
                session_id=stream.stream_id,
                protocol=proto_det.protocol,
                starttls_state=tls_machine.state.current_state,
                tls_data=tls_data,
                certs=certs
            )

            all_findings.extend(findings)

        # Phase 3: ML Anomaly Detection (train on observed sessions, detect outliers)
        if session_data_for_ml and len(session_data_for_ml) >= 3:
            # Train on all TLS sessions in the capture
            proto_for_training = EmailProtocol.SMTP  # Default; could detect dominant protocol
            if session_data_for_ml:
                self.anomaly_engine.train_on_sessions(session_data_for_ml, proto_for_training)

                # Detect anomalies in each session
                for session in session_data_for_ml:
                    anomaly_result = self.anomaly_engine.detect_anomaly(
                        session_id=session["session_id"],
                        protocol=proto_for_training,
                        tls_data=session["tls_data"],
                        certs=session["certs"],
                        packet_count=session["packet_count"],
                        duration=session["duration"]
                    )
                    if anomaly_result:
                        anomaly_results.append(anomaly_result)

        # Phase 4: Posture Scoring
        posture = self.scorer.calculate_posture(
            findings=all_findings,
            tls_session_count=tls_session_count,
            protocol_session_count=protocol_session_count,
            securemailscope_version=self.version
        )

        metadata = ingestor.get_metadata()
        metadata["reconstructed_streams"] = len(streams)
        metadata["ml_anomalies_detected"] = len([a for a in anomaly_results if a.is_anomaly])
        metadata["ml_engine_summary"] = self.anomaly_engine.get_summary()

        return posture, metadata
