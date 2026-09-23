"""
E2E Validation Harness for SecureMailScope.
Ties M1-M8 together and validates against ground truth json files.
"""
import pytest
import json
from pathlib import Path
from typing import List, Dict, Any

from securemailscope.ingestion.reader import PcapIngestor
from securemailscope.tcp.stream import TCPReconstructor
from securemailscope.protocols.detector import ProtocolDetector, EmailProtocol
from securemailscope.starttls.machine import StartTLSMachine, TLSState
from securemailscope.tls.parser import TLSParser
from securemailscope.certificates.analyzer import CertificateAnalyzer
from securemailscope.rules.engine import SecurityPolicyEngine, FindingResult

def analyze_pcap(filepath: str) -> Dict[str, Any]:
    """Orchestrates the entire M1-M8 pipeline. (Mimics core engine)"""
    # 1. Ingestion
    ingestor = PcapIngestor(filepath)
    # 2. TCP Reconstruction
    tcp_recon = TCPReconstructor()

    for ts, ip_pkt, _ in ingestor.read_packets():
        tcp_recon.process_packet(ip_pkt, ts)

    streams = tcp_recon.get_streams()
    proto_detector = ProtocolDetector()

    results = []

    # Process each reconstructed stream
    for stream in streams:
        # Sort packets chronologically by timestamp for correct state machine processing
        # (not by sequence number, since client/server have different sequence spaces)
        sorted_pkts = sorted(stream.packets, key=lambda p: p.timestamp)

        # Separate client vs server payloads based on actual packet direction
        client_to_server_payload = b""
        server_to_client_payload = b""

        for pkt in sorted_pkts:
            # Determine direction based on src_port relative to stream's src/dst ports
            # This handles the case where packets may have been mis-assigned during reconstruction
            if pkt.src_port == stream.src_port and pkt.dst_port == stream.dst_port:
                # Packet flows client -> server (same direction as first packet)
                client_to_server_payload += pkt.payload
            elif pkt.src_port == stream.dst_port and pkt.dst_port == stream.src_port:
                # Packet flows server -> client (reverse direction)
                server_to_client_payload += pkt.payload
            else:
                # Fallback: assume first packet direction for unknown packets
                if pkt.src_port == stream.src_port:
                    client_to_server_payload += pkt.payload
                else:
                    server_to_client_payload += pkt.payload

        # Combine for initial protocol detection (server payload first for banners)
        full_initial_payload = server_to_client_payload + client_to_server_payload

        # 3. Protocol Detection
        proto_det = proto_detector.detect(full_initial_payload, port=stream.dst_port)
        if proto_det.protocol == EmailProtocol.UNKNOWN:
            continue

        # 4 & 5. STARTTLS Machine & TLS Parsing
        tls_machine = StartTLSMachine(proto_det.protocol)
        tls_parser = TLSParser()
        tls_data = None
        certs = []

        is_currently_tls = False

        # Read packets chronologically to drive the state machine
        for pkt in sorted_pkts:
            if not pkt.payload:
                continue

            is_from_client = (pkt.src_port == stream.src_port)

            if not is_currently_tls:
                # Text processing
                try:
                    text = pkt.payload.decode('latin-1')
                    state = tls_machine.process_payload(text, is_from_client)
                    if state == TLSState.STARTTLS_ACCEPTED:
                        is_currently_tls = True
                except UnicodeDecodeError:
                    pass
            else:
                # Binary (TLS) processing
                state = tls_machine.process_binary(pkt.payload)
                tls_data = tls_parser.process_payload(pkt.payload)

        # 6. Certificate Analysis
        if tls_data:
            for raw_cert in tls_data.certificates:
                cert_details = CertificateAnalyzer.analyze_der(raw_cert.raw_der)
                if cert_details:
                    certs.append(cert_details)

        # 7. Rules Engine
        findings = SecurityPolicyEngine.evaluate_session(
            session_id=stream.stream_id,
            protocol=proto_det.protocol,
            starttls_state=tls_machine.state.current_state,
            tls_data=tls_data,
            certs=certs
        )

        results.append({
            "stream_id": stream.stream_id,
            "protocol": proto_det.protocol.name,
            "reconstruction_quality": stream.reconstruction_quality,
            "findings": [f.rule_id for f in findings],
            "anomalies": list(tls_machine.state.anomalies) if tls_machine.state.anomalies else []
        })

    return {
        "metadata": ingestor.get_metadata(),
        "streams": results
    }


def get_test_fixtures():
    """Load all PCAP + JSON pairs from tests/robustness/fixtures/"""
    base = Path("C:/Users/kshit/SecureMailScope/backend/tests/robustness/fixtures")
    pcap_dir = base / "pcaps"
    gt_dir = base / "ground_truth"

    fixtures = []
    if not pcap_dir.exists():
        return fixtures

    for pcap_file in pcap_dir.glob("*.pcap"):
        gt_file = gt_dir / f"{pcap_file.stem}.json"
        if gt_file.exists():
            fixtures.append((str(pcap_file), str(gt_file)))

    return fixtures


@pytest.mark.parametrize("pcap_file, gt_file", get_test_fixtures())
def test_end_to_end_validation(pcap_file, gt_file):
    """Run E2E validation against ground truth."""
    with open(gt_file, "r") as f:
        ground_truth = json.load(f)

    result = analyze_pcap(pcap_file)

    assert len(result["streams"]) == 1, f"Expected 1 stream, got {len(result['streams'])}"
    stream = result["streams"][0]

    # Compare against Ground Truth
    assert stream["protocol"] == ground_truth["expected_protocol"]
    assert stream["reconstruction_quality"] == ground_truth["expected_reconstruction_quality"]

    # Verify findings match
    actual_findings = set(stream["findings"])
    expected_findings = set(ground_truth["expected_findings"])
    assert actual_findings == expected_findings, f"Findings mismatch. Expected {expected_findings}, got {actual_findings}"

    # Verify anomalies
    actual_anomalies = set(stream["anomalies"])
    expected_anomalies = set(ground_truth["expected_anomalies"])
    assert actual_anomalies == expected_anomalies, f"Anomalies mismatch. Expected {expected_anomalies}, got {actual_anomalies}"
