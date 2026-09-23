"""
Performance Benchmark Suite for SecureMailScope M1-M8 Pipeline.
Measures processing time, memory usage, and throughput on representative captures.
"""
import time
import psutil
import os
from pathlib import Path
from typing import Dict, Any

from securemailscope.ingestion.reader import PcapIngestor
from securemailscope.tcp.stream import TCPReconstructor
from securemailscope.protocols.detector import ProtocolDetector, EmailProtocol
from securemailscope.starttls.machine import StartTLSMachine, TLSState
from securemailscope.tls.parser import TLSParser
from securemailscope.certificates.analyzer import CertificateAnalyzer
from securemailscope.rules.engine import SecurityPolicyEngine


def benchmark_pcap(filepath: str) -> Dict[str, Any]:
    """
    Run M1-M8 pipeline on a PCAP and collect performance metrics.
    """
    # Get file size
    file_size_bytes = os.path.getsize(filepath)
    file_size_mb = file_size_bytes / (1024 * 1024)

    # Track memory before
    process = psutil.Process()
    mem_before = process.memory_info().rss / (1024 * 1024)  # MB

    start_time = time.time()

    # === M1-M8 Pipeline ===
    ingestor = PcapIngestor(filepath)
    tcp_recon = TCPReconstructor()

    packet_count = 0
    for ts, ip_pkt, _ in ingestor.read_packets():
        tcp_recon.process_packet(ip_pkt, ts)
        packet_count += 1

    streams = tcp_recon.get_streams()
    proto_detector = ProtocolDetector()

    session_count = 0
    tls_session_count = 0
    finding_count = 0

    for stream in streams:
        sorted_pkts = sorted(stream.packets, key=lambda p: p.timestamp)

        server_to_client_payload = b""
        client_to_server_payload = b""

        for pkt in sorted_pkts:
            if pkt.src_port == stream.src_port and pkt.dst_port == stream.dst_port:
                client_to_server_payload += pkt.payload
            elif pkt.src_port == stream.dst_port and pkt.dst_port == stream.src_port:
                server_to_client_payload += pkt.payload

        full_initial_payload = server_to_client_payload + client_to_server_payload

        proto_det = proto_detector.detect(full_initial_payload, port=stream.dst_port)
        if proto_det.protocol == EmailProtocol.UNKNOWN:
            continue

        session_count += 1

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
                tls_data = tls_parser.process_payload(pkt.payload)

        if tls_data and tls_data.handshake_complete:
            tls_session_count += 1

        if tls_data:
            for raw_cert in tls_data.certificates:
                cert_details = CertificateAnalyzer.analyze_der(raw_cert.raw_der)
                if cert_details:
                    certs.append(cert_details)

        findings = SecurityPolicyEngine.evaluate_session(
            session_id=stream.stream_id,
            protocol=proto_det.protocol,
            starttls_state=tls_machine.state.current_state,
            tls_data=tls_data,
            certs=certs
        )

        finding_count += len(findings)

    end_time = time.time()

    # Track memory after
    mem_after = process.memory_info().rss / (1024 * 1024)  # MB
    mem_peak = mem_after - mem_before

    elapsed = end_time - start_time

    return {
        "file_path": filepath,
        "file_size_bytes": file_size_bytes,
        "file_size_mb": round(file_size_mb, 3),
        "packet_count": packet_count,
        "stream_count": len(streams),
        "session_count": session_count,
        "tls_session_count": tls_session_count,
        "finding_count": finding_count,
        "processing_time_sec": round(elapsed, 4),
        "throughput_packets_per_sec": round(packet_count / elapsed, 2) if elapsed > 0 else 0,
        "throughput_mb_per_sec": round(file_size_mb / elapsed, 3) if elapsed > 0 else 0,
        "memory_delta_mb": round(mem_peak, 2)
    }


def run_benchmark_suite():
    """Run benchmark on all available test fixtures."""
    base = Path("C:/Users/kshit/SecureMailScope/backend/tests/robustness/fixtures/pcaps")
    results = []

    print("=" * 80)
    print("SecureMailScope M1-M8 Performance Benchmark")
    print("=" * 80)

    for pcap_file in sorted(base.glob("*.pcap")):
        print(f"\nBenchmarking: {pcap_file.name}")
        result = benchmark_pcap(str(pcap_file))
        results.append(result)

        print(f"  File Size: {result['file_size_mb']} MB ({result['file_size_bytes']} bytes)")
        print(f"  Packets: {result['packet_count']}")
        print(f"  Streams: {result['stream_count']}")
        print(f"  Email Sessions: {result['session_count']}")
        print(f"  TLS Sessions: {result['tls_session_count']}")
        print(f"  Findings: {result['finding_count']}")
        print(f"  Processing Time: {result['processing_time_sec']} sec")
        print(f"  Throughput: {result['throughput_packets_per_sec']} packets/sec, {result['throughput_mb_per_sec']} MB/sec")
        print(f"  Memory Delta: {result['memory_delta_mb']} MB")

    print("\n" + "=" * 80)
    print("Aggregate Statistics")
    print("=" * 80)

    total_packets = sum(r['packet_count'] for r in results)
    total_time = sum(r['processing_time_sec'] for r in results)
    total_size_mb = sum(r['file_size_mb'] for r in results)
    total_sessions = sum(r['session_count'] for r in results)
    total_tls = sum(r['tls_session_count'] for r in results)
    total_findings = sum(r['finding_count'] for r in results)
    avg_throughput_pps = total_packets / total_time if total_time > 0 else 0
    avg_throughput_mbps = total_size_mb / total_time if total_time > 0 else 0

    print(f"Total Files Benchmarked: {len(results)}")
    print(f"Total Packets Processed: {total_packets}")
    print(f"Total Size: {round(total_size_mb, 3)} MB")
    print(f"Total Processing Time: {round(total_time, 4)} sec")
    print(f"Total Email Sessions: {total_sessions}")
    print(f"Total TLS Sessions: {total_tls}")
    print(f"Total Findings: {total_findings}")
    print(f"Average Throughput: {round(avg_throughput_pps, 2)} packets/sec, {round(avg_throughput_mbps, 3)} MB/sec")
    print("=" * 80)

    return results


if __name__ == "__main__":
    run_benchmark_suite()
