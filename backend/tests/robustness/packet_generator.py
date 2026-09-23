"""
Synthetic Packet Generator for Robustness Testing
Generates PCAP files with intentional TCP irregularities to test reconstruction logic.
"""
import time
import dpkt
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional

class SyntheticPCAPGenerator:
    """Generates synthetic PCAPs with controlled TCP behaviors."""

    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        # Using PCAP writer (standard, faster for our synthetic needs)
        self.writer = None
        self.file_obj = None

    def __enter__(self):
        self.file_obj = open(self.output_path, "wb")
        self.writer = dpkt.pcap.Writer(self.file_obj)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file_obj:
            self.file_obj.close()

    def write_packet(self, ts: float, src_ip: bytes, dst_ip: bytes,
                     sport: int, dport: int, seq: int, ack: int,
                     flags: int, payload: bytes = b""):
        """Write a single full Ethernet->IP->TCP packet."""
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=payload)
        ip = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        self.writer.writepkt(eth, ts)

class GroundTruthGenerator:
    """Creates ground truth files alongside PCAPs."""

    @staticmethod
    def generate(filepath: str, name: str, expected_protocol: str, expected_tls: bool,
                 expected_findings: List[str], expected_reconstruction_quality: str,
                 expected_anomalies: List[str] = None):
        """Write ground truth JSON spec."""
        truth = {
            "name": name,
            "expected_protocol": expected_protocol,
            "expected_tls": expected_tls,
            "expected_reconstruction_quality": expected_reconstruction_quality,
            "expected_findings": expected_findings,
            "expected_anomalies": expected_anomalies or []
        }
        with open(filepath, "w") as f:
            json.dump(truth, f, indent=2)

def generate_robustness_fixtures(base_dir: str):
    """Generate the suite of robustness PCAPs and their ground truths."""
    base = Path(base_dir)
    pcap_dir = base / "pcaps"
    gt_dir = base / "ground_truth"
    pcap_dir.mkdir(exist_ok=True, parents=True)
    gt_dir.mkdir(exist_ok=True, parents=True)

    c_ip = b"\x0a\x00\x00\x01" # 10.0.0.1
    s_ip = b"\x0a\x00\x00\x02" # 10.0.0.2
    c_port = 12345
    s_port = 25
    ts_base = 1700000000.0

    # 1. Clean Baseline (SMTP, Plaintext)
    name = "clean_baseline"
    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        # Handshake: ISN c=100, s=200. SYN consumes 1 seq each side.
        gen.write_packet(ts_base, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_base + 0.1, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_base + 0.2, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        # Auth / Banner (server seq=201, len=28)
        gen.write_packet(ts_base + 0.3, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        # Client EHLO (client seq=101, len=13)
        gen.write_packet(ts_base + 0.4, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"EHLO client.com\r\n")

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", False,
        ["PROTO-001"], # Expected unencrypted email finding
        "complete"
    )

    # 2. Out-of-Order Segments (TCP)
    name = "out_of_order"
    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        # Handshake
        gen.write_packet(ts_base, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_base + 0.1, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_base + 0.2, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)

        # OOO: App Layer (Server sends banner, but client EHLO arrives BEFORE banner in capture)
        # Server banner is seq=201, len=28
        server_banner_ts = ts_base + 0.4
        client_ehlo_ts = ts_base + 0.3

        gen.write_packet(client_ehlo_ts, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"EHLO client.com\r\n")
        gen.write_packet(server_banner_ts, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", False,
        ["PROTO-001"],
        "complete" # The recombiner should sort by seq
    )

    # 3. Retransmissions
    name = "retransmissions"
    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts_base, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_base + 0.1, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_base + 0.2, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)

        # Banner sent
        gen.write_packet(ts_base + 0.3, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        # Banner re-sent (retransmission)
        gen.write_packet(ts_base + 0.35, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", False,
        ["PROTO-001"],
        "complete" # Retransmissions should be detected but still considered complete
    )

    # 4. Missing Segment / Truncated Stream
    name = "missing_segment"
    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        gen.write_packet(ts_base, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_base + 0.1, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_base + 0.2, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)

        # Gap in sequence numbers (201 -> 300 missing, jumps to 300)
        gen.write_packet(ts_base + 0.3, s_ip, c_ip, s_port, c_port, 300, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")

    GroundTruthGenerator.generate(
        str(gt_dir / f"{name}.json"), name, "SMTP", False,
        ["PROTO-001"],
        "partial" # partial quality because of missing seq
    )

    print(f"Generated robustness fixtures in {base_dir}")

if __name__ == "__main__":
    generate_robustness_fixtures("C:/Users/kshit/SecureMailScope/backend/tests/robustness/fixtures")
