import pytest
import dpkt
import io
import time
from securemailscope.ingestion.reader import PcapIngestor

def test_pcap_ingestion_synthetic(tmp_path):
    """Test reading a simple synthetic PCAP file using dpkt."""
    pcap_file = tmp_path / "test.pcap"

    # Create a synthetic PCAP with 2 TCP packets
    with open(pcap_file, "wb") as f:
        writer = dpkt.pcap.Writer(f)

        # Build Ethernet + IP + TCP packet 1
        tcp1 = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
        ip1 = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01", p=dpkt.ip.IP_PROTO_TCP, data=tcp1)
        ip1.len = len(ip1)
        eth1 = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip1)
        writer.writepkt(eth1, time.time())

        # Build Ethernet + IP + TCP packet 2
        tcp2 = dpkt.tcp.TCP(sport=25, dport=12345, seq=200, ack=101, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        ip2 = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01", p=dpkt.ip.IP_PROTO_TCP, data=tcp2)
        ip2.len = len(ip2)
        eth2 = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip2)
        writer.writepkt(eth2, time.time() + 0.01)

    ingestor = PcapIngestor(str(pcap_file))
    meta = ingestor.get_metadata()

    assert meta["filename"] == "test.pcap"
    assert len(meta["sha256"]) == 64

    packets = list(ingestor.read_packets())
    assert len(packets) == 2
    assert ingestor.stats["valid_packets"] == 2
    assert ingestor.stats["malformed_packets"] == 0
