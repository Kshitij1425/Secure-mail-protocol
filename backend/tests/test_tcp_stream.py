import pytest
import dpkt
import time
from securemailscope.tcp.stream import TCPReconstructor, TCPStream, TCPPacket

def test_tcp_stream_syn_ack():
    """Test TCP stream reconstruction with SYN and SYN-ACK packets."""
    recon = TCPReconstructor()

    # Create SYN packet (client -> server)
    tcp_syn = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
    ip_syn = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn)
    ip_syn.len = len(ip_syn)

    # Create SYN-ACK packet (server -> client)
    tcp_syn_ack = dpkt.tcp.TCP(sport=25, dport=12345, seq=200, ack=101, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    ip_syn_ack = dpkt.ip.IP(src=b"\x7f\x00\x00\x02", dst=b"\x7f\x00\x00\x01", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn_ack)
    ip_syn_ack.len = len(ip_syn_ack)

    recon.process_packet(ip_syn, time.time())
    recon.process_packet(ip_syn_ack, time.time() + 0.01)

    streams = recon.get_streams()
    assert len(streams) == 1
    stream = streams[0]
    assert stream.reconstruction_quality in ("complete", "incomplete", "partial")
    assert stream.packets_analyzed == 2

def test_tcp_stream_rst():
    """Test that RST packets mark a stream as malformed."""
    recon = TCPReconstructor()

    tcp_syn = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
    ip_syn = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn)
    ip_syn.len = len(ip_syn)

    tcp_rst = dpkt.tcp.TCP(sport=25, dport=12345, seq=200, flags=dpkt.tcp.TH_RST)
    ip_rst = dpkt.ip.IP(src=b"\x7f\x00\x00\x02", dst=b"\x7f\x00\x00\x01", p=dpkt.ip.IP_PROTO_TCP, data=tcp_rst)
    ip_rst.len = len(ip_rst)

    recon.process_packet(ip_syn, time.time())
    recon.process_packet(ip_rst, time.time() + 0.01)

    streams = recon.get_streams()
    assert len(streams) == 1
    assert streams[0].reconstruction_quality == "malformed"

def test_tcp_stream_payload():
    """Test that payload data is captured in the stream."""
    recon = TCPReconstructor()

    tcp_syn = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
    ip_syn = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn)
    ip_syn.len = len(ip_syn)

    tcp_data = dpkt.tcp.TCP(sport=12345, dport=25, seq=101, ack=201, flags=dpkt.tcp.TH_ACK, data=b"hello")
    ip_data = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp_data)
    ip_data.len = len(ip_data)

    recon.process_packet(ip_syn, time.time())
    recon.process_packet(ip_data, time.time() + 0.01)

    streams = recon.get_streams()
    assert len(streams) == 1
    assert streams[0].payload_bytes == 5

def test_tcp_stream_id_consistency():
    """Test that stream IDs are consistent regardless of packet order."""
    recon = TCPReconstructor()

    tcp_syn = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
    ip_syn = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn)
    ip_syn.len = len(ip_syn)

    tcp_syn_ack = dpkt.tcp.TCP(sport=25, dport=12345, seq=200, ack=101, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
    ip_syn_ack = dpkt.ip.IP(src=b"\x7f\x00\x00\x02", dst=b"\x7f\x00\x00\x01", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn_ack)
    ip_syn_ack.len = len(ip_syn_ack)

    # Process in reverse order
    recon.process_packet(ip_syn_ack, time.time())
    recon.process_packet(ip_syn, time.time() + 0.01)

    streams = recon.get_streams()
    assert len(streams) == 1

def test_tcp_stream_multiple_streams():
    """Test that multiple independent TCP streams are tracked separately."""
    recon = TCPReconstructor()

    # Stream 1
    tcp1 = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
    ip1 = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp1)
    ip1.len = len(ip1)

    # Stream 2
    tcp2 = dpkt.tcp.TCP(sport=54321, dport=80, seq=500, flags=dpkt.tcp.TH_SYN)
    ip2 = dpkt.ip.IP(src=b"\x7f\x00\x00\x03", dst=b"\x7f\x00\x00\x04", p=dpkt.ip.IP_PROTO_TCP, data=tcp2)
    ip2.len = len(ip2)

    recon.process_packet(ip1, time.time())
    recon.process_packet(ip2, time.time() + 0.01)

    streams = recon.get_streams()
    assert len(streams) == 2

def test_tcp_stream_statistics():
    """Test that stream statistics are correctly computed."""
    recon = TCPReconstructor()

    tcp_syn = dpkt.tcp.TCP(sport=12345, dport=25, seq=100, flags=dpkt.tcp.TH_SYN)
    ip_syn = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp_syn)
    ip_syn.len = len(ip_syn)

    recon.process_packet(ip_syn, time.time())

    stats = recon.get_statistics()
    assert stats["total_streams"] == 1
    assert stats["total_packets_processed"] == 1
    assert "quality_distribution" in stats

def test_tcp_stream_no_tcp():
    """Test that non-TCP packets are ignored."""
    recon = TCPReconstructor()

    # Create UDP packet
    udp = dpkt.udp.UDP(sport=12345, dport=25)
    ip_udp = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x02", p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip_udp.len = len(ip_udp)

    result = recon.process_packet(ip_udp, time.time())
    assert result is None
    assert len(recon.get_streams()) == 0