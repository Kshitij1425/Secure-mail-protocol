#!/usr/bin/env python3
"""
Generate a beautiful synthetic .pcap for SecureMailScope upload.
Contains: TLS handshake, SMTP + STARTTLS, HTTP GET / API call, and anomalous flows.
"""
import random
from scapy.all import (
    Ether, IP, TCP, UDP, Raw,
    wrpcap
)
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# Build packets
def make_tcp_flow(src_ip, dst_ip, src_port, dst_port, payload_bytes, flags="PA"):
    eth = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=random.randint(1000, 9999))
    tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=random.randint(100000, 999999))
    pkt = eth / ip / tcp / Raw(load=payload_bytes)
    return pkt

# 1. TLS handshake (ClientHello) — beautiful purple theme
pkt_tls_client = make_tcp_flow(
    src_ip="192.168.10.5", dst_ip="93.184.216.34",
    src_port=54321, dst_port=443,
    payload_bytes=b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03\x03" + b"\x00" * 20,
    flags="S"
)

# 2. SMTP greeting + STARTTLS — enterprise mail
pkt_smtp_220 = make_tcp_flow(
    src_ip="10.0.0.15", dst_ip="192.168.88.20",
    src_port=45678, dst_port=25,
    payload_bytes=b"220 mail.corp.local ESMTP SecureMailScope Ready\r\n",
    flags="PA"
)

pkt_smtp_starttls = make_tcp_flow(
    src_ip="10.0.0.15", dst_ip="192.168.88.20",
    src_port=45678, dst_port=25,
    payload_bytes=b"STARTTLS\r\n",
    flags="PA"
)

# 3. HTTP GET to /api/health — modern REST
pkt_http = make_tcp_flow(
    src_ip="172.16.1.100", dst_ip="localhost",
    src_port=58765, dst_port=8000,
    payload_bytes=b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nUser-Agent: SecureMailScope/1.0\r\n\r\n",
    flags="PA"
)

# 4. Anomaly: malformed TLS version + large payload (potential exfil)
pkt_anomaly = make_tcp_flow(
    src_ip="192.168.99.99", dst_ip="10.10.10.10",
    src_port=9999, dst_port=4444,
    payload_bytes=b"\xde\xad\xbe\xef" + b"X" * 512 + b"\n[ANOMALY] oversized_tunnel",
    flags="PA"
)

# 5. DNS query to 8.8.8.8 over UDP
pkt_dns = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53, dport=53) / Raw(load=b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06secure\x04mail\x03com\x00\x00\x01\x00\x01")

packets = [
    pkt_tls_client, pkt_smtp_220, pkt_smtp_starttls,
    pkt_http, pkt_anomaly, pkt_dns,
    # Duplicate with slightly different timing for flow richness
    make_tcp_flow("192.168.10.5", "93.184.216.34", 54321, 443, b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x03\x03" + b"\x01" * 20, flags="PA"),
]

output_path = "C:\\Users\\kshit\\SecureMailScope\\beautiful_synthetic.pcap"
wrpcap(output_path, packets)
print(f"Created beautiful PCAP: {output_path} ({len(packets)} packets, ~{sum(len(bytes(p)) for p in packets)} bytes)")
