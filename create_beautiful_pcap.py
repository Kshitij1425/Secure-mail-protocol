#!/usr/bin/env python3
"""Generate a beautiful synthetic PCAP file for SecureMailScope demo uploads."""
from scapy.all import IP, TCP, UDP, Raw, wrpcap
import os

# Create packets for a synthetic email/session capture
packets = []

# 1. SMTP handshake (port 25) - synthetic
packets.append(IP(src="192.168.1.100", dst="10.0.0.5")/TCP(sport=54321, dport=25, flags="S"))
packets.append(IP(src="10.0.0.5", dst="192.168.1.100")/TCP(sport=25, dport=54321, flags="SA"))
packets.append(IP(src="192.168.1.100", dst="10.0.0.5")/TCP(sport=54321, dport=25, flags="A"))
packets.append(IP(src="192.168.1.100", dst="10.0.0.5")/TCP(sport=54321, dport=25, flags="PA")/Raw(b"EHLO demo.securemail.local\r\n"))
packets.append(IP(src="10.0.0.5", dst="192.168.1.100")/TCP(sport=25, dport=54321, flags="A"))

# 2. TLS handshake to secure email server (port 465 / SMTPS)
packets.append(IP(src="192.168.1.100", dst="10.0.0.10")/TCP(sport=54322, dport=465, flags="S"))
packets.append(IP(src="10.0.0.10", dst="192.168.1.100")/TCP(sport=465, dport=54322, flags="SA"))
packets.append(IP(src="192.168.1.100", dst="10.0.0.10")/TCP(sport=54322, dport=465, flags="A"))

# 3. DNS query / response (port 53)
packets.append(IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54323, dport=53)/Raw(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"))
packets.append(IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=54323)/Raw(b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\x00\x05\x01\x01\x01\x01"))

# 4. HTTPS session (port 443) - synthetic TLS + HTTP headers
packets.append(IP(src="192.168.1.100", dst="10.0.0.20")/TCP(sport=54324, dport=443, flags="S"))
packets.append(IP(src="10.0.0.20", dst="192.168.1.100")/TCP(sport=443, dport=54324, flags="SA"))
packets.append(IP(src="192.168.1.100", dst="10.0.0.20")/TCP(sport=54324, dport=443, flags="A"))

# 5. Encrypted email payload (port 993 IMAPS) with synthetic payload
packets.append(IP(src="192.168.1.100", dst="10.0.0.30")/TCP(sport=54325, dport=993, flags="PA")/Raw(b"* 1 FETCH (FLAGS (\\Seen) BODY[HEADER] {1024}\r\nFrom: sender@example.com\r\nTo: recipient@securemail.local\r\nSubject: Secure Transmission\r\n\r\n"))

output_path = r"C:\Users\kshit\SecureMailScope\uploads\beautiful_demo.pcap"
os.makedirs(os.path.dirname(output_path), exist_ok=True)
wrpcap(output_path, packets)
print(f"Created beautiful PCAP: {output_path}")
print(f"Total packets: {len(packets)}")
