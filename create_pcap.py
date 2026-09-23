from scapy.all import IP, TCP, Ether, Raw, wrpcap

def create_sample_pcap(filename="sample_email.pcap"):
    # Create a dummy HTTPS-like packet (simulating encrypted email traffic)
    # Ether -> IP -> TCP -> Raw (Simulated TLS payload)

    pkt1 = Ether() / IP(src="192.168.1.50", dst="172.217.16.142") / TCP(dport=443, sport=54321, flags="PA") / Raw(load=b"\x16\x03\x01\x00\x6e\x01\x00\x00\x6a\x03\x03")
    pkt2 = Ether() / IP(src="172.217.16.142", dst="192.168.1.50") / TCP(dport=54321, sport=443, flags="PA") / Raw(load=b"\x16\x03\x01\x00\x4a\x02\x00\x00\x46\x03\x03")

    packets = [pkt1, pkt2]
    wrpcap(filename, packets)
    print(f"Sample PCAP created: {filename}")

if __name__ == "__main__":
    create_sample_pcap()
