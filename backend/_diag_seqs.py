from securemailscope.ingestion.reader import PcapIngestor
from securemailscope.tcp.stream import TCPReconstructor

for name in ['imap_starttls_tls12', 'pop3_starttls_rejected']:
    pcap = f'tests/robustness/fixtures/pcaps/{name}.pcap'
    ingestor = PcapIngestor(pcap)
    tcp_recon = TCPReconstructor()
    for ts, ip_pkt, _ in ingestor.read_packets():
        tcp_recon.process_packet(ip_pkt, ts)
    streams = tcp_recon.get_streams()
    for stream in streams:
        print(f"=== {name} ===")
        print(f"Quality: {stream.reconstruction_quality}")
        print(f"Missing seqs: {stream.missing_sequences}")
        sorted_pkts = sorted(stream.packets, key=lambda p: p.timestamp)
        for i, pkt in enumerate(sorted_pkts):
            d = "C->S" if pkt.src_port == stream.src_port else "S->C"
            is_syn = pkt.flags["syn"]
            plen = len(pkt.payload)
            # SYN consumes 1 seq number even with 0 payload
            effective_len = max(plen, 1) if is_syn else plen
            next_seq = pkt.seq + effective_len
            print(f"  [{i}] {d} seq={pkt.seq} plen={plen} syn={is_syn} -> next_expected_seq={next_seq}")
    print()
