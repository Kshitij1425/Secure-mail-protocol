# 1. Clean Baseline (SMTP, Plaintext)
    name = "clean_baseline"
    with SyntheticPCAPGenerator(str(pcap_dir / f"{name}.pcap")) as gen:
        # Handshake
        gen.write_packet(ts_base, c_ip, s_ip, c_port, s_port, 100, 0, dpkt.tcp.TH_SYN)
        gen.write_packet(ts_base + 0.1, s_ip, c_ip, s_port, c_port, 200, 101, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        gen.write_packet(ts_base + 0.2, c_ip, s_ip, c_port, s_port, 101, 201, dpkt.tcp.TH_ACK)
        # Auth / Banner (server seq=201, payload len=28, next seq should be 201+28=229)
        gen.write_packet(ts_base + 0.3, s_ip, c_ip, s_port, c_port, 201, 101, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"220 mail.example.com ESMTP\r\n")
        # Client EHLO (client seq=101, payload len=13, next seq=114)
        gen.write_packet(ts_base + 0.4, c_ip, s_ip, c_port, s_port, 101, 229, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"EHLO client.com\r\n")
