import time
from securemailscope.core.orchestrator import Orchestrator

def benchmark():
    pcap = "tests/robustness/fixtures/pcaps/layer_b_smtp_tls13_secure.pcap"

    start = time.time()
    orc = Orchestrator()
    posture, meta = orc.analyze(pcap)
    elapsed = time.time() - start

    packets = meta.get("valid_packets", 0)
    throughput = packets / elapsed if elapsed > 0 else 0

    print("M10.5 Full-Pipeline Benchmark")
    print("-" * 30)
    print(f"Capture: {pcap}")
    print(f"Total time : {elapsed:.3f} s")
    print(f"Packets    : {packets}")
    print(f"Throughput : {throughput:.0f} pkts/sec")
    print(f"TCP Streams: {meta.get('reconstructed_streams', 0)}")
    print(f"Email Sess : {posture.total_sessions}")
    print(f"TLS Sess   : {posture.tls_sessions}")
    print(f"Score      : {posture.overall_score:.0f}/100 ({posture.status.value})")

if __name__ == "__main__":
    benchmark()
