"""
Reproducible performance benchmark for the real pipeline.

Builds captures of ~1K / 10K / 100K / 1M packets by replicating the fixture
conversations (real OpenSSL TLS handshakes + SMTP/IMAP/POP3 dialogues) with
distinct client ports/addresses per copy, then measures separately:

  * ingest + TCP reassembly         (Orchestrator metadata timing)
  * full analysis pipeline           (Orchestrator.analyze wall time)
  * persistence to SQLite            (AnalysisService._persist)
  * report rendering (JSON/HTML/PDF) (reports.render)
  * peak resident memory             (psutil, sampled in a thread)

Usage (from backend/):
    python -m tests.performance.benchmark --sizes 1000 10000 100000 1000000 --out ../PERFORMANCE_RESULTS.json
"""
import argparse
import json
import os
import platform
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

import dpkt

BACKEND = Path(__file__).resolve().parents[2]
PCAPS = BACKEND / "tests" / "robustness" / "fixtures" / "pcaps"
SEEDS = ["ml_mixed_estate.pcap", "implicit_tls_mixed.pcap", "clean_baseline.pcap", "smtp_starttls_downgrade.pcap",
         "smtp_plaintext_auth.pcap", "layer_b_imap_tls12_segmented.pcap"]


def _seed_packets():
    out = []
    for name in SEEDS:
        with open(PCAPS / name, "rb") as f:
            for ts, buf in dpkt.pcap.Reader(f):
                out.append((ts, buf))
    return out


def build_capture(path: Path, target_packets: int) -> int:
    seed = _seed_packets()
    n = 0
    copy = 0
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        while n < target_packets:
            for ts, buf in seed:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                # Rewrite the client side so every copy is a distinct connection.
                port_off = copy % 10000
                subnet = copy // 10000
                if tcp.sport >= 40000:
                    tcp.sport = 40000 + (tcp.sport - 40000 + port_off * 3) % 25000
                    ip.src = ip.src[:2] + struct.pack("!H", subnet)
                elif tcp.dport >= 40000:
                    tcp.dport = 40000 + (tcp.dport - 40000 + port_off * 3) % 25000
                    ip.dst = ip.dst[:2] + struct.pack("!H", subnet)
                tcp.sum = 0
                ip.sum = 0
                w.writepkt(bytes(eth), ts=ts + copy * 0.5)
                n += 1
                if n >= target_packets:
                    break
            copy += 1
    return n


class PeakRSS:
    def __init__(self):
        import psutil
        self.proc = psutil.Process()
        self.peak = self.proc.memory_info().rss
        self._stop = False

    def __enter__(self):
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()
        return self

    def _run(self):
        while not self._stop:
            self.peak = max(self.peak, self.proc.memory_info().rss)
            time.sleep(0.02)

    def __exit__(self, *a):
        self._stop = True
        self.t.join()


def run(size: int, workdir: Path, reports: bool) -> dict:
    import logging
    logging.getLogger("securemailscope").setLevel(logging.ERROR)
    from securemailscope.core.orchestrator import Orchestrator
    from securemailscope.reports.document import document_from_result
    from securemailscope.reports.render import render_html, render_json, render_pdf

    cap = workdir / f"bench_{size}.pcap"
    packets = build_capture(cap, size)
    mb = cap.stat().st_size / 1e6
    import psutil
    base_rss = psutil.Process().memory_info().rss
    whole = PeakRSS().__enter__()
    with PeakRSS() as mem:
        t0 = time.perf_counter()
        result = Orchestrator().analyze(str(cap))
        t_analysis = time.perf_counter() - t0
    row = {
        "packets": packets, "capture_mb": round(mb, 2),
        "tcp_streams": result.reconstructed_stream_count, "email_sessions": result.email_session_count,
        "tls_sessions": result.tls_session_count, "findings": len(result.findings),
        "ingest_reassembly_s": result.metadata["timings_seconds"]["ingest_and_reassembly"],
        "full_analysis_s": round(t_analysis, 3),
        "packets_per_s": round(packets / t_analysis, 1), "mb_per_s": round(mb / t_analysis, 2),
        "peak_rss_mb": round(mem.peak / 1e6, 1), "rss_increase_mb": round((mem.peak - base_rss) / 1e6, 1),
    }

    # Persistence (fresh SQLite database)
    os.environ["SECUREMAILSCOPE_DATABASE_URL"] = f"sqlite:///{(workdir / f'bench_{size}.db').as_posix()}"
    os.environ["SECUREMAILSCOPE_UPLOAD_DIR"] = str(workdir / "u")
    os.environ["SECUREMAILSCOPE_REPORTS_DIR"] = str(workdir / "r")
    from securemailscope.api.config import get_settings
    from securemailscope.api import database
    get_settings.cache_clear()
    database.reset_engine()
    database.init_db()
    from securemailscope.api.services.analyzers import AnalysisService
    with database.get_session_local()() as db:
        capture = database.CaptureDB(capture_id=f"bench-{size}", filename=cap.name, file_hash="0" * 64,
                                     file_path=str(cap), file_size=cap.stat().st_size)
        db.add(capture)
        db.commit()
        t0 = time.perf_counter()
        AnalysisService()._persist(capture, result, db, t_analysis)
        row["persistence_s"] = round(time.perf_counter() - t0, 3)
    database.reset_engine()

    if reports:
        doc = document_from_result(result)
        for fmt, fn in (("json", render_json), ("html", render_html), ("pdf", render_pdf)):
            t0 = time.perf_counter()
            data = fn(doc)
            row[f"report_{fmt}_s"] = round(time.perf_counter() - t0, 3)
            row[f"report_{fmt}_mb"] = round(len(data) / 1e6, 2)
    whole.__exit__()
    row["peak_rss_mb_incl_persistence_reports"] = round(whole.peak / 1e6, 1)
    row["end_to_end_s"] = round(t_analysis + row["persistence_s"] +
                                sum(v for k, v in row.items() if k.startswith("report_") and k.endswith("_s")), 3)
    cap.unlink(missing_ok=True)
    return row


def environment() -> dict:
    import psutil
    import cryptography
    import sklearn
    import numpy
    return {
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(), "processor": platform.processor(),
        "cpu_logical": psutil.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 1e9, 1),
        "python": sys.version.split()[0], "dpkt": dpkt.__version__, "cryptography": cryptography.__version__,
        "scikit_learn": sklearn.__version__, "numpy": numpy.__version__,
        "notes": "single process, single thread; timings are wall clock (time.perf_counter)",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", nargs="+", type=int, default=[1000, 10000, 100000])
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-reports-above", type=int, default=100000,
                    help="skip report rendering for captures larger than this")
    args = ap.parse_args()
    results = {"environment": environment(), "runs": []}
    with tempfile.TemporaryDirectory(prefix="sms_bench_") as tmp:
        for size in args.sizes:
            row = run(size, Path(tmp), reports=size <= args.no_reports_above)
            results["runs"].append(row)
            print(json.dumps(row))
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
