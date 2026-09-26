# Performance Report (measured 2026-09-26)

Reproduce: `cd backend && python -m tests.performance.benchmark --sizes 1000 10000 100000 1000000 --out ../PERFORMANCE_RESULTS.json`.
Raw results: [PERFORMANCE_RESULTS.json](PERFORMANCE_RESULTS.json).

## Environment

Windows 11 (10.0.26200), AMD64 Family 23 Model 24 (8 logical CPUs), 14.9 GB RAM, Python 3.12.5,
dpkt 1.9.8, cryptography 50.0.1, scikit-learn 1.9.0, numpy 2.5.2. Single process, single thread,
wall-clock timing (`time.perf_counter`). Other workloads on the machine were not controlled.

## Workload

Captures are built by replicating the repository fixtures (real OpenSSL TLS handshakes with
certificate chains, SMTP/IMAP/POP3 STARTTLS dialogues, implicit TLS, plaintext sessions) with a
distinct client address/port per copy: roughly 45 connections per 1,000 packets, 84% of them with
TLS, ~200 bytes per packet on average. Real-world captures with long mail transfers have far fewer
connections per packet and would process faster per packet.

## Results

| Packets | Capture | TCP streams | Email / TLS sessions | Findings | Ingest + reassembly | Full analysis | Throughput | Persistence (SQLite) | JSON / HTML / PDF report | End-to-end | Peak RSS (analysis) | Peak RSS (incl. persistence, reports) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1,000 | 0.2 MB | 45 | 45 / 39 | 18 | 0.08 s | 0.87 s | 1,152 pkt/s | 0.06 s | 0.02 / 0.05 / 0.97 s | 2.0 s | 165 MB | 213 MB |
| 10,000 | 2.0 MB | 452 | 452 / 383 | 211 | 0.60 s | 1.44 s | 6,943 pkt/s (1.39 MB/s) | 0.30 s | 0.14 / 0.17 / 4.0 s | 6.1 s | 220 MB | 237 MB |
| 100,000 | 19.9 MB | 4,513 | 4,513 / 3,802 | 2,133 | 5.6 s | 12.6 s | 7,937 pkt/s (1.58 MB/s) | 2.6 s | 1.5 / 0.8 / 4.4 s | 21.9 s | 305 MB | 486 MB |
| 1,000,000 | 198.7 MB | 45,131 | 45,131 / 38,006 | 21,375 | 58.1 s | 214.0 s | 4,674 pkt/s (0.93 MB/s) | 26.1 s | not run | 240.1 s | 1,129 MB | 1,997 MB |

The 1K-packet row is dominated by one-time costs (first scikit-learn import, model construction).
Largest tested capture: 1,000,000 packets / 198.7 MB. The API's default upload limit is 100 MB
(about 500k packets of this workload).

## Stage breakdown and optimisations made during the audit

| Change | Before | After |
|---|---|---|
| TCP quality recomputed (sorting every packet) on every packet | O(n^2 log n) per stream | Computed once at finalize |
| ML scoring per session (sklearn call overhead ~33 ms each) | 91% of analysis time at 5k packets | One batched call |
| ML rareness explanation scanned the whole baseline per flagged session | O(flagged x n) | Precomputed value frequencies |
| PDF rendered every row of every table | 71.8 s at 100k packets | Tables capped at 400 rows (JSON/HTML keep all rows): 4.4 s |
| Persistence built all ORM objects in one identity map | 83 s, ~2.3 GB at 1M packets | Chunked Core inserts: 26 s |
| **1M packets end-to-end** | **398 s** | **240 s** |

## Limitations and interpretation

* Throughput per packet falls at 1M packets (4.7k vs 7.9k pkt/s) with 45k concurrent
  connections; memory for retained handshake bytes and per-session objects grows linearly with
  the number of connections (about 25 KB per email session at peak during analysis).
* Earlier documents quoted "~15-33 packets/sec" measured on 3-30 packet files; those numbers
  measured interpreter start-up, not throughput, and are withdrawn.
* No multi-process parallelism, no streaming persistence; analysis is synchronous in the API
  request. No claims are made beyond the measured sizes.
