"""
Recording TCP relay: writes a PCAP of real client<->server traffic without a
packet-capture driver.

    client --> relay (127.0.0.1:listen_port) --> mail server (127.0.0.1:upstream_port)

Every byte the real client and the real mail server exchange is forwarded
unchanged and recorded with its receive timestamp. On shutdown the recording
is written as a PCAP in which:

* application bytes (SMTP/IMAP/POP3 dialogue, TLS records) and their order and
  timing are exactly what the peers exchanged;
* Ethernet/IPv4/TCP headers are *reconstructed*: addresses and the server port
  are configurable, sequence/acknowledgement numbers are consistent, one TCP
  segment is written per socket read (split at the MSS), and SYN / FIN
  handshakes are added around each connection.

It exists for environments where raw capture (tcpdump / Npcap / pktmon) is not
available. When raw capture is available, prefer `lab/docker` (tcpdump).
"""
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import List, Optional, Tuple

import dpkt

MSS = 1460


@dataclass
class Record:
    ts: float
    c2s: bool
    data: bytes = b""
    flags: str = "data"   # data | syn | fin_client | fin_server


@dataclass
class Connection:
    client_port: int
    records: List[Record] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, rec: Record):
        with self.lock:
            self.records.append(rec)


class RecordingRelay:
    def __init__(self, upstream: Tuple[str, int], listen_port: int = 0, *, client_ip="10.77.0.10",
                 server_ip="10.77.0.25", server_port: Optional[int] = None, seed: int = 7,
                 plaintext_substitutions: Optional[List[Tuple[bytes, bytes]]] = None):
        self.upstream = upstream
        self.client_ip, self.server_ip = client_ip, server_ip
        self.server_port = server_port or upstream[1]
        # Same-length byte substitutions applied ONLY to plaintext bytes recorded before
        # the first TLS record of a connection (e.g. the lab host's real hostname in a
        # server greeting). TLS bytes are never modified. Recorded in the manifest.
        self.substitutions = plaintext_substitutions or []
        for old, new in self.substitutions:
            if len(old) != len(new):
                raise ValueError("substitutions must preserve length (TCP sequence consistency)")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.connections: List[Connection] = []
        self._rng = random.Random(seed)
        self._threads: List[threading.Thread] = []
        self._stop = False
        self._accept = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept.start()

    # ------------------------------------------------------------ relaying
    def _accept_loop(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                client, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn = Connection(client_port=40000 + self._rng.randrange(20000))
            conn.add(Record(time.time(), True, flags="syn"))
            self.connections.append(conn)
            server = socket.create_connection(self.upstream, timeout=10)
            for s in (client, server):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            done = threading.Event()
            t1 = threading.Thread(target=self._pump, args=(client, server, conn, True, done), daemon=True)
            t2 = threading.Thread(target=self._pump, args=(server, client, conn, False, done), daemon=True)
            self._threads += [t1, t2]
            t1.start()
            t2.start()

    def _pump(self, src, dst, conn: Connection, c2s: bool, done: threading.Event):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                conn.add(Record(time.time(), c2s, data))
                dst.sendall(data)
        except OSError:
            pass
        finally:
            conn.add(Record(time.time(), c2s, flags="fin_client" if c2s else "fin_server"))
            for s in (dst, src):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            done.set()

    def close(self, grace: float = 1.0):
        deadline = time.time() + grace
        for t in self._threads:
            t.join(max(0.0, deadline - time.time()))
        self._stop = True
        self.sock.close()
        self._accept.join(1)

    # --------------------------------------------------------------- output
    def packets(self):
        """Yield (ts, frame_bytes) for every recorded connection."""
        cip, sip = ip_address(self.client_ip).packed, ip_address(self.server_ip).packed
        for conn in self.connections:
            c_seq = self._rng.randrange(1 << 32)
            s_seq = self._rng.randrange(1 << 32)
            fin_sent = {True: False, False: False}

            def frame(ts, c2s, seq, ack, flags, payload=b""):
                src, dst = (cip, sip) if c2s else (sip, cip)
                sport, dport = (conn.client_port, self.server_port) if c2s else (self.server_port, conn.client_port)
                tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq % (1 << 32), ack=ack % (1 << 32),
                                   flags=flags, win=65535, data=payload)
                ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
                ip.len = len(ip)
                eth = dpkt.ethernet.Ethernet(src=b"\x02\x00\x00\x00\x00\x0a", dst=b"\x02\x00\x00\x00\x00\x19",
                                             type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
                return ts, bytes(eth)

            with conn.lock:
                recs = sorted(conn.records, key=lambda r: r.ts)
            tls_started = False
            for r in recs:
                if r.data[:1] == b"" and r.data[1:2] == b"":
                    tls_started = True
                if not tls_started and r.data:
                    for old, new in self.substitutions:
                        r.data = r.data.replace(old, new)
            A, S, P, F = dpkt.tcp.TH_ACK, dpkt.tcp.TH_SYN, dpkt.tcp.TH_PUSH, dpkt.tcp.TH_FIN
            for r in recs:
                if r.flags == "syn":
                    yield frame(r.ts, True, c_seq, 0, S)
                    yield frame(r.ts + 0.0001, False, s_seq, c_seq + 1, S | A)
                    c_seq += 1
                    s_seq += 1
                    yield frame(r.ts + 0.0002, True, c_seq, s_seq, A)
                elif r.flags in ("fin_client", "fin_server"):
                    c2s = r.flags == "fin_client"
                    if fin_sent[c2s]:
                        continue
                    fin_sent[c2s] = True
                    if c2s:
                        yield frame(r.ts, True, c_seq, s_seq, F | A)
                        c_seq += 1
                    else:
                        yield frame(r.ts, False, s_seq, c_seq, F | A)
                        s_seq += 1
                else:
                    for i in range(0, len(r.data), MSS):
                        seg = r.data[i:i + MSS]
                        if r.c2s:
                            yield frame(r.ts, True, c_seq, s_seq, P | A, seg)
                            c_seq += len(seg)
                        else:
                            yield frame(r.ts, False, s_seq, c_seq, P | A, seg)
                            s_seq += len(seg)


def write_pcap(path, relays: List[RecordingRelay]):
    frames = [f for r in relays for f in r.packets()]
    frames.sort(key=lambda x: x[0])
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh, nano=False)
        for ts, fr in frames:
            w.writepkt(fr, ts=ts)
    return len(frames)
