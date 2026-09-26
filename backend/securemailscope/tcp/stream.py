"""
TCP stream reconstruction.

Each TCP connection is reassembled per direction using sequence numbers, the
way a receiving host would deliver bytes to the application:

* duplicate / retransmitted bytes are delivered once,
* out-of-order segments are buffered until the gap before them is filled,
* overlapping segments keep the bytes that arrived first; overlaps whose bytes
  differ are counted as conflicts (a classic evasion / corruption indicator),
* sequence numbers are handled modulo 2**32 (wraparound safe),
* gaps that are never filled are recorded and delivery resumes after them.

All input is treated as attacker controlled, so every buffer is bounded
(see ``TCPLimits``). Once a limit is hit the stream keeps counting bytes but
stops retaining them and is flagged ``truncated_by_limit``.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import ipaddress

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.tcp.stream")

SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31

CLIENT_TO_SERVER = "c2s"
SERVER_TO_CLIENT = "s2c"

# Ports we treat as "server side" when the TCP handshake was not captured.
WELL_KNOWN_SERVER_PORTS = {25, 110, 143, 465, 587, 993, 995, 2525}


@dataclass
class TCPLimits:
    """Resource limits applied to hostile captures."""
    max_streams: int = 100_000
    # Application bytes retained per direction. Posture analysis only needs the
    # plaintext negotiation and the TLS handshake, which fit comfortably.
    max_retained_bytes_per_direction: int = 256 * 1024
    # Hard ceiling on retained application bytes across the whole capture.
    max_total_retained_bytes: int = 512 * 1024 * 1024
    # Out-of-order data buffered per direction while waiting for a gap to fill.
    max_pending_bytes_per_direction: int = 4 * 1024 * 1024
    max_pending_segments_per_direction: int = 4096


@dataclass
class TCPPacket:
    """A TCP segment as observed on the wire (kept for API compatibility)."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    payload: bytes
    flags: Dict[str, bool]
    payload_size: int
    total_size: int


@dataclass
class DeliveredChunk:
    """Contiguous application bytes delivered in order for one direction."""
    direction: str
    timestamp: float
    frame: int
    data: bytes
    _offset: int = 0
    _length: int = 0


@dataclass
class _Direction:
    """Per-direction reassembly state."""
    isn: Optional[int] = None          # initial sequence number (from SYN) if seen
    base: Optional[int] = None         # absolute seq of relative offset 0
    next_rel: int = 0                  # next relative offset expected
    pending: Dict[int, Tuple[bytes, float, int]] = field(default_factory=dict)
    pending_bytes: int = 0
    retained_bytes: int = 0
    delivered_bytes: int = 0
    packets: int = 0
    payload_packets: int = 0
    wire_payload_bytes: int = 0
    retransmitted_bytes: int = 0
    retransmitted_segments: int = 0
    overlap_conflicts: int = 0
    out_of_order_segments: int = 0
    gaps: List[Tuple[int, int]] = field(default_factory=list)  # (rel_start, length)
    fin_seen: bool = False
    truncated_by_limit: bool = False
    last_delivered_frame: int = 0
    # Bytes of already-delivered data kept only for overlap comparison.
    history: bytearray = field(default_factory=bytearray)


@dataclass
class TCPStream:
    """A reconstructed TCP connection.

    ``src_*`` is the client (connection initiator) and ``dst_*`` the server when
    that can be established; see ``direction_basis`` for how it was decided.
    """
    stream_id: str
    src_ip: Any
    dst_ip: Any
    src_port: int
    dst_port: int
    direction: str = "client_to_server"
    direction_basis: str = "unknown"   # syn | syn_ack | well_known_port | first_packet
    start_time: float = 0.0
    end_time: float = 0.0
    first_frame: int = 0
    last_frame: int = 0
    packets: List[TCPPacket] = field(default_factory=list)  # empty unless keep_packets=True
    reconstruction_quality: str = "incomplete"  # complete | partial | incomplete | inconsistent
    missing_sequences: List[int] = field(default_factory=list)
    retransmissions: List[int] = field(default_factory=list)
    bytes_analyzed: int = 0
    packets_analyzed: int = 0
    payload_bytes: int = 0
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    truncated_by_limit: bool = False
    chunks: List[DeliveredChunk] = field(default_factory=list)
    c2s: _Direction = field(default_factory=_Direction)
    s2c: _Direction = field(default_factory=_Direction)

    @property
    def client_ip(self) -> str:
        return format_ip(self.src_ip)

    @property
    def server_ip(self) -> str:
        return format_ip(self.dst_ip)

    def direction_payload(self, direction: str) -> bytes:
        return b"".join(c.data for c in self.chunks if c.direction == direction)

    def quality_summary(self) -> Dict[str, Any]:
        return {
            "quality": self.reconstruction_quality,
            "handshake_observed": self.syn_seen and self.syn_ack_seen,
            "direction_basis": self.direction_basis,
            "gaps": len(self.c2s.gaps) + len(self.s2c.gaps),
            "missing_bytes": sum(g[1] for g in self.c2s.gaps + self.s2c.gaps),
            "retransmitted_segments": self.c2s.retransmitted_segments + self.s2c.retransmitted_segments,
            "out_of_order_segments": self.c2s.out_of_order_segments + self.s2c.out_of_order_segments,
            "overlap_conflicts": self.c2s.overlap_conflicts + self.s2c.overlap_conflicts,
            "fin_seen": self.fin_seen,
            "rst_seen": self.rst_seen,
            "truncated_by_limit": self.truncated_by_limit,
        }


def format_ip(value: Any) -> str:
    """Render an address from dpkt (raw bytes) or a string as text."""
    if isinstance(value, (bytes, bytearray)):
        try:
            return str(ipaddress.ip_address(bytes(value)))
        except ValueError:
            return value.hex()
    return str(value)


def _rel(seq: int, base: int) -> int:
    """Signed distance from ``base`` to ``seq`` in 32-bit sequence space."""
    d = (seq - base) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_HALF else d


class TCPReconstructor:
    """Reassembles TCP connections from IP packets."""

    def __init__(self, reassembly_timeout: float = 5.0, limits: Optional[TCPLimits] = None,
                 keep_packets: bool = False):
        self.reassembly_timeout = reassembly_timeout
        self.limits = limits or TCPLimits()
        self.keep_packets = keep_packets
        self.streams: Dict[str, TCPStream] = {}
        # connection key -> stream_id of the currently open instance
        self._active: Dict[Tuple, str] = {}
        self._instances: Dict[Tuple, int] = {}
        self.packets_processed = 0
        self.dropped_streams = 0
        self._total_retained = 0
        self._finalized = False

    # ------------------------------------------------------------------ keys
    @staticmethod
    def _endpoint_key(src_ip, src_port, dst_ip, dst_port) -> Tuple:
        a = (bytes(src_ip) if isinstance(src_ip, (bytes, bytearray)) else str(src_ip).encode(), src_port)
        b = (bytes(dst_ip) if isinstance(dst_ip, (bytes, bytearray)) else str(dst_ip).encode(), dst_port)
        return (a, b) if a <= b else (b, a)

    def _generate_stream_id(self, src_ip, dst_ip, src_port: int, dst_port: int) -> str:
        """Readable, URL-safe id: ``tcp-<client>_<cport>-<server>_<sport>``."""
        return f"tcp-{format_ip(src_ip)}_{src_port}-{format_ip(dst_ip)}_{dst_port}"

    # --------------------------------------------------------------- packets
    def process_packet(self, packet: Any, timestamp: float, frame: int = 0) -> Optional[TCPStream]:
        """Feed one dpkt IP/IP6 packet. Returns the stream it belongs to."""
        tcp = getattr(packet, "data", None)
        if tcp is None:
            return None
        proto = getattr(packet, "p", None)
        if proto is None:
            proto = getattr(packet, "nxt", None)  # IPv6
        if proto != 6 or not hasattr(tcp, "seq") or not hasattr(tcp, "flags"):
            return None
        src_ip = getattr(packet, "src", None)
        dst_ip = getattr(packet, "dst", None)
        if src_ip is None or dst_ip is None:
            return None

        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        flags = self._parse_tcp_flags(int(tcp.flags))
        payload = bytes(tcp.data) if isinstance(getattr(tcp, "data", b""), (bytes, bytearray)) else b""

        key = self._endpoint_key(src_ip, src_port, dst_ip, dst_port)
        stream = self._stream_for(key, src_ip, src_port, dst_ip, dst_port, flags, timestamp, frame)
        if stream is None:
            return None

        is_c2s = (format_ip(src_ip) == stream.client_ip and src_port == stream.src_port)
        d = stream.c2s if is_c2s else stream.s2c
        d.packets += 1

        stream.end_time = max(stream.end_time, timestamp)
        stream.start_time = min(stream.start_time, timestamp)
        stream.last_frame = frame or stream.last_frame
        stream.packets_analyzed += 1
        stream.bytes_analyzed += len(payload) + 20
        stream.payload_bytes += len(payload)
        self.packets_processed += 1

        if flags["syn"]:
            if flags["ack"]:
                stream.syn_ack_seen = True
            else:
                stream.syn_seen = True
            if d.isn is None:
                d.isn = int(tcp.seq)
                d.base = (int(tcp.seq) + 1) % SEQ_MOD
        if flags["rst"]:
            stream.rst_seen = True
        if flags["fin"]:
            stream.fin_seen = True
            d.fin_seen = True

        if self.keep_packets:
            stream.packets.append(TCPPacket(
                timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                seq=int(tcp.seq), ack=int(tcp.ack), payload=payload, flags=flags,
                payload_size=len(payload), total_size=len(payload) + 20))

        if payload:
            d.payload_packets += 1
            d.wire_payload_bytes += len(payload)
            self._accept_segment(stream, d, CLIENT_TO_SERVER if is_c2s else SERVER_TO_CLIENT,
                                 int(tcp.seq), payload, timestamp, frame)
        return stream

    def _stream_for(self, key, src_ip, src_port, dst_ip, dst_port, flags, ts, frame) -> Optional[TCPStream]:
        sid = self._active.get(key)
        stream = self.streams.get(sid) if sid else None

        # A fresh SYN on a connection that was closed starts a new instance
        # (port reuse). A retransmitted SYN on an open connection does not.
        if stream is not None and flags["syn"] and not flags["ack"] and (stream.fin_seen or stream.rst_seen) \
                and (stream.c2s.delivered_bytes or stream.s2c.delivered_bytes):
            stream = None

        if stream is not None:
            return stream

        if len(self.streams) >= self.limits.max_streams:
            self.dropped_streams += 1
            return None

        # Decide who is the client.
        if flags["syn"] and not flags["ack"]:
            client, server, basis = (src_ip, src_port), (dst_ip, dst_port), "syn"
        elif flags["syn"] and flags["ack"]:
            client, server, basis = (dst_ip, dst_port), (src_ip, src_port), "syn_ack"
        elif dst_port in WELL_KNOWN_SERVER_PORTS and src_port not in WELL_KNOWN_SERVER_PORTS:
            client, server, basis = (src_ip, src_port), (dst_ip, dst_port), "well_known_port"
        elif src_port in WELL_KNOWN_SERVER_PORTS and dst_port not in WELL_KNOWN_SERVER_PORTS:
            client, server, basis = (dst_ip, dst_port), (src_ip, src_port), "well_known_port"
        elif src_port > dst_port:
            client, server, basis = (src_ip, src_port), (dst_ip, dst_port), "first_packet"
        else:
            client, server, basis = (dst_ip, dst_port), (src_ip, src_port), "first_packet"

        instance = self._instances.get(key, 0) + 1
        self._instances[key] = instance
        sid = self._generate_stream_id(client[0], server[0], client[1], server[1])
        if instance > 1:
            sid = f"{sid}-{instance}"
        stream = TCPStream(stream_id=sid, src_ip=client[0], dst_ip=server[0], src_port=client[1],
                           dst_port=server[1], direction_basis=basis, start_time=ts, end_time=ts,
                           first_frame=frame, last_frame=frame)
        self.streams[sid] = stream
        self._active[key] = sid
        return stream

    # ----------------------------------------------------------- reassembly
    def _accept_segment(self, stream: TCPStream, d: _Direction, direction: str, seq: int,
                        payload: bytes, ts: float, frame: int) -> None:
        if d.base is None:
            # Handshake not captured: anchor on the first data segment seen.
            d.base = seq
        rel = _rel(seq, d.base)
        end = rel + len(payload)

        if end <= d.next_rel:
            # Entirely old data: retransmission. Compare with what we delivered.
            d.retransmitted_segments += 1
            d.retransmitted_bytes += len(payload)
            if len(stream.retransmissions) < 1000:
                stream.retransmissions.append(seq)
            self._check_overlap(d, rel, payload)
            return

        if rel < d.next_rel:
            # Partial overlap with delivered data: trim the old part.
            overlap = d.next_rel - rel
            d.retransmitted_bytes += overlap
            self._check_overlap(d, rel, payload[:overlap])
            payload = payload[overlap:]
            rel = d.next_rel

        if rel > d.next_rel:
            # Out-of-order: hold until the gap is filled.
            d.out_of_order_segments += 1
            existing = d.pending.get(rel)
            if existing is not None:
                if existing[0][:len(payload)] != payload[:len(existing[0])]:
                    d.overlap_conflicts += 1
                if len(existing[0]) >= len(payload):
                    return
                d.pending_bytes -= len(existing[0])
            if (d.pending_bytes + len(payload) > self.limits.max_pending_bytes_per_direction
                    or len(d.pending) >= self.limits.max_pending_segments_per_direction):
                d.truncated_by_limit = True
                stream.truncated_by_limit = True
                return
            d.pending[rel] = (payload, ts, frame)
            d.pending_bytes += len(payload)
            return

        self._deliver(stream, d, direction, payload, ts, frame)
        self._drain_pending(stream, d, direction, ts, frame)

    def _drain_pending(self, stream: TCPStream, d: _Direction, direction: str,
                       trigger_ts: Optional[float] = None, trigger_frame: Optional[int] = None) -> None:
        """Deliver buffered segments that are now contiguous. They become available to
        the application when the gap-filling segment arrives, so they are delivered
        under that segment's frame (keeps chunk order == application order)."""
        while d.pending:
            ready = [r for r in d.pending if r <= d.next_rel]
            if not ready:
                return
            for r in sorted(ready):
                data, ts, frame = d.pending.pop(r)
                d.pending_bytes -= len(data)
                end = r + len(data)
                if end <= d.next_rel:
                    self._check_overlap(d, r, data)
                    continue
                if r < d.next_rel:
                    cut = d.next_rel - r
                    self._check_overlap(d, r, data[:cut])
                    data = data[cut:]
                self._deliver(stream, d, direction, data,
                              trigger_ts if trigger_ts is not None else ts,
                              trigger_frame if trigger_frame is not None else frame)

    def _deliver(self, stream: TCPStream, d: _Direction, direction: str, data: bytes,
                 ts: float, frame: int) -> None:
        # Delivery within a direction is monotonic in frame order.
        frame = max(frame, d.last_delivered_frame)
        d.last_delivered_frame = frame
        d.next_rel += len(data)
        d.delivered_bytes += len(data)
        room = min(self.limits.max_retained_bytes_per_direction - len(d.history),
                   self.limits.max_total_retained_bytes - self._total_retained)
        if room <= 0:
            d.truncated_by_limit = True
            stream.truncated_by_limit = True
            return
        kept = data[:room]
        if len(kept) < len(data):
            d.truncated_by_limit = True
            stream.truncated_by_limit = True
        start = len(d.history)
        d.history += kept
        d.retained_bytes += len(kept)
        self._total_retained += len(kept)
        # Chunks reference ``history`` by offset; bytes are materialised once in _finalize.
        last = stream.chunks[-1] if stream.chunks else None
        if last is not None and last.direction == direction and last.frame == frame \
                and last._offset + last._length == start:
            last._length += len(kept)
        else:
            chunk = DeliveredChunk(direction=direction, timestamp=ts, frame=frame, data=b"")
            chunk._offset, chunk._length = start, len(kept)
            stream.chunks.append(chunk)

    @staticmethod
    def _check_overlap(d: _Direction, rel: int, data: bytes) -> None:
        """Count retransmissions whose bytes disagree with what was delivered."""
        if rel < 0:
            data = data[-rel:]
            rel = 0
        seen = bytes(d.history[rel:rel + len(data)])
        if seen and seen != data[:len(seen)]:
            d.overlap_conflicts += 1

    # -------------------------------------------------------------- finalize
    def _finalize(self) -> None:
        for stream in self.streams.values():
            for d, direction in ((stream.c2s, CLIENT_TO_SERVER), (stream.s2c, SERVER_TO_CLIENT)):
                # Unfilled gaps: record them and deliver what follows.
                while d.pending:
                    nxt = min(d.pending)
                    gap = nxt - d.next_rel
                    if gap > 0:
                        d.gaps.append((d.next_rel, gap))
                        stream.missing_sequences.append(((d.base or 0) + d.next_rel) % SEQ_MOD)
                        d.next_rel = nxt
                        # Keep history offsets aligned with sequence space.
                        pad = min(gap, max(0, self.limits.max_retained_bytes_per_direction - len(d.history)))
                        d.history += b"\x00" * pad
                    self._drain_pending(stream, d, direction)
            for chunk in stream.chunks:
                src = stream.c2s.history if chunk.direction == CLIENT_TO_SERVER else stream.s2c.history
                chunk.data = bytes(src[chunk._offset:chunk._offset + chunk._length])
            # Reassembly complete; the byte history is no longer needed.
            stream.c2s.history = bytearray()
            stream.s2c.history = bytearray()
            self._update_stream_quality(stream)
            # Delivery order == capture order of the segment that completed each chunk.
            stream.chunks.sort(key=lambda c: (c.frame, c.timestamp))
        self._finalized = True

    def _update_stream_quality(self, stream: TCPStream) -> None:
        conflicts = stream.c2s.overlap_conflicts + stream.s2c.overlap_conflicts
        gaps = stream.c2s.gaps + stream.s2c.gaps
        if conflicts:
            stream.reconstruction_quality = "inconsistent"
        elif gaps or stream.truncated_by_limit:
            stream.reconstruction_quality = "partial"
        elif stream.syn_seen and stream.syn_ack_seen and stream.payload_bytes > 0:
            stream.reconstruction_quality = "complete"
        else:
            stream.reconstruction_quality = "incomplete"

    def _parse_tcp_flags(self, flags_byte: int) -> Dict[str, bool]:
        return {
            "fin": bool(flags_byte & 0x01), "syn": bool(flags_byte & 0x02),
            "rst": bool(flags_byte & 0x04), "psh": bool(flags_byte & 0x08),
            "ack": bool(flags_byte & 0x10), "urg": bool(flags_byte & 0x20),
            "ece": bool(flags_byte & 0x40), "cwr": bool(flags_byte & 0x80),
        }

    # ------------------------------------------------------------ accessors
    def get_streams(self) -> List[TCPStream]:
        if not self._finalized:
            self._finalize()
        return list(self.streams.values())

    def get_stream(self, stream_id: str) -> Optional[TCPStream]:
        if not self._finalized:
            self._finalize()
        return self.streams.get(stream_id)

    def get_statistics(self) -> Dict[str, Any]:
        streams = self.get_streams()
        quality_counts: Dict[str, int] = {}
        for s in streams:
            quality_counts[s.reconstruction_quality] = quality_counts.get(s.reconstruction_quality, 0) + 1
        n = max(len(streams), 1)
        return {
            "total_streams": len(streams),
            "total_packets_processed": self.packets_processed,
            "packets_reassembled": sum(s.packets_analyzed for s in streams),
            "dropped_streams_limit": self.dropped_streams,
            "quality_distribution": quality_counts,
            "avg_packets_per_stream": sum(s.packets_analyzed for s in streams) / n,
            "avg_bytes_per_stream": sum(s.bytes_analyzed for s in streams) / n,
        }
