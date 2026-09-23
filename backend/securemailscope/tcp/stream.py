import struct
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timezone

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.tcp.stream")

@dataclass
class TCPPacket:
    """Represents a TCP packet from the capture."""

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
class TCPStream:
    """Represents a reconstructed TCP stream."""

    stream_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    direction: str = "bidirectional"  # "client_to_server", "server_to_client", "bidirectional"
    start_time: float = 0.0
    end_time: float = 0.0
    packets: List[TCPPacket] = field(default_factory=list)
    reconstruction_quality: str = "incomplete"  # complete, partial, incomplete, malformed
    missing_sequences: List[int] = field(default_factory=list)
    retransmissions: List[int] = field(default_factory=list)
    bytes_analyzed: int = 0
    packets_analyzed: int = 0
    payload_bytes: int = 0

    def __post_init__(self):
        # Determine direction based on initial packets
        if self.packets:
            first_packet = self.packets[0]
            if first_packet.src_port == self.src_port and first_packet.dst_port == self.dst_port:
                self.direction = "server_to_client"
            else:
                self.direction = "client_to_server"

class TCPReconstructor:
    """Implements reliable TCP stream reconstruction with quality assessment."""

    def __init__(self, reassembly_timeout: float = 5.0):
        self.reassembly_timeout = reassembly_timeout
        self.streams: Dict[str, TCPStream] = {}
        self.packets_processed = 0

    def _generate_stream_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """Generate a consistent stream ID."""
        # Normalize order for consistency
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"

    def process_packet(self, packet: Any, timestamp: float) -> Optional[TCPStream]:
        """
        Process a single TCP packet and update the stream reconstruction.
        Returns the completed or updated stream if significant changes.
        """
        # Extract TCP header information from dpkt packet
        # The IP packet's data attribute contains the transport layer (TCP/UDP/etc)
        tcp = getattr(packet, 'data', None)
        if tcp is None:
            return None

        # Only process TCP packets; ignore UDP/other transport protocols
        # dpkt identifies TCP with IP_PROTO_TCP = 6
        ip_proto = getattr(packet, 'p', None)
        if ip_proto != 6:  # IP_PROTO_TCP
            return None

        # Extract IP information
        src_ip = getattr(packet, 'src', None) or getattr(packet, 'saddr', None)
        dst_ip = getattr(packet, 'dst', None) or getattr(packet, 'daddr', None)
        if src_ip is None or dst_ip is None:
            return None

        src_port = tcp.sport
        dst_port = tcp.dport

        stream_id = self._generate_stream_id(src_ip, dst_ip, src_port, dst_port)

        if stream_id not in self.streams:
            # Initialize new stream
            stream = TCPStream(
                stream_id=stream_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                start_time=timestamp,
                end_time=timestamp
            )
            self.streams[stream_id] = stream
        else:
            stream = self.streams[stream_id]
            stream.end_time = max(stream.end_time, timestamp)

        # Parse TCP header
        tcp_flags = self._parse_tcp_flags(tcp.flags)

        # Extract payload
        payload = getattr(tcp, 'data', None) if hasattr(tcp, 'data') else b''

        # Extract sequence and acknowledgment numbers
        seq = tcp.seq
        ack = tcp.ack

        # Create TCPPacket object
        tcp_packet = TCPPacket(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            payload=payload,
            flags=tcp_flags,
            payload_size=len(payload),
            total_size=len(payload) + 20  # Basic TCP header size
        )

        stream = self.streams[stream_id]
        stream.packets.append(tcp_packet)
        stream.packets_analyzed += 1
        stream.bytes_analyzed += tcp_packet.total_size
        stream.payload_bytes += tcp_packet.payload_size

        self.packets_processed += 1

        # Update stream quality
        self._update_stream_quality(stream)

        return stream

    def _parse_tcp_flags(self, flags_byte: int) -> Dict[str, bool]:
        """Parse TCP control bits from flags byte."""
        return {
            "fin": bool(flags_byte & 0x01),
            "syn": bool(flags_byte & 0x02),
            "rst": bool(flags_byte & 0x04),
            "psh": bool(flags_byte & 0x08),
            "ack": bool(flags_byte & 0x10),
            "urg": bool(flags_byte & 0x20),
            "ece": bool(flags_byte & 0x40),
            "cwr": bool(flags_byte & 0x80)
        }

    def _update_stream_quality(self, stream: TCPStream) -> None:
        """Assess and update the reconstruction quality of a stream."""
        packets = stream.packets

        if not packets:
            stream.reconstruction_quality = "incomplete"
            return

        # Sort packets by sequence number for analysis
        sorted_packets = sorted(packets, key=lambda p: p.seq)

        # Check for critical issues
        has_rst = any(p.flags.get('rst', False) for p in packets)
        has_syn_ack = any(p.flags.get('syn', False) and p.flags.get('ack', False) for p in packets)

        if has_rst:
            stream.reconstruction_quality = "malformed"
            return

        if not has_syn_ack:
            stream.reconstruction_quality = "incomplete"
            return

        # Check sequence continuity
        missing_seqs = self._detect_missing_sequences(sorted_packets)
        stream.missing_sequences = missing_seqs

        # Check for retransmissions
        stream.retransmissions = self._detect_retransmissions(sorted_packets)

        # Assess completeness
        total_bytes = stream.payload_bytes
        if total_bytes == 0:
            stream.reconstruction_quality = "incomplete"
        elif len(missing_seqs) == 0:
            # If all sequences are present, payload is completely reconstructed
            stream.reconstruction_quality = "complete"
        else:
            stream.reconstruction_quality = "partial"

    def _detect_missing_sequences(self, packets: List[TCPPacket]) -> List[int]:
        """Detect missing sequence numbers in the stream per direction."""
        if len(packets) < 2:
            return []

        missing = []

        # Split packets by direction
        # Direction 1: Initial src_ip:src_port to dst_ip:dst_port
        p1 = [p for p in packets if p.src_port == packets[0].src_port]
        # Direction 2: The reverse
        p2 = [p for p in packets if p.src_port != packets[0].src_port]

        for directional_packets in (p1, p2):
            if len(directional_packets) < 2:
                continue

            sorted_by_seq = sorted(directional_packets, key=lambda p: p.seq)

            for i in range(len(sorted_by_seq) - 1):
                curr_seq = sorted_by_seq[i].seq
                next_seq = sorted_by_seq[i + 1].seq

                if next_seq > curr_seq:
                    gap = next_seq - curr_seq - len(sorted_by_seq[i].payload)
                    # allow gap=1 for SYN/FIN taking a sequence number
                    if gap > 1:
                        # We only track the start of the missing block for simplicity
                        missing.extend(range(curr_seq + len(sorted_by_seq[i].payload), next_seq, gap))

        return missing

    def _detect_retransmissions(self, packets: List[TCPPacket]) -> List[int]:
        """Detect sequence numbers that appear in multiple packets per direction (retransmissions)."""
        retransmissions = []

        p1 = [p for p in packets if p.src_port == packets[0].src_port]
        p2 = [p for p in packets if p.src_port != packets[0].src_port]

        for directional_packets in (p1, p2):
            seq_counts = {}
            for packet in directional_packets:
                # Ignore zero payload ACKs unless SYN/FIN
                if len(packet.payload) == 0 and not (packet.flags.get('syn') or packet.flags.get('fin')):
                    continue
                seq = packet.seq
                if seq in seq_counts:
                    seq_counts[seq] += 1
                    if seq_counts[seq] > 1 and seq not in retransmissions:
                        retransmissions.append(seq)
                else:
                    seq_counts[seq] = 1

        return retransmissions

    def get_streams(self) -> List[TCPStream]:
        """Return all reconstructed streams."""
        return list(self.streams.values())

    def get_stream(self, stream_id: str) -> Optional[TCPStream]:
        """Get a specific stream by ID."""
        return self.streams.get(stream_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Return processing statistics."""
        streams = self.get_streams()

        quality_counts = {}
        for stream in streams:
            quality = stream.reconstruction_quality
            quality_counts[quality] = quality_counts.get(quality, 0) + 1

        return {
            "total_streams": len(streams),
            "total_packets_processed": self.packets_processed,
            "packets_reassembled": sum(s.packets_analyzed for s in streams),
            "quality_distribution": quality_counts,
            "avg_packets_per_stream": (
                sum(s.packets_analyzed for s in streams) / max(len(streams), 1)
            ),
            "avg_bytes_per_stream": (
                sum(s.bytes_analyzed for s in streams) / max(len(streams), 1)
            )
        }