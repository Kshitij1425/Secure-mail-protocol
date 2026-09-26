"""
PCAP / PCAPNG ingestion.

The capture is untrusted input. The reader:

* verifies the file magic before handing it to dpkt,
* decodes the link layer according to the capture's declared link type,
* counts (never raises on) malformed frames,
* stops cleanly at a truncated / corrupt tail and records it,
* enforces an optional packet limit and wall-clock budget.
"""
import hashlib
import time
import dpkt
from pathlib import Path
from typing import Generator, Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.ingestion")

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link-layer types (https://www.tcpdump.org/linktypes.html)
DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LOOP = 0, 1, 101, 108
DLT_RAW_ALT = {12, 14}
DLT_LINUX_SLL, DLT_LINUX_SLL2 = 113, 276
DLT_IPV4, DLT_IPV6 = 228, 229


class AnalysisLimitExceeded(Exception):
    """Raised when a capture exceeds a configured resource budget."""


def detect_capture_format(path: str) -> Optional[str]:
    """Return 'pcap', 'pcapng' or None based on the file magic."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return None


class PcapIngestor:
    """Ingests PCAP and PCAPNG files deterministically and handles malformed packets gracefully."""

    def __init__(self, file_path: str, max_packets: int = 0, time_budget_seconds: float = 0.0):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError("Capture file not found")
        self.max_packets = max_packets
        self.time_budget_seconds = time_budget_seconds
        self.file_size = self.file_path.stat().st_size
        self.sha256_hash = self._calculate_sha256()
        self.format = detect_capture_format(str(self.file_path))
        self.link_type: Optional[int] = None
        self.stats: Dict[str, Any] = {
            "total_packets": 0,
            "valid_packets": 0,
            "malformed_packets": 0,
            "ignored_non_ip": 0,
            "start_time": None,
            "end_time": None,
            "truncated": False,
            "truncation_reason": None,
        }

    def _calculate_sha256(self) -> str:
        """SHA-256 of the capture file for forensic integrity."""
        sha256 = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            while chunk := f.read(1 << 20):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_metadata(self) -> Dict[str, Any]:
        """Capture metadata. Only the base name is exposed, never the server-side path."""
        meta = {
            "filename": self.file_path.name,
            "size_bytes": self.file_size,
            "sha256": self.sha256_hash,
            "format": self.format,
            "link_type": self.link_type,
            "analysis_time": datetime.now(timezone.utc).isoformat(),
        }
        meta.update(self.stats)
        return meta

    def _decode_link(self, buf: bytes):
        lt = self.link_type
        if lt == DLT_EN10MB:
            frame = dpkt.ethernet.Ethernet(buf)   # handles 802.1Q/QinQ and MPLS
            return frame.data
        if lt == DLT_LINUX_SLL:
            return dpkt.sll.SLL(buf).data
        if lt == DLT_LINUX_SLL2:
            return dpkt.sll2.SLL2(buf).data
        if lt in (DLT_NULL, DLT_LOOP):
            return dpkt.loopback.Loopback(buf).data
        if lt in (DLT_RAW, DLT_IPV4, DLT_IPV6) or lt in DLT_RAW_ALT:
            if buf and (buf[0] >> 4) == 6:
                return dpkt.ip6.IP6(buf)
            return dpkt.ip.IP(buf)
        # Unknown link type: try Ethernet, then raw IP.
        try:
            return dpkt.ethernet.Ethernet(buf).data
        except Exception:
            return dpkt.ip.IP(buf)

    def read_packets(self) -> Generator[Tuple[float, Any, int], None, None]:
        """Yield (timestamp, ip_packet, frame_number) for every IPv4/IPv6 packet."""
        if self.format is None:
            raise ValueError("Invalid capture: not a PCAP or PCAPNG file")
        logger.info(f"Starting ingestion of {self.file_path.name} (SHA-256: {self.sha256_hash[:12]}...)")
        started = time.monotonic()

        with open(self.file_path, "rb") as f:
            try:
                reader = dpkt.pcapng.Reader(f) if self.format == "pcapng" else dpkt.pcap.Reader(f)
                self.link_type = reader.datalink()
            except Exception as e:
                logger.error(f"Failed to initialize capture reader: {type(e).__name__}")
                raise ValueError("Invalid capture: unreadable PCAP/PCAPNG header")

            frame_num = 0
            iterator = iter(reader)
            while True:
                try:
                    ts, buf = next(iterator)
                except StopIteration:
                    break
                except Exception as e:
                    # Truncated or corrupt record: keep what was read so far.
                    self.stats["truncated"] = True
                    self.stats["truncation_reason"] = f"corrupt or truncated record after frame {frame_num} ({type(e).__name__})"
                    logger.warning(f"Capture truncated/corrupt after frame {frame_num}")
                    break

                frame_num += 1
                self.stats["total_packets"] += 1
                if self.max_packets and frame_num > self.max_packets:
                    raise AnalysisLimitExceeded(f"capture exceeds the {self.max_packets}-packet limit")
                if self.time_budget_seconds and frame_num % 5000 == 0 \
                        and time.monotonic() - started > self.time_budget_seconds:
                    raise AnalysisLimitExceeded(f"ingestion exceeded {self.time_budget_seconds:.0f}s budget")

                ts = float(ts)
                if self.stats["start_time"] is None or ts < self.stats["start_time"]:
                    self.stats["start_time"] = ts
                if self.stats["end_time"] is None or ts > self.stats["end_time"]:
                    self.stats["end_time"] = ts

                try:
                    pkt = self._decode_link(buf)
                except Exception:
                    self.stats["malformed_packets"] += 1
                    continue
                if isinstance(pkt, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    self.stats["valid_packets"] += 1
                    yield ts, pkt, frame_num
                else:
                    self.stats["ignored_non_ip"] += 1

        logger.info(
            f"Ingestion finished: {self.stats['total_packets']} frames, {self.stats['valid_packets']} IP, "
            f"{self.stats['malformed_packets']} malformed, {self.stats['ignored_non_ip']} non-IP."
        )
