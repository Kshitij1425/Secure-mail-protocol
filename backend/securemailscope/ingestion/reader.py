import hashlib
import os
import dpkt
from pathlib import Path
from typing import Generator, Tuple, Dict, Any, Optional
from datetime import datetime, timezone

from securemailscope.utils.logger import get_logger

logger = get_logger("securemailscope.ingestion")

class PcapIngestor:
    """Ingests PCAP and PCAPNG files deterministically and handles malformed packets gracefully."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        self.file_size = self.file_path.stat().st_size
        self.sha256_hash = self._calculate_sha256()
        self.stats = {
            "total_packets": 0,
            "valid_packets": 0,
            "malformed_packets": 0,
            "ignored_non_ip": 0,
            "start_time": None,
            "end_time": None
        }

    def _calculate_sha256(self) -> str:
        """Calculate the SHA-256 hash of the PCAP file for forensic integrity."""
        sha256 = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_metadata(self) -> Dict[str, Any]:
        """Return capture file metadata."""
        meta = {
            "filename": self.file_path.name,
            "filepath": str(self.file_path.absolute()),
            "size_bytes": self.file_size,
            "sha256": self.sha256_hash,
            "analysis_time": datetime.now(timezone.utc).isoformat()
        }
        meta.update(self.stats)
        return meta

    def read_packets(self) -> Generator[Tuple[float, Any, int], None, None]:
        """
        Yields (timestamp, ip_packet, frame_number).
        Handles both PCAP and PCAPNG via dpkt.
        """
        logger.info(f"Starting ingestion of {self.file_path.name} (SHA-256: {self.sha256_hash[:12]}...)")

        with open(self.file_path, "rb") as f:
            # Check magic number to pick reader
            magic = f.read(4)
            f.seek(0)

            is_pcapng = magic == b"\x0a\x0d\x0d\x0a"

            try:
                if is_pcapng:
                    reader = dpkt.pcapng.Reader(f)
                else:
                    reader = dpkt.pcap.Reader(f)
            except Exception as e:
                logger.error(f"Failed to initialize PCAP reader: {e}")
                raise ValueError(f"Invalid PCAP/PCAPNG format: {e}")

            frame_num = 0
            for ts, buf in reader:
                frame_num += 1
                self.stats["total_packets"] += 1

                if self.stats["start_time"] is None:
                    self.stats["start_time"] = ts
                self.stats["end_time"] = ts

                try:
                    # Parse link-layer (usually Ethernet)
                    eth = dpkt.ethernet.Ethernet(buf)

                    # Handle IP layers (IPv4 and IPv6)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip_pkt = eth.data
                        self.stats["valid_packets"] += 1
                        yield ts, ip_pkt, frame_num
                    elif isinstance(eth.data, dpkt.ip6.IP6):
                        ip_pkt = eth.data
                        self.stats["valid_packets"] += 1
                        yield ts, ip_pkt, frame_num
                    else:
                        # Raw IP or other link-layer encapsulation
                        try:
                            ip_pkt = dpkt.ip.IP(buf)
                            self.stats["valid_packets"] += 1
                            yield ts, ip_pkt, frame_num
                        except Exception:
                            self.stats["ignored_non_ip"] += 1
                except Exception as e:
                    self.stats["malformed_packets"] += 1
                    logger.debug(f"Frame #{frame_num} malformed: {e}")
                    continue

        logger.info(
            f"Ingestion finished: {self.stats['valid_packets']} valid packets, "
            f"{self.stats['malformed_packets']} malformed, {self.stats['ignored_non_ip']} non-IP."
        )
