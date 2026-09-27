"""Shared helpers for the browser QA scripts (run against a running API and dashboard)."""
import json
import re
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = os.environ.get("SMS_API", "http://127.0.0.1:8000")
UI = os.environ.get("SMS_UI", "http://127.0.0.1:5173")
FIXTURES = ROOT / "backend" / "tests" / "robustness" / "fixtures" / "pcaps"
REAL = ROOT / "backend" / "tests" / "real_captures"


def upload(path: Path, policy: str = "balanced") -> str:
    """Analyse a capture through the public API (multipart upload); returns the capture id."""
    boundary = "----smsqa"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"policy\"\r\n\r\n{policy}\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{API}/analyze", data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["capture_id"]


def api_get(path: str):
    with urllib.request.urlopen(f"{API}{path}", timeout=60) as r:
        return json.loads(r.read())


def seed() -> dict:
    """The analyses every QA run works on (created fresh, so no stored ids are assumed)."""
    return {
        "mixed": upload(FIXTURES / "ml_mixed_estate.pcap"),
        "before": upload(REAL / "real_remediation_before.pcap"),
        "after": upload(REAL / "real_remediation_after.pcap"),
        "imap": upload(REAL / "real_imap_starttls_weak_tls10.pcap", policy="strict"),
    }


def watch(page, problems: list):
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("console", lambda m: problems.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
    page.on("response", lambda r: problems.append(f"HTTP {r.status} {r.request.method} {r.url}") if r.status >= 400 else None)
    # A link that downloads a file is reported by Chromium as an aborted navigation (net::ERR_ABORTED);
    # those downloads are verified separately, so only other failures count.
    page.on("requestfailed", lambda r: None if (r.failure == "net::ERR_ABORTED" and re.search(r"/(download|bundle|stix)", r.url))
            else problems.append(f"request failed {r.method} {r.url}: {r.failure}"))
