"""
Download the external validation captures listed in sources.json into downloads/ (git-ignored)
and verify each pinned SHA-256. Files that do not match are deleted, never used.

Usage (from backend/):  python -m tests.external_captures.fetch
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOWNLOADS = HERE / "downloads"


def main() -> int:
    sources = json.loads((HERE / "sources.json").read_text(encoding="utf-8"))
    DOWNLOADS.mkdir(exist_ok=True)
    failed = 0
    for c in sources["captures"]:
        dest = DOWNLOADS / c["file"]
        if not dest.exists() or hashlib.sha256(dest.read_bytes()).hexdigest() != c["sha256"]:
            req = urllib.request.Request(c["url"], headers={"User-Agent": "SecureMailScope-validation/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                dest.write_bytes(r.read())
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        if digest != c["sha256"]:
            dest.unlink()
            print(f"MISMATCH {c['file']}: got {digest}; file removed")
            failed += 1
        else:
            print(f"ok       {c['file']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
