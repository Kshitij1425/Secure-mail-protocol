"""
Forensic evidence bundle: deterministic ZIP of JSON files with integrity metadata.

Deterministic: fixed entry order, fixed ZIP timestamps (the analysis timestamp), sorted JSON
keys, no creation-time values. The same stored analysis always yields byte-identical bundles.
Contains analysis results and metadata only - never packet payloads or message content.
"""
import hashlib
import io
import json
import zipfile
from datetime import datetime
from typing import Any, Dict

from securemailscope.reports.redact import raw_label, redact_document

BUNDLE_FORMAT = "securemailscope-evidence-bundle/1"


def _dumps(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8")


def build_bundle(doc: Dict[str, Any], redact: bool = False) -> bytes:
    d = redact_document(doc) if redact else raw_label(doc)
    cap, ana = d["capture"], d["analysis"]
    files = {
        "capture/metadata.json": {"capture": cap, "analysis": ana},
        "analysis/posture.json": d["posture"],
        "analysis/findings.json": d["findings"],
        "analysis/remediation.json": d["remediation_plan"],
        "analysis/sessions.json": d["sessions"],
        "analysis/certificates.json": d["certificates"],
        "analysis/certificate_inventory.json": d.get("certificate_inventory", []),
        "analysis/anomalies.json": {"model": d.get("ml"), "results": d["anomalies"],
                                    "note": "ML anomalies are statistical outliers requiring investigation; "
                                            "they are not confirmed vulnerabilities or compromise."},
        "analysis/timeline.json": d.get("timeline", []),
        "analysis/document.json": d,
    }
    readme = (
        "SecureMailScope forensic evidence bundle\n"
        f"Format: {BUNDLE_FORMAT}\n"
        f"Capture: {cap.get('filename')}  SHA-256: {cap.get('sha256')}\n"
        f"Analysed: {ana.get('analyzed_at')}  Tool: {d['tool'].get('version')}  Policy: {ana.get('policy_profile')}\n"
        f"Mode: {d['redaction']['mode']}\n\n"
        "Passive analysis of a stored capture. Contents are analysis results and metadata; no packet payloads\n"
        "or message contents are included. Verify integrity with manifest.json (SHA-256 of every file) and\n"
        "manifest.sha256 (SHA-256 of manifest.json). Evidence frame numbers refer to the original capture.\n"
    ).encode("utf-8")

    blobs = {"README.txt": readme}
    blobs.update({name: _dumps(obj) for name, obj in files.items()})
    manifest = {
        "bundle_format": BUNDLE_FORMAT,
        "capture_id": cap.get("capture_id"),
        "capture_filename": cap.get("filename"),
        "capture_sha256": cap.get("sha256"),
        "analyzed_at": ana.get("analyzed_at"),
        "tool": d["tool"],
        "policy_profile": ana.get("policy_profile"),
        "redaction": d["redaction"],
        "contains_packet_payloads": False,
        "files": [{"path": n, "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()} for n, b in sorted(blobs.items())],
    }
    mbytes = _dumps(manifest)
    blobs["manifest.json"] = mbytes
    blobs["manifest.sha256"] = f"{hashlib.sha256(mbytes).hexdigest()}  manifest.json\n".encode()

    try:
        t = datetime.fromisoformat(ana.get("analyzed_at"))
        stamp = (max(t.year, 1980), t.month, t.day, t.hour, t.minute, t.second - t.second % 2)
    except (TypeError, ValueError):
        stamp = (1980, 1, 1, 0, 0, 0)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in sorted(blobs):
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, blobs[name])
    return buf.getvalue()
