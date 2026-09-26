"""
CLI + report tests. Every report here is produced from a real capture through the
full pipeline (the previous tests rendered reports from a bare posture object with
no sessions, findings or certificates, which is how reports lacking findings slipped
through).
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from securemailscope.cli import main as cli_main
from securemailscope.core.orchestrator import Orchestrator
from securemailscope.reports.document import document_from_result
from securemailscope.reports.render import render_html, render_json, render_pdf, safe_report_basename

BACKEND = Path(__file__).resolve().parent.parent
PCAPS = BACKEND / "tests" / "robustness" / "fixtures" / "pcaps"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def doc_for(name: str):
    return document_from_result(Orchestrator().analyze(str(PCAPS / name)), filename=name)


def _stable(doc):
    d = json.loads(json.dumps(doc, default=str))
    d["analysis"]["analyzed_at"] = None
    d["posture"]["analyzed_at"] = None
    return d


def test_json_report_carries_real_evidence():
    doc = doc_for("smtp_weak_deprecated.pcap")
    assert doc["capture"]["sha256"] == sha256(PCAPS / "smtp_weak_deprecated.pcap")
    assert doc["capture"]["total_packets"] > 0
    assert {f["rule_id"] for f in doc["findings"]} == {"TLS-001", "TLS-004", "CERT-001", "CERT-003", "CERT-005"}
    assert len(doc["certificates"]) == 1 and doc["certificates"][0]["is_expired"] is True
    assert doc["sessions"][0]["tls"]["negotiated_version"] == "TLSv1.0"
    assert doc["analysis"]["scoring_policy_version"] == "2.0"
    assert all(f["evidence_frames"] for f in doc["findings"]), "every finding must cite capture frames"
    assert doc["remediation_plan"][0]["priority"] == 1


def test_report_determinism_same_capture():
    a, b = _stable(doc_for("implicit_tls_mixed.pcap")), _stable(doc_for("implicit_tls_mixed.pcap"))
    assert a == b


def test_html_escapes_untrusted_values():
    doc = doc_for("clean_baseline.pcap")
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    doc["capture"]["filename"] = evil
    doc["findings"][0]["description"] = evil
    html = render_html(doc).decode()
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html  # CSP forbids script even if escaping regressed


def test_html_sections_present():
    html = render_html(doc_for("smtp_starttls_tls12_chain.pcap")).decode()
    for section in ("Executive summary", "Capture metadata", "Posture by dimension", "Prioritised remediation",
                    "Findings", "Email sessions", "Certificates", "ML anomalies", "Method &amp; limitations"):
        assert section in html


def test_pdf_report_generated_and_escaped():
    doc = doc_for("smtp_weak_deprecated.pcap")
    doc["findings"][0]["description"] = "<b>bold & <font size=40>"  # would break ReportLab markup if unescaped
    pdf = render_pdf(doc)
    assert pdf.startswith(b"%PDF-") and len(pdf) > 2000


def test_json_roundtrip():
    doc = doc_for("pop3_starttls_rejected.pcap")
    assert json.loads(render_json(doc))["findings"][0]["rule_id"] in {"PROTO-001", "STLS-001"}


@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd.pcap", "passwd"), ("C:\\Windows\\evil.pcap", "evil"),
    ("a/b/c.pcapng", "c"), ("..", "capture"), ("x" * 500 + ".pcap", "x" * 80), ("rep\x00ort.pcap", "rep_ort"),
])
def test_safe_report_basename(name, expected):
    out = safe_report_basename(name)
    assert "/" not in out and "\\" not in out and ".." not in out
    assert out == expected or out.startswith(expected)


def test_cli_end_to_end(tmp_path):
    pcap = PCAPS / "smtp_starttls_tls12_chain.pcap"
    rc = cli_main(["analyze", str(pcap), "--output-dir", str(tmp_path), "--json", "--html", "--pdf"])
    assert rc == 0
    report = json.loads((tmp_path / "smtp_starttls_tls12_chain_report.json").read_text())
    assert report["capture"]["sha256"] == sha256(pcap)
    assert (tmp_path / "smtp_starttls_tls12_chain_report.html").exists()
    assert (tmp_path / "smtp_starttls_tls12_chain_report.pdf").read_bytes().startswith(b"%PDF-")


def test_cli_subprocess_summary(tmp_path):
    pcap = PCAPS / "smtp_starttls_tls13_secure.pcap"
    result = subprocess.run([sys.executable, str(BACKEND / "securemailscope" / "cli.py"), "analyze", str(pcap),
                             "--output-dir", str(tmp_path), "--json"], capture_output=True, text=True, cwd=BACKEND)
    assert result.returncode == 0, result.stderr
    assert "Email sessions: 1" in result.stdout
    assert "Security Posture: 100/100" in result.stdout
    assert f"Packets: {Orchestrator().analyze(str(pcap)).packet_count}" in result.stdout


def test_cli_exit_codes(tmp_path):
    assert cli_main(["analyze", str(tmp_path / "missing.pcap")]) == 2
    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(b"this is not a capture")
    assert cli_main(["analyze", str(bogus)]) == 3
    assert cli_main(["analyze", str(PCAPS / "ml_mixed_estate.pcap"), "--max-packets", "10"]) == 4
