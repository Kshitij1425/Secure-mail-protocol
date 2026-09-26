#!/usr/bin/env python3
"""
SecureMailScope command-line interface.

Usage:
    securemailscope analyze <capture.pcap|pcapng> [--output-dir DIR] [--json] [--html] [--pdf]

Runs the full analysis pipeline on the given capture (no fixtures, no shortcuts)
and writes reports rendered from the same canonical document used by the API.

Exit codes: 0 success, 1 analysis error, 2 file not found, 3 not a valid capture,
4 resource limit exceeded, 5 requested report format unavailable.
"""
import argparse
import logging
import sys
from pathlib import Path

if __package__ in (None, ""):
    # Allow ``python securemailscope/cli.py`` from the backend directory.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securemailscope import __version__ as VERSION
from securemailscope.core.orchestrator import Orchestrator
from securemailscope.ingestion.reader import AnalysisLimitExceeded
from securemailscope.reports.document import document_from_result
from securemailscope.reports.render import RENDERERS, ReportUnavailable, safe_report_basename


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="securemailscope",
        description="SecureMailScope - passive email TLS posture analysis of PCAP/PCAPNG captures",
        epilog="Example: securemailscope analyze capture.pcap --output-dir ./reports --json --html --pdf")
    parser.add_argument("command", choices=["analyze"], help="Command: analyze a capture")
    parser.add_argument("capture", help="PCAP/PCAPNG file to analyze")
    parser.add_argument("--output-dir", default=".", help="Output directory for reports (default: current dir)")
    parser.add_argument("--json", action="store_true", help="Write JSON report")
    parser.add_argument("--html", action="store_true", help="Write HTML report")
    parser.add_argument("--pdf", action="store_true", help="Write PDF report")
    parser.add_argument("--max-packets", type=int, default=0, help="Abort if the capture has more packets (0 = no limit)")
    parser.add_argument("--verbosity", choices=["quiet", "normal", "verbose"], default="normal")
    args = parser.parse_args(argv)

    logging.getLogger("securemailscope").setLevel(logging.DEBUG if args.verbosity == "verbose" else logging.WARNING)
    capture = Path(args.capture)
    if not capture.is_file():
        print(f"ERROR: capture file not found: {args.capture}", file=sys.stderr)
        return 2

    try:
        result = Orchestrator(securemailscope_version=VERSION, max_packets=args.max_packets).analyze(str(capture))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    except AnalysisLimitExceeded as e:
        print(f"ERROR: resource limit exceeded: {e}", file=sys.stderr)
        return 4
    except Exception as e:  # pragma: no cover - unexpected
        print(f"ERROR: analysis failed: {type(e).__name__}", file=sys.stderr)
        if args.verbosity == "verbose":
            import traceback
            traceback.print_exc()
        return 1

    doc = document_from_result(result, filename=capture.name)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = safe_report_basename(capture.name)
    status = 0
    for fmt, wanted in (("json", args.json), ("html", args.html), ("pdf", args.pdf)):
        if not wanted:
            continue
        render, _ = RENDERERS[fmt]
        try:
            data = render(doc)
        except ReportUnavailable as e:
            print(f"WARNING: {fmt.upper()} report skipped: {e}", file=sys.stderr)
            status = 5
            continue
        path = out_dir / f"{stem}_report.{fmt}"
        path.write_bytes(data)
        if args.verbosity != "quiet":
            print(f"{fmt.upper()} report: {path}")

    if args.verbosity != "quiet":
        p = result.posture
        cap = doc["capture"]
        print()
        print("# SecureMailScope Analysis")
        print(f"Capture: {capture.name}")
        print(f"SHA-256: {cap['sha256']}")
        print(f"Packets: {cap['total_packets']}  (IP: {cap['ip_packets']}, malformed: {cap['malformed_packets']})")
        print(f"TCP streams: {cap['reconstructed_streams']}")
        print(f"Email sessions: {result.email_session_count}")
        print(f"TLS sessions: {result.tls_session_count}")
        print()
        score = "n/a" if p.overall_score is None else f"{p.overall_score:.0f}/100"
        print(f"Security Posture: {score}")
        print(f"Status: {p.status.value}")
        print()
        by_sev = {}
        for f in result.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        print(f"Findings: {len(result.findings)} " + (str(by_sev) if by_sev else ""))
        print(f"ML anomalies (supplementary): {sum(1 for a in result.anomalies if a.is_anomaly)} "
              f"[{(doc.get('ml') or {}).get('status')}]")
        if doc["remediation_plan"]:
            print()
            print("Top issues:")
            for r in doc["remediation_plan"][:5]:
                print(f"{r['priority']}. {r['rule_id']} {r['title']} ({r['severity']}) - {r['affected_sessions']} session(s)")
    return status


if __name__ == "__main__":
    sys.exit(main())
