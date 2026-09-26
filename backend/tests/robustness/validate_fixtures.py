"""
Compare the full analysis pipeline against every fixture's ground truth.

Usage (from backend/):  python -m tests.robustness.validate_fixtures [--verbose]
Also imported by tests/test_real_pcap_validation.py.
"""
import json
import sys
from pathlib import Path
from typing import Dict, List

from securemailscope.core.orchestrator import Orchestrator

FIXTURES = Path(__file__).parent / "fixtures"


def load_cases() -> List[Dict]:
    cases = []
    for gt in sorted((FIXTURES / "ground_truth").glob("*.json")):
        truth = json.loads(gt.read_text(encoding="utf-8"))
        pcap = next((p for p in (FIXTURES / "pcaps").glob(truth["name"] + ".*")), None)
        if pcap is not None and "expected_sessions" in truth:
            cases.append({"truth": truth, "pcap": pcap})
    return cases


def session_view(s) -> Dict:
    t = s.tls_data
    return {
        "protocol": s.protocol.name,
        "starttls_state": s.starttls_state.name,
        "tls_version": t.server_version if t else None,
        "findings": sorted({f.rule_id for f in s.findings}),
        "certificates": len(s.certificates),
        "reconstruction_quality": s.stream.reconstruction_quality,
        "implicit_tls": s.implicit_tls,
        "handshake_status": t.handshake_status if t else None,
    }


def check_case(case) -> List[str]:
    truth, pcap = case["truth"], case["pcap"]
    result = Orchestrator().analyze(str(pcap))
    errors = []
    got = sorted((session_view(s) for s in result.sessions), key=lambda v: json.dumps(v, sort_keys=True))
    want = sorted(truth["expected_sessions"], key=lambda v: json.dumps(v, sort_keys=True))
    if len(got) != len(want):
        errors.append(f"email sessions: expected {len(want)}, got {len(got)}")
    for g, w in zip(got, want):
        for k, v in w.items():
            if v is None and k == "handshake_status":
                continue
            if g.get(k) != v:
                errors.append(f"{k}: expected {v!r}, got {g.get(k)!r}")
    if truth.get("expected_streams") is not None and result.reconstructed_stream_count != truth["expected_streams"]:
        errors.append(f"streams: expected {truth['expected_streams']}, got {result.reconstructed_stream_count}")
    if truth.get("expected_posture_status") and result.posture.status.value != truth["expected_posture_status"]:
        errors.append(f"posture: expected {truth['expected_posture_status']}, got {result.posture.status.value}")
    if truth.get("expected_certificate_visibility"):
        vis = {s.tls_data.certificate_visibility for s in result.sessions if s.tls_data}
        if vis != {truth["expected_certificate_visibility"]}:
            errors.append(f"certificate_visibility: {vis}")
    if truth.get("expected_chain_status"):
        st = {s.chain.get("status") for s in result.sessions}
        if st != {truth["expected_chain_status"]}:
            errors.append(f"chain status: {st}")
    forbidden = truth.get("forbidden_strings_in_outputs") or []
    if forbidden:
        blob = json.dumps([{"f": [f.__dict__ for f in s.findings], "st": s.starttls.__dict__ if s.starttls else None}
                           for s in result.sessions], default=str)
        for fs in forbidden:
            if fs in blob:
                errors.append(f"forbidden credential material present in outputs: {fs!r}")
    return errors


def main(verbose=False) -> int:
    failures = 0
    for case in load_cases():
        errs = check_case(case)
        name = case["truth"]["name"]
        print(f"{'PASS' if not errs else 'FAIL'}  {name}")
        for e in errs:
            print(f"        - {e}")
        failures += bool(errs)
    print(f"\n{failures} failing fixture(s)")
    return failures


if __name__ == "__main__":
    import logging
    logging.disable(logging.WARNING)
    sys.exit(1 if main("--verbose" in sys.argv) else 0)
