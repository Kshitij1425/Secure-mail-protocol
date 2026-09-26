"""
Canonical analysis document.

One JSON-serialisable structure describes an analysis. It is produced either
directly from an ``OrchestratorResult`` (CLI) or from persisted rows (API), and
every report format (JSON / HTML / PDF) and the dashboard render from it. The
integration tests assert both producers yield the same document.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from securemailscope.rules.engine import RULE_CATALOGUE, Severity

REPORT_VERSION = "2.0"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

LIMITATIONS = [
    "Passive analysis: only what is visible on the wire is assessed; no server is contacted.",
    "TLS 1.3 encrypts the server Certificate message; certificates of TLS 1.3 sessions are NOT OBSERVED.",
    "Certificate trust is not evaluated: no trust-anchor store is consulted. Chain checks verify only that "
    "each presented certificate is signed by the next one.",
    "Certificate validity is evaluated at the capture's first-packet time (see 'certificate_validity_reference').",
    "STARTTLS rejection is consistent with misconfiguration or an on-path downgrade; a capture cannot prove which.",
    "ML anomaly detection is unsupervised and fitted per capture on its own TLS sessions. An anomaly is a "
    "statistical outlier, not a confirmed vulnerability, and never changes findings or the posture score.",
    "IP fragment reassembly is not performed; fragmented TCP segments are ignored.",
    "Evidence frames refer to 1-based frame numbers in the original capture file.",
]


def _iso(v) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.isoformat()
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v), timezone.utc).isoformat()
    return str(v)


def finding_priority_key(f: Dict[str, Any]):
    return (SEVERITY_RANK.get(f["severity"], 9), -f.get("confidence", 0), f["rule_id"], f["finding_id"])


def session_doc(s, capture_id: Optional[str] = None) -> Dict[str, Any]:
    t = s.tls_data
    st = s.starttls
    stream = s.stream
    tls = None
    if t is not None:
        tls = {
            "negotiated_version": t.server_version,
            "client_hello_version": t.client_version,
            "client_max_version": t.client_max_version,
            "client_offered_versions": t.client_offered_versions,
            "cipher_suite": t.cipher_suite_name,
            "cipher_suite_code": f"0x{t.cipher_suite_hex:04X}" if t.cipher_suite_hex is not None else None,
            "cipher_strength": t.cipher.strength if t.cipher else None,
            "key_exchange": t.key_exchange,
            "key_exchange_group": t.key_exchange_group,
            "dh_prime_bits": t.dh_prime_bits,
            "forward_secrecy": t.has_forward_secrecy if t.server_version else None,
            "sni": t.sni,
            "alpn": t.alpn,
            "client_offered_cipher_count": len(t.client_supported_ciphers),
            "handshake_status": t.handshake_status,
            "certificate_visibility": t.certificate_visibility,
            "alerts": t.alert_details,
            "protocol_violations": t.protocol_violations,
            "fallback_scsv_offered": t.fallback_scsv_offered,
            "evidence_frames": t.evidence_frames,
        }
    return {
        "session_id": s.session_id,
        "capture_id": capture_id,
        "stream_id": stream.stream_id,
        "protocol": s.protocol.name,
        "client": {"ip": stream.client_ip, "port": stream.src_port},
        "server": {"ip": stream.server_ip, "port": stream.dst_port},
        "start_time": _iso(stream.start_time),
        "end_time": _iso(stream.end_time),
        "first_frame": stream.first_frame,
        "last_frame": stream.last_frame,
        "packet_count": stream.packets_analyzed,
        "payload_bytes": stream.payload_bytes,
        "detection": {"method": s.detection.detection_method if s.detection else None,
                      "confidence": s.detection.confidence if s.detection else None},
        "implicit_tls": s.implicit_tls,
        "starttls": {
            "final_state": s.starttls_state.name,
            "advertised_by_server": st.starttls_advertised if st else None,
            "attempts": st.starttls_attempts if st else 0,
            "server_response": st.starttls_response if st else None,
            "plaintext_auth_mechanisms": list(st.plaintext_auth_mechanisms) if st else [],
            "pipelined_after_starttls": bool(st.pipelined_after_starttls) if st else False,
        },
        "tls": tls,
        "reconstruction": stream.quality_summary(),
        "chain": {k: v for k, v in (s.chain or {}).items() if k != "links"} | (
            {"links": s.chain.get("links", [])} if s.chain else {}),
        "evidence_frames": dict(s.evidence_frames),
        "finding_ids": [f.finding_id for f in s.findings],
        "certificate_ids": [f"{s.session_id}~c{c.chain_position}" for c in s.certificates],
    }


def certificate_doc(session_id: str, c) -> Dict[str, Any]:
    return {
        "certificate_id": f"{session_id}~c{c.chain_position}",
        "session_id": session_id,
        "chain_position": c.chain_position,
        "fingerprint_sha256": c.fingerprint_sha256,
        "subject": c.subject,
        "issuer": c.issuer,
        "common_name": c.common_name,
        "serial_number": c.serial_number,
        "not_before": _iso(c.not_before),
        "not_after": _iso(c.not_after),
        "validity_reference": c.validity_reference,
        "is_expired": c.is_expired,
        "is_not_yet_valid": c.is_not_yet_valid,
        "is_self_signed": c.is_self_signed,
        "is_ca": c.is_ca,
        "public_key_algorithm": c.public_key_algorithm,
        "public_key_size_bits": c.public_key_size_bits,
        "signature_algorithm": c.signature_algorithm,
        "san_list": list(c.san_list),
        "weak_key": c.weak_key,
        "weak_signature": c.weak_signature,
        "issued_by_next": c.issued_by_next,
        "trust_status": c.trust_status,
    }


def finding_doc(f, impacts: Dict[str, float]) -> Dict[str, Any]:
    sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
    return {
        "finding_id": f.finding_id,
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": sev,
        "confidence": round(float(f.confidence), 3),
        "category": f.category,
        "dimension": f.dimension or (RULE_CATALOGUE[f.rule_id].dimension if f.rule_id in RULE_CATALOGUE else None),
        "evidence_type": f.evidence_type,
        "session_id": f.session_id,
        "description": f.description,
        "recommendation": f.recommendation,
        "references": f.standards_ref,
        "evidence": f.evidence,
        "evidence_frames": list(f.evidence_frames),
        "risk_contribution": round(impacts.get(f.finding_id, 0.0), 2),
    }


def anomaly_doc(a) -> Dict[str, Any]:
    return {
        "session_id": a.session_id,
        "is_anomaly": a.is_anomaly,
        "anomaly_score": round(float(a.anomaly_score), 4),
        "anomaly_level": a.anomaly_level.value,
        "explanation": a.explanation,
        "features": {k: v for k, v in a.features.items() if k not in ("session_id",)},
        "classification": "ML_ANOMALY (statistical outlier; not a confirmed vulnerability)",
    }


def impact_by_finding(posture) -> Dict[str, float]:
    """Posture points attributed to the root cause each finding belongs to."""
    out: Dict[str, float] = {}
    for d in posture.dimension_scores:
        for c in d.top_contributors:
            for fid in c.finding_ids:
                out[fid] = max(out.get(fid, 0.0), c.impact_points)
    return out


def remediation_plan(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group findings by rule into a prioritised remediation list."""
    by_rule: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f["severity"] == "INFO":
            continue
        e = by_rule.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "title": RULE_CATALOGUE[f["rule_id"]].title
                                              if f["rule_id"] in RULE_CATALOGUE else f["title"],
                                              "severity": f["severity"], "recommendation": f["recommendation"],
                                              "references": f["references"], "affected_sessions": set(),
                                              "finding_count": 0, "risk_contribution": 0.0})
        if SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[e["severity"]]:
            e["severity"] = f["severity"]
        e["affected_sessions"].add(f["session_id"])
        e["finding_count"] += 1
        e["risk_contribution"] = max(e["risk_contribution"], f.get("risk_contribution", 0.0))
    plan = sorted(by_rule.values(), key=lambda e: (SEVERITY_RANK[e["severity"]], -len(e["affected_sessions"]),
                                                   -e["risk_contribution"], e["rule_id"]))
    for i, e in enumerate(plan, 1):
        e["priority"] = i
        e["affected_sessions"] = len(e["affected_sessions"])
    return plan


def document_from_result(result, capture_id: Optional[str] = None, filename: Optional[str] = None,
                         analyzed_at: Optional[datetime] = None) -> Dict[str, Any]:
    meta = result.metadata
    posture = result.posture
    impacts = impact_by_finding(posture)
    sessions = [session_doc(s, capture_id) for s in result.sessions]
    findings = sorted((finding_doc(f, impacts) for f in result.findings), key=finding_priority_key)
    certs = [certificate_doc(s.session_id, c) for s in result.sessions for c in s.certificates]
    anomalies = [anomaly_doc(a) for a in result.anomalies]
    pdict = posture.to_dict()
    pdict["root_cause_groups"] = posture.root_cause_groups
    pdict["coverage"] = meta.get("coverage", {})
    return {
        "report_version": REPORT_VERSION,
        "tool": {"name": "SecureMailScope", "version": meta.get("tool_version")},
        "capture": {
            "capture_id": capture_id,
            "filename": filename or meta.get("filename"),
            "sha256": meta.get("sha256"),
            "size_bytes": meta.get("size_bytes"),
            "format": meta.get("format"),
            "link_type": meta.get("link_type"),
            "total_packets": meta.get("total_packets"),
            "ip_packets": meta.get("valid_packets"),
            "malformed_packets": meta.get("malformed_packets"),
            "truncated": meta.get("truncated"),
            "truncation_reason": meta.get("truncation_reason"),
            "reconstructed_streams": meta.get("reconstructed_streams"),
            "email_sessions": meta.get("email_session_count"),
            "tls_sessions": meta.get("tls_session_count"),
            "capture_start": _iso(meta.get("start_time")),
            "capture_end": _iso(meta.get("end_time")),
        },
        "analysis": {
            "analyzed_at": _iso(analyzed_at or posture.analyzed_at),
            "rule_policy_version": meta.get("rule_policy_version"),
            "scoring_policy_version": posture.scoring_policy_version,
            "ml_model_version": (meta.get("ml_engine_summary") or {}).get("model_version"),
            "certificate_validity_reference": meta.get("certificate_validity_reference"),
            "tcp": meta.get("tcp"),
        },
        "posture": pdict,
        "remediation_plan": remediation_plan(findings),
        "sessions": sessions,
        "findings": findings,
        "certificates": certs,
        "anomalies": anomalies,
        "ml": meta.get("ml_engine_summary"),
        "limitations": LIMITATIONS,
    }
