"""
Canonical analysis document.

One JSON-serialisable structure describes an analysis. It is produced either
directly from an ``OrchestratorResult`` (CLI) or from persisted rows (API), and
every report format (JSON / HTML / PDF) and the dashboard render from it. The
integration tests assert both producers yield the same document.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from securemailscope.rules.engine import RULE_CATALOGUE, RULE_GUIDANCE, Severity

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
        "timeline": [dict(e, ts=_iso(e["ts"]) if e.get("ts") is not None else None) for e in s.timeline],
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
        "why_it_matters": RULE_GUIDANCE.get(f.rule_id, {}).get("why"),
        "expected_effect": RULE_GUIDANCE.get(f.rule_id, {}).get("effect"),
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
                                              "why_it_matters": RULE_GUIDANCE.get(f["rule_id"], {}).get("why"),
                                              "expected_effect": RULE_GUIDANCE.get(f["rule_id"], {}).get("effect"),
                                              "finding_ids": [],
                                              "finding_count": 0, "risk_contribution": 0.0})
        if SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[e["severity"]]:
            e["severity"] = f["severity"]
        e["affected_sessions"].add(f["session_id"])
        e["finding_ids"].append(f["finding_id"])
        e["finding_count"] += 1
        e["risk_contribution"] = max(e["risk_contribution"], f.get("risk_contribution", 0.0))
    plan = sorted(by_rule.values(), key=lambda e: (SEVERITY_RANK[e["severity"]], -len(e["affected_sessions"]),
                                                   -e["risk_contribution"], e["rule_id"]))
    for i, e in enumerate(plan, 1):
        e["priority"] = i
        e["session_ids"] = sorted(e["affected_sessions"])
        e["affected_sessions"] = len(e["affected_sessions"])
    return plan


def certificate_inventory(certs: List[Dict[str, Any]], sessions: List[Dict[str, Any]],
                          capture_start: Optional[str]) -> List[Dict[str, Any]]:
    """Distinct certificates (by fingerprint) with reuse across sessions and servers."""
    by_sess = {s["session_id"]: s for s in sessions}
    inv: Dict[str, Dict[str, Any]] = {}
    ref = datetime.fromisoformat(capture_start) if capture_start else None
    for c in certs:
        e = inv.setdefault(c["fingerprint_sha256"], {
            "fingerprint_sha256": c["fingerprint_sha256"], "subject": c["subject"], "issuer": c["issuer"],
            "common_name": c["common_name"], "serial_number": c["serial_number"], "not_before": c["not_before"],
            "not_after": c["not_after"], "public_key_algorithm": c["public_key_algorithm"],
            "public_key_size_bits": c["public_key_size_bits"], "signature_algorithm": c["signature_algorithm"],
            "san_list": c["san_list"], "is_ca": c["is_ca"], "is_self_signed": c["is_self_signed"],
            "is_expired": c["is_expired"], "is_not_yet_valid": c["is_not_yet_valid"], "weak_key": c["weak_key"],
            "weak_signature": c["weak_signature"], "trust_status": c["trust_status"],
            "days_to_expiry_at_capture": None, "certificate_ids": [], "session_ids": [], "servers": [],
            "sni_requested": [], "chain_positions": [], "extraction": "observed in cleartext Certificate message",
            "chain_linkage": set(), "trust_validation": "not performed (no trust anchors)"})
        if ref and c["not_after"]:
            e["days_to_expiry_at_capture"] = (datetime.fromisoformat(c["not_after"]) - ref).days
        e["certificate_ids"].append(c["certificate_id"])
        e["chain_positions"].append(c["chain_position"])
        sess = by_sess.get(c["session_id"])
        if sess and sess["session_id"] not in e["session_ids"]:
            e["session_ids"].append(sess["session_id"])
            srv = f"{sess['server']['ip']}:{sess['server']['port']}"
            if srv not in e["servers"]:
                e["servers"].append(srv)
            sni = (sess.get("tls") or {}).get("sni")
            if sni and sni not in e["sni_requested"]:
                e["sni_requested"].append(sni)
        if c["issued_by_next"]:
            e["chain_linkage"].add(c["issued_by_next"])
    out = []
    for e in inv.values():
        e["chain_linkage"] = sorted(e["chain_linkage"])
        e["session_count"] = len(e["session_ids"])
        out.append(e)
    return sorted(out, key=lambda e: (-e["session_count"], e["subject"] or ""))


def protocol_summary(sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for sess in sessions:
        p = out.setdefault(sess["protocol"], {"sessions": 0, "implicit_tls": 0, "starttls_established": 0,
                                              "starttls_rejected": 0, "plaintext": 0, "tls_failed": 0, "other": 0})
        p["sessions"] += 1
        st = sess["starttls"]["final_state"]
        if sess["implicit_tls"]:
            p["implicit_tls"] += 1
        elif st in ("TLS_ESTABLISHED", "TLS_HANDSHAKE_STARTED"):
            p["starttls_established"] += 1
        elif st == "STARTTLS_REJECTED":
            p["starttls_rejected"] += 1
        elif st == "PLAINTEXT":
            p["plaintext"] += 1
        elif st == "TLS_FAILED":
            p["tls_failed"] += 1
        else:
            p["other"] += 1
    return out


def tls_summary(sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    versions: Dict[str, int] = {}
    ciphers: Dict[str, int] = {}
    kx: Dict[str, int] = {}
    fs = {"yes": 0, "no": 0, "unknown": 0}
    visibility: Dict[str, int] = {}
    for sess in sessions:
        t = sess.get("tls")
        if not t:
            continue
        v = t.get("negotiated_version") or "not observed"
        versions[v] = versions.get(v, 0) + 1
        if t.get("cipher_suite"):
            ciphers[t["cipher_suite"]] = ciphers.get(t["cipher_suite"], 0) + 1
        k = t.get("key_exchange_group") or t.get("key_exchange")
        if k:
            kx[k] = kx.get(k, 0) + 1
        f = t.get("forward_secrecy")
        fs["yes" if f is True else "no" if f is False else "unknown"] += 1
        vis = t.get("certificate_visibility") or "not_observed"
        visibility[vis] = visibility.get(vis, 0) + 1
    return {"versions": versions, "cipher_suites": ciphers, "key_exchange": kx, "forward_secrecy": fs,
            "certificate_visibility": visibility}


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
            "policy_profile": meta.get("policy_profile", "balanced"),
            "policy_profile_detail": meta.get("policy_profile_detail"),
            "mode": "passive (stored capture only; no traffic generated, nothing decrypted)",
            "tcp": meta.get("tcp"),
        },
        "posture": pdict,
        "remediation_plan": remediation_plan(findings),
        "protocol_summary": protocol_summary(sessions),
        "tls_summary": tls_summary(sessions),
        "certificate_inventory": certificate_inventory(certs, sessions, _iso(meta.get("start_time"))),
        "timeline": sorted((e for sess in sessions for e in sess["timeline"]),
                           key=lambda e: (e["ts"] is None, e["ts"] or "", e["frame"] or 0)),
        "sessions": sessions,
        "findings": findings,
        "certificates": certs,
        "anomalies": anomalies,
        "ml": meta.get("ml_engine_summary"),
        "limitations": LIMITATIONS,
    }
