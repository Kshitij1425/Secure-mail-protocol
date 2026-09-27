"""
Capture comparison: difference between two stored analyses (A = baseline, B = later).

Findings and configurations are matched per *asset* = protocol + server address + port,
because session identifiers (client ports, capture ids) differ between captures.
Everything is computed from the two persisted canonical documents; nothing is inferred.
"""
from typing import Any, Dict, List, Tuple

SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _asset(session: Dict[str, Any]) -> str:
    return f"{session['protocol']} {session['server']['ip']}:{session['server']['port']}"


def _profile(doc: Dict[str, Any]) -> Dict[str, Any]:
    cap, post, ana = doc["capture"], doc["posture"], doc["analysis"]
    return {"capture_id": cap.get("capture_id"), "filename": cap.get("filename"), "sha256": cap.get("sha256"),
            "captured_at": cap.get("capture_start"), "analyzed_at": ana.get("analyzed_at"),
            "policy_profile": ana.get("policy_profile", "balanced"), "score": post.get("overall_score"),
            "status": post.get("status"), "email_sessions": cap.get("email_sessions"),
            "tls_sessions": cap.get("tls_sessions"), "findings": len(doc.get("findings", [])),
            "anomalies": sum(1 for a in doc.get("anomalies", []) if a.get("is_anomaly"))}


def _assets(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    certs_by_sess: Dict[str, List[Dict]] = {}
    for c in doc.get("certificates", []):
        certs_by_sess.setdefault(c["session_id"], []).append(c)
    out: Dict[str, Dict[str, Any]] = {}
    for s in doc.get("sessions", []):
        a = out.setdefault(_asset(s), {"sessions": 0, "tls_versions": set(), "cipher_suites": set(),
                                       "key_exchange": set(), "starttls_states": set(), "certificates": {}})
        a["sessions"] += 1
        t = s.get("tls") or {}
        a["tls_versions"].add(t.get("negotiated_version") or "not observed")
        if t.get("cipher_suite"):
            a["cipher_suites"].add(t["cipher_suite"])
        if t.get("key_exchange_group") or t.get("key_exchange"):
            a["key_exchange"].add(t.get("key_exchange_group") or t.get("key_exchange"))
        a["starttls_states"].add("implicit TLS" if s.get("implicit_tls") else s["starttls"]["final_state"])
        for c in certs_by_sess.get(s["session_id"], []):
            if c["chain_position"] == 0:
                a["certificates"][c["fingerprint_sha256"]] = {
                    "fingerprint_sha256": c["fingerprint_sha256"], "subject": c["subject"],
                    "not_after": c["not_after"], "is_expired": c["is_expired"],
                    "public_key": f"{c['public_key_algorithm']} {c['public_key_size_bits']}",
                    "signature_algorithm": c["signature_algorithm"]}
    return out


def _finding_keys(doc: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    sess = {s["session_id"]: s for s in doc.get("sessions", [])}
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in doc.get("findings", []):
        s = sess.get(f["session_id"])
        asset = _asset(s) if s else "capture"
        e = out.setdefault((f["rule_id"], asset), {"rule_id": f["rule_id"], "title": f["title"], "asset": asset,
                                                  "severity": f["severity"], "sessions": set(), "finding_ids": []})
        if SEV[f["severity"]] < SEV[e["severity"]]:
            e["severity"] = f["severity"]
        e["sessions"].add(f["session_id"])
        e["finding_ids"].append(f["finding_id"])
    return out


def _anomalous_sessions(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ML-flagged sessions with the security properties an analyst needs to judge them."""
    sess = {s["session_id"]: s for s in doc.get("sessions", [])}
    leaf = {c["session_id"]: c for c in doc.get("certificates", []) if c.get("chain_position") == 0}
    out = []
    for a in doc.get("anomalies", []):
        s = sess.get(a["session_id"])
        if not a.get("is_anomaly") or not s:
            continue
        t = s.get("tls") or {}
        c = leaf.get(s["session_id"])
        out.append({
            "session_id": s["session_id"], "stream_id": s["stream_id"], "asset": _asset(s), "protocol": s["protocol"],
            "client": f"{s['client']['ip']}:{s['client']['port']}", "server": f"{s['server']['ip']}:{s['server']['port']}",
            "anomaly_level": a.get("anomaly_level"), "anomaly_score": a.get("anomaly_score"),
            "explanation": a.get("explanation"),
            "properties": {
                "tls_version": t.get("negotiated_version"), "cipher_suite": t.get("cipher_suite"),
                "forward_secrecy": t.get("forward_secrecy"),
                "certificate_key": f"{c['public_key_algorithm']} {c['public_key_size_bits']}" if c else None,
                "certificate_expired": c.get("is_expired") if c else None,
            },
        })
    return out


def compare_anomalies(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """New / resolved / persisting ML-anomalous sessions between two analyses.

    A session is matched first as the *same session* (same client and server endpoints, e.g. the
    same file re-analysed), otherwise by *same server* (protocol, address, port), the key used for
    findings. ML results are relative to each capture's own norm, so a change can also reflect a
    different session population rather than a configuration change."""
    xa, xb = _anomalous_sessions(a), _anomalous_sessions(b)
    streams_a = {s["stream_id"] for s in a.get("sessions", [])}
    streams_b = {s["stream_id"] for s in b.get("sessions", [])}
    assets_a = {_asset(s) for s in a.get("sessions", [])}
    assets_b = {_asset(s) for s in b.get("sessions", [])}
    left = list(xa)
    persisting, new = [], []
    for eb in xb:
        match = next((ea for ea in left if ea["stream_id"] == eb["stream_id"]), None)
        basis = "same session"
        if match is None:
            match = next((ea for ea in left if ea["asset"] == eb["asset"]), None)
            basis = "same server"
        if match is not None:
            left.remove(match)
            persisting.append({"match": basis, "asset": eb["asset"], "a": match, "b": eb})
        else:
            other = ("session present, not anomalous" if eb["stream_id"] in streams_a
                     else "server present, not anomalous" if eb["asset"] in assets_a else "not observed")
            new.append({**eb, "in_other": other})
    resolved = [{**ea, "in_other": "session present, not anomalous" if ea["stream_id"] in streams_b
                 else "server present, not anomalous" if ea["asset"] in assets_b else "not observed"} for ea in left]
    key = lambda e: (e.get("asset", ""), e.get("session_id", ""))
    return {"new": sorted(new, key=key), "resolved": sorted(resolved, key=key),
            "persisting": sorted(persisting, key=lambda e: e["asset"])}


def _counts(d: Dict[str, int], e: Dict[str, int]) -> List[Dict[str, Any]]:
    return [{"key": k, "a": d.get(k, 0), "b": e.get(k, 0), "delta": e.get(k, 0) - d.get(k, 0)}
            for k in sorted(set(d) | set(e))]


def compare_documents(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    pa, pb = _profile(a), _profile(b)
    fa, fb = _finding_keys(a), _finding_keys(b)

    def item(e, side_a=None, side_b=None):
        return {"rule_id": e["rule_id"], "title": e["title"], "asset": e["asset"],
                "severity_a": side_a["severity"] if side_a else None, "severity_b": side_b["severity"] if side_b else None,
                "sessions_a": len(side_a["sessions"]) if side_a else 0,
                "sessions_b": len(side_b["sessions"]) if side_b else 0,
                "finding_ids_a": side_a["finding_ids"] if side_a else [],
                "finding_ids_b": side_b["finding_ids"] if side_b else []}

    new = [item(fb[k], None, fb[k]) for k in fb if k not in fa]
    resolved = [item(fa[k], fa[k], None) for k in fa if k not in fb]
    persisting = [item(fb[k], fa[k], fb[k]) for k in fb if k in fa]
    order = lambda i: (SEV[i["severity_b"] or i["severity_a"]], i["rule_id"], i["asset"])

    aa, ab = _assets(a), _assets(b)
    asset_rows = []
    for key in sorted(set(aa) | set(ab)):
        x, y = aa.get(key), ab.get(key)
        row = {"asset": key, "present_in": "both" if x and y else "a" if x else "b"}
        for field in ("tls_versions", "cipher_suites", "key_exchange", "starttls_states"):
            va, vb = sorted(x[field]) if x else [], sorted(y[field]) if y else []
            row[field] = {"a": va, "b": vb, "changed": va != vb}
        ca, cb = (x or {}).get("certificates", {}), (y or {}).get("certificates", {})
        row["leaf_certificates"] = {"a": list(ca.values()), "b": list(cb.values()), "changed": set(ca) != set(cb)}
        row["sessions"] = {"a": (x or {}).get("sessions", 0), "b": (y or {}).get("sessions", 0)}
        asset_rows.append(row)

    dims_a = {d["dimension"]: d for d in a["posture"].get("dimensions", [])}
    dims_b = {d["dimension"]: d for d in b["posture"].get("dimensions", [])}
    dims = [{"dimension": k, "name": (dims_b.get(k) or dims_a.get(k))["name"],
             "a": (dims_a.get(k) or {}).get("score"), "b": (dims_b.get(k) or {}).get("score"),
             "delta": None if (dims_a.get(k) or {}).get("score") is None or (dims_b.get(k) or {}).get("score") is None
             else round(dims_b[k]["score"] - dims_a[k]["score"], 2)} for k in sorted(set(dims_a) | set(dims_b))]

    ta, tb = a.get("tls_summary", {}), b.get("tls_summary", {})
    notes = []
    if pa["policy_profile"] != pb["policy_profile"]:
        notes.append(f"Policy profiles differ ({pa['policy_profile']} vs {pb['policy_profile']}): severity and score "
                     "changes may reflect the policy rather than the configuration.")
    if pa["sha256"] and pa["sha256"] == pb["sha256"]:
        notes.append("Both analyses are of the same capture file (identical SHA-256).")
    if not set(aa) & set(ab):
        notes.append("The captures share no server asset; differences reflect different systems, not a change over time.")
    delta = None if pa["score"] is None or pb["score"] is None else round(pb["score"] - pa["score"], 2)
    return {
        "a": pa, "b": pb,
        "posture": {"score_a": pa["score"], "score_b": pb["score"], "delta": delta,
                    "status_a": pa["status"], "status_b": pb["status"], "dimensions": dims},
        "findings": {"new": sorted(new, key=order), "resolved": sorted(resolved, key=order),
                     "persisting": sorted(persisting, key=order)},
        "assets": asset_rows,
        "tls_versions": _counts(ta.get("versions", {}), tb.get("versions", {})),
        "cipher_suites": _counts(ta.get("cipher_suites", {}), tb.get("cipher_suites", {})),
        "protocols": _counts({k: v["sessions"] for k, v in a.get("protocol_summary", {}).items()},
                             {k: v["sessions"] for k, v in b.get("protocol_summary", {}).items()}),
        "anomalies": {"a": pa["anomalies"], "b": pb["anomalies"], "delta": pb["anomalies"] - pa["anomalies"]},
        "anomaly_sessions": compare_anomalies(a, b),
        "notes": notes,
        "method": "Findings are matched by rule and asset (protocol, server address and port). ML-anomalous sessions are "
                  "matched as the same session (same endpoints) or else the same server. Scores and ML results come from "
                  "each stored analysis; nothing is recomputed. ML results are relative to each capture's own norm.",
    }
