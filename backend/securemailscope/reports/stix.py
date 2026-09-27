"""
STIX 2.1 export of observations.

Scope decision: SecureMailScope findings describe cryptographic posture, not threat activity,
so the export contains *observations* only:

* SCOs  - ipv4-addr / ipv6-addr, network-traffic (per email session), x509-certificate
* observed-data - one per email session (capture timestamps)
* note  - one per deterministic finding and per ML outlier, referencing the observed-data
* identity (the tool) and one report (report_types: observed-data)

No indicator, malware, attack-pattern or "malicious" labels are produced: an unusual or
weak configuration is not evidence of compromise. IDs are deterministic (UUIDv5), so the
same stored analysis yields the same bundle.

Redacted documents carry pseudonyms (for example ``ip-001``) instead of addresses. Those
cannot be expressed as ipv4-addr / network-traffic without inventing addresses, so each
session is then described by a custom ``x-securemailscope-redacted-session`` SCO holding
the pseudonymous endpoints, ports, protocols and times.
"""
import ipaddress
import json
import uuid
from typing import Any, Dict, List

# Namespace defined by STIX 2.1 for deterministic SCO identifiers (Section 2.9).
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
SMS_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://securemailscope.invalid/stix")


def _sco_id(kind: str, contributing: Dict[str, Any]) -> str:
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, json.dumps(contributing, sort_keys=True, separators=(',', ':')))}"


def _sdo_id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(SMS_NAMESPACE, '|'.join(parts))}"


def _ts(value) -> str:
    """STIX timestamps: UTC with millisecond precision and a Z suffix."""
    from datetime import datetime, timezone
    d = datetime.fromisoformat(value) if isinstance(value, str) else value
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def build_stix_bundle(doc: Dict[str, Any]) -> Dict[str, Any]:
    cap, ana = doc["capture"], doc["analysis"]
    key = cap.get("sha256") or "unknown"
    created = _ts(ana["analyzed_at"])
    objs: Dict[str, Dict[str, Any]] = {}

    identity = {"type": "identity", "spec_version": "2.1", "id": _sdo_id("identity", "securemailscope-tool"),
                "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
                "name": "SecureMailScope", "identity_class": "system",
                "description": "Passive email TLS posture analyzer (automated system)."}
    objs[identity["id"]] = identity

    def is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def ip_obj(value: str) -> str:
        kind = "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
        oid = _sco_id(kind, {"value": value})
        objs.setdefault(oid, {"type": kind, "spec_version": "2.1", "id": oid, "value": value})
        return oid

    certs_by_session: Dict[str, List[Dict]] = {}
    for c in doc.get("certificates", []):
        certs_by_session.setdefault(c["session_id"], []).append(c)

    observed_for_session: Dict[str, str] = {}
    for s in doc.get("sessions", []):
        protocols = ["tcp", s["protocol"].lower()] + (["tls"] if s.get("tls") else [])
        if is_ip(s["client"]["ip"]) and is_ip(s["server"]["ip"]):
            src, dst = ip_obj(s["client"]["ip"]), ip_obj(s["server"]["ip"])
            nt = {"start": _ts(s["start_time"]), "end": _ts(s["end_time"]), "src_ref": src, "dst_ref": dst,
                  "src_port": s["client"]["port"], "dst_port": s["server"]["port"],
                  "protocols": ["ipv6" if ":" in s["client"]["ip"] else "ipv4"] + protocols}
            nt_id = _sco_id("network-traffic", nt)
            objs[nt_id] = {"type": "network-traffic", "spec_version": "2.1", "id": nt_id, **nt, "is_active": False}
            refs = [nt_id, src, dst]
        else:
            rs = {"client": s["client"]["ip"], "client_port": s["client"]["port"], "server": s["server"]["ip"],
                  "server_port": s["server"]["port"], "protocols": protocols,
                  "start": _ts(s["start_time"]), "end": _ts(s["end_time"])}
            kind = "x-securemailscope-redacted-session"
            rs_id = _sco_id(kind, rs)
            objs[rs_id] = {"type": kind, "spec_version": "2.1", "id": rs_id, **rs,
                           "x_note": "Endpoints are pseudonyms from a redacted analysis, not addresses."}
            refs = [rs_id]
        for c in certs_by_session.get(s["session_id"], []):
            sco = {"hashes": {"SHA-256": c["fingerprint_sha256"]}, "serial_number": c["serial_number"]}
            cid = _sco_id("x509-certificate", sco)
            objs.setdefault(cid, {"type": "x509-certificate", "spec_version": "2.1", "id": cid, **sco,
                                  "subject": c["subject"], "issuer": c["issuer"],
                                  "validity_not_before": _ts(c["not_before"]), "validity_not_after": _ts(c["not_after"]),
                                  "signature_algorithm": c["signature_algorithm"],
                                  "subject_public_key_algorithm": c["public_key_algorithm"]})
            refs.append(cid)
        od_id = _sdo_id("observed-data", key, s["session_id"])
        objs[od_id] = {"type": "observed-data", "spec_version": "2.1", "id": od_id, "created": created,
                       "modified": created, "created_by_ref": identity["id"],
                       "first_observed": _ts(s["start_time"]), "last_observed": _ts(s["end_time"]),
                       "number_observed": 1, "object_refs": refs,
                       "x_securemailscope_session_id": s["session_id"],
                       "x_securemailscope_capture_sha256": key}
        observed_for_session[s["session_id"]] = od_id

    for f in doc.get("findings", []):
        od = observed_for_session.get(f["session_id"])
        if not od:
            continue
        nid = _sdo_id("note", key, f["finding_id"])
        objs[nid] = {"type": "note", "spec_version": "2.1", "id": nid, "created": created, "modified": created,
                     "created_by_ref": identity["id"], "abstract": f"{f['rule_id']}: {f['title']}",
                     "content": f"{f['description']}\n\nRecommendation: {f['recommendation']}\n"
                                f"Evidence class: {f['evidence_type']}. Posture finding; not an indicator of compromise.",
                     "object_refs": [od], "x_securemailscope_rule_id": f["rule_id"],
                     "x_securemailscope_severity": f["severity"], "x_securemailscope_evidence_class": f["evidence_type"],
                     "x_securemailscope_evidence_frames": f["evidence_frames"]}

    for a in doc.get("anomalies", []):
        od = observed_for_session.get(a["session_id"])
        if not a.get("is_anomaly") or not od:
            continue
        nid = _sdo_id("note", key, "anomaly", a["session_id"])
        objs[nid] = {"type": "note", "spec_version": "2.1", "id": nid, "created": created, "modified": created,
                     "created_by_ref": identity["id"], "abstract": f"ML outlier ({a['anomaly_level']}) - requires investigation",
                     "content": f"{a['explanation']}\nStatistical outlier relative to this capture; not a confirmed "
                                f"vulnerability or compromise.",
                     "object_refs": [od], "x_securemailscope_anomaly_score": a["anomaly_score"]}

    refs = sorted(o["id"] for o in objs.values() if o["type"] in ("observed-data", "note"))
    if refs:
        rid = _sdo_id("report", key)
        objs[rid] = {"type": "report", "spec_version": "2.1", "id": rid, "created": created, "modified": created,
                     "created_by_ref": identity["id"], "published": created, "report_types": ["observed-data"],
                     "name": f"SecureMailScope observations: {cap.get('filename')}",
                     "description": f"Passive analysis of capture SHA-256 {key}, policy profile "
                                    f"{ana.get('policy_profile')}. Observations and posture notes only.",
                     "object_refs": refs}
    return {"type": "bundle", "id": _sdo_id("bundle", key, created),
            "objects": sorted(objs.values(), key=lambda o: (o["type"], o["id"]))}
