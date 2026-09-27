"""
Privacy / redaction mode for reports and bundles.

Replaces identifying values with consistent pseudonyms *within one output*:
IP addresses -> ip-001..., hostnames -> host-001.redacted, organisation names -> org-001,
e-mail addresses -> user-001@redacted, the capture file name -> capture-<sha prefix>.

Kept intact: protocol, ports, TLS versions, cipher suites, key sizes, algorithms,
validity dates, fingerprints, serial numbers, findings, scores.

Caveat (documented in every redacted output): certificate fingerprints and serial numbers
are kept because they are cryptographic evidence, but they can be looked up in public
Certificate Transparency logs and may therefore re-identify a public server.
"""
import copy
import ipaddress
import json
import re
from typing import Any, Dict, List, Set

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+")
_DN_ATTR = re.compile(r"\b(CN|O|OU)=((?:[^,\\]|\\.)+)")

REDACTION_NOTE = ("Identifying values (IP addresses, host names, organisation names, e-mail addresses, file name) "
                  "are replaced by pseudonyms that are consistent within this output only. Cryptographic evidence "
                  "(versions, suites, key sizes, validity, fingerprints, serial numbers) is unchanged; fingerprints "
                  "and serial numbers can still be looked up in public Certificate Transparency logs.")


def _collect(doc: Dict[str, Any]):
    ips: Set[str] = set()
    hosts: Set[str] = set()
    orgs: Set[str] = set()
    for s in doc.get("sessions", []):
        for side in ("client", "server"):
            if s.get(side, {}).get("ip"):
                ips.add(s[side]["ip"])
        t = s.get("tls") or {}
        if t.get("sni"):
            hosts.add(t["sni"])
    for c in doc.get("certificates", []):
        for dn in (c.get("subject") or "", c.get("issuer") or ""):
            for attr, val in _DN_ATTR.findall(dn):
                (hosts if attr == "CN" and "." in val and " " not in val else orgs).add(val)
        for san in c.get("san_list") or []:
            hosts.add(san)
        if c.get("common_name"):
            cn = c["common_name"]
            (hosts if "." in cn and " " not in cn else orgs).add(cn)
    return ips, hosts, orgs


def redact_document(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return a redacted deep copy of a canonical analysis document."""
    ips, hosts, orgs = _collect(doc)
    blob = json.dumps(doc, sort_keys=True, default=str)
    for m in _IPV4.findall(blob):
        try:
            ipaddress.ip_address(m)
            ips.add(m)
        except ValueError:
            pass
    emails = set(_EMAIL.findall(blob))

    mapping: List = []
    for i, v in enumerate(sorted(ips), 1):
        mapping.append((v, f"ip-{i:03d}"))
    for i, v in enumerate(sorted(emails), 1):
        mapping.append((v, f"user-{i:03d}@redacted"))
    for i, v in enumerate(sorted(hosts - emails), 1):
        mapping.append((v, f"host-{i:03d}.redacted"))
    for i, v in enumerate(sorted(orgs), 1):
        mapping.append((v, f"org-{i:03d}"))
    # Longest first so that "mail.example.org" is replaced before "example.org".
    mapping.sort(key=lambda kv: -len(kv[0]))

    out = copy.deepcopy(doc)

    def walk(node):
        if isinstance(node, dict):
            return {walk(k) if isinstance(k, str) else k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str):
            for old, new in mapping:
                if old in node:
                    # Boundaries exclude only alphanumerics/dots, so values embedded in identifiers
                    # such as "tcp-10.0.0.1_5000-..." are replaced too, but "10.0.0.2" never
                    # matches inside "10.0.0.25".
                    node = re.sub(r"(?<![A-Za-z0-9.])" + re.escape(old) + r"(?![A-Za-z0-9])", new, node)
            return node
        return node

    out = walk(out)
    cap = out.get("capture", {})
    sha = (cap.get("sha256") or "")[:12]
    cap["filename"] = f"capture-{sha}.pcap" if sha else "capture.pcap"
    for c in out.get("certificates", []):
        c.pop("der_base64", None)  # DER embeds names; excluded from redacted outputs
    out["redaction"] = {"mode": "REDACTED", "note": REDACTION_NOTE,
                        "pseudonymised": {"ip_addresses": len(ips), "hostnames": len(hosts - emails),
                                          "organisations": len(orgs), "email_addresses": len(emails)}}
    return out


def raw_label(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(doc)
    out["redaction"] = {"mode": "RAW", "note": "No redaction applied. May contain IP addresses and host names."}
    return out
