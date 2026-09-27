"""
Report renderers (JSON / HTML / PDF) over the canonical analysis document.

All values in the document may be attacker-controlled (certificate subjects,
SNI, banners, filenames). HTML is rendered with Jinja2 autoescaping and a
Content-Security-Policy that forbids scripts; PDF text is XML-escaped before it
reaches ReportLab's paragraph markup.
"""
import io
import json
import re
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]),
                   trim_blocks=True, lstrip_blocks=True)


class ReportUnavailable(RuntimeError):
    """Raised when a report format cannot be produced in this environment."""


def safe_report_basename(name: str) -> str:
    """Filesystem-safe stem derived from untrusted text (never contains path separators)."""
    # Treat both separators as path separators on every OS, then keep the last component.
    last = str(name).replace("\\", "/").split("/")[-1]
    stem = last.rsplit(".", 1)[0] if "." in last.strip(".") else last
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem)[:80].strip("._")
    return stem or "capture"


def render_json(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, indent=2, sort_keys=False, default=str).encode("utf-8")


def render_html(doc: Dict[str, Any]) -> bytes:
    return _env.get_template("report.html.j2").render(doc=doc).encode("utf-8")


def render_pdf(doc: Dict[str, Any]) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    except ImportError as e:  # pragma: no cover - exercised when reportlab is absent
        raise ReportUnavailable("PDF export requires the 'reportlab' package") from e
    from html import escape

    def P(text, style="BodyText"):
        return Paragraph(escape("" if text is None else str(text)), styles[style])

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7.5, leading=9))
    buf = io.BytesIO()
    pdf = SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title="SecureMailScope Forensic Report", author="SecureMailScope")
    cap, post, ana = doc["capture"], doc["posture"], doc["analysis"]
    mode = (doc.get("redaction") or {}).get("mode", "RAW")
    profile = (ana.get("policy_profile_detail") or {}).get("name") or ana.get("policy_profile", "balanced")
    story = [P("SecureMailScope - Email Cryptographic Posture Report", "Title"),
             P(f"Report mode: {mode} | Policy profile: {profile} | Passive analysis of a stored capture; "
               f"no traffic generated, nothing decrypted.", "Small"),
             P(f"Capture: {cap.get('filename')}"), P(f"SHA-256: {cap.get('sha256')}", "Small"),
             P(f"Analyzed: {ana.get('analyzed_at')} | rule policy {ana.get('rule_policy_version')} | "
               f"scoring policy {ana.get('scoring_policy_version')} | tool {doc['tool'].get('version')}", "Small"),
             Spacer(1, 6)]
    score = post.get("overall_score")
    story.append(P("1. Executive summary", "Heading2"))
    story.append(P(f"Posture: {'n/a' if score is None else f'{score:.0f}/100'} ({post.get('status')}). "
                   f"{cap.get('email_sessions')} email session(s), {cap.get('tls_sessions')} with TLS, "
                   f"{len(doc['findings'])} finding(s), {sum(1 for a in doc['anomalies'] if a['is_anomaly'])} "
                   f"ML anomaly(ies)."))
    grid = TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8ef")), ("VALIGN", (0, 0), (-1, -1), "TOP")])

    def table(rows, widths=None):
        header, body = rows[0], rows[1:]
        if not body:
            body = [["none observed"] + [""] * (len(header) - 1)]
        extra = len(body) - PDF_MAX_ROWS
        body = body[:PDF_MAX_ROWS]
        t = Table([[P(c, "Small") for c in r] for r in [header] + body], colWidths=widths, repeatRows=1)
        t.setStyle(grid)
        if extra > 0:
            return [t, P(f"... {extra} more row(s) omitted from the PDF; see the JSON or HTML report.", "Small")]
        return t

    def add(x):
        story.extend(x) if isinstance(x, list) else story.append(x)

    if mode == "REDACTED":
        story.append(P((doc.get("redaction") or {}).get("note", ""), "Small"))
    # Same 14-section structure as the HTML report.
    story.append(P("2. Capture metadata", "Heading2"))
    add(table([["Property", "Value"]] + [[k, v] for k, v in cap.items()], [45 * mm, 135 * mm]))
    story.append(P("3. Security posture", "Heading2"))
    add(table([["Dimension", "Score", "Findings", "Coverage %", "Evidence"]] + [
        [d["name"], "n/a" if d["score"] is None else f"{d['score']:.0f}", d["findings_count"],
         d["coverage_percent"], d["evidence_quality"]] for d in post.get("dimensions", [])]))
    story.append(P("4. Protocol summary", "Heading2"))
    add(table([["Protocol", "Sessions", "Implicit TLS", "STARTTLS to TLS", "Rejected", "Plaintext", "TLS failed"]] + [
        [k, v["sessions"], v["implicit_tls"], v["starttls_established"], v["starttls_rejected"], v["plaintext"],
         v["tls_failed"]] for k, v in (doc.get("protocol_summary") or {}).items()]))
    story.append(P("5. TLS summary", "Heading2"))
    ts = doc.get("tls_summary") or {}
    add(table([["TLS property", "Observed values"]] + [
        ["Negotiated versions", "; ".join(f"{k}: {v}" for k, v in (ts.get("versions") or {}).items())],
        ["Cipher suites", "; ".join(f"{k}: {v}" for k, v in (ts.get("cipher_suites") or {}).items())],
        ["Key exchange", "; ".join(f"{k}: {v}" for k, v in (ts.get("key_exchange") or {}).items())],
        ["Forward secrecy", "; ".join(f"{k}: {v}" for k, v in (ts.get("forward_secrecy") or {}).items())]],
        [45 * mm, 135 * mm]))
    story.append(P("6. Certificate summary (observed; trust not evaluated)", "Heading2"))
    add(table([["Subject", "Issuer", "Validity (at capture time)", "Key / Signature", "Linkage"]] + [
        [c["subject"], c["issuer"], f"{c['not_before']} - {c['not_after']}"
         + (" EXPIRED" if c["is_expired"] else "") + (" NOT-YET-VALID" if c["is_not_yet_valid"] else ""),
         f"{c['public_key_algorithm']} {c['public_key_size_bits']} / {c['signature_algorithm']}",
         c["issued_by_next"] or "-"] for c in doc["certificates"]] or [["Not observed", "", "", "", ""]]))
    story.append(PageBreak())
    story.append(P("7. Findings (deterministic rules)", "Heading2"))
    add(table([["Finding", "Severity", "Evidence", "Frames", "Description"]] + [
        [f"{f['rule_id']} - {f['title']}\n{f['session_id']}", f["severity"], f["evidence_type"],
         ", ".join(map(str, f["evidence_frames"])) or "-", f["description"]] for f in doc["findings"]]
        or [["-", "", "", "", "No findings"]], [48 * mm, 16 * mm, 24 * mm, 14 * mm, 78 * mm]))
    story.append(P("8. Affected sessions", "Heading2"))
    add(table([["Session", "Proto", "STARTTLS / TLS", "Cipher", "Quality"]] + [
        [f"{s['client']['ip']}:{s['client']['port']} -> {s['server']['ip']}:{s['server']['port']}", s["protocol"],
         f"{s['starttls']['final_state']} / {(s['tls'] or {}).get('negotiated_version') or 'none'}",
         (s["tls"] or {}).get("cipher_suite") or "-", s["reconstruction"]["quality"]] for s in doc["sessions"]]
        or [["-", "", "", "", ""]], [55 * mm, 14 * mm, 40 * mm, 50 * mm, 21 * mm]))
    story.append(P("9. Anomalies (supplementary ML; not vulnerabilities)", "Heading2"))
    story.append(P(f"Model: {(doc.get('ml') or {}).get('engine')} {(doc.get('ml') or {}).get('model_version')}; "
                   f"status {(doc.get('ml') or {}).get('status')}. A session weaker than this capture's norm and rare "
                   f"in it; requires investigation.", "Small"))
    add(table([["Session", "Level", "Score", "Explanation"]] + [
        [a["session_id"], a["anomaly_level"], a["anomaly_score"], a["explanation"]]
        for a in doc["anomalies"] if a["is_anomaly"]] or [["-", "", "", "No anomalies flagged"]],
        [55 * mm, 18 * mm, 15 * mm, 92 * mm]))
    story.append(P("10. Evidence timeline", "Heading2"))
    events = [e for e in (doc.get("timeline") or []) if e.get("type") in (
        "starttls_command", "starttls_response", "plaintext_auth", "server_hello", "certificate", "tls_alert", "finding")]
    add(table([["Capture time (UTC)", "Frame", "Event", "Class"]] + [
        [e.get("ts") or "analysis", e.get("frame") or "-", e.get("label"), e.get("evidence_class")] for e in events],
        [42 * mm, 14 * mm, 96 * mm, 28 * mm]))
    story.append(P("Key protocol events only; the JSON and HTML reports contain every event.", "Small"))
    story.append(P("11. Recommendations", "Heading2"))
    add(table([["#", "Rule", "Severity", "Sessions", "Recommendation"]] + [
        [r["priority"], f"{r['rule_id']} {r['title']}", r["severity"], r["affected_sessions"], r["recommendation"]]
        for r in doc["remediation_plan"]] or [["-", "No actionable findings", "", "", ""]],
        [8 * mm, 50 * mm, 18 * mm, 16 * mm, 88 * mm]))
    story.append(P("12. Methodology", "Heading2"))
    detail = ana.get("policy_profile_detail") or {}
    for line in [ana.get("mode"),
                 "Pipeline: capture ingestion, TCP reassembly, SMTP/IMAP/POP3 identification, STARTTLS tracking, TLS "
                 f"handshake parsing, X.509 analysis, deterministic rules (policy {ana.get('rule_policy_version')}), "
                 f"posture scoring (policy {ana.get('scoring_policy_version')}), supplementary ML.",
                 f"Policy profile {profile}: {detail.get('description') or ''}",
                 f"Certificate validity reference: {ana.get('certificate_validity_reference')}."]:
        if line:
            story.append(P(f"- {line}", "Small"))
    story.append(P("13. Limitations", "Heading2"))
    for line in doc["limitations"]:
        story.append(P(f"- {line}", "Small"))
    story.append(P("14. Integrity", "Heading2"))
    add(table([["Item", "Value"], ["Capture SHA-256", cap.get("sha256")], ["Analysis timestamp", ana.get("analyzed_at")],
               ["Tool version", f"SecureMailScope {doc['tool'].get('version')}"],
               ["Policy profile", ana.get("policy_profile")], ["ML model", ana.get("ml_model_version") or "n/a"],
               ["Report mode", mode]], [45 * mm, 135 * mm]))
    if doc.get("analyst_annotations"):
        story.append(P("Appendix A. Analyst notes and selected items", "Heading2"))
        story.append(P("Analyst metadata selected for this report. Not evidence; does not change findings or the "
                       "score. In redacted reports, addresses, host names and e-mail addresses in notes are "
                       "pseudonymised; review free text before sharing.", "Small"))
        add(table([["Item", "Type", "Note", "Added (UTC)"]] + [
            [a["target"], a["target_type"], a["note"] or "(selected without note)", a["created_at"] or ""]
            for a in doc["analyst_annotations"]], [62 * mm, 18 * mm, 72 * mm, 28 * mm]))
    story.append(P("SecureMailScope is an independent academic project (SIH 2026, SIH26159); it is not affiliated "
                   "with or endorsed by any government agency.", "Small"))
    pdf.build(story)
    return buf.getvalue()


PDF_MAX_ROWS = 400  # per table; the JSON/HTML reports always contain every row


RENDERERS = {"json": (render_json, "application/json"),
             "html": (render_html, "text/html; charset=utf-8"),
             "pdf": (render_pdf, "application/pdf")}
