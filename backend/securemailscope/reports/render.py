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
    story = [P("SecureMailScope - Email Cryptographic Posture Report", "Title"),
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

    story.append(P("2. Capture metadata", "Heading2"))
    add(table([["Property", "Value"]] + [[k, v] for k, v in cap.items()], [45 * mm, 135 * mm]))
    story.append(P("3. Posture by dimension", "Heading2"))
    add(table([["Dimension", "Score", "Findings", "Coverage %", "Evidence"]] + [
        [d["name"], "n/a" if d["score"] is None else f"{d['score']:.0f}", d["findings_count"],
         d["coverage_percent"], d["evidence_quality"]] for d in post.get("dimensions", [])]))
    story.append(P("4. Prioritised remediation", "Heading2"))
    add(table([["#", "Rule", "Severity", "Sessions", "Recommendation"]] + [
        [r["priority"], f"{r['rule_id']} {r['title']}", r["severity"], r["affected_sessions"], r["recommendation"]]
        for r in doc["remediation_plan"]] or [["-", "No actionable findings", "", "", ""]],
        [8 * mm, 50 * mm, 18 * mm, 16 * mm, 88 * mm]))
    story.append(PageBreak())
    story.append(P("5. Findings (deterministic rules)", "Heading2"))
    add(table([["Finding", "Severity", "Evidence", "Frames", "Description"]] + [
        [f"{f['rule_id']} - {f['title']}\n{f['session_id']}", f["severity"], f["evidence_type"],
         ", ".join(map(str, f["evidence_frames"])) or "-", f["description"]] for f in doc["findings"]]
        or [["-", "", "", "", "No findings"]], [48 * mm, 16 * mm, 24 * mm, 14 * mm, 78 * mm]))
    story.append(P("6. Sessions", "Heading2"))
    add(table([["Session", "Proto", "STARTTLS / TLS", "Cipher", "Quality"]] + [
        [f"{s['client']['ip']}:{s['client']['port']} -> {s['server']['ip']}:{s['server']['port']}", s["protocol"],
         f"{s['starttls']['final_state']} / {(s['tls'] or {}).get('negotiated_version') or 'none'}",
         (s["tls"] or {}).get("cipher_suite") or "-", s["reconstruction"]["quality"]] for s in doc["sessions"]]
        or [["-", "", "", "", ""]], [55 * mm, 14 * mm, 40 * mm, 50 * mm, 21 * mm]))
    story.append(P("7. Certificates (observed; trust not evaluated)", "Heading2"))
    add(table([["Subject", "Issuer", "Validity (at capture time)", "Key / Signature", "Linkage"]] + [
        [c["subject"], c["issuer"], f"{c['not_before']} - {c['not_after']}"
         + (" EXPIRED" if c["is_expired"] else "") + (" NOT-YET-VALID" if c["is_not_yet_valid"] else ""),
         f"{c['public_key_algorithm']} {c['public_key_size_bits']} / {c['signature_algorithm']}",
         c["issued_by_next"] or "-"] for c in doc["certificates"]] or [["Not observed", "", "", "", ""]]))
    story.append(P("8. ML anomalies (supplementary, not vulnerabilities)", "Heading2"))
    story.append(P(f"Model: {(doc.get('ml') or {}).get('engine')} {(doc.get('ml') or {}).get('model_version')}; "
                   f"status {(doc.get('ml') or {}).get('status')}.", "Small"))
    add(table([["Session", "Level", "Score", "Explanation"]] + [
        [a["session_id"], a["anomaly_level"], a["anomaly_score"], a["explanation"]]
        for a in doc["anomalies"] if a["is_anomaly"]] or [["-", "", "", "No anomalies flagged"]],
        [55 * mm, 18 * mm, 15 * mm, 92 * mm]))
    story.append(P("9. Method and limitations", "Heading2"))
    for line in doc["limitations"]:
        story.append(P(f"- {line}", "Small"))
    pdf.build(story)
    return buf.getvalue()


PDF_MAX_ROWS = 400  # per table; the JSON/HTML reports always contain every row


RENDERERS = {"json": (render_json, "application/json"),
             "html": (render_html, "text/html; charset=utf-8"),
             "pdf": (render_pdf, "application/pdf")}
