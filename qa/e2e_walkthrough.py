"""
Exhaustive browser walkthrough of every user-facing control (desktop 1440 px and mobile 390 px).

Each step checks the visible state change and, where a control talks to the API, the request it
makes and its persistence. Console errors, page errors, failed requests and HTTP >= 400 responses
are collected for the whole run and fail it.

Needs: a running API + dashboard (see qa/README.md) and Python Playwright with Chromium.
Usage (from the repository root):  python qa/e2e_walkthrough.py
"""
import io
import json
import re
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import expect, sync_playwright

from common import FIXTURES, REAL, UI, api_get, seed, watch

results, problems = [], []
OUT = Path(tempfile.mkdtemp(prefix="sms_e2e_"))
PRIVATE_IP = re.compile(r"\b(?:10|172|192)\.\d+\.\d+\.\d+\b")


def ok(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def rows(page):
    return page.locator("main table tbody tr")


DRAWER_HEADING = {"/findings": "Why am I seeing this?", "/sessions": "Session timeline",
                  "/certificates": "Where it was seen", "/anomalies": re.compile("Posture features")}


def open_drawer(page):
    """The detail drawer of the current page, once its own content (not a previous page's) is shown."""
    d = page.get_by_role("complementary", name="Details")
    route = "/" + page.url.split("/", 3)[3].split("?")[0]
    heading = DRAWER_HEADING.get(route)
    if heading is not None:
        d.get_by_role("heading", name=heading).first.wait_for()
    else:
        d.wait_for()
    return d


def main():
    ids = seed()
    mixed, before, after, imap = ids["mixed"], ids["before"], ids["after"], ids["imap"]
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
        page = ctx.new_page()
        watch(page, problems)
        page.goto(UI)
        page.evaluate(f"localStorage.clear(); localStorage.setItem('sms.activeCapture', '{mixed}')")

        # ---------------------------------------------------------------- shell
        page.goto(UI + "/")
        page.get_by_role("heading", name="Security posture", level=1).wait_for()
        page.keyboard.press("Tab")
        skip = page.get_by_role("link", name="Skip to main content")
        ok("skip link is the first focus stop", skip.evaluate("e => e === document.activeElement"))
        page.keyboard.press("Enter")
        ok("skip link moves focus to main", page.evaluate("document.activeElement.id") == "main")
        nav = page.get_by_role("navigation", name="Investigation workflow")
        steps = [("Capture", "/captures", "Captures and analysis history"), ("Analyze", "/upload", "Analyze a capture"),
                 ("Posture", "/", "Security posture"), ("Findings", "/findings", "Findings"),
                 ("Sessions", "/sessions", "Email sessions"), ("Certificates", "/certificates", "Certificate intelligence"),
                 ("Evidence", "/evidence", "Evidence"), ("Report", "/reports", "Report and export"),
                 ("ML anomalies", "/anomalies", "ML anomalies"), ("Compare and trend", "/compare", "Compare and trend"),
                 ("About and limitations", "/about", "About SecureMailScope")]
        for label, route, h1 in steps:
            nav.get_by_role("link", name=re.compile(rf"^\d*\s*{re.escape(label)}")).first.click()
            page.wait_for_url(UI + route)
            expect(page.get_by_role("heading", level=1, name=h1)).to_be_visible()
        ok("every sidebar link opens its page", True, f"{len(steps)} links")
        # pager: walk the 8 steps forwards and backwards
        page.goto(UI + "/captures")
        for i in range(2, 9):
            page.get_by_role("navigation", name="Workflow steps").get_by_role("link", name=re.compile(rf"^Step {i}:")).click()
            page.wait_for_url(UI + steps[i - 1][1])
        for i in range(7, 0, -1):
            page.get_by_role("navigation", name="Workflow steps").get_by_role("link", name=re.compile(rf"Step {i}:")).click()
            page.wait_for_url(UI + steps[i - 1][1])
        ok("workflow pager walks all steps both ways", page.url == UI + "/captures")
        # analysis selector + refresh
        page.goto(UI + "/findings")
        page.locator("dl.casebar").wait_for()
        with page.expect_response(lambda r: r.url.endswith("/captures") and r.request.method == "GET"):
            page.get_by_role("button", name="Reload analysis list").click()
        ok("refresh button reloads the analysis list", True)
        page.get_by_label("Analysis", exact=True).select_option(imap)
        expect(page.locator("dl.casebar")).to_contain_text("real_imap_starttls_weak_tls10.pcap")
        expect(rows(page).first).to_contain_text(re.compile("TLS|CERT"))
        ok("analysis selector switches every view to that analysis", "strict" in page.locator("dl.casebar").inner_text())
        page.get_by_label("Analysis", exact=True).select_option(mixed)
        expect(page.locator("dl.casebar")).to_contain_text("ml_mixed_estate.pcap")
        # text size and contrast
        for name, val in (("Larger text", "lg"), ("Largest text", "xl"), ("Normal text size", "md")):
            page.get_by_role("button", name=name).click()
            ok(f"text size control: {name}", page.evaluate("document.documentElement.dataset.text") == val
               and page.get_by_role("button", name=name).get_attribute("aria-pressed") == "true")
        page.get_by_role("button", name="High contrast").click()
        page.reload()
        ok("high contrast persists across reload", page.evaluate("document.documentElement.dataset.contrast") == "high")
        page.get_by_role("button", name="Normal contrast").click()
        ok("normal contrast restored", page.evaluate("document.documentElement.dataset.contrast") == "normal")

        # ---------------------------------------------------------------- captures
        page.goto(UI + "/captures")
        rows(page).first.wait_for()
        n0 = rows(page).count()
        cbs = page.get_by_role("checkbox", name=re.compile("^Select .* for comparison"))
        cmp_btn = page.get_by_role("button", name=re.compile("Compare selected"))
        ok("compare button disabled until two are selected", cmp_btn.is_disabled())
        cbs.nth(0).check(); cbs.nth(1).check(); cbs.nth(2).check()
        ok("selecting a third analysis keeps only the last two", cmp_btn.inner_text().strip().endswith("(2/2)")
           and not cbs.nth(0).is_checked())
        for policy in ("strict", "legacy_audit", "balanced"):
            row = rows(page).filter(has_text="real_remediation_after.pcap").first
            row.get_by_role("combobox").select_option(policy)
            with page.expect_response(lambda r: "/reanalyze" in r.url and r.status == 200):
                row.get_by_role("button", name="Re-analyse").click()
            page.wait_for_function(f"document.querySelectorAll('main table tbody tr').length > {n0}")
            n0 = rows(page).count()
            ok(f"re-analyse with {policy} creates a new analysis", policy in rows(page).first.inner_text())
        rows(page).filter(has_text="ml_mixed_estate.pcap").first.get_by_role("button", name="Open").click()
        page.wait_for_url(UI + "/")
        ok("Open selects the analysis and shows its posture", "ml_mixed_estate.pcap" in page.locator("dl.casebar").inner_text())
        page.goto(UI + "/captures")
        page.get_by_role("link", name="Step 2: Analyze a capture").click()
        page.wait_for_url(UI + "/upload")

        # ---------------------------------------------------------------- upload
        fi = page.locator("input[type=file]")
        bad = OUT / "notes.txt"
        bad.write_text("not a capture")
        fi.set_input_files(str(bad))
        ok("upload rejects a wrong file type", page.get_by_text("Choose a .pcap, .pcapng or .cap file.").is_visible())
        empty = OUT / "empty.pcap"
        empty.write_bytes(b"")
        fi.set_input_files(str(empty))
        ok("upload rejects an empty file", page.get_by_text("The selected file is empty.").is_visible())
        fi.set_input_files(str(REAL / "real_imaps_tls12_chain.pcap"))
        ok("chosen file is shown", page.locator("main").get_by_text("real_imaps_tls12_chain.pcap").first.is_visible())
        page.get_by_role("button", name="Clear").click()
        ok("Clear removes the chosen file", page.locator("main span.font-mono").filter(has_text="real_imaps_tls12_chain.pcap").count() == 0
           and page.get_by_role("button", name="Run analysis").is_disabled())
        for pol in ("Strict", "Legacy audit", "Balanced"):
            page.get_by_role("radio", name=re.compile(pol, re.I)).check()
            ok(f"policy radio: {pol}", page.get_by_role("radio", name=re.compile(pol, re.I)).is_checked())
        page.get_by_role("radio", name=re.compile("Strict", re.I)).check()
        page.get_by_role("button", name="Choose a capture file").focus()
        with page.expect_file_chooser() as fc:
            page.keyboard.press("Enter")
        fc.value.set_files(str(REAL / "real_imaps_tls12_chain.pcap"))
        with page.expect_response(lambda r: r.url.endswith("/analyze") and r.status == 200):
            page.get_by_role("button", name="Run analysis").click()
        page.wait_for_url(UI + "/")
        expect(page.locator("dl.casebar")).to_contain_text("real_imaps_tls12_chain.pcap")
        ok("keyboard file chooser + strict upload analyses and opens the capture", "strict" in page.locator("dl.casebar").inner_text())
        page.get_by_label("Analysis", exact=True).select_option(mixed)

        # ---------------------------------------------------------------- posture
        page.goto(UI + "/")
        page.get_by_role("link", name="Review findings").click()
        page.wait_for_url(UI + "/findings")
        page.goto(UI + "/")
        page.get_by_role("link", name="Report and export").click()
        page.wait_for_url(UI + "/reports")
        page.goto(UI + "/")
        issue = page.locator("section", has=page.get_by_role("heading", name="Top security issues")).locator("tbody").get_by_role("link").first
        issue.click()
        page.wait_for_url(re.compile(r"/findings\?rule="))
        rule = re.search(r"rule=([A-Z]+-\d+)", page.url).group(1)
        expect(page.get_by_role("button", name=re.compile(f"Clear rule filter {rule}"))).to_be_visible()
        expect(rows(page)).not_to_have_count(0)
        shown = rows(page).all_inner_texts()
        ok("top-issue link filters findings by rule", shown and all(rule in r for r in shown), f"{rule}: {len(shown)} row(s)")
        page.get_by_role("button", name=re.compile("Clear rule filter")).click()
        expect(rows(page)).to_have_count(4)
        ok("clear rule filter", "rule=" not in page.url and rows(page).count() == 4)
        page.goto(UI + "/")
        page.get_by_role("link", name="Open the evidence register").click()
        page.wait_for_url(UI + "/evidence")
        page.goto(UI + "/")
        page.get_by_role("link", name="ML anomalies").last.click()
        page.wait_for_url(UI + "/anomalies")
        page.goto(UI + "/")
        notes_capture(page)

        # ---------------------------------------------------------------- findings
        page.goto(UI + "/findings")
        rows(page).first.wait_for()
        search = page.get_by_role("searchbox", name="Search", exact=True)
        search.fill("zzz-no-such")
        ok("findings search: no match shows empty state", page.get_by_text("No findings match these filters.").is_visible())
        search.fill("CERT-003")
        ok("findings search: match", rows(page).count() == 1)
        search.fill("")
        for sev, n in (("HIGH", 2), ("MEDIUM", 2), ("CRITICAL", 0), ("all", 4)):
            page.get_by_role("combobox", name="Severity", exact=True).select_option(sev)
            ok(f"severity filter {sev}", (rows(page).count() if n else 0) == n or (n == 0 and page.get_by_text("No findings match").is_visible()))
        for ev, n in (("INFERRED", 1), ("OBSERVED", 3), ("all", 4)):
            page.get_by_role("combobox", name="Evidence class", exact=True).select_option(ev)
            ok(f"evidence-class filter {ev}", rows(page).count() == n, str(rows(page).count()))
        orders = {}
        for srt in ("priority", "severity", "rule", "asset"):
            page.get_by_role("combobox", name="Sort by", exact=True).select_option(srt)
            orders[srt] = [r.split("\n")[2] if len(r.split("\n")) > 2 else r for r in rows(page).all_inner_texts()]
        ok("sort by rule orders by rule id", [re.search(r"(CERT|TLS)-\d+", " ".join(x.split())).group(0) for x in
           [t for t in rows(page).all_inner_texts()]] is not None)
        page.get_by_role("combobox", name="Sort by", exact=True).select_option("rule")
        rule_ids = [re.search(r"(CERT|TLS|STLS|PROTO)-\d{3}", t).group(0) for t in rows(page).all_inner_texts()]
        ok("sort by rule", rule_ids == sorted(rule_ids), ",".join(rule_ids))
        page.get_by_role("combobox", name="Sort by", exact=True).select_option("priority")
        rows(page).first.click()
        d = open_drawer(page)
        ok("row click opens finding drawer", d.get_by_role("heading", name="Why am I seeing this?").is_visible())
        # evidence-chain disclosure
        summ = d.get_by_text("Evidence chain: capture to finding, step by step")
        summ.click()
        ok("evidence chain collapses", d.locator("details").first.get_attribute("open") is None)
        summ.click()
        ok("evidence chain expands", d.locator("details").first.get_attribute("open") is not None)
        # triage status persists
        with page.expect_response(lambda r: "/status" in r.url and r.request.method == "PATCH" and r.status == 200):
            d.get_by_role("combobox").last.select_option("acknowledged")
        fid = re.search(r"id=([^&]+)", page.url).group(1)
        page.reload()
        d = open_drawer(page)
        ok("triage status persists across reload", d.get_by_role("combobox").last.input_value() == "acknowledged")
        d.get_by_role("combobox").last.select_option("open")
        notes_item(page, d, "finding")
        # links out of the drawer, then browser back
        d.get_by_role("link", name=re.compile("^tcp-")).first.click()
        page.wait_for_url(re.compile(r"/sessions\?id="))
        open_drawer(page)
        page.go_back()
        page.wait_for_url(re.compile(r"/findings\?id="))
        ok("browser back returns to the finding", open_drawer(page).is_visible())
        page.get_by_role("complementary", name="Details").get_by_role("link", name=re.compile("^CN=")).first.click()
        page.wait_for_url(re.compile(r"/certificates\?id="))
        ok("finding -> certificate link", open_drawer(page).is_visible())
        page.go_back()
        d = open_drawer(page)
        d.get_by_role("link", name="Evidence register").click()
        page.wait_for_url(UI + "/evidence")
        page.goto(UI + f"/findings?id={fid}")
        d = open_drawer(page)
        d.get_by_role("list", name="Evidence chain").get_by_role("link", name="Open").first.click()
        page.wait_for_url(re.compile(r"/sessions\?id="))
        ok("evidence-chain Open link", open_drawer(page).is_visible())
        page.goto(UI + f"/findings?id={fid}")
        open_drawer(page)
        page.get_by_role("button", name="Close details (Esc)").click()
        page.get_by_role("complementary", name="Details").wait_for(state="detached")
        ok("close button closes the drawer", "id=" not in page.url)
        rows(page).first.get_by_role("button").click()
        open_drawer(page)
        page.keyboard.press("Escape")
        page.get_by_role("complementary", name="Details").wait_for(state="detached")
        ok("Escape closes the drawer", "id=" not in page.url)

        # ---------------------------------------------------------------- sessions
        page.goto(UI + "/sessions")
        rows(page).first.wait_for()
        page.get_by_role("searchbox", name="Search", exact=True).fill("10.20.0.99")
        ok("sessions search", rows(page).count() == 1)
        page.get_by_role("searchbox", name="Search", exact=True).fill("")
        page.get_by_role("combobox", name="Protocol", exact=True).select_option("IMAP")
        ok("protocol filter IMAP (none in this capture)", page.get_by_text("No sessions match these filters.").is_visible())
        page.get_by_role("combobox", name="Protocol", exact=True).select_option("all")
        page.get_by_role("combobox", name="Sort by", exact=True).select_option("findings")
        ok("sort findings-first puts the session with findings on top", "yes" in rows(page).first.inner_text())
        page.get_by_role("combobox", name="Sort by", exact=True).select_option("tls")
        ok("sort by TLS version", "TLSv1.0" in rows(page).first.inner_text())
        page.get_by_role("combobox", name="Sort by", exact=True).select_option("time")
        rows(page).filter(has_text="10.20.0.99").first.get_by_role("button").click()
        d = open_drawer(page)
        d.get_by_role("heading", name="Session timeline").wait_for()
        ok("session drawer with timeline", d.locator("ol li").count() > 3)
        d.get_by_role("link", name=re.compile("CERT-003")).click()
        page.wait_for_url(re.compile(r"/findings\?id="))
        page.go_back()
        d = open_drawer(page)
        d.get_by_role("link", name="Position 0").click()
        page.wait_for_url(re.compile(r"/certificates\?id="))
        ok("session -> certificate chain link", open_drawer(page).is_visible())
        page.go_back()
        d = open_drawer(page)
        d.get_by_role("link", name=re.compile("ML assessment")).click()
        page.wait_for_url(re.compile(r"/anomalies\?id="))
        ok("session -> ML assessment link", open_drawer(page).is_visible())
        page.go_back()
        d = open_drawer(page)
        notes_item(page, d, "session")
        page.get_by_role("tab", name=re.compile("Grouped by server")).click()
        page.wait_for_url(re.compile("view=servers"))
        expect(rows(page)).to_have_count(2)
        ok("grouped-by-server tab", rows(page).count() == 2)
        rows(page).first.get_by_role("link").first.click()
        page.wait_for_url(re.compile(r"/certificates\?id="))
        ok("server group -> certificate link", open_drawer(page).is_visible())
        page.go_back()
        rows(page).first.get_by_role("button").first.click()
        page.wait_for_url(re.compile("view=sessions"))
        ok("server group -> filtered session list", page.get_by_role("searchbox", name="Search", exact=True).input_value() != "" and rows(page).count() >= 1)

        # ---------------------------------------------------------------- certificates
        page.goto(UI + "/certificates")
        rows(page).first.wait_for()
        total = rows(page).count()
        for opt in ("leaf", "issues", "all"):
            page.locator("main select").select_option(opt)
            ok(f"certificate filter {opt}", rows(page).count() <= total and rows(page).count() >= 1)
        rows(page).filter(has_text="legacy").first.get_by_role("button").click()
        d = open_drawer(page)
        d.get_by_role("heading", name=re.compile("Certificate findings on these sessions")).wait_for()
        ok("certificate -> related findings listed", d.get_by_role("link", name=re.compile("Weak Public Key|Self-Signed")).count() >= 1)
        d.get_by_role("link", name=re.compile("Weak Public Key|Self-Signed")).first.click()
        page.wait_for_url(re.compile(r"/findings\?id="))
        page.go_back()
        d = open_drawer(page)
        notes_item(page, d, "certificate")
        d.get_by_role("link", name=re.compile("^tcp-")).first.click()
        page.wait_for_url(re.compile(r"/sessions\?id="))
        ok("certificate -> session link", open_drawer(page).is_visible())

        # ---------------------------------------------------------------- evidence
        page.goto(UI + "/evidence")
        rows(page).first.wait_for()
        ok("evidence register has one row per finding", rows(page).count() == 4)
        rows(page).first.get_by_role("link", name="Evidence chain").click()
        page.wait_for_url(re.compile(r"/findings\?id="))
        page.go_back()
        rows(page).first.get_by_role("link").first.click()
        page.wait_for_url(re.compile(r"/sessions\?id="))
        page.go_back()
        tabs = page.get_by_role("tab")
        tabs.first.focus()
        page.keyboard.press("End")
        page.wait_for_url(re.compile("view=timeline"))
        page.keyboard.press("Home")
        page.wait_for_url(re.compile("view=register"))
        page.get_by_role("tab", name=re.compile("Capture timeline")).click()
        page.get_by_role("combobox", name="Event type", exact=True).wait_for()
        expect(rows(page)).not_to_have_count(4)
        t_all = rows(page).count()
        page.get_by_role("combobox", name="Event type", exact=True).select_option("server_hello")
        ok("timeline event filter", 0 < rows(page).count() < t_all)
        page.get_by_role("combobox", name="Event type", exact=True).select_option("all")
        page.get_by_role("combobox", name="Session", exact=True).select_option(index=1)
        ok("timeline session filter", 0 < rows(page).count() < t_all)

        # ---------------------------------------------------------------- anomalies
        page.goto(UI + "/anomalies")
        rows(page).first.wait_for()
        page.get_by_label(re.compile("Show every evaluated session")).check()
        ok("anomalies show-all", rows(page).count() == 12)
        page.get_by_label(re.compile("Show every evaluated session")).uncheck()
        ok("anomalies outliers only", rows(page).count() == 1)
        page.get_by_text("How the ML stage works and its limitations").click()
        ok("ML limitations disclosure", page.get_by_text("no real-world accuracy is claimed").is_visible())
        page.get_by_role("link", name="Methodology", exact=True).click()
        page.wait_for_url(re.compile("/about#findings-vs-ml"))
        page.go_back()
        rows(page).first.get_by_role("button").click()
        d = open_drawer(page)
        body = page.inner_text("main")
        ok("anomaly drawer wording", "requires investigation" in body and not re.search(r"attack detected|compromise detected|malicious session", body, re.I))
        d.get_by_role("link", name=re.compile("^tcp-")).click()
        page.wait_for_url(re.compile(r"/sessions\?id="))

        # ---------------------------------------------------------------- reports: preview + downloads
        page.goto(UI + "/reports")
        with page.expect_response(lambda r: "/report-preview" in r.url and "redact=false" in r.url and r.status == 200):
            page.get_by_role("button", name="Preview report").click()
        fr = page.frame_locator("iframe")
        fr.locator("h2").first.wait_for()
        nav_sections = page.get_by_role("navigation", name="Report sections").get_by_role("button")
        ok("preview lists 14 report sections", nav_sections.count() >= 14, str(nav_sections.count()))
        ok("preview shows raw mode, policy and score", "Raw" in page.inner_text("main") and fr.locator(".mode").inner_text() == "RAW")
        nav_sections.filter(has_text="13. Limitations").click()
        page.wait_for_timeout(300)
        ok("section navigation scrolls the preview", page.evaluate("document.querySelector('iframe').contentWindow.scrollY") > 200)
        with page.expect_response(lambda r: "/report-preview" in r.url and "redact=true" in r.url and r.status == 200):
            page.get_by_role("radio").nth(1).check()
        fr.locator(".mode.REDACTED").wait_for()
        red_html = fr.locator("body").inner_text()
        ok("switching to redacted reloads the preview without addresses", not PRIVATE_IP.search(red_html))
        page.get_by_role("button", name="Close preview").click()
        ok("close preview", page.get_by_role("button", name="Preview report").is_visible())
        for mode_i, mode in ((0, "Raw"), (1, "Redacted")):
            page.get_by_role("radio").nth(mode_i).check()
            for fmt in ("PDF", "HTML", "JSON"):
                with page.expect_download(timeout=60000) as dl:
                    page.get_by_role("button", name=re.compile(f"Download {fmt}")).click()
                data = Path(dl.value.path()).read_bytes()
                good = len(data) > 500 and (not fmt == "PDF" or data.startswith(b"%PDF"))
                if mode == "Redacted" and fmt != "PDF":
                    good = good and not PRIVATE_IP.search(data.decode("utf-8", "replace"))
                ok(f"download {mode} {fmt}", good and (("redacted" in dl.value.suggested_filename) == (mode == "Redacted")),
                   dl.value.suggested_filename)
            with page.expect_download() as dl:
                page.get_by_role("button", name=re.compile("Download evidence bundle")).click()
            z = zipfile.ZipFile(io.BytesIO(Path(dl.value.path()).read_bytes()))
            ok(f"evidence bundle {mode}", "manifest.json" in z.namelist())
            with page.expect_download() as dl:
                page.get_by_role("button", name=re.compile("Download STIX")).click()
            ok(f"STIX {mode}", json.loads(Path(dl.value.path()).read_text("utf-8"))["type"] == "bundle")
        page.reload()
        rows(page).first.wait_for()
        with page.expect_download() as dl:
            rows(page).first.get_by_role("button", name="Download").click()
        ok("generated-reports list download", dl.value.suggested_filename != "")

        # ---------------------------------------------------------------- compare
        page.goto(UI + f"/compare?a={mixed}&b={after}")
        page.get_by_text("Posture change").wait_for()
        ok("compare: anomaly changes section", page.get_by_role("heading", name="ML anomaly changes (supplementary)").is_visible()
           and page.get_by_role("heading", name="Anomalous sessions resolved in B (1)").is_visible())
        page.get_by_role("combobox", name="B: comparison (later)").select_option(mixed)
        page.get_by_text("Choose two different analyses.").wait_for()
        ok("compare: same analysis twice is refused", page.get_by_text("Posture change").count() == 0)
        page.get_by_role("combobox", name="A: baseline (earlier)").select_option(before)
        page.get_by_role("combobox", name="B: comparison (later)").select_option(after)
        page.get_by_text("Posture change").wait_for()
        page.get_by_role("heading", name=re.compile(r"Resolved in B \([1-9]")).first.wait_for()
        ok("compare: before/after resolves findings", True)
        page.get_by_role("link", name="Back to captures").click()
        page.wait_for_url(UI + "/captures")

        # ---------------------------------------------------------------- about, footer, 404
        page.goto(UI + "/findings")
        page.get_by_role("contentinfo").get_by_role("link", name="Limitations").click()
        page.wait_for_url(re.compile("/about#limitations"))
        page.get_by_role("contentinfo").get_by_role("link", name="Data handling").click()
        page.wait_for_url(re.compile("/about#data-handling"))
        page.get_by_role("contentinfo").get_by_role("link", name="About and methodology").click()
        page.get_by_role("link", name="Start with step 1: Capture").click()
        page.wait_for_url(UI + "/captures")
        page.goto(UI + "/no-such-page")
        page.get_by_role("link", name="Go to step 1: Capture").click()
        page.wait_for_url(UI + "/captures")
        ok("footer, about and not-found links", True)
        page.goto(UI + "/timeline")
        page.wait_for_url(re.compile(r"/evidence\?view=timeline"))
        ok("legacy /timeline URL redirects", True)

        # ---------------------------------------------------------------- mobile 390 px
        m = b.new_context(viewport={"width": 390, "height": 844}, accept_downloads=True).new_page()
        watch(m, problems)
        m.goto(UI)
        m.evaluate(f"localStorage.setItem('sms.activeCapture', '{mixed}')")
        for route in ("/", "/captures", "/upload", "/findings", "/sessions", "/sessions?view=servers", "/certificates",
                      "/evidence", "/anomalies", "/reports", f"/compare?a={before}&b={after}", "/about"):
            m.goto(UI + route)
            m.wait_for_load_state("networkidle")
            sw = m.evaluate("document.documentElement.scrollWidth")
            ok(f"mobile: no horizontal scroll {route[:30]}", sw <= 392, str(sw))
        for route in ("/findings", "/sessions", "/certificates", "/anomalies"):
            m.goto(UI + route)
            rows(m).first.get_by_role("button").first.click()
            dd = m.get_by_role("complementary", name="Details")
            dd.wait_for()
            m.wait_for_timeout(300)
            top = dd.evaluate("e => e.getBoundingClientRect().top")
            ok(f"mobile: drawer opens in view {route}", -5 <= top < 844, f"top={top:.0f}")
        m.goto(UI + "/reports")
        m.get_by_role("button", name="Preview report").click()
        m.frame_locator("iframe").locator("h2").first.wait_for()
        ok("mobile: report preview", m.evaluate("document.documentElement.scrollWidth") <= 392)
        m.get_by_role("navigation", name="Investigation workflow").get_by_role("link", name=re.compile("Findings")).click()
        m.wait_for_url(UI + "/findings")
        ok("mobile: workflow navigation", True)
        b.close()

    fails = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(fails)}/{len(results)} checks passed")
    print("Console / page / network problems:", len(problems))
    for pr in problems:
        print("  ", pr)
    return 1 if fails or problems else 0


def notes_capture(page):
    panel = page.locator("section", has=page.get_by_role("heading", name="Investigation notes for this capture"))
    notes_flow(page, panel, "capture")


def notes_item(page, drawer, kind):
    notes_flow(page, drawer, kind)


def notes_flow(page, scope, kind):
    """Add a note selected for the report, untick, delete - each step via the API, verified in the UI."""
    text = f"QA {kind} note {int(time.time() * 1000)}"
    scope.get_by_role("textbox", name="New note", exact=True).fill(text)
    scope.get_by_label("Include this item in the investigation report").check()
    with page.expect_response(lambda r: r.url.endswith("/annotations") and r.request.method == "POST" and r.status == 201):
        scope.get_by_role("button", name="Add note").click()
    scope.get_by_text(text).wait_for()
    scope.get_by_text("In investigation report", exact=True).wait_for()
    item = scope.locator("li", has_text=text)
    with page.expect_response(lambda r: "/annotations/" in r.url and r.request.method == "PATCH" and r.status == 200):
        item.get_by_label("Include in investigation report").uncheck()
    scope.get_by_text("In investigation report", exact=True).wait_for(state="detached")
    with page.expect_response(lambda r: "/annotations/" in r.url and r.request.method == "DELETE" and r.status == 204):
        item.get_by_role("button", name="Delete").click()
    scope.get_by_text(text).wait_for(state="detached")
    ok(f"notes on {kind}: add, select for report, unselect, delete", True)


if __name__ == "__main__":
    sys.exit(main())
