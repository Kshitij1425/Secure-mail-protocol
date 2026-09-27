"""
Automated accessibility scan (axe-core 4.x, WCAG 2.0/2.1/2.2 A and AA rules) of every dashboard route,
in normal and high-contrast mode, at desktop and 390 px width, including open detail drawers.

Needs: a running API + dashboard (see qa/README.md), Python Playwright with Chromium, and
frontend/node_modules/axe-core (installed by `npm ci` as a dev dependency).

Usage (from the repository root):  python qa/a11y_scan.py [--json out.json]
Exit code 1 if any violation is found.
"""
import argparse
import json
import sys

from playwright.sync_api import sync_playwright

from common import ROOT, UI, api_get, seed

AXE = ROOT / "frontend" / "node_modules" / "axe-core" / "axe.min.js"
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]


def run_axe(page):
    page.add_script_tag(path=str(AXE))
    return page.evaluate("""async (tags) => {
        const r = await axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] });
        return r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help,
            nodes: v.nodes.slice(0, 5).map(n => ({ target: n.target.join(' '), summary: n.failureSummary })) }));
    }""", TAGS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()
    ids = seed()
    mixed, after, before = ids["mixed"], ids["after"], ids["before"]
    first_finding = api_get(f"/captures/{mixed}/findings")[0]["finding_id"]
    first_session = api_get(f"/captures/{mixed}/sessions")[0]["session_id"]
    inv = api_get(f"/captures/{mixed}/certificate-inventory")[0]["fingerprint_sha256"]
    anom = [a for a in api_get(f"/captures/{mixed}/anomalies") if a["is_anomaly"]][0]["id"]
    from urllib.parse import quote
    pages = {
        "Posture (overview)": "/", "Captures": "/captures", "Upload": "/upload",
        "Findings": "/findings", "Finding drawer": f"/findings?id={quote(first_finding)}",
        "Sessions": "/sessions", "Sessions by server": "/sessions?view=servers", "Session drawer": f"/sessions?id={quote(first_session)}",
        "Certificates": "/certificates", "Certificate drawer": f"/certificates?id={inv}",
        "Evidence register": "/evidence", "Evidence timeline": "/evidence?view=timeline",
        "Anomalies": "/anomalies", "Anomaly drawer": f"/anomalies?id={anom}",
        "Reports": "/reports", "Compare and trend": f"/compare?a={before}&b={after}", "About": "/about",
        "Not found": "/no-such-page",
    }
    results, total = [], 0
    with sync_playwright() as p:
        b = p.chromium.launch()
        for width, contrast in ((1440, "normal"), (1440, "high"), (390, "normal")):
            page = b.new_page(viewport={"width": width, "height": 900})
            page.goto(UI)
            page.evaluate(f"localStorage.setItem('sms.activeCapture', '{mixed}'); localStorage.setItem('sms.contrast', '{contrast}')")
            for name, route in pages.items():
                page.goto(UI + route)
                page.wait_for_load_state("networkidle")
                page.wait_for_timeout(300)
                v = run_axe(page)
                total += len(v)
                results.append({"page": name, "width": width, "contrast": contrast, "violations": v})
                status = "OK  " if not v else "FAIL"
                print(f"{status} {width:>4}px {contrast:<6} {name}: {len(v)} violation(s)")
                for x in v:
                    print(f"       [{x['impact']}] {x['id']}: {x['help']}")
                    for n in x["nodes"]:
                        print(f"           {n['target']}")
            if width == 1440 and contrast == "normal":
                # report preview (iframe with the real report) is part of the Reports page
                page.goto(UI + "/reports")
                page.get_by_role("button", name="Preview report").click()
                page.frame_locator("iframe").locator("h2").first.wait_for()
                v = run_axe(page)
                total += len(v)
                results.append({"page": "Reports + preview", "width": width, "contrast": contrast, "violations": v})
                print(f"{'OK  ' if not v else 'FAIL'} {width:>4}px {contrast:<6} Reports + preview: {len(v)} violation(s)")
                for x in v:
                    print(f"       [{x['impact']}] {x['id']}: {x['help']}")
            page.close()
        b.close()
    print(f"\n{len(results)} page states scanned, {total} violation(s)")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
