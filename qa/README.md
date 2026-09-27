# Browser QA

Scripts that drive the real dashboard and API (no mocks). They create their own analyses through
the API, so they can run against any database; a fresh one is recommended.

Prerequisites: backend and frontend installed (see the main README), `npm ci` in `frontend/`
(installs axe-core), and Python Playwright with Chromium:

```
pip install playwright && python -m playwright install chromium
```

Start the API and dashboard (a throw-away database is recommended):

```powershell
$env:SECUREMAILSCOPE_DATABASE_URL = "sqlite:///C:/temp/sms-qa/qa.db"
$env:SECUREMAILSCOPE_UPLOAD_DIR = "C:\temp\sms-qa\uploads"; $env:SECUREMAILSCOPE_REPORTS_DIR = "C:\temp\sms-qa\reports"
cd backend; python -m uvicorn securemailscope.api.main:app --host 127.0.0.1 --port 8000
# second terminal
cd frontend; npm run dev -- --host 127.0.0.1 --port 5173
```

Run (from the repository root):

| Command | What it checks |
|---|---|
| `python qa/e2e_walkthrough.py` | Every interactive control on desktop and 390 px: navigation, pager, analysis selector, text size, contrast, captures (compare selection, re-analysis), upload (validation, policy, keyboard file chooser), findings (search, filters, sort, drawer, evidence chain, triage persistence, notes), sessions, certificates, evidence tabs and filters, anomalies, report preview (sections, raw/redacted), all downloads, compare (including ML anomaly changes), about, 404. Fails on any console error, page error, failed request or HTTP >= 400. |
| `python qa/a11y_scan.py` | axe-core WCAG 2.0/2.1/2.2 A and AA rules on every route and detail drawer, normal and high-contrast, 1440 px and 390 px, plus the report preview. Fails on any violation. |

Set `SMS_API` / `SMS_UI` to use other addresses.

Coverage limits: Chromium only; no screen-reader testing (NVDA/JAWS/VoiceOver) and no other
browsers were exercised. axe checks rules that can be automated; it does not replace manual review.
