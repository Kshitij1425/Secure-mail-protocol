# SecureMailScope Design System

Goal: SecureMailScope should feel like a serious technical-intelligence / cyber-forensics
workstation: restrained, dense, readable and calm. It must not look like, or imply affiliation
with, any government body.

## Research basis (public, visual only)

| Source | Access | What was observed (interface only) |
|---|---|---|
| ntro.gov.in (live) | Not reachable from the build environment (connection refused / reset on every attempt, 2026-09-27) | - |
| ntro.gov.in public pages archived by the Internet Archive (2021-2025: archive, recruitment notice pages) | Reachable | Fixed-width table layout; header banner; flat text navigation (Home, Tenders, Recruitments, Publications, Archive); centred notice listings with underlined headings; no accessibility controls |
| nciipc.gov.in (a public-facing body under NTRO), archived pages (2020 advisory, 2024 about page) | Reachable (the 2026 snapshot is an ISP block page and was ignored) | Flat navigation (Home, About Us, Updates, Documents, Forms, Events, Contact); "Last updated" line; footer row of policy links; dense numbered data tables ("S. No. / CVE / Base Score / ...") |
| GIGW 3.0 (Guidelines for Indian Government Websites) | Public guidance | Skip link, text-size control, contrast control, breadcrumbs, "last updated", footer policy links |

Only operational content visible on those pages was the public notices themselves; none of it
was used. No asset, logo, emblem, seal, slogan, colour scheme or markup was copied.

### Adopted

* Restraint: no gradients, glows, HUD elements, decorative imagery or animation.
* Register-style numbered tables ("S. No.") for findings, the evidence register, server groups and trends.
* A document-style record header (the **case bar**): capture, SHA-256, capture time, policy, posture.
* Flat, numbered navigation; breadcrumbs; footer utility links; "last updated".
* Accessibility controls in a utility strip (GIGW): skip link, A / A+ / A++, high contrast.

### Deliberately not adopted

* Any emblem, seal, logo, tricolour or government colour scheme; "Government of India" wording.
* Fixed-width 1024 px table layout (the workstation is responsive to 390 px).

The footer and About page state that SecureMailScope is an independent academic project, not
affiliated with or endorsed by any government agency.

## Tokens (`frontend/src/index.css`)

| Token | Value | Use |
|---|---|---|
| `--chrome` | #13233F | Application band (header) |
| `--ground` / `--panel` / `--sunken` | #EEF1F5 / #FFFFFF / #F6F8FA | Workspace, panels, table heads |
| `--ink` / `--ink-2` / `--ink-3` | #16202E / 70 84 104 / 104 118 138 | Text hierarchy |
| `--signal` | #1F5AA6 | Links, focus, selection, the one accent |
| `--sev-*` | #7A1717, #B42318, #E0613F, #F09A7A, #9AA3B0 | Ordinal severity ramp (validated for colour-vision deficiency); always with a text label |
| `--ok` / `--warn` | green / amber | Evidence class and alert tones, always with text |
| `--ml` | #5E3C99 | ML outputs only, distinct from severity |

Typography: IBM Plex Sans / Mono, bundled locally (no external requests). Base 16 px; A+ 17.5 px;
A++ 19 px. High-contrast mode redefines the tokens to black on white.

## Components (`frontend/src/components`)

| Component | Behaviour |
|---|---|
| Utility strip, header, side navigation, footer (`Shell.tsx`) | 8 numbered workflow steps + "Supporting analysis"; footer policy links |
| Case bar | Record under investigation on every analysis page |
| Workflow pager | Previous / next step at the bottom of each step page |
| `PageTitle`, `Breadcrumbs` | Title + lead; breadcrumb trail |
| `Panel` | Titled section with header bar; square-ish corners (4 px) |
| `.tbl` | Dense tables; numbers right-aligned; `sno` column; row hover and selection |
| `Severity`, `EvidenceTag` | Text + swatch / outlined tag; never colour alone |
| `Drawer` | Detail panel beside the table (xl) or below it; takes focus on open; scrolls into view on narrow screens; Esc closes |
| `Tabs`, `TabPanel` | WAI-ARIA tabs; arrow keys, Home/End |
| `Disclosure` | Native `details` accordion item |
| `Alert` | info / warn / error / ok with icon and text |
| `StateBlock` | Loading, error (with retry), empty (with next action) |
| `AnalystNotes` | Notes and "include in investigation report" per item |
| Charts (`charts.tsx`, trend chart) | Severity distribution, dimension bars, posture trend; direct labels and accessible names |
| `EvidenceChainView` | Numbered chain capture -> finding with evidence class per step |

Upload shows a determinate upload bar, then an indeterminate "analysing on the server" state
(the server does not report stage progress, so none is invented).

## Wording rules

* Deterministic finding: "a defined security rule was triggered".
* ML: "anomalous security configuration", "unusual relative to the capture baseline",
  "requires investigation". Never "attack detected", "compromise detected" or "malicious session".
* Certificates: extraction, chain linkage and trust are reported separately; trust is "not evaluated".
