# Presentation chart legibility check — TEMPLATE (HUMAN ONLY)

> **Status: blank checklist. No results are recorded here.** This check must be
> done by a person who opens the PNGs at actual slide size. The agent that
> created this file did not judge visual legibility and must not fill in the
> result cells or invent a review.
>
> The repository statement remains **manual-guided, not blind**; this checklist
> does not change any finding or rating.

## What to check

For each chart below, open the file at presentation/slide size and confirm:

- axis labels, tick values and the UTC / seconds-since-first-packet caption are readable;
- legends and colour meanings are distinguishable;
- titles and annotations (including any OUTFILE-staging and CSV-download markers in
  Case 02, or DNS-rate phases in Case 03) do not overlap or run off the image;
- the chart makes sense when projected, not just when zoomed in on a workstation.

All four charts are 3080 × 2200 PNGs generated at 220 dpi. The owner has already
viewed Cases 01 and 04 informally and reported them fine, but every case should
still be checked here before the presentation.

## Results (fill in by the person doing the check)

| Case | PNG path | Legible at slide size? (yes / no) | Issues observed | Checked by | Date (UTC) |
|---|---|---|---|---|---|
| 01 — SSH (real loopback) | `cases/case01_ssh_sessions/viz/case01_ssh_sessions_timeline.png` | `<yes/no>` | `<none / describe>` | `<name>` | `<YYYY-MM-DD>` |
| 02 — SQLi (synthetic) | `cases/case02_web_sqli/viz/case02_web_sqli_timeline.png` | `<yes/no>` | `<none / describe>` | `<name>` | `<YYYY-MM-DD>` |
| 03 — DNS tunnel (real loopback) | `cases/case03_dns_tunnel/viz/case03_dns_tunnel_timeline.png` | `<yes/no>` | `<none / describe>` | `<name>` | `<YYYY-MM-DD>` |
| 04 — C2 beacon (synthetic) | `cases/case04_c2_beacon/viz/case04_c2_beacon_timeline.png` | `<yes/no>` | `<none / describe>` | `<name>` | `<YYYY-MM-DD>` |

## Outcome (fill in after checking all four)

- Charts that need regeneration or annotation changes: `<list or none>`
- Any change made to a chart script: `<none / describe>` (if a script changes,
  regenerate the PNG and then the hash manifest).
- Final statement: `<write the honest result; do not claim a check that was not done>`
