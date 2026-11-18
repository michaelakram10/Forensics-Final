# Blind independent check — TEMPLATE (HUMAN ONLY)

> **Status: template only. No results are recorded here.** This check must be
> performed by a teammate who has not seen `project.md`, `lab/`, `ground_truth/`
> or any of this repository's existing reports. The agent that created this file
> did not perform a blind analysis and must not fill it in.
>
> The committed analysis is and remains **manual-guided, not blind**. Nothing in
> this template changes that statement. If this check is completed by a person,
> report the result honestly — including disagreements — and do **not** edit the
> committed ratings to force agreement.

## 0. Scope and handover (fill in by the lead)

- Case chosen: `<case05_... | case02_web_sqli | case04_c2_beacon>` (Case 02 or 04 suggested)
- Teammate performing the check: `<name>`
- Date of handover (UTC): `<YYYY-MM-DDTHH:MM:SSZ>`
- Files handed over (only these): `cases/<case>/raw/<case>.pcap` and `cases/<case>/raw/<case>.pcap.sha256`
- Confirmation that the teammate has NOT opened `project.md`, `lab/`,
  `ground_truth/`, `report/`, `cases/*/report/` or any other analysis file: `<yes/no>`

## 1. Verify the evidence before analysis

```bash
cd cases/<case>/raw
sha256sum -c <case>.pcap.sha256
```

Record the exact output: `<paste output>`

## 2. Independent analysis (teammate writes this section)

Using Zeek and tshark only, and without consulting the repository's reports:

### 2.1 Timeline written from scratch

| UTC | Event | Evidence (log + uid / frame) |
|---|---|---|
| `<time>` | `<event>` | `<evidence>` |

### 2.2 Findings written from scratch

Ratings must follow `report/methodology.md` Section 5 (Certain / Likely /
Inferred). Observation and interpretation are kept as separate findings.

| ID | Finding | MITRE (if applicable) | Rating | Evidence | Reasoning |
|---|---|---|---|---|---|
| `<B1>` | `<finding>` | `<T#### or n/a>` | `<rating>` | `<evidence>` | `<reasoning>` |

## 3. Comparison with the committed findings

Fill this in only after the blind analysis in Section 2 is complete. Compare
against `report/confidence_matrix.md` and `cases/<case>/timeline/timeline.csv`.

| Committed finding | Blind result | Verdict (agrees / differs / missed / extra) | Note |
|---|---|---|---|
| `<F2.1>` | `<blind ID or description>` | `<verdict>` | `<note>` |

## 4. Honest conclusion

- Agreements: `<count and list>`
- Differences: `<count and list, with why>`
- Missed by blind check: `<count and list>`
- Extra in blind check: `<count and list>`
- Did any disagreement change a committed rating? **No — committed ratings are
  not edited by this check.**
- Statement: `<write the result plainly, including any disagreements>`

Save the completed document as `docs/blind_check_<case>.md`.
