# Human-only work — blank handover

> This is a handover list only. It contains **no results**. The agent that
> created it did not perform any of these tasks and must not fill in outcomes.
> The repository statement remains **manual-guided, not blind**; none of these
> items changes a finding or rating.

| Task | Person / precondition | Inputs | Exact output to produce | Template / runbook |
|---|---|---|---|---|
| B1 — Blind independent check | A teammate who has NOT seen `project.md`, `lab/`, `ground_truth/`, the existing reports or the confidence matrix | Only `cases/<case>/raw/<case>.pcap` and its `.sha256` (Case 02 or 04 suggested) | `docs/blind_check_<case>.md`, filled with their own timeline, rated findings and honest agreement/difference table | `docs/BLIND_CHECK_TEMPLATE.md` |
| B2 — Real two-host capture | Person with two lab VMs on an isolated host-only network (for example attacker `192.168.56.10`, victim `192.168.56.30`) | Runbook below; exact tcpdump command, start/stop times and VM clock offsets must be recorded | A new `cases/case05_<name>/` with sealed pcap + `.sha256`, `report/pcap_notes.md`, Zeek/tshark outputs, timeline, findings and one custody row | `docs/TWO_HOST_CAPTURE_RUNBOOK.md`, then `docs/NEW_CASE_PIPELINE.md` |
| B3 — Chart legibility | A person opening the PNGs at presentation/slide size | All four `cases/*/viz/*_timeline.png` files; `report/PRESENTATION.pdf` for context | `docs/PRESENTATION_CHART_CHECK.md` filled in for all four cases (Cases 01 and 04 were viewed informally by the owner; Cases 02 and 03 still need checking) | `docs/PRESENTATION_CHART_CHECK.md` |
| B3 — Presentation rehearsal | The five named owners in the roles table at the top of `report/FINAL_REPORT.md` | `report/PRESENTATION.pdf` and each owner's files | No separate file is defined in `REMAINING_TASKS.md`; each owner must be able to explain their files | `report/FINAL_REPORT.md` roles table |

After any chart or script change, regenerate PDFs with `python3 tools/export_pdf.py`
and the hash manifest with `python3 tools/make_appendix.py` (manifest last).
Do not commit or push without instruction.
