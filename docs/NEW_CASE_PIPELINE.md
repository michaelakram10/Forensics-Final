# New-case pipeline (`case05_...`) — reference runbook

> This document lists the exact command sequence used for the four existing
> cases, adapted for a new case. It is a reference, not a claim that `case05`
> exists. Do not run the whole-repo variants of the scripts if they would
> overwrite existing evidence outputs; use the explicit case argument where the
> script supports it (see the hard-coded list notes below).
>
> Analysis remains **manual-guided, not blind** unless a separate human blind
> check is actually performed (`docs/BLIND_CHECK_TEMPLATE.md`). Any new ratings
> follow `report/methodology.md` Section 5.

## 0. Before starting — scripts with hard-coded case lists

These lines must be edited to recognise a fifth case before running the
whole-repo commands. Do not edit them until a real new case exists.

| Script | Lines to edit | What they contain |
|---|---|---|
| `tools/generate_timelines.py` | 27–32 (`CASES` title dict); 88 and 107 (case-specific swimlane branches); 182, 208, 235, 257 (per-case analytical panels); 274–275 (`PANELS` mapping) | Without edits, `build()` fails on `PANELS[case]` for a new case; pass the case name explicitly to limit output |
| `tools/export_flows.py` | 20 (`CASES` list); 21–22 (`BASE` basename map) | Accepts case names as arguments (`sys.argv[1:]`), but `BASE[case]` must contain the new case |
| `tools/make_excerpts.py` | 11–12 (`BASE` map); 13–30 (`EXCERPTS` filters); 58–61 (hard-coded note about Cases 01/03) | Has **no** CLI case argument: running it rewrites *all* existing excerpts and `report/excerpts_index.md`; edit deliberately or run only when intending a full refresh |
| `tools/verify_counts.py` | none | Generic: takes `<case_dir_name> <pcap_basename>` from argv (lines 9–10) |
| `tools/make_appendix.py` | 14–19 (`LOGS` map of expected Zeek TSV logs) | Needed for Appendix A excerpts; the hash-manifest scan (lines 35–41) discovers new files automatically |
| `tools/build_timeline.py` (related) | 25, 46, 51, 65 (case-specific branches) | A `case05` falls through to the generic path; check the resulting CSV before use |
| `tools/seal_evidence.sh` | none | Loops over **all** `cases/*/raw` (lines 5–13); do not run it on an existing tree, since it chmods and rewrites every sidecar |

## 1. Prepare directories and seal the new pcap

```bash
export TZ=UTC; export PATH=/opt/zeek/bin:$PATH
CASE=case05_<descriptive_name>
BASE=case05
mkdir -p cases/$CASE/raw cases/$CASE/zeek/tsv cases/$CASE/zeek/json \
         cases/$CASE/tshark cases/$CASE/tcpdump cases/$CASE/timeline \
         cases/$CASE/viz cases/$CASE/flows cases/$CASE/excerpts cases/$CASE/report
# Place the pcap as cases/$CASE/raw/$BASE.pcap (by a human, with acquisition notes).
( cd cases/$CASE/raw && sha256sum "$BASE.pcap" > "$BASE.pcap.sha256" && chmod 444 "$BASE.pcap" "$BASE.pcap.sha256" )
( cd cases/$CASE/raw && sha256sum -c "$BASE.pcap.sha256" )
```

`tools/seal_evidence.sh` is the whole-tree equivalent; do not run it here because
it would touch existing sealed files (see table above).

## 2. Zeek logs

```bash
./tools/run_zeek.sh "$CASE" "$BASE"
```

`run_zeek.sh` verifies the pcap hash, refreshes only that case's `zeek/tsv` and
`zeek/json`, and writes `zeek/zeek_version.txt`. Record tshark/capinfos and
tcpdump output as NEW files under `cases/$CASE/tshark/` and
`cases/$CASE/tcpdump/`; never edit existing cases' outputs.

## 3. Second-tool verification

```bash
python3 ./tools/verify_counts.py "$CASE" "$BASE" | tee "cases/$CASE/report/verify_counts.md"
```

Expected: flows, packets and IP bytes all CONFIRMED, or a written explanation of
any difference (byte definitions are in `report/methodology.md` Section 4.2).

## 4. Timeline

```bash
python3 ./tools/build_timeline.py "$CASE"    # writes cases/$CASE/timeline/timeline.csv
```

Every row must carry an `evidence_ref` to a log and uid/frame. For complex
cases, a hand-written timeline may be substituted (as for Cases 01 and 03), but
the same evidence-referencing rule applies.

## 5. Charts

```bash
python3 ./tools/generate_timelines.py "$CASE"    # after the edits in section 0
```

Optional case-specific statistics, if relevant:

```bash
python3 ./tools/beacon_stats.py "$CASE"
zeek-cut query < cases/$CASE/zeek/tsv/dns.log | python3 ./tools/dns_stats.py
```

## 6. Flows (Zeek-derived view + independent NetFlow records)

```bash
python3 ./tools/export_flows.py "$CASE"    # after adding the case to CASES/BASE
```

Writes `cases/$CASE/flows/case05_flows.csv` and refreshes
`report/flows_reconciliation.md`. Keep the "Zeek-derived, not NetFlow" wording for
those CSVs. Independent exporter output can now be added in a NEW folder:

```bash
mkdir -p "cases/$CASE/netflow/export"
nfpcapd -r "cases/$CASE/raw/$BASE.pcap" -w "cases/$CASE/netflow" -I "$BASE"
for f in cases/$CASE/netflow/nfcapd.*; do
  n=$(basename "$f")
  nfdump -r "$f" -o csv -N > "cases/$CASE/netflow/export/$n.csv"
  nfdump -r "$f" -o null -N > "cases/$CASE/netflow/export/$n.summary.txt" 2>&1
done
```

Sum the per-file CSV totals and add the case to `report/netflow_reconciliation.md`;
the installed tools are `nfpcapd`/`nfdump` 1.7.10-release.

## 7. Focused excerpts

```bash
python3 ./tools/make_excerpts.py    # only after adding filters/BASE for the new case
```

Creates new filtered pcaps and `SHA256SUMS.txt` under `cases/$CASE/excerpts/`
and refreshes `report/excerpts_index.md` (this script has no case argument).

## 8. Custody row

Append ONE new row to `custody/custody_log.csv` (do not change existing rows):

```text
<UTC timestamp>,kali,<host>,case05,"<action>",<pcap sha256>,"<notes>"
```

Use the new pcap's real SHA-256 from step 1; `kali` is the shared lab account
(see `custody/README.md`). Documentation-only updates use `n/a` in the hash
column.

## 9. Reports, PDFs and manifest (always last)

Write `cases/$CASE/report/report.md`, `verification.md`, `pcap_notes.md` and
update `report/FINAL_REPORT.md`, `report/confidence_matrix.md`,
`report/tool_versions.md` and roles tables as needed. Then:

```bash
python3 ./tools/export_pdf.py        # rebuild FINAL_REPORT.pdf + PRESENTATION.pdf
python3 ./tools/make_appendix.py     # rebuild APPENDIX_A + hash_manifest.md LAST
```

## 10. Final checks

```bash
( cd cases/$CASE/raw && sha256sum -c "$BASE.pcap.sha256" )
git status --short
git diff --stat
python3 - <<'PY'
import hashlib, re
from pathlib import Path
entries = re.findall(r'^([0-9a-f]{64})  (.+)$', Path('report/hash_manifest.md').read_text(), re.M)
bad = [n for h, n in entries if not Path(n).exists() or hashlib.sha256(Path(n).read_bytes()).hexdigest() != h]
print(f'manifest entries: {len(entries)}')
print(f'mismatches: {len(bad)}')
PY
```

Confirm no changes under any `raw/` directory or `supplementary/` before any
commit. Do not commit or push without instructions.
