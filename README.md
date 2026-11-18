# Project 09 — Digital Forensics: Network Session Reconstruction

This repository contains the submitted digital-forensics project: evidence handling,
Zeek/tshark/tcpdump analysis, timelines, visualizations, confidence ratings, flow
exports, pcap excerpts and the final forensic report. The exercise manual
(`project.md`) is deliberately not included in this public submission.

**Provenance:** Cases 01 and 03 are **real loopback lab captures**; Cases 02 and 04 are
**synthetic Scapy reconstructions**. See `report/data_provenance.md`.

> The public GitHub submission deliberately **excludes** `project.md`, `lab/` and
> `ground_truth/`. They remain only on the presenter's private machine, outside this
> repository. The analysis was manual-guided, not blind; no "frozen before unsealing"
> claim is made.

## Prerequisites

- Zeek 9.0.1 (`/opt/zeek/bin/zeek` and `zeek-cut`).
- tshark and capinfos 4.6.x (4.6.9 in `report/tool_versions.md`).
- tcpdump 4.99.6.
- jq 1.8.2.
- Python 3.14.7 with the packages in `requirements.txt`:
  `python3 -m pip install -r requirements.txt`.
- WeasyPrint and the Python `markdown` package are required for PDF export; both
  are listed in `requirements.txt`. Their versions are not recorded in
  `report/tool_versions.md`, so they are left unpinned.

## How to verify my work (60 seconds)

```bash
cd Forensics-Final
for f in cases/*/raw/*.sha256; do (cd "$(dirname "$f")" && sha256sum -c "$(basename "$f")"); done
zeek-cut uid query < cases/case03_dns_tunnel/zeek/tsv/dns.log | head -n 3
tshark -r cases/case02_web_sqli/raw/case02.pcap -Y 'http.request.method=="POST"' \
  -T fields -e urlencoded-form.key -e urlencoded-form.value
sha256sum cases/case02_web_sqli/tshark/http_objects/customers.csv
```

Expected: 4 × `OK`; `dnscat.<hex...>` query names; `username/password/Login` and
`admin/password/Login`; `9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6`.

## Layout

```text
.
├── cases/
│   ├── case01_ssh_sessions/   # REAL loopback SSH capture
│   ├── case02_web_sqli/         # synthetic SQLi + CSV exfil
│   ├── case03_dns_tunnel/       # REAL loopback dnscat2 capture
│   └── case04_c2_beacon/        # synthetic TLS beaconing
│       ├── raw/                 # sealed pcap + .sha256
│       ├── zeek/{tsv,json}/     # Zeek 9.0.1 logs + queries.md
│       ├── tshark/ tcpdump/     # cross-tool output
│       ├── timeline/            # evidence-referenced timeline.csv
│       ├── viz/                 # 220-dpi PNG
│       ├── flows/               # Zeek-derived flow export + README
│       ├── excerpts/            # filtered pcap excerpts + SHA256SUMS.txt
│       └── report/              # per-case report, notes, verification
├── supplementary/               # superseded SYNTHETIC case01/case03 (labelled)
├── custody/custody_log.csv
├── tools/                       # sealing, Zeek, verification, timelines, exports
└── report/
    ├── FINAL_REPORT.md / .pdf   # final deliverable
    ├── PRESENTATION.md / .pdf   # presenter slide deck
    ├── methodology.md
    ├── confidence_matrix.md     # 41 findings, one rating each
    ├── data_provenance.md
    ├── tool_versions.md
    ├── flows_reconciliation.md
    ├── excerpts_index.md
    ├── hash_manifest.md
    ├── APPENDIX_A_raw_evidence.md
    └── figures/case01.mmd … case04.mmd
```

## Reproduction

```bash
export TZ=UTC; export PATH=/opt/zeek/bin:$PATH

for pair in "case01_ssh_sessions case01" "case02_web_sqli case02" \
            "case03_dns_tunnel case03" "case04_c2_beacon case04"; do
  c=${pair%% *}; n=${pair##* }
  ./tools/run_zeek.sh "$c" "$n"
  python3 ./tools/verify_counts.py "$c" "$n" | tee "cases/$c/report/verify_counts.md"
done

python3 ./tools/generate_timelines.py
python3 ./tools/export_flows.py
python3 ./tools/make_excerpts.py
python3 ./tools/export_pdf.py
python3 ./tools/make_appendix.py         # regenerate appendix + hash manifest
```

`ground_truth/` and `lab/` are not needed for the analysis; acquisition notes for the real captures are in each case's `report/pcap_notes.md`.

## Results at a glance

- All 4 Zeek↔tshark reconciliations: **CONFIRMED** (flows, packets, IP bytes).
- Case 01: 3 real SSH sessions, 107 packets, 18/18 per-stream counters match; no scan/burst.
- Case 02: 17 HTTP requests, 11 SQLi; 28,370 B CSV with identical hash from two tools.
- Case 03: real dnscat2, 445 query/response pairs, 890 packets; dnscat2 Certain from signature.
- Case 04: 46 C2-port attempts; 45 intervals from 46 timestamps (median 56.91 s); 86,263 B upload.
- 41 findings: 21 Certain, 15 Likely, 5 Inferred.

## Honesty note

The synthetic cases are modelled on the attacks described; never describe them as real tool
captures. The real captures are loopback lab exercises, not traffic from a real victim.
