# Automated test results

**Run:** 2026-11-18T21:37Z
**Repository commit tested:** `84e7dcfb472f87d3e74ba757955dd8447e99d17c`
**Environment:** `TZ=UTC`, Zeek 9.0.1 on `PATH=/opt/zeek/bin`, TShark 4.6.9,
Python 3.14.7, `nfdump`/`nfpcapd` 1.7.10-release.

All commands below were actually executed. Output is quoted verbatim from the
captured run. Tests 1, 2 and 5 ran in the main repository and only read files.
Test 3 ran in a disposable clone at `/tmp/opencode/forensics-test`, so no
committed evidence was touched. Test 4 ran in that same clone after Test 3.
No raw pcap and no `supplementary/` file was modified; the clone was discarded
afterwards.

## Summary

| # | Test | Result |
|---|---|---|
| 1 | Sealed-pcap hashes + hash manifest | PASS — 4/4 `OK`, 0 manifest mismatches |
| 2 | Cross-tool reconciliation + README spot checks | PASS — all rows `CONFIRMED`, expected values observed |
| 3 | Full clean-room reproduction from a fresh clone | PASS — all scripts exit 0, all counts `CONFIRMED` |
| 4 | Failure-mode / tamper gate | PASS — corrupted pcap rejected by `sha256sum -c` and `run_zeek.sh` |
| 5 | Syntax, structure, ratings, PDF, independent NetFlow | PASS — see outputs below |
| — | Blind check, real two-VM capture, slide-legibility, rehearsal | NOT TESTABLE BY COMMAND — human-only, see `docs/HUMAN_ONLY_HANDOVER.md` |

## 1. Integrity (main repo, read-only)

```console
$ for f in cases/*/raw/*.sha256; do (cd "$(dirname "$f")" && sha256sum -c "$(basename "$f")"); done
case01.pcap: OK
case02.pcap: OK
case03.pcap: OK
case04.pcap: OK

$ python3 - <<PY (hash manifest verification)
manifest entries: 339
mismatches: 0
```

(The 339-entry count is the state before this report was added. After adding
this file the manifest was regenerated again; see "Final state" at the end.)

## 2. Cross-tool functionality and README spot checks (main repo, read-only)

```console
$ for pair in ...; do python3 tools/verify_counts.py "$c" "$b"; done

### case01_ssh_sessions
### Reconciliation for case01_ssh_sessions

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 3 | 3 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 107 | 107 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 15916 | 15916 | 0 | CONFIRMED |

Sanity: tshark frame bytes 17414 - 14 x 107 packets = 15916 (must equal tshark IP bytes 15916).

### case02_web_sqli
### Reconciliation for case02_web_sqli

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 3 | 3 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 203 | 203 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 105459 | 105459 | 0 | CONFIRMED |

Sanity: tshark frame bytes 108301 - 14 x 203 packets = 105459 (must equal tshark IP bytes 105459).

### case03_dns_tunnel
### Reconciliation for case03_dns_tunnel

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 1 | 1 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 890 | 890 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 104305 | 104305 | 0 | CONFIRMED |

Sanity: tshark frame bytes 116765 - 14 x 890 packets = 104305 (must equal tshark IP bytes 104305).

### case04_c2_beacon
### Reconciliation for case04_c2_beacon

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 52 | 52 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 2032 | 2032 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 849392 | 849392 | 0 | CONFIRMED |

Sanity: tshark frame bytes 877840 - 14 x 2032 packets = 849392 (must equal tshark IP bytes 849392).

$ zeek-cut uid query < cases/case03_dns_tunnel/zeek/tsv/dns.log | head -n 3
Chubce1wik6p4KDZeg	dnscat.87ff03bb73000000005fa2769a17431349604b950c74cf27751cb25e3987.b86d38264bde3c1cbcc94e8bec2d0c05e62443f7938905b7d04b44952a50.9f741f9cf17edcdde4b0ac85f7
Chubce1wik6p4KDZeg	dnscat.bfaa03bb731bd0a9b82c790000532222e2e9256897372d52dcb1e2c7e01c.dd5b47730bea27887f25b55d5e135ccf423fab
Chubce1wik6p4KDZeg	dnscat.947700bb73e8808cf1bcfc000159fc043e6c6d63c156c106ac2d0078337c.fd7d

$ tshark -r cases/case02_web_sqli/raw/case02.pcap -Y 'http.request.method=="POST"' -T fields -e urlencoded-form.key -e urlencoded-form.value
username,password,Login	admin,password,Login

$ sha256sum cases/case02_web_sqli/tshark/http_objects/customers.csv
9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6  cases/case02_web_sqli/tshark/http_objects/customers.csv
```

Expected README values were observed: `dnscat.<hex>` DNS queries, the
`username/password/Login` + `admin/password/Login` POST fields, and the
`9b44747e…ca4c6` customers CSV hash.

## 3. Full clean-room reproduction (disposable clone)

```console
$ git clone ...
Cloning into '/tmp/opencode/forensics-test'...
done.

$ for f in cases/*/raw/*.sha256; do (cd "$(dirname "$f")" && sha256sum -c "$(basename "$f")"); done
case01.pcap: OK
case02.pcap: OK
case03.pcap: OK
case04.pcap: OK
```

`./tools/run_zeek.sh <case> <caseNN>` then `python3 tools/verify_counts.py <case>
<caseNN>` for all four cases; every hash check printed `OK` and every
reconciliation row printed `CONFIRMED` with zero deltas (same values as Test 2):
case01 3/107/15916, case02 3/203/105459, case03 1/890/104305,
case04 52/2032/849392 (flows/packets/IP bytes).

```console
$ ./tools/run_zeek.sh case01_ssh_sessions case01
case01.pcap: OK
--- TSV logs ---
capture_loss.log
conn.log
known_hosts.log
known_services.log
loaded_scripts.log
packet_filter.log
software.log
ssh.log
stats.log
--- JSON logs ---
capture_loss.log
conn.log
known_hosts.log
known_services.log
loaded_scripts.log
packet_filter.log
software.log
ssh.log
stats.log
```

(Equivalent log lists were produced for case02: `conn`, `files`, `http`,
`known_hosts`, `known_services`, `packet_filter`, `software`, `stats`,
`capture_loss`, `loaded_scripts`, plus `extract_files`; case03: `conn`, `dns`,
`known_services`, `notice`, `packet_filter`, `stats`, `capture_loss`,
`loaded_scripts`; case04: `conn`, `known_hosts`, `ssl`, `stats`,
`capture_loss`, `loaded_scripts`, `packet_filter`.)

```console
$ python3 tools/generate_timelines.py
wrote /tmp/opencode/forensics-test/cases/case01_ssh_sessions/viz/case01_ssh_sessions_timeline.png
wrote /tmp/opencode/forensics-test/cases/case02_web_sqli/viz/case02_web_sqli_timeline.png
wrote /tmp/opencode/forensics-test/cases/case03_dns_tunnel/viz/case03_dns_tunnel_timeline.png
wrote /tmp/opencode/forensics-test/cases/case04_c2_beacon/viz/case04_c2_beacon_timeline.png

$ python3 tools/export_flows.py
case01_ssh_sessions: 3 Zeek flows -> flow CSV; 3 tshark streams
case02_web_sqli: 3 Zeek flows -> flow CSV; 3 tshark streams
case03_dns_tunnel: 1 Zeek flows -> flow CSV; 1 tshark streams
case04_c2_beacon: 52 Zeek flows -> flow CSV; 52 tshark streams
wrote report/flows_reconciliation.md

$ python3 tools/make_excerpts.py
wrote cases/case01_ssh_sessions/excerpts/case01_ssh_22.pcap (749b034e7e96...)
wrote cases/case02_web_sqli/excerpts/case02_http.pcap (6a1b9a2e4290...)
wrote cases/case02_web_sqli/excerpts/case02_outfile.pcap (3afe0be55179...)
wrote cases/case02_web_sqli/excerpts/case02_csv_download.pcap (87b87e0fccec...)
wrote cases/case03_dns_tunnel/excerpts/case03_dns_tunnel.pcap (306b5eb9cb01...)
wrote cases/case03_dns_tunnel/excerpts/case03_dnscat_queries.pcap (306b5eb9cb01...)
wrote cases/case04_c2_beacon/excerpts/case04_c2_8443.pcap (def050971690...)
wrote cases/case04_c2_beacon/excerpts/case04_large_upload.pcap (9fff5f3414e8...)
wrote report/excerpts_index.md

$ python3 tools/export_pdf.py
wrote report/FINAL_REPORT.pdf (970989 bytes)
wrote report/PRESENTATION.pdf (38838 bytes)

$ python3 tools/make_appendix.py
wrote report/APPENDIX_A_raw_evidence.md
wrote report/hash_manifest.md (339 files)

$ git status --short
 M cases/case01_ssh_sessions/flows/README.md
 M cases/case01_ssh_sessions/zeek/json/conn.log
 M cases/case01_ssh_sessions/zeek/json/packet_filter.log
 M cases/case01_ssh_sessions/zeek/json/ssh.log
 M cases/case01_ssh_sessions/zeek/json/stats.log
 M cases/case01_ssh_sessions/zeek/tsv/capture_loss.log
 M cases/case01_ssh_sessions/zeek/tsv/conn.log
 M cases/case01_ssh_sessions/zeek/tsv/known_hosts.log
 M cases/case01_ssh_sessions/zeek/tsv/known_services.log
 M cases/case01_ssh_sessions/zeek/tsv/loaded_scripts.log
 M cases/case01_ssh_sessions/zeek/tsv/packet_filter.log
 M cases/case01_ssh_sessions/zeek/tsv/software.log
 M cases/case01_ssh_sessions/zeek/tsv/ssh.log
 M cases/case01_ssh_sessions/zeek/tsv/stats.log
 M cases/case02_web_sqli/flows/README.md
 M cases/case02_web_sqli/zeek/json/conn.log
 M cases/case02_web_sqli/zeek/json/files.log
 M cases/case02_web_sqli/zeek/json/http.log
 M cases/case02_web_sqli/zeek/json/known_hosts.log
 M cases/case02_web_sqli/zeek/json/packet_filter.log
 M cases/case02_web_sqli/zeek/json/stats.log
 M cases/case02_web_sqli/zeek/tsv/capture_loss.log
 M cases/case02_web_sqli/zeek/tsv/conn.log
 M cases/case02_web_sqli/zeek/tsv/files.log
 M cases/case02_web_sqli/zeek/tsv/http.log
 M cases/case02_web_sqli/zeek/tsv/known_hosts.log
 M cases/case02_web_sqli/zeek/tsv/known_services.log
 M cases/case02_web_sqli/zeek/tsv/loaded_scripts.log
 M cases/case02_web_sqli/zeek/tsv/packet_filter.log
 M cases/case02_web_sqli/zeek/tsv/software.log
 M cases/case02_web_sqli/zeek/tsv/stats.log
 M cases/case03_dns_tunnel/flows/README.md
 M cases/case03_dns_tunnel/zeek/json/conn.log
 M cases/case03_dns_tunnel/zeek/json/dns.log
 M cases/case03_dns_tunnel/zeek/json/packet_filter.log
 M cases/case03_dns_tunnel/zeek/json/stats.log
 M cases/case03_dns_tunnel/zeek/tsv/capture_loss.log
 M cases/case03_dns_tunnel/zeek/tsv/conn.log
 M cases/case03_dns_tunnel/zeek/tsv/dns.log
 M cases/case03_dns_tunnel/zeek/tsv/known_services.log
 M cases/case03_dns_tunnel/zeek/tsv/loaded_scripts.log
 M cases/case03_dns_tunnel/zeek/tsv/notice.log
 M cases/case03_dns_tunnel/zeek/tsv/packet_filter.log
 M cases/case03_dns_tunnel/zeek/tsv/stats.log
 M cases/case04_c2_beacon/flows/README.md
 M cases/case04_c2_beacon/zeek/json/conn.log
 M cases/case04_c2_beacon/zeek/json/packet_filter.log
 M cases/case04_c2_beacon/zeek/json/ssl.log
 M cases/case04_c2_beacon/zeek/json/stats.log
 M cases/case04_c2_beacon/zeek/tsv/capture_loss.log
 M cases/case04_c2_beacon/zeek/tsv/conn.log
 M cases/case04_c2_beacon/zeek/tsv/known_hosts.log
 M cases/case04_c2_beacon/zeek/tsv/known_services.log
 M cases/case04_c2_beacon/zeek/tsv/loaded_scripts.log
 M cases/case04_c2_beacon/zeek/tsv/packet_filter.log
 M cases/case04_c2_beacon/zeek/tsv/ssl.log
 M cases/case04_c2_beacon/zeek/tsv/stats.log
 M report/APPENDIX_A_raw_evidence.md
 M report/FINAL_REPORT.pdf
 M report/flows_reconciliation.md
 M report/hash_manifest.md
```

**Interpretation of the clean-room `git status` (important, not a failure):**

- No `cases/*/raw/` or `supplementary/` file appears. Regenerated Zeek logs
  differ from the committed copies in `#open`/`#close` timestamps, connection
  UIDs and similar run-specific fields; the packet/flow/byte counts and all
  findings are unchanged. This is expected Zeek nondeterminism, not evidence
  corruption.
- `report/FINAL_REPORT.pdf`, `report/APPENDIX_A_raw_evidence.md` and
  `report/hash_manifest.md` change because they embed generation time / content
  hashes. That is expected.
- **Known script inconsistency:** `tools/export_flows.py` rewrites
  `report/flows_reconciliation.md` and all four `cases/*/flows/README.md` files
  with the stale text "`nfpcapd`/`nfdump` are not installed", overwriting the
  corrected wording committed in `bbd30ad`. This was confirmed by reading the
  regenerated clone file. The committed main-repo files still have the correct
  wording; the script was not changed in this test round.

## 4. Failure-mode / tamper gate (disposable clone, after Test 3)

```console
$ chmod u+w cases/case01_ssh_sessions/raw/case01.pcap && printf x >> cases/case01_ssh_sessions/raw/case01.pcap

$ (cd cases/case01_ssh_sessions/raw && sha256sum -c case01.pcap.sha256)
case01.pcap: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
[exit 1]

$ ./tools/run_zeek.sh case01_ssh_sessions case01
case01.pcap: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
[exit 1]
```

The integrity gate genuinely blocks a modified pcap. This was done only in the
throwaway clone; the main repository's sealed pcap is untouched.

## 5. Structural checks and independent NetFlow (main repo, read-only)

```console
$ python3 - <<PY (structural checks)
python syntax OK: 11 files
shell syntax OK: 3 files
matrix IDs: 41; missing from FINAL_REPORT: []
matrix ratings: {'Certain': 21, 'Likely': 15, 'Inferred': 5} | report states: 21 Certain, 15 Likely, 5 Inferred
case01_ssh_sessions: timeline rows=12 empty_refs=0; Zeek flows=3 flow CSV rows=3
case02_web_sqli: timeline rows=17 empty_refs=0; Zeek flows=3 flow CSV rows=3
case03_dns_tunnel: timeline rows=18 empty_refs=0; Zeek flows=1 flow CSV rows=1
case04_c2_beacon: timeline rows=14 empty_refs=0; Zeek flows=52 flow CSV rows=52
valid PNGs: 4 (all 3080x2200)
manifest: 339 entries, 0 mismatches
PDF contains F4.7b: True | pages: 17

$ python3 - <<PY (independent netflow sums)
case01_ssh_sessions: nfdump flows=9 packets=107 bytes=15916; Zeek/tshark packets=107 bytes=15916; deltas=0/0
case02_web_sqli: nfdump flows=9 packets=203 bytes=105459; Zeek/tshark packets=203 bytes=105459; deltas=0/0
case03_dns_tunnel: nfdump flows=890 packets=890 bytes=104305; Zeek/tshark packets=890 bytes=104305; deltas=0/0
case04_c2_beacon: nfdump flows=152 packets=2032 bytes=849392; Zeek/tshark packets=2032 bytes=849392; deltas=0/0
```

The PNG check is a **file-level** check only (valid PNG header, 3080 × 2200);
it does not certify slide-size legibility. See `docs/PRESENTATION_CHART_CHECK.md`.

## What this does not prove

These remain human-only and are documented in `docs/HUMAN_ONLY_HANDOVER.md`:
the blind independent reconstruction, the real two-host capture and clock
offsets, visual slide-size legibility of the four PNGs, and the owner
rehearsal. No command output can honestly satisfy those items.

## Final state

After this file was created, `python3 tools/make_appendix.py` was re-run to
include it in the hash manifest. The regenerated manifest contains **340
entries with 0 mismatches**. No PDF source Markdown changed, so the PDFs were
not rebuilt in this final step (they were rebuilt inside the clean-room clone
during Test 3 only). The main-repository working tree contained no changes to
`cases/*/raw/` or `supplementary/`.
