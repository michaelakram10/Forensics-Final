# Methodology — Project 09 Network Session Reconstruction

## 1. Scope and honesty statement

Four captures are analysed. **Two are real lab captures and two are synthetic:**

| Case | Provenance |
|---|---|
| 01 | **Real** isolated-lab capture (loopback `127.0.0.1`, SSH exercise, 2026-11-16) |
| 02 | Synthetic Scapy reconstruction (DVWA-style SQL injection, staged CSV download) |
| 03 | **Real** isolated-lab capture (loopback `127.0.0.1`, dnscat2 DNS tunnel, 2026-11-18) |
| 04 | Synthetic Scapy reconstruction (periodic TLS beaconing on port 8443) |

The full provenance table, including hashes and the loopback caveat, is in `report/data_provenance.md`.
The original synthetic Case 01 and Case 03 reconstructions are preserved, clearly
labelled, under `supplementary/`.

**This was a manual-guided analysis, not a blind one.** The analyst had access to
`project.md` (the exercise manual, which includes the generator scripts and expected
findings) while writing the reports. No claim in this repository that findings were
"frozen before unsealing" or that agreement with ground truth demonstrates blind
accuracy is supported; such language has been removed. Findings are still derived only
from artifacts (pcap bytes, Zeek logs, tshark/tcpdump output), and confidence ratings
follow the rubric in Section 5 — but the analyst was not isolated from the exercise
material. `ground_truth/` is not used as analytic evidence anywhere in the findings.

All addresses are loopback or RFC 1918 / documentation ranges and all domains use
`.test` where synthetic; nothing touched a real network.

## 2. Environment

Recorded automatically in `report/tool_versions.md`:

| Item | Value |
|---|---|
| OS | Kali Linux (user `kali`) |
| Zeek | 9.0.1 (`/opt/zeek/bin/zeek`) |
| tshark / capinfos | 4.6.9 |
| tcpdump | 4.99.6 |
| jq | 1.8.2 |
| Python | 3.14.7 |
| scapy / pandas / matplotlib / numpy | 2.8.0 / 2.3.3 / 3.10.9+dfsg1 / 2.4.6 |
| Time zone for all analysis | UTC (`export TZ=UTC`) |

An independent NetFlow export was attempted but could not be produced: `nfpcapd`,
`nfdump`, `softflowd` and `argus` are not installed, and installation is not possible
in this environment (no passwordless sudo). `pandoc` is also unavailable. Flow exports
are therefore derived from Zeek `conn.log` (Section 4.5) and PDFs are generated with
WeasyPrint (Section 4.7).

## 3. Evidence handling

1. Every pcap was hashed with `tools/seal_evidence.sh`, which writes a `*.pcap.sha256`
   sidecar and makes both files read-only (`chmod 444`).
2. `custody/custody_log.csv` records generation/sealing, the real-capture swap for
   Cases 01 and 03, and each analysis session. The log's hashes match the sidecars.
3. Every script that reads a pcap verifies the hash first (`run_zeek.sh` runs
   `sha256sum -c` and aborts on mismatch). `verify_counts.py` reads the same sealed
   originals with tshark.
4. Analysis writes only into per-case output directories; sealed originals are never
   modified. Focused excerpts (Section 4.6) are convenience copies and are hashed
   separately.

## 4. Exact commands

### 4.1 Zeek (every case)

```bash
export TZ=UTC; export PATH=/opt/zeek/bin:$PATH
./tools/run_zeek.sh case01_ssh_sessions case01
./tools/run_zeek.sh case02_web_sqli       case02
./tools/run_zeek.sh case03_dns_tunnel     case03
./tools/run_zeek.sh case04_c2_beacon      case04
```

`run_zeek.sh` verifies the hash, then runs in the case's `zeek/tsv` and `zeek/json`
directories respectively:

```bash
zeek -C -r caseNN.pcap local frameworks/files/hash-all-files frameworks/files/extract-all-files
zeek -C -r caseNN.pcap LogAscii::use_json=T local
```

`-C` ignores checksum errors; `-r` reads offline. TSV logs are used with `zeek-cut`,
JSON logs with `jq`/pandas. Every query used is recorded in `cases/*/zeek/queries.md`.

### 4.2 Second-tool verification

```bash
./tools/verify_counts.py <case> <caseNN> | tee cases/<case>/report/verify_counts.md
```

Byte definitions are kept distinct: Zeek `orig_bytes`/`resp_bytes` = TCP/UDP payload;
`*_ip_bytes` = IP header + payload; tshark `frame.len` includes the 14-byte Ethernet
header. The identity checked in every case is:

```text
Σ frame.len − 14 × packets = Σ ip.len = Zeek Σ *_ip_bytes
```

Case-specific tshark/tcpdump commands and claim-by-claim tables are in
`cases/*/report/verification.md`; raw output is under `cases/*/tshark/` and `tcpdump/`.

Note: tshark 4.6 prints `tcp.flags.syn`/`ack` as `True`/`False`, not `1`/`0`.

### 4.3 Timeline and visualization

```bash
./tools/build_timeline.py <case>              # Zeek JSON -> cases/<case>/timeline/timeline.csv
python3 ./tools/generate_timelines.py          # matplotlib, 220 dpi, Zeek JSON only
./tools/beacon_stats.py case04_c2_beacon
zeek-cut query < cases/case03_dns_tunnel/zeek/tsv/dns.log | ./tools/dns_stats.py
```

Case 01 and Case 03 timelines were written manually from the Zeek logs because the
generic heuristics in `build_timeline.py` were designed for the old synthetic cases.
Every timeline row has an `evidence_ref` to a log and uid/frame. Mermaid sequence
diagrams are in `report/figures/caseNN.mmd`.

The chart script spreads each connection's bytes evenly across its duration (rather
than attributing them all to the start time), packs overlapping connections into
sub-lanes, uses explicit symlog ticks to avoid overlapping labels, distinguishes
OUTFILE staging from the CSV download in Case 02, and uses a DNS query-rate phase
view for Case 03. All titles read the first-packet time from the data.

### 4.4 Flow-oriented view

```bash
python3 ./tools/export_flows.py
```

Produces `cases/*/flows/caseNN_flows.csv` (one row per Zeek connection, NetFlow-like
columns) plus `report/flows_reconciliation.md`. These are **exports of Zeek conn.log,
not NetFlow exporter records** — `nfpcapd`/`nfdump` are unavailable. Reconciliation
compares flow-CSV row counts with tshark TCP/UDP stream counts.

### 4.5 Focused pcap excerpts

```bash
python3 ./tools/make_excerpts.py
```

Writes filtered pcaps under `cases/*/excerpts/` (e.g. SSH-only, HTTP-only, dnscat DNS,
port 8443), each with a `SHA256SUMS.txt`. Index: `report/excerpts_index.md`.

### 4.6 Exports

```bash
python3 ./tools/export_pdf.py    # report/FINAL_REPORT.pdf, report/PRESENTATION.pdf
```

Uses Python `markdown` + WeasyPrint because `pandoc` is unavailable.

## 5. Confidence-rating method

Ratings follow Section 7.1 of the guide, applied in order:

| Rating | Must satisfy ALL of |
|---|---|
| **Certain** | Directly visible as a field/string with no interpretation beyond protocol semantics; reproduced by a second tool with matching values; no plausible alternative explanation consistent with the artifacts. |
| **Likely** | Strong indicators plus best-single-explanation, but the decisive evidence (payload, intent, host outcome, identity) is not visible. |
| **Inferred** | Drawn from statistics/timing/analogy, an alternative explanation remains plausible, or confirmation would need data absent from the capture. |

Downgrade rules: intent/tool identity/host-side effects are at most Likely (usually
Inferred); encrypted payload content is Inferred at best; a value not independently
reproduced is capped at Likely and marked UNRESOLVED; a claim without an artifact
reference is not a finding; MITRE IDs for inferred techniques are written
"consistent with T####". Observation and interpretation are kept as separate findings.

The ratings in `report/confidence_matrix.md` are the committed ratings. No
"frozen before unsealing" claim is made: the analysis was manual-guided, and no
ground-truth-based accuracy claim is presented as evidence of blindness.

## 6. Limitations

- **No ground-truth console log was kept:** Case 03 burst and session-count
  interpretations rely on traffic patterns only; no terminal scrollback was
  available to convert (VM local +5 h) and compare against 18:27:23 / 18:29:41 UTC.
- **Real captures (Cases 01, 03) are on loopback**: they show a single host talking to
  itself. There is no separate attacker IP or authoritative DNS server in the capture.
- `capinfos` prints the VM's local time (UTC−5); all analysis times are UTC. The two
  differ by exactly 5 hours and refer to the same packets.
- SSH and dnscat2/TLS payloads are encrypted; only sizes, timing and visible handshake
  fields are available. Command names, credentials and tunnel file content are not
  recoverable from these captures.
- The synthetic TLS handshake in Case 04 omits a Certificate message; Zeek 9.0.1 still
  reports `established=T`. This is recorded as a limitation, not proof of validation.
- Case 02's INTO OUTFILE success and cookie validity are inferred from subsequent
  requests, not seen as server-side state.
- No `weird.log` was produced by Zeek 9.0.1 on the synthetic cases; the absence is
  recorded rather than hidden.
- The timeline builder labels the six benign HTTPS sessions in Case 04 "periodic"
  because their inter-arrival variation is small relative to their long mean interval;
  the report treats them as benign based on SNI, port, byte asymmetry and absolute
  irregularity.
