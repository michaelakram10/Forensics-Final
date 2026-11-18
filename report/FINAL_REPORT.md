# Network Session Reconstruction — Forensic Report

**Project 09 — Digital Forensics**
**Date:** 2026-11-18  **Version:** 1.1

| Role | Owner of (files) | Assigned to |
|---|---|---|
| Log/pcap analyst | `custody/custody_log.csv`, `cases/*/tshark/capinfos.txt`, `cases/*/report/pcap_notes.md` | Team member 1 |
| Zeek-log specialist | `cases/*/zeek/{tsv,json}/*`, `cases/*/zeek/queries.md`, `tools/run_zeek.sh` | Team member 2 |
| Cross-tool verification owner | `cases/*/tshark/*`, `cases/*/tcpdump/*`, `tools/verify_counts.py`, `cases/*/report/verification.md` | Team member 3 |
| Timeline builder | `tools/build_timeline.py`, `cases/*/timeline/timeline.csv` | Team member 4 |
| Timeline-visualization author | `tools/generate_timelines.py`, `cases/*/viz/*.png`, `report/figures/*.mmd` | Team member 5 |
| Confidence-rating author | `report/confidence_matrix.md` | Team member 6 |
| Report writer | `cases/*/report/report.md`, this file, `report/methodology.md` | Team member 7 |
| Presenter / evidence custodian | `tools/seal_evidence.sh`, custody log, `report/PRESENTATION.md` | Team member 8 |

*Individual names were not recorded in the lab handover; the table maps each role to its
deliverables so names can be inserted without restructuring the report.*

---

## 1. Executive Summary

**Scope.** Four cases were reconstructed from sealed pcaps with Zeek and independently
cross-checked with tshark and tcpdump. **Two are real lab captures (Cases 01 and 03);
two are Scapy-generated synthetic reconstructions (Cases 02 and 04).** All four
Zeek↔tshark reconciliations are CONFIRMED for flows, packets and IP bytes.

| Case | Provenance | Technique(s) | Target | Data moved | Highest-confidence conclusion | Main limitation |
|---|---|---|---|---|---|---|
| 01 | **Real** loopback SSH capture | SSH sessions; auth-like exchanges (T1110.001 *consistent with*) | `127.0.0.1:22` | 10,304 B payload total; 4,509 B up / 5,795 B down | Exactly 3 completed SSH sessions, identical banners, 18/18 per-stream byte counters match | Encrypted payload; no credentials, commands or host effects; **no scan and no brute-force burst in this capture** |
| 02 | Synthetic | SQL injection, staging, HTTP exfiltration (T1190, T1048.003) | 192.168.56.30:80 | `customers.csv` 28,370 B, sha256 `9b44747e…ca4c6` | 17 HTTP requests, 11 injections, identical file hash from two extraction tools | INTO OUTFILE success and cookie validity inferred |
| 03 | **Real** loopback dnscat2 capture | DNS tunnelling (T1071.004, T1572) | `127.0.0.1:53` | 116,765 frame B; 79,385 L7 B; 8,090 B encoded queries / 8,067 B answers | dnscat2 identified **Certain** from the `dnscat.` signature on all 445 queries | Encrypted payload: structure only, no plaintext or exfiltration quantity |
| 04 | Synthetic | Periodic TLS beaconing on 8443 (T1071.001, T1571/T1573, T1008) | 203.0.113.50 / .51 | 86,263 B upload; 4,219 B tasking response | 46 attempts, ~57 s median interval, same SNI on both IPs, 44 stream byte checks match | Tasking/exfiltration purpose and single-implant identity inferred |

**Confidence totals:** 21 Certain, 14 Likely, 5 Inferred across 40 findings — see
`report/confidence_matrix.md`. Every row carries exactly one rating; observation and
interpretation are separate findings.

**Analysis honesty.** This was a **manual-guided, not blind** exercise: `project.md`
and the exercise material were available to the analyst. No claim that ratings were
"frozen before unsealing" or that agreement with expected values demonstrates blind
accuracy is made. Private generator/ground-truth material is excluded from this
submission; see `report/data_provenance.md` and Appendix F.

**Key limitations:** real captures are on loopback (no distinct attacker/victim IPs);
SSH, dnscat2 and TLS payloads are encrypted; no host evidence; synthetic TLS omits a
Certificate message; `nfpcapd`/`nfdump` and `pandoc` are unavailable (flow CSVs derive
from Zeek `conn.log`; PDFs use WeasyPrint).

---

## 2. Methodology (reproducible)

Full detail: `report/methodology.md`.

### 2.1 Environment

| Item | Value |
|---|---|
| OS | Kali Linux (user `kali`) |
| Zeek | 9.0.1 (`/opt/zeek/bin/zeek`) |
| tshark / capinfos | 4.6.9 |
| tcpdump | 4.99.6 |
| jq | 1.8.2 |
| Python | 3.14.7 |
| scapy / pandas / matplotlib / numpy | 2.8.0 / 2.3.3 / 3.10.9+dfsg1 / 2.4.6 |
| Analysis time zone | UTC (`export TZ=UTC`) |

`report/tool_versions.md` records the raw version output.

### 2.2 Evidence handling

Pcaps were hashed with `tools/seal_evidence.sh` (SHA-256 sidecar, read-only originals).
`run_zeek.sh` re-verifies the hash before every Zeek run. `custody/custody_log.csv`
records generation, the Case 01/03 capture swap, and analysis sessions (Appendix C).

### 2.3 Commands

```bash
export TZ=UTC; export PATH=/opt/zeek/bin:$PATH
./tools/run_zeek.sh <case_dir> <caseNN>                 # Zeek TSV + JSON
python3 tools/verify_counts.py <case_dir> <caseNN>      # Zeek vs tshark
python3 tools/build_timeline.py <case_dir>              # Zeek JSON -> CSV
python3 tools/generate_timelines.py                     # 220-dpi charts
python3 tools/export_flows.py                           # flow CSVs + reconciliation
python3 tools/make_excerpts.py                          # focused pcap excerpts
python3 tools/export_pdf.py                             # this report + slide deck as PDF
```

Byte accounting identity verified in every case:
`Σ frame.len − 14 × packets = Σ ip.len = Zeek Σ *_ip_bytes`.
Exact `zeek-cut`/`jq` queries and observed output: `cases/*/zeek/queries.md`.

### 2.4 Rating method

Certain / Likely / Inferred with downgrade rules are defined in `report/methodology.md`
§5. Mixed ratings were split into separate rows in `report/confidence_matrix.md`.

---

## 3. Case 01 — SSH sessions on loopback (real capture)

### 3.1 Summary

This is a **real 107-packet tcpdump capture** from an isolated lab on loopback
(`127.0.0.1 → 127.0.0.1`). It contains exactly three completed SSH sessions to
`127.0.0.1:22`: one short (0.120797 s) and two long (19.858788 s, 14.196392 s).
Capture span is 34.385135 s, epoch `1794846054.608130` (2026-11-16 16:20:54.608130Z)
→ `1794846088.993265` (16:21:28.993265Z). All sessions present client banner
`SSH-2.0-libssh_0.12.2` ×3 and server banner `SSH-2.0-OpenSSH_10.6p1 Debian-1` ×3,
with identical algorithms and host-key fingerprint `SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn`.
Zeek records 0 / 5 / 5 authentication attempts and `auth_success` unset / `F` / `T`.
**There is no port scan and no 36-attempt brute-force burst** in this file; SSH
payload after key exchange is encrypted, so no credentials, commands or host effects
are observable.

### 3.2 Evidence inventory

| Evidence | Key facts |
|---|---|
| `cases/case01_ssh_bruteforce/raw/case01.pcap` | SHA-256 `771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99`; sidecar `OK`; 107 packets, 17,414 frame bytes, 15,916 IP bytes |
| `zeek/tsv/conn.log`, `zeek/json/conn.log` | 3 rows, all `127.0.0.1:ephemeral → 127.0.0.1:22`, `SF`, service ssh |
| `zeek/tsv/ssh.log`, `software.log` | 3 × libssh_0.12.2 client, 3 × OpenSSH_10.6p1 server; negotiated algorithms; auth heuristic unset/0, F/5, T/5 |
| `tshark/capinfos.txt`, `conv_tcp.txt`, `frame_detail.txt`, `ssh_banners.txt`, `tcp_flags.txt` | 3 streams; banners 3/3; 3 SYN, 3 SYN/ACK, 6 FIN, 0 RST |
| `tshark/stream_bytes_*.txt`, `packet_histogram_long.txt` | 18/18 per-stream counters match; 52→84 B encrypted pair sequences |
| `tcpdump/full_text_dump.txt` | 107 packet lines, UTC |
| `report/verify_counts.md`, `pcap_notes.md`, `verification.md`, `timeline/timeline.csv` | Reconciliation, stage notes, claim table, 12-row evidence-referenced timeline |

### 3.3 Reconstructed timeline (subset)

| UTC | Event | Evidence |
|---|---|---|
| 16:20:54.608130 | Short session SYN; banners .608280/.624584; FIN .723511; 0.120797 s | conn uid `CF3dQ73otQFUMGzMMi` / f1–f25 |
| 16:20:54.939960 | Long session A SYN (0.33183 s after first); identical banners/algorithms | `CPbK9Z6ezH8vbIQn1` / f26–f31 |
| 16:20:55.059953 → 16:21:10.848695 | Six 52→84 B encrypted pairs in long A (1.97–3.95 s gaps) | f46–f62 |
| 16:21:14.795393 → 14.798748 | Long A final 76 B packet and FINs; Zeek `F`/5 | `CPbK9Z6ezH8vbIQn1` / f64–f72 |
| 16:21:14.796806 | Long session B SYN during long A teardown | `CIkYPK3CLHxdbW23vh` / f66 |
| 16:21:14.912492 → 16:21:24.779803 | Five 52→84 B encrypted pairs in long B | f88–f98 |
| 16:21:28.726199 → 28.993265 | Final 92 B client / 28 B server exchange, orderly close; Zeek `T`/5; capture ends | `CIkYPK3CLHxdbW23vh` / f101–f107 |

**Figure 3.1** — Three SSH sessions on loopback, 2026-11-16 (UTC):

![Figure 3.1 — three SSH sessions on loopback](cases/case01_ssh_bruteforce/viz/case01_ssh_bruteforce_timeline.png)

*Short session 34416 closes in
0.121 s; long session A (34430) runs 19.859 s; long session B (54844) starts during
A's TCP teardown and runs 14.196 s. Markers show SYN, plaintext banners, repeated
encrypted 52→84 B exchanges and FINs. No port scan or 36-attempt burst is present;
encrypted SSH content is not depicted.*
**Figure 3.2** — `report/figures/case01.mmd`:
*Case 01 flow reconstruction — one loopback host opens three SSH sessions using a
libssh_0.12.2 client banner; Zeek's heuristic records `auth_success=F` then `T`.*

### 3.4 Findings

Full nine-finding table with justifications: `report/confidence_matrix.md` (F1.1–F1.9).
Certain 5 / Likely 3 / Inferred 1. Headlines: three completed SSH sessions and uniform
banners (Certain); measured long-session sizes/durations (Certain); repeated encrypted
auth-like exchanges and the F/T outcomes (Likely); tool identity, commands and host
effects undeterminable (Inferred). ATT&CK T1110.001 / T1021.004 / T1078 are recorded
as *consistent with*, not proven.

### 3.5 Cross-tool verification

`report/verify_counts.md`: flows 3/3, packets 107/107, IP bytes 15,916/15,916 — all
CONFIRMED. Ethernet identity: **17,414 − 14 × 107 = 15,916**. All 18 per-stream
counters match. Zeek duration deltas of 29/39/67 µs are explained by Zeek ending at
the server FIN versus tshark including the final ACK. Full claim table:
`cases/case01_ssh_bruteforce/report/verification.md`.

### 3.6 Data moved

| Direction | Payload B | IP B | Packets |
|---|---:|---:|---:|
| Client → server | 4,509 | 6,709 | 48 |
| Server → client | 5,795 | 9,207 | 59 |
| Total | 10,304 | 15,916 | 107 |

Per session (client/server payload): 1,227/1,741 B; 1,679/2,077 B; 1,603/1,977 B.
Volumes are small and roughly symmetric; no evidence of bulk transfer.

### 3.7 Limitations

Real lab capture on loopback only; encrypted SSH payload; Zeek auth fields are
analyzer heuristics, not decryption; no endpoint evidence, credentials, usernames,
commands, command output or file contents; tool identity unknown (`libssh` is a
library); short 34.4 s window. Any intent, tool identity or host effect is
Likely/Inferred at most.

---

## 4. Case 02 — SQL injection and database dump exfiltration over HTTP (synthetic)

### 4.1 Summary

On 2026-11-03, a Firefox-UA session logged in with cleartext `admin/password`, then a
sqlmap-UA session made 11 injections (13:21:35–13:21:42Z) enumerating the schema, five
password hashes and staging `/var/www/html/dump/customers.csv`; a curl-UA session
downloaded it at 13:22:12.874Z (28,370 B, 501 lines).

### 4.2 Evidence inventory

| File | SHA-256 / note |
|---|---|
| `raw/case02.pcap` | `e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9` (203 packets) |
| `tshark/http_objects/customers.csv` | SHA-256 `9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6`, MD5 `98e5d93bc6b74b21df42629bb7b03dfe` |
| Zeek extracted file | identical SHA-256 |

### 4.3 Reconstructed timeline

`cases/case02_web_sqli/timeline/timeline.csv` (17 rows). Key events: 13:20:04.205 login
POST; 13:21:35.455 first injection; 13:21:38.240 ORDER BY 3 error; 13:21:41.321 users
dump; 13:21:42.067 INTO OUTFILE; 13:22:12.874 CSV download.

**Figure 4.1** — SQLi and CSV exfiltration timeline (UTC). The OUTFILE staging request
and the later customers.csv download are labelled separately:

![Figure 4.1 — SQL injection and CSV exfiltration](cases/case02_web_sqli/viz/case02_web_sqli_timeline.png)

**Figure 4.2** — `report/figures/case02.mmd`.

### 4.4 Findings

F2.1–F2.10 in `report/confidence_matrix.md` (F2.7 split into 7a observation / 7b use):
6 Certain, 5 Likely, 0 Inferred. ATT&CK T1190, T1078.001, T1074.001 (Likely),
T1048.003, T1213 *consistent with*.

### 4.5 Cross-tool verification

All quantitative claims CONFIRMED; MIME type `text/plain` (Zeek sniff) vs `text/csv`
(HTTP header) is DISCREPANT-EXPLAINED. Reconciliation: 3/3 flows, 203/203 packets,
105459/105459 IP bytes.

### 4.6 Data moved

`customers.csv`, 28,370 B, 501 lines, fields `id,first_name,last_name,email,phone,card_last4`,
synthetic data; identical hashes from Zeek and tshark extraction.

### 4.7 Limitations

No server-side evidence; User-Agent spoofable; cleartext only.

---

## 5. Case 03 — dnscat2 DNS tunneling on loopback (real capture)

### 5.1 Summary

Every query name in this real capture begins with the `dnscat.` signature and contains
only hex labels — a direct identification of dnscat2 (Certain). Records are mixed
CNAME (164), MX (150) and TXT (131) across 445 unique names (41–240 chars, mean
43.398, median 41; two 240-char maxima at frames 281/283). Record-type rotation (274
transitions) and a ~1 s cadence component (160/444 intervals) are consistent with an
automated tunneling client. First-label bytes show two session markers, `0xbb73` (263
queries) and `0x9658` (182 queries), overlapping across frames 241–803 — likely two
concurrent logical channels. A short maximum-length-name burst at 18:27:31Z suggests
a batched data flush. The capture ends immediately after the final query/response pair,
with no distinguishable teardown.

### 5.2 Evidence inventory

| Evidence | Key facts |
|---|---|
| `raw/case03.pcap` | SHA-256 `e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb`, 131,029 B, 890 packets |
| `zeek/tsv/dns.log`, `conn.log` | 445 queries + 445 responses; 1 UDP flow `Chubce1wik6p4KDZeg`, 298.506573 s |
| `tshark/dns_queries.tsv`, `dns_answers.tsv`, `dns_stats.txt` | qtype counts, lengths, timestamps |
| `report/decode_dnscat2.py`, `tshark/dnscat2_extract.txt` | 8,090 B encoded queries / 8,067 B answers; structural markers |
| `timeline/timeline.csv` | 16 evidence-referenced events |

### 5.3 Reconstructed timeline (subset)

`cases/case03_dns_tunnel/timeline/timeline.csv` includes first query/response
(18:25:25.008/.144Z, RTT 0.137 s), first CNAME (frame 19), the second marker from
frame 241 (18:27:23Z), the large-name burst at frames 281/283/285 (18:27:31Z), and
the final pair frames 889/890 (18:30:23.513/.514Z). Full timestamps and evidence refs
are in the CSV.

**Figure 5.1** — 445 query/response pairs over a single loopback UDP flow, 18:25:25–18:30:23 UTC (298.5 s):

![Figure 5.1 — dnscat2 DNS tunnel timeline](cases/case03_dns_tunnel/viz/case03_dns_tunnel_timeline.png)

*Payload encrypted — structure, sizing and timing only.*
**Figure 5.2** — `report/figures/case03.mmd`:
*dnscat2 tunnel sequence (single loopback UDP flow; UTC). Payload encrypted — structure only.*

### 5.4 Findings

F3.1–F3.9 (with F3.4 split into observation 4a and interpretation 4b) in
`report/confidence_matrix.md`: Certain 5 / Likely 3 / Inferred 2. Tool identity is
Certain from the `dnscat.` signature, not from generic traffic statistics.
ATT&CK T1071.004, T1572, T1573/T1027, T1048.

### 5.5 Cross-tool verification

Zeek 9.0.1 and TShark 4.6.9 agree exactly: 1/1 flows, 890/890 packets,
104,305/104,305 IP bytes (delta 0); 116,765 frame bytes − 14×890 = 104,305. Exactly
**two** tools were used for measurement; tcpdump only rendered a readable dump. The
13:25–13:30 rendering seen without `TZ=UTC` is VM-local UTC−5 for the same instants;
all reported times are UTC.

### 5.6 Data moved

116,765 frame bytes; 104,305 IP bytes; 79,385 L7 bytes (27,322 out / 52,063 in).
Encoded tunnel frames: 8,090 bytes from query labels and 8,067 from answers.
Payload is encrypted with a pre-shared key not in the capture: only framing, sizing
and timing are recoverable — no plaintext, file, command or exfiltration quantity can
be attributed.

### 5.7 Limitations

Loopback-only capture (no real client/server IPs, no host evidence, authoritative
server not separately visible); UTC vs VM-local time distinction; encrypted dnscat2
payload; no legitimate DNS baseline in this single-flow capture. Old synthetic-case
claims (base32, 14,000-byte secret, `exfil-lab.test`, 202 queries) do not apply.

---

## 6. Case 04 — Periodic TLS beaconing on a non-standard port (synthetic)

### 6.1 Summary

Between 14:00:00Z and 14:43:11Z, 192.168.56.40 made 46 attempts to port 8443: 20
answered to 203.0.113.50, two unanswered, then 24 to 203.0.113.51. All 44 completed
TLS sessions use TLS 1.2, cipher `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and SNI
`updates.cdn-lab.test`. Outliers: 4,219 B down then 2,302 B up 6 s later (beacon 8),
and 86,263 B up at 14:31:37Z. Six HTTPS sessions to 198.51.100.20 use a different SNI.

### 6.2 Evidence inventory

| File | Note |
|---|---|
| `raw/case04.pcap` | SHA-256 `eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675`, 2032 packets |
| `zeek/tsv/{conn,ssl}.log` | 52 / 50 rows |
| `tshark/beacon_stats.txt`, `c2_syn_times.txt`, `client_bytes_*.txt` | interval and byte checks |

### 6.3 Reconstructed timeline and timing

`cases/case04_c2_beacon/timeline/timeline.csv` (14 rows). Beacon statistics
(`tools/beacon_stats.py`):

| Group | n | mean | median | stdev | CV | MAD | S0 | med orig B | med resp B |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| .50:8443 | 22 | 57.9 | 56.6 | 13.2 | 0.23 | 3.5 | 2 | 578 | 227 |
| .51:8443 | 24 | 57.7 | 57.1 | 4.9 | 0.09 | 2.4 | 0 | 594 | 227 |
| benign :443 | 6 | 506.3 | 465.6 | 157.6 | 0.31 | 20.7 | 0 | 793 | 99855 |

**45 intervals computed from 46 first-SYN timestamps**: mean 57.58 s, median 56.91 s,
min 6.00 s, max 71.37 s. The 6.00 s minimum is the follow-up session to beacon 8,
not a beacon period; excluding it gives n=44, mean 58.75 s, median 57.02 s, min 49.02 s.

**Figure 6.1** — TLS beaconing timeline (UTC), with the 6 s follow-up and the 86,263 B upload visible:

![Figure 6.1 — TLS beaconing timeline](cases/case04_c2_beacon/viz/case04_c2_beacon_timeline.png)

**Figure 6.2** — `report/figures/case04.mmd`

### 6.4 Findings

F4.1–F4.8 in `report/confidence_matrix.md`, with F4.2 and F4.7 split into separate
observation/interpretation rows: 5 Certain, 3 Likely, 2 Inferred. ATT&CK T1071.001,
T1571/T1573, T1008 (Likely), T1041 (volume Certain / purpose Inferred), T1029 and
T1105 *consistent with*.

### 6.5 Cross-tool verification

7 CONFIRMED claims; all three reconciliation rows CONFIRMED (52/52 flows,
2032/2032 packets, 849392/849392 IP bytes). Per-stream client bytes match for all
44 streams.

### 6.6 Data moved

Typical beacon 578–594 B up / 227 B down; outliers 4,219 B down, 2,302 B up,
86,263 B up. TLS payload unreadable.

### 6.7 Limitations

Encrypted payload; synthetic TLS without Certificate (Zeek 9.0.1 still reports
`established=T`); primary CV inflated by the follow-up and outage; no host evidence.

---

## 7. Consolidated Confidence Matrix

| Case | Certain | Likely | Inferred | Total |
|---|---:|---:|---:|---:|
| 01 (real) | 5 | 3 | 1 | 9 |
| 02 (synthetic) | 6 | 5 | 0 | 11 |
| 03 (real) | 5 | 3 | 2 | 10 |
| 04 (synthetic) | 5 | 3 | 2 | 10 |
| **Total** | **21** | **14** | **5** | **40** |

Full justifications: `report/confidence_matrix.md`; rubric: `report/methodology.md` §5.
No "frozen before unsealing" claim is made — see Appendix F.

---

## 8. Cross-Case Lessons

1. **What the second tool added:** tshark recovered cleartext POST credentials (Case 02),
   independently verified the dnscat2 DNS fields (Case 03), and supplied per-stream byte
   totals and packet-size details that Zeek reports only in aggregate (Cases 01/04).
2. **Field-definition differences:** the recurring Zeek↔tshark byte delta was exactly
   14 B per frame (Ethernet header); Zeek MIME sniffing vs HTTP `Content-Type`, and
   tshark 4.6 boolean flag fields, were the other explained differences.
3. **What the network alone cannot support:** encrypted payload content, command names,
   credential validity, tool identity, INTO OUTFILE write success, purpose of large
   uploads, and host-side effects. These remain Likely or Inferred even where expected.
4. **Real vs synthetic matters:** the real Case 01 capture contains no port scan or
   brute-force burst; the real Case 03 capture is dnscat2 with an encrypted payload, not
   a decodable base32 file. Reports were rewritten to match the evidence actually present.

---

## Appendix A — Raw Evidence Preserved

Verbatim `capinfos` outputs and `head -n 28` / `tail -n 12` excerpts of cited Zeek logs:
**`report/APPENDIX_A_raw_evidence.md`**. Full outputs live under
`cases/*/{tshark,tcpdump,zeek/{tsv,json}}/`.

## Appendix B — Hash Manifest

`report/hash_manifest.md` — SHA-256 of project files. It excludes only the manifest
itself and Python bytecode caches; all other files, including `.gitignore`, root docs,
excerpts, flow CSVs and the appendix, are listed. Scope is stated in the manifest header.

## Appendix C — Chain of Custody

`custody/custody_log.csv` (10 entries):

```csv
utc_time,user,host,case,action,pcap_sha256
2026-11-18T19:06:05Z,kali,kali,case01,"generated and sealed by Presenter",09e1de1777d611debc7bbee5cbb63478c5a6c7a5aec04edccc086bcbc90b6d8e
2026-11-18T19:06:05Z,kali,kali,case02,"generated and sealed by Presenter",e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9
2026-11-18T19:06:05Z,kali,kali,case03,"generated and sealed by Presenter",00dbcc9650c4f4a85e7296b5a26127d0f35763db1eaddc5b488ed47b45e6908c
2026-11-18T19:06:05Z,kali,kali,case04,"generated and sealed by Presenter",eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675
2026-11-18T19:12:04Z,kali,kali,case01,"Zeek + tshark + tcpdump analysis session",09e1de1777d611debc7bbee5cbb63478c5a6c7a5aec04edccc086bcbc90b6d8e
2026-11-18T19:12:04Z,kali,kali,case02,"Zeek + tshark + tcpdump analysis session",e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9
2026-11-18T19:12:04Z,kali,kali,case03,"Zeek + tshark + tcpdump analysis session",00dbcc9650c4f4a85e7296b5a26127d0f35763db1eaddc5b488ed47b45e6908c
2026-11-18T19:12:04Z,kali,kali,case04,"Zeek + tshark + tcpdump analysis session",eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675
2026-11-18T19:29:12Z,kali,kali,case01,"replaced synthetic with real loopback SSH lab capture",771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99
2026-11-18T19:29:12Z,kali,kali,case03,"replaced synthetic with real loopback dnscat2 capture",e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb
```

The first eight entries refer to the original synthetic captures; Cases 01 and 03 were
subsequently replaced, and the superseded reconstructions are preserved under
`supplementary/`.

## Appendix D — Scripts

`tools/run_zeek.sh`, `seal_evidence.sh`, `custody.sh`, `verify_counts.py`,
`dns_stats.py`, `decode_dns_tunnel.py`, `beacon_stats.py`, `build_timeline.py`,
`generate_timelines.py`, `export_flows.py`, `make_excerpts.py`, `export_pdf.py`,
`make_appendix.py`;
case-local `cases/case03_dns_tunnel/report/decode_dnscat2.py`. Presenter-side generator
scripts are excluded from this public submission (see Appendix F).

## Appendix E — Derived views

- Timelines: `cases/*/timeline/timeline.csv` — 12 / 17 / 16 / 14 events for Cases 01–04,
  each with an `evidence_ref` to a log uid or frame.
- Charts: `cases/*/viz/*_timeline.png`; sequence diagrams: `report/figures/case01.mmd` …
  `case04.mmd`.
- Flow exports: `cases/*/flows/caseNN_flows.csv` + `report/flows_reconciliation.md`
  (Zeek `conn.log`-derived, not NetFlow exporter records).
- Focused pcap excerpts: `cases/*/excerpts/*.pcap` + `SHA256SUMS.txt`, indexed in
  `report/excerpts_index.md`.
- Slide deck: `report/PRESENTATION.md` / `.pdf`.

## Appendix F — Data provenance and analysis honesty

`report/data_provenance.md` is the authoritative provenance table: Cases 01 and 03 are
**real loopback lab captures**; Cases 02 and 04 are **synthetic Scapy reconstructions**;
the superseded synthetic Case 01/03 material is in `supplementary/` and is clearly
labelled.

**This analysis was manual-guided, not blind.** `project.md`, `lab/` and
`ground_truth/` were available during the exercise and are therefore **excluded from
the public submission repository**. No claim that confidence ratings were frozen
before ground truth was available, or that agreement with expected values proves blind
accuracy, is made. Findings are derived from pcap/Zeek/tshark artifacts and rated under
the rubric in `report/methodology.md` §5; the ratings in `report/confidence_matrix.md`
are the committed ratings and no separate "accuracy after unsealing" score is claimed.
