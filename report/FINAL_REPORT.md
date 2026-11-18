# Network Session Reconstruction — Forensic Report

**Project 09 — Digital Forensics**
**Date:** 2026-11-18  **Version:** 1.2

| Role | Owner of (files) | Assigned to |
|---|---|---|
| Evidence custody, pcap analysis & presentation | custody log, `seal_evidence.sh`, `capinfos.txt`, `pcap_notes.md`, `PRESENTATION.md` | Michael Akram |
| Zeek analysis & cross-tool verification | `zeek/*`, `run_zeek.sh`, `tshark/*`, `tcpdump/*`, `verify_counts.py`, `verification.md` | Yousef Basem |
| Timeline construction & visualization | `build_timeline.py`, `generate_timelines.py`, `timeline.csv`, `viz/*.png`, `figures/*.mmd` | Mahgoub Hany |
| Confidence ratings & methodology | `confidence_matrix.md`, `methodology.md` | Mohamed Mohamed Fawzy |
| Report writing & data provenance | case `report/report.md`, this file, `data_provenance.md`, appendices | Yasser Yasser Mahmmoud |

*Five named contributors were supplied; the original eight role labels are grouped into
these five ownership areas. No separate assignee was recorded for sub-tasks not named
under a person.*

---

## 1. Executive Summary

**Scope.** Four cases were reconstructed from sealed pcaps with Zeek and independently
cross-checked with tshark and tcpdump. **Two are real lab captures (Cases 01 and 03);
two are Scapy-generated synthetic reconstructions (Cases 02 and 04).** All four
Zeek↔tshark reconciliations are CONFIRMED for flows, packets and IP bytes.

| Case | Provenance | Technique(s) | Target | Data moved | Highest-confidence conclusion | Main limitation |
|---|---|---|---|---|---|---|
| 01 | **Real** loopback SSH capture | SSH sessions; auth-like exchanges (T1110.001 *consistent with*) | `127.0.0.1:22` | 10,304 B payload total; 4,509 B up / 5,795 B down | Exactly 3 completed SSH sessions, identical banners, 18/18 per-stream byte counters match | Encrypted payload; no credentials, commands or host effects; **no scan and no burst of many short sessions in this capture** |
| 02 | Synthetic | SQL injection, staging, HTTP exfiltration (T1190, T1048.003) | 192.168.56.30:80 | `customers.csv` 28,370 B, sha256 `9b44747e…ca4c6` | 17 HTTP requests, 11 injections, identical file hash from two extraction tools | INTO OUTFILE success and cookie validity inferred |
| 03 | **Real** loopback dnscat2 capture | DNS tunnelling (T1071.004, T1572) | `127.0.0.1:53` | 116,765 frame B; 79,385 L7 B; 8,090 B encoded queries / 8,067 B answers | dnscat2 identified **Certain** from the `dnscat.` signature on all 445 queries | Encrypted payload: structure only, no plaintext or exfiltration quantity |
| 04 | Synthetic | Periodic TLS beaconing on 8443 (T1071.001, T1571/T1573, T1008) | 203.0.113.50 / .51 | 86,263 B upload; 4,219 B tasking response | 46 attempts, ~57 s median interval, same SNI on both IPs, 44 stream byte checks match | Tasking/exfiltration purpose and single-implant identity inferred |

**Confidence totals:** 21 Certain, 15 Likely, 5 Inferred across 41 findings — see
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
**There is no port scan and no burst of many short sessions** in this file; SSH
payload after key exchange is encrypted, so no credentials, commands or host effects
are observable.

### 3.2 Evidence inventory

| Evidence | Key facts |
|---|---|
| `cases/case01_ssh_sessions/raw/case01.pcap` | SHA-256 `771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99`; sidecar `OK`; 107 packets, 17,414 frame bytes, 15,916 IP bytes |
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

![Figure 3.1 — three SSH sessions on loopback](cases/case01_ssh_sessions/viz/case01_ssh_sessions_timeline.png)

*Short session 34416 closes in
0.121 s; long session A (34430) runs 19.859 s; long session B (54844) starts during
A's TCP teardown and runs 14.196 s. Markers show SYN, plaintext banners, repeated
encrypted 52→84 B exchanges and FINs. No port scan or burst of many short sessions is present;
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


| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F1.1 | Three completed TCP SSH sessions from loopback to `127.0.0.1:22`; all `SF`, 107 frames, 15,916 IP bytes | n/a | **Certain** | `conn.log` 3 rows; `tshark/conv_tcp.txt`; `report/verify_counts.md` | Addresses, ports, states and counts directly visible and reproduced by both tools (3/3 flows, 107/107 packets, 15,916/15,916 IP bytes). |
| F1.2 | Identical plaintext banners in all sessions: client `SSH-2.0-libssh_0.12.2` ×3, server `SSH-2.0-OpenSSH_10.6p1 Debian-1` ×3; same algorithms and host key `SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn` | n/a | **Certain** | `ssh.log`, `software.log`, `tshark/ssh_banners.txt` | Banners/algorithms are cleartext and identical in Zeek and tshark. |
| F1.3 | Short session (client port 34416): 0.120797 s, 13/12 pkts, 1,227/1,741 B payload, one encrypted exchange then client FIN; Zeek `auth_attempts=0`, `auth_success` unset | n/a | **Certain** | `conn.log` uid `CF3dQ73otQFUMGzMMi`, `ssh.log`, frames 1–25 | Timing, counters and logged heuristic values are measured; payload not interpreted. |
| F1.4 | Two long sessions (34430, 54844): 19.858788 / 14.196392 s, 18/24 and 17/23 pkts, 1,679/2,077 and 1,603/1,977 B payload | n/a | **Certain** | `conn.log`, `tshark/stream_bytes_diff.txt`, `packet_histogram_long.txt` | Sizes and durations measured and cross-tool identical (18/18 per-stream counters match). |
| F1.5 | Both long sessions contain repeated encrypted authentication-like exchanges; Zeek records `auth_attempts=5` for each | T1110.001 *(consistent with)* | **Likely** | `ssh.log` 5/5; tshark 52→84 B pairs (6 and 5) | Zeek's counter is a heuristic over encrypted packets; pairs do not map 1:1. Not a burst of many short sessions. |
| F1.6 | First long session ends with `auth_success=F` and client FIN after a final 76 B server packet — consistent with failed authentication | T1110.001 *(consistent with)* | **Likely** | `ssh.log` uid `CPbK9Z6ezH8vbIQn1`; frames 64, 65, 71 | Failure indication is heuristic + teardown; encrypted payload cannot confirm the reason. |
| F1.7 | Second long session ends with `auth_success=T`, final 92 B client / 28 B server exchange and orderly FINs — consistent with successful SSH login | T1021.004, T1078 *(consistent with)* | **Likely** | `ssh.log` uid `CIkYPK3CLHxdbW23vh`; frames 101–107 | Strong metadata/heuristic indicators; no credential, user or host-side evidence. |
| F1.8 | Specific automation tool, credentials, command names and host effects cannot be determined; `libssh` is a library, not a tool identity | n/a | **Inferred** | `ssh.log` banners; `tcpdump/full_text_dump.txt` encrypted records | Only the library banner is visible; naming a tool or decrypting commands exceeds the artifacts. |
| F1.9 | No port scan, no RSTs, no non-22 destination and no burst of many short sessions in this capture | n/a | **Certain** | 3 `conn.log` rows, all `SF`; `tshark/tcp_flags.txt` 0 RST / 3 client SYNs | The 107-frame file is complete; no such burst is present. |

### 3.5 Cross-tool verification

`report/verify_counts.md`: flows 3/3, packets 107/107, IP bytes 15,916/15,916 — all
CONFIRMED. Ethernet identity: **17,414 − 14 × 107 = 15,916**. All 18 per-stream
counters match. Zeek duration deltas of 29/39/67 µs are explained by Zeek ending at
the server FIN versus tshark including the final ACK. Full claim table:
`cases/case01_ssh_sessions/report/verification.md`.

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


| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F2.1 | Target is 192.168.56.30:80, Apache/2.4.58 (Debian) | T1190 | **Certain** | Cleartext `Server:` header; `conn.log` service=http | Header visible in Zeek HTTP metadata and tshark. |
| F2.2 | Credentials `admin` / `password` sent in cleartext to /login.php | T1078.001 | **Certain** | tshark `urlencoded-form.key/value` → `username,password,Login` = `admin,password,Login`; Zeek `request_body_len=44` | Body content visible in tshark; Zeek independently confirms the 44-byte body. |
| F2.3 | The login succeeded and a session cookie was issued | T1078.001 | **Likely** | 302 to index.php with Set-Cookie PHPSESSID/security=low; 15 later requests carry the cookie | Redirect + reuse strongly imply success; server-side state is not visible. |
| F2.4 | The `id` parameter of /vulnerabilities/sqli/ was injected 11 times | T1190 | **Certain** | 11 decoded URIs in `http.log` (depths 1–11); tshark count of URIs containing `%27` = 11 | Payload strings are cleartext and reproduced by both tools. |
| F2.5 | The injection worked: SQL syntax error, extra rows and differentiated ORDER BY responses | T1190 | **Certain** | response bodies 4095–4345 B; ORDER BY 3 (3979 B) differs from ORDER BY 2 (3978 B); error text in cleartext responses | Response content visible in the artifacts. |
| F2.6 | The attacker determined the column count is 2 | T1190 | **Likely** | ORDER BY 2 normal, ORDER BY 3 error, UNION SELECT 1,2 succeeds | Responses observed; the inference about attacker knowledge is an interpretation. |
| F2.7a | Schema names and five password hashes were returned to the attacker | T1213 *(consistent with)* | **Certain** | 4345 B response to `UNION SELECT user,password FROM users`; 4121/4241 B information_schema responses | Response bodies contain the data in cleartext. |
| F2.7b | That returned data was actually used by the attacker | T1213 *(consistent with)* | **Likely** | Subsequent enumeration and staged dump requests | Sequence is suggestive; no host-side evidence of use. |
| F2.8 | An automated tool consistent with sqlmap was in use | n/a | **Likely** | `User-Agent: sqlmap/1.7.11#stable (https://sqlmap.org)`; 0.4–0.9 s cadence | UA can be forged; timing is consistent but not conclusive. |
| F2.9 | A dump file was written to the web root via INTO OUTFILE | T1074.001 | **Likely** | URI contains `INTO OUTFILE '/var/www/html/dump/customers.csv'`; 30 s later GET of that path returns 200 | Write success is not directly visible; availability strongly implies it. |
| F2.10 | customers.csv (28,370 B, 500 rows + header) was downloaded by 192.168.56.10 | T1048.003 | **Certain** | `http.log`, `files.log`, Zeek extraction and tshark HTTP export; both SHA-256 = `9b44747e…ca4c6`, MD5 = `98e5d93b…3dfe` | File reassembled by two tools with identical hashes; 501 lines counted. |

### 4.5 Cross-tool verification

All quantitative claims CONFIRMED; MIME type `text/plain` (Zeek sniff) vs `text/csv`
(HTTP header) is DISCREPANT-EXPLAINED. Reconciliation: 3/3 flows, 203/203 packets,
105459/105459 IP bytes.

### 4.6 Data moved

`customers.csv`, 28,370 B, 501 lines, fields `id,first_name,last_name,email,phone,card_last4`,
synthetic data; identical hashes from Zeek and tshark extraction.

### 4.7 Limitations

No server-side evidence: cookie validity, `INTO OUTFILE` write success and actual
use of the returned schema/password data are inferred from subsequent requests,
not observed state. The sqlmap User-Agent is spoofable and the 0.4–0.9 s cadence
is consistent with automation but not conclusive. HTTP content is cleartext, so
most measurements are Certain, but intent and tool identity are not. This is a
synthetic Scapy reconstruction with no endpoint/disk/process evidence; no
`weird.log` was produced by Zeek 9.0.1 on this synthetic case. The analysis was
manual-guided, not blind; no "frozen before unsealing" claim is made.

---

## 5. Case 03 — dnscat2 DNS tunneling on loopback (real capture)

### 5.1 Summary

Every query name in this real capture begins with the `dnscat.` signature and contains
only hex labels — a direct identification of dnscat2 (Certain). Records are mixed
CNAME (164), MX (150) and TXT (131) across 445 unique names (41–240 chars, mean
43.398, median 41; two 240-char maxima at frames 281/283). Record-type rotation (274
transitions) and a ≈1 query/s per-session cadence component (160/444 intervals near
1 s) are consistent with an automated tunneling client. Tool identity is taken from the
**first DNS label `dnscat`** (direct-mode signature), not the last two labels. The
typical query name is 41 characters; the 240-character names occur only in short bursts.
First-label bytes show two session markers, `0xbb73` (263 queries) and `0x9658` (182
queries), overlapping across frames 241–803 — likely two concurrent logical channels. A short maximum-length-name burst at 18:27:31Z suggests
a batched data flush. The capture ends immediately after the final query/response pair,
with no distinguishable teardown.

### 5.2 Evidence inventory

| Evidence | Key facts |
|---|---|
| `raw/case03.pcap` | SHA-256 `e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb`, 131,029 B, 890 packets |
| `zeek/tsv/dns.log`, `conn.log` | 445 queries + 445 responses; 1 UDP flow `Chubce1wik6p4KDZeg`, 298.506573 s |
| `tshark/dns_queries.tsv`, `dns_answers.tsv`, `dns_stats.txt` | qtype counts, lengths, timestamps |
| `report/decode_dnscat2.py`, `tshark/dnscat2_extract.txt` | 8,090 B encoded queries / 8,067 B answers; structural markers |
| `timeline/timeline.csv` | 18 evidence-referenced events |

### 5.3 Reconstructed timeline (subset)

`cases/case03_dns_tunnel/timeline/timeline.csv` includes first query/response
(18:25:25.008/.144Z, RTT 0.137 s), first CNAME (frame 19), the second marker from
frame 241 (18:27:23Z), the large-name burst at frames 281/283/285 (18:27:31Z), and
the final pair frames 889/890 (18:30:23.513/.514Z). Full timestamps and evidence refs
are in the CSV.

**Polling-rate phases** (from Zeek `dns.log`; phase boundaries at t = 118.8 s and 256.0 s):

| Phase | Window (s since first query) | UTC | Queries | Rate | Reading |
|---|---|---|---:|---:|---|
| 1 | 0.0 – 118.8 | 18:25:25 → 18:27:23 | 120 | 1.01 /s | one session polling |
| 2 | 118.8 – 256.0 | 18:27:23 → 18:29:41 | 282 | 2.06 /s | two sessions polling; second handshake at t = 118.81 s |
| 3 | 256.0 – 298.5 | 18:29:41 → 18:30:23 | 43 | 1.01 /s | back to one session |

**Figure 5.1** — 445 query/response pairs over a single loopback UDP flow, 18:25:25–18:30:23 UTC (298.5 s):

![Figure 5.1 — dnscat2 DNS tunnel timeline](cases/case03_dns_tunnel/viz/case03_dns_tunnel_timeline.png)

*Payload encrypted — structure, sizing and timing only.*
**Figure 5.2** — `report/figures/case03.mmd`:
*dnscat2 tunnel sequence (single loopback UDP flow; UTC). Payload encrypted — structure only.*

### 5.4 Findings

F3.1–F3.10 (with F3.4 split into observation 4a and interpretation 4b) in
`report/confidence_matrix.md`: Certain 5 / Likely 4 / Inferred 2. F3.10 rates the
one → two → one session interpretation **Likely** from the measured polling-rate
doubling and the second session marker. Tool identity is Certain from the first-label
`dnscat.` signature, not from generic traffic statistics.
ATT&CK T1071.004, T1572, T1573/T1027, T1048.


| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F3.1 | dnscat2 C2 tool identified from the `dnscat.` protocol signature | T1071.004, T1572 | **Certain** | 445/445 Zeek `dns.log` queries begin `dnscat.`; `tshark -e dns.qry.name`; `report/decode_dnscat2.py` (0 non-hex labels) | Direct signature match in every query is stronger than generic statistics, which only support the finding. |
| F3.2 | One persistent loopback UDP flow (127.0.0.1:44651→127.0.0.1:53) for 298.506573 s | T1071.004 | **Certain** | Zeek `conn.log` uid `Chubce1wik6p4KDZeg`, 445/445 pkts, duration 298.506573; tshark `udp.stream`=0 only | Directly measured by both tools with zero deltas. |
| F3.3 | Covert channel carried in CNAME/MX/TXT records with hex labels | T1572 | **Certain** | qtypes CNAME 164 / MX 150 / TXT 131 (Zeek and tshark agree); 445 unique names; name length 41–240 | Unusual RR types plus hex-only labels observed directly; 274 type transitions show mixed rotation. |
| F3.4a | Two distinct session-marker byte values present in first labels | T1572 | **Certain** | `decode_dnscat2.py`: bytes[3:5] `0xbb73`×263 (frames 1–803), `0x9658`×182 (frames 241–889) | Direct byte-level measurement from tshark-derived extraction. |
| F3.4b | Overlapping markers suggest two concurrent logical channels | T1572 | **Likely** | Same markers coexist across frames 241–803 | Interpretation of F3.4a; encryption prevents confirming two independent sessions. |
| F3.5 | Regular automated beaconing cadence | T1071.004 | **Likely** | 445 queries / 298.5 s ≈1.49/s; intervals mean 0.672 s, median 0.554 s; 160/444 in 0.9–1.1 s | Machine-like periodicity consistent with an automated tunnel client, not a direct artifact. |
| F3.6 | Maximum-length name burst suggests batched data flush | T1048 | **Likely** | Frames 281/283 = 240-char names (115 bytes), frame 285 = 181 chars, all within ~104 ms at 18:27:31Z | Size spike consistent with data/key-exchange-sized messages; content unconfirmable. |
| F3.7 | Encrypted dnscat2 payload; only structure recoverable | T1573, T1027 | **Certain** | Structured framing (varying nonce bytes, byte[2]=0x01×439, two session markers); no key in pcap; plaintext absent | Encryption and absence of key material are directly established limits; no content claimed. |
| F3.8 | Bidirectional volume pattern indicates interactive C2 rather than bulk one-way exfiltration | T1071.004 | **Inferred** | resp/orig L7 = 52,063/27,322 ≈1.9; hex-derived query/answer 8,090/8,067 bytes near-symmetric | Encrypted content prevents definitive data-movement classification. |
| F3.9 | Tunnel still open when capture ended | T1071.004 | **Inferred** | Last pair frames 889/890 at 18:30:23.513/.514; `conn_state=SF`, duration matches capture; no distinguishable close marker | Absence of teardown plus capture boundary suggests active tunnel at stop. |
| F3.10 | Polling rate rises from ≈1.01 to ≈2.06 queries/s at t=118.8 s and returns to ≈1.01 queries/s at t=256.0 s; likely two dnscat2 sessions polling rather than one client speeding up | T1071.004, T1572 | **Likely** | Zeek `dns.log`: 120 queries / 118.8 s, 282 / 137.2 s, 43 / 42.5 s; second marker `0x9658` at frame 241, t=118.813 s (18:27:23.821Z) | Rates and the new marker are measured; the one→two→one session count is inferred from the doubling. No console log was retained to confirm. |

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
payload; no legitimate DNS baseline in this single-flow capture. **No ground-truth
console log was kept; interpretations of bursts and the session-count change rely on
traffic patterns only.** Old synthetic-case claims (base32, 14,000-byte secret,
`exfil-lab.test`, 202 queries) do not apply.

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


| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F4.1 | 192.168.56.40 connected to 203.0.113.50:8443 22 times (20 answered, 2 unanswered) and to 203.0.113.51:8443 24 times | T1071.001 | **Certain** | `conn.log` groups 20+2 SF/S0 and 24 SF; tshark 50 SYNs to 8443, 22 streams to .50, 20 SYN/ACKs | Counts reproduced by both tools. |
| F4.2a | Connections are periodic: primary median 56.6 s (MAD 3.5 s), backup median 57.1 s (MAD 2.4 s) | n/a | **Certain** | `beacon_stats.py`; 45 intervals from 46 first-SYN timestamps: mean 57.58 s, median 56.91 s (excluding the 6.00 s follow-up: n=44, mean 58.75 s, median 57.02 s) | Regularity measured twice; this row records the measurement only. |
| F4.2b | The periodic pattern is consistent with C2 beaconing | T1029 *(consistent with)* | **Likely** | Same statistics plus fixed sizes and non-standard port | Classification rests on regularity + metadata, not on readable payload. |
| F4.3 | Traffic is TLS 1.2 on non-standard port 8443 with SNI `updates.cdn-lab.test` | T1571, T1573 | **Certain** | `ssl.log` 44 rows: TLSv12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, that SNI; tshark ClientHello fields | Plaintext handshake fields, both tools. |
| F4.4 | Payload content is not determinable | T1573 | **Certain** | only Application Data records after handshake; random synthetic ciphertext | By definition outside the artifacts. Note: synthetic TLS omits Certificate; Zeek 9.0.1 reports `established=T` here. |
| F4.5 | After two unanswered primary attempts, the host switched to .51 with the same SNI and byte pattern | T1008 | **Likely** | S0 rows at 14:19:20.508Z and 14:20:15.456Z with `orig_pkts=3`; first .51 session at 14:21:04.997Z; identical SNI/sizes | Identical metadata suggests one implant; another host could imitate the pattern. |
| F4.6 | Beacon 8 delivered a ~4.2 KB server→client response and a ~2.3 KB upload followed 6 s later | T1105 *(consistent with)* | **Inferred** | 14:06:59.317Z resp_bytes=4219; 14:07:05.317Z orig_bytes=2302 | Direction and size asymmetry suggest tasking/result, but contents are unknown. |
| F4.7a | 86,263 B left the host in one session to .51 | n/a | **Certain** | `conn.log` orig_bytes=86263 at 14:31:37.763Z; tshark client-byte diff matches for all 44 streams | Volume measured twice; this row records the measurement only. |
| F4.7b | That upload was exfiltration | T1041 | **Inferred** | Same volume plus regular beacon timing | Purpose is not visible in encrypted traffic. |
| F4.8 | The six sessions to 198.51.100.20:443 (SNI `www.example.test`) are unrelated to the C2 | n/a | **Likely** | 6 sessions, different SNI/IP/port, large downloads (~100 KB median), irregular absolute timing | Differences are clear, but unrelatedness cannot be proven. |

### 6.5 Cross-tool verification

7 CONFIRMED claims; all three reconciliation rows CONFIRMED (52/52 flows,
2032/2032 packets, 849392/849392 IP bytes). Per-stream client bytes match for all
44 streams.

### 6.6 Data moved

Typical beacon 578–594 B up / 227 B down; outliers 4,219 B down, 2,302 B up,
86,263 B up. TLS payload unreadable.

### 6.7 Limitations

Encrypted TLS payload: only handshake fields, sizes and timing are visible. The
synthetic TLS omits a Certificate message, yet Zeek 9.0.1 reports
`established=T`; no chain fingerprints are available. No `weird.log` was produced
by Zeek 9.0.1 on this synthetic case. The primary-group CV is inflated by the
6.00 s follow-up session and two unanswered attempts; the timeline builder's
"periodic" label on the six benign HTTPS sessions is a heuristic artefact, so
they are treated as benign from SNI, port, byte asymmetry and absolute
irregularity. No host evidence exists for a single-implant identity, tasking or
exfiltration purpose: those remain Likely/Inferred. The analysis was
manual-guided, not blind; no "frozen before unsealing" claim is made.

---

## 7. Consolidated Confidence Matrix

| Case | Certain | Likely | Inferred | Total |
|---|---:|---:|---:|---:|
| 01 (real) | 5 | 3 | 1 | 9 |
| 02 (synthetic) | 6 | 5 | 0 | 11 |
| 03 (real) | 5 | 4 | 2 | 11 |
| 04 (synthetic) | 5 | 3 | 2 | 10 |
| **Total** | **21** | **15** | **5** | **41** |

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
   burst of many short sessions; the real Case 03 capture is dnscat2 with an encrypted payload, not
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

`custody/custody_log.csv` (15 entries; `notes` column marks superseded
synthetic captures and records public-safe acquisition details):

```csv
utc_time,user,host,case,action,pcap_sha256,notes
2026-11-16T16:21:29Z,kali,kali,case01,"real loopback SSH capture acquired with tcpdump on lo; operator-reported",771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99,"acquisition note: cases/case01_ssh_sessions/report/pcap_notes.md; VM clock UTC-5 plus 5h equals UTC; VM name not recorded"
2026-11-18T18:30:24Z,kali,kali,case03,"real loopback dnscat2 DNS capture acquired; exact tcpdump command not retained",e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb,"acquisition note: cases/case03_dns_tunnel/report/pcap_notes.md; direct-mode --dns server=127.0.0.1; secret omitted; VM clock UTC-5 plus 5h equals UTC"
2026-11-18T19:06:05Z,kali,kali,case01,"generated and sealed by Presenter",09e1de1777d611debc7bbee5cbb63478c5a6c7a5aec04edccc086bcbc90b6d8e,"superseded synthetic capture; preserved under supplementary/synthetic_case01/; replaced at 19:29:12Z"
2026-11-18T19:06:05Z,kali,kali,case02,"generated and sealed by Presenter",e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9,"synthetic Scapy primary case; unchanged by the re-audit"
2026-11-18T19:06:05Z,kali,kali,case03,"generated and sealed by Presenter",00dbcc9650c4f4a85e7296b5a26127d0f35763db1eaddc5b488ed47b45e6908c,"superseded synthetic capture; preserved under supplementary/synthetic_case03/; replaced at 19:29:12Z"
2026-11-18T19:06:05Z,kali,kali,case04,"generated and sealed by Presenter",eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675,"synthetic Scapy primary case; unchanged by the re-audit"
2026-11-18T19:12:04Z,kali,kali,case01,"Zeek + tshark + tcpdump analysis session",09e1de1777d611debc7bbee5cbb63478c5a6c7a5aec04edccc086bcbc90b6d8e,"superseded synthetic hash; see replacement and acquisition rows for the real capture"
2026-11-18T19:12:04Z,kali,kali,case02,"Zeek + tshark + tcpdump analysis session",e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9,"synthetic primary case"
2026-11-18T19:12:04Z,kali,kali,case03,"Zeek + tshark + tcpdump analysis session",00dbcc9650c4f4a85e7296b5a26127d0f35763db1eaddc5b488ed47b45e6908c,"superseded synthetic hash; see replacement and acquisition rows for the real capture"
2026-11-18T19:12:04Z,kali,kali,case04,"Zeek + tshark + tcpdump analysis session",eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675,"synthetic primary case"
2026-11-18T19:29:12Z,kali,kali,case01,"replaced synthetic with real loopback SSH lab capture",771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99,"sealed evidence is the real 107-packet capture; primary folder renamed to case01_ssh_sessions in re-audit"
2026-11-18T19:29:12Z,kali,kali,case03,"replaced synthetic with real loopback dnscat2 capture",e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb,"sealed evidence is the real 890-packet capture; acquisition note records operator-reported setup"
2026-11-18T19:56:23Z,kali,kali,case01,"re-audit: acquisition notes added, case01 folder renamed to case01_ssh_sessions",n/a,"documentation-only custody entry; no pcap changed"
2026-11-18T19:56:23Z,kali,kali,case03,"re-audit: acquisition notes added and polling-rate phases documented",n/a,"documentation-only custody entry; no pcap changed"
2026-11-18T20:30:48Z,kali,kali,all,"documentation update per repo_gap_analysis.md",n/a,"embedded rated findings; reworded case01 burst references; expanded case02/04 reports; no pcap changed"
```

The original synthetic Case 01/03 entries are explicitly marked superseded by the
real-capture replacements; their pcaps are preserved under `supplementary/`.

## Appendix D — Scripts

`tools/run_zeek.sh`, `seal_evidence.sh`, `custody.sh`, `verify_counts.py`,
`dns_stats.py`, `decode_dns_tunnel.py`, `beacon_stats.py`, `build_timeline.py`,
`generate_timelines.py`, `export_flows.py`, `make_excerpts.py`, `export_pdf.py`,
`make_appendix.py`;
case-local `cases/case03_dns_tunnel/report/decode_dnscat2.py`. Presenter-side generator
scripts are excluded from this public submission (see Appendix F).

## Appendix E — Derived views

- Timelines: `cases/*/timeline/timeline.csv` — 12 / 17 / 18 / 14 events for Cases 01–04,
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
