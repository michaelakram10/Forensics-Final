# Case 01 — SSH sessions on loopback (real capture)

**Case directory:** `cases/case01_ssh_sessions/`  
**Analysis basis:** Zeek TSV/JSON logs regenerated from the sealed pcap; tshark and tcpdump raw evidence.  
**Time basis:** UTC (`export TZ=UTC`). Ratings follow `../../report/confidence_matrix.md` (Case 01 rows correspond to the findings below).

## Summary

This is a **real 107-packet tcpdump capture** from an isolated lab. All traffic is on **loopback** (`127.0.0.1 → 127.0.0.1`). It contains exactly **three completed SSH TCP sessions** to `127.0.0.1:22`: one short (0.120797 s) and two long (19.858788 s and 14.196392 s). The capture spans **34.385135 s**, from `1794846054.608130` (2026-11-16 16:20:54.608130Z) to `1794846088.993265` (16:21:28.993265Z). All three sessions present the same plaintext banners — client `SSH-2.0-libssh_0.12.2`, server `SSH-2.0-OpenSSH_10.6p1 Debian-1` — and the same negotiated algorithms and host-key fingerprint. Zeek's SSH analyzer records 0 authentication attempts in the short session and 5 in each long session, with `auth_success` `F` for the first long session and `T` for the second. **There is no port scan and no burst of many short sessions in this capture**; the earlier synthetic version of Case 01 is preserved under `supplementary/synthetic_case01/` and does not apply here. SSH payload after key exchange is encrypted, so credentials, user identity, commands and host effects are not recoverable.

**Operator-reported context (not derived from the pcap):** the retained setup
notes in `pcap_notes.md` state that the sessions were generated with Hydra v9.7
against `127.0.0.1:22` with a short wordlist. The sealed pcap alone does not
prove tool identity, and this context does **not** change any finding or rating
in this report.

## Evidence inventory

| Evidence | Location | Key facts |
|---|---|---|
| Sealed pcap + sidecar | `raw/case01.pcap`, `raw/case01.pcap.sha256` | SHA-256 `771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99`; sidecar check `OK`; 19,150 bytes |
| Capture metadata | `tshark/capinfos.txt` | 107 packets; 17,414 frame bytes; 34.385135 s; first/last UTC as above; Ethernet |
| TCP conversations | `tshark/conv_tcp.txt` | 3 streams: 34416 (25 frames), 34430 (42), 54844 (40), all ↔ port 22 |
| Frame detail | `tshark/frame_detail.txt` | epoch/UTC, flags, `tcp.len`, `frame.len`, `ssh.protocol` for all 107 frames |
| Banners | `tshark/ssh_banners.txt` | 3 × libssh client banner, 3 × OpenSSH server banner |
| Flags | `tshark/tcp_flags.txt` | 6 SYN flags (3 client SYNs + 3 SYN/ACKs), 6 FINs, 0 RSTs |
| Byte tables | `tshark/stream_bytes_zeek.txt`, `tshark/stream_bytes_tshark.txt`, `tshark/stream_bytes_diff.txt` | 18/18 per-stream counters match; totals 4,509 B client / 5,795 B server payload |
| Packet-size histogram | `tshark/packet_histogram_long.txt` | 52→84 B encrypted pair sequences and gaps in streams 1 and 2 |
| Full text dump | `tcpdump/full_text_dump.txt` | 107 lines, `tcpdump -nn -tttt`, UTC |
| Zeek logs | `zeek/tsv/`, `zeek/json/` | `conn.log` (3 rows), `ssh.log` (3 rows), `software.log`, `stats.log`; queries in `zeek/queries.md` |
| Counts reconciliation | `report/verify_counts.md` | flows 3/3, packets 107/107, IP bytes 15,916/15,916 |
| Notes / verification | `report/pcap_notes.md`, `report/verification.md` | stage-by-stage reconstruction and 14 claim checks |
| Timeline | `timeline/timeline.csv` | 12 custom UTC rows, each with an evidence reference |

## Reconstructed timeline

Full custom timeline: `timeline/timeline.csv` (TSV UIDs are used as `evidence_ref` values).

| UTC | Event | Evidence |
|---|---|---|
| 16:20:54.608130 | Short session SYN; banners at .608280 and .624584; client FIN .723511; 0.120797 s | `CF3dQ73otQFUMGzMMi`, f1–f25 |
| 16:20:54.939960 | Long session A SYN (0.33183 s after first); identical banners/algorithms | `CPbK9Z6ezH8vbIQn1`, f26–f31 |
| 16:20:55.059953 → 16:21:10.848695 | Six 52→84 B encrypted pairs in long A (gaps 1.97–3.95 s) | f46–f62 |
| 16:21:14.795393 → 14.798748 | Long A final 76 B packet and FINs; Zeek `auth_success=F`, `auth_attempts=5` | `CPbK9Z6ezH8vbIQn1`, f64–f72 |
| 16:21:14.796806 | Long session B SYN, overlapping long A's TCP teardown | `CIkYPK3CLHxdbW23vh`, f66 |
| 16:21:14.912492 → 16:21:24.779803 | Five 52→84 B encrypted pairs in long B | f88–f98 |
| 16:21:28.726199 → 28.993265 | Final 92 B client / 28 B server exchange, orderly close; Zeek `auth_success=T`, `auth_attempts=5`; capture ends | `CIkYPK3CLHxdbW23vh`, f101–f107 |

## Findings

| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F1.1 | Three completed TCP SSH sessions from loopback to `127.0.0.1:22`; all `SF`, 107 frames, 15,916 IP bytes | n/a | **Certain** | `conn.log` 3 rows; `tshark/conv_tcp.txt` 3 streams; `verify_counts.md` | Addresses, ports, states and counts are directly visible and reproduced by both tools. |
| F1.2 | Identical plaintext banners in all sessions: client `SSH-2.0-libssh_0.12.2` ×3, server `SSH-2.0-OpenSSH_10.6p1 Debian-1` ×3; same KEX/cipher/host key | n/a | **Certain** | `ssh.log`, `software.log`, `tshark/ssh_banners.txt` | Banners and algorithm strings are cleartext and identical across Zeek and tshark. |
| F1.3 | Short session `CF3dQ73otQFUMGzMMi`: 0.120797 s, 13/12 packets, 1,227/1,741 B payload, one encrypted exchange then client FIN; Zeek `auth_attempts=0`, `auth_success` unset | n/a | **Certain** | `conn.log`, `ssh.log`, frames 1–25 | Timing, counters and logged heuristic values are measured; no interpretation of payload is made. |
| F1.4 | Long sessions `CPbK9Z6ezH8vbIQn1` and `CIkYPK3CLHxdbW23vh`: 19.858788 s / 14.196392 s, 18/24 and 17/23 packets, 1,679/2,077 and 1,603/1,977 B payload | n/a | **Certain** | `conn.log`, `tshark/stream_bytes_diff.txt`, `tshark/packet_histogram_long.txt` | Sizes, durations and repeated encrypted exchange sizes are measured and cross-tool identical. |
| F1.5 | Both long sessions contain repeated encrypted authentication-like exchanges; Zeek records `auth_attempts=5` for each | T1110.001 *(consistent with)* | **Likely** | `ssh.log` 5/5; tshark 52→84 B pairs (6 in stream 1, 5 in stream 2) | Zeek's counter is an analyzer heuristic over encrypted packets, and pairs do not map 1:1 to it; this is not evidence of a burst of many short sessions. |
| F1.6 | First long session ends with `auth_success=F` and a client FIN after a final 76 B server packet — consistent with failed authentication | T1110.001 *(consistent with)* | **Likely** | `ssh.log` `CPbK9Z6ezH8vbIQn1`; frames 64, 65, 71 | Failure indication comes from Zeek's heuristic plus teardown behaviour; the encrypted payload cannot confirm the reason. |
| F1.7 | Second long session ends with `auth_success=T`, a final 92 B client / 28 B server exchange and orderly FINs — consistent with a successful SSH login | T1021.004, T1078 *(consistent with)* | **Likely** | `ssh.log` `CIkYPK3CLHxdbW23vh`; frames 101–107 | Strong metadata/heuristic indicators, but no credential, user identity or host-side evidence is available. |
| F1.8 | A specific automation tool, credentials, command names and host effects cannot be determined; `libssh` is a library used by many clients | n/a | **Inferred** | `ssh.log` banners; `tcpdump/full_text_dump.txt` encrypted records | Only the library banner is visible; naming a tool or decrypting commands would exceed the artifacts. |
| F1.9 | This capture contains no port scan, no RSTs, no non-22 destination and no burst of many short sessions | n/a | **Certain** | 3 `conn.log` rows, `state=SF`; `tshark/tcp_flags.txt` 0 RST, 3 client SYNs | The 107-frame file is complete; no such burst is present. |

**Case 01 confidence counts:** Certain **5**, Likely **3**, Inferred **1** (9 findings).

## Cross-tool verification

`tools/verify_counts.py` (`report/verify_counts.md`) reports:

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows | 3 | 3 | 0 | CONFIRMED |
| Packets | 107 | 107 | 0 | CONFIRMED |
| IP bytes | 15,916 | 15,916 | 0 | CONFIRMED |

The 14-byte Ethernet header identity holds exactly: **17,414 frame bytes − 14 × 107 packets = 15,916 IP bytes**. Per-stream comparison (`tshark/stream_bytes_diff.txt`) matches all 18 counters. Connection durations differ by 29/39/67 µs between Zeek (SYN → server FIN) and tshark (first → last frame including the final ACK); this is a convention difference, documented in `report/verification.md` V7. TSV and JSON Zeek runs assign different UIDs; all other fields agree. Full claim-by-claim checks are in `report/verification.md`.

## Data moved

| Direction | TCP payload bytes | IP bytes | Packets |
|---|---:|---:|---:|
| Client → server (all 3 sessions) | 4,509 | 6,709 | 48 |
| Server → client (all 3 sessions) | 5,795 | 9,207 | 59 |
| Total | 10,304 | 15,916 | 107 |

Per session: short 1,227/1,741 B; long A 1,679/2,077 B; long B 1,603/1,977 B (client/server payload). The volumes are small and roughly symmetric; there is **no evidence of bulk transfer or file exfiltration** in this capture. Because SSH is encrypted, the content of even these bytes is unknown.

## Limitations

- Real lab capture on **loopback** only: one host and one local SSH service; no external network perspective, no intermediate hops.
- SSH payload after key exchange is **encrypted**; Zeek's `auth_success`/`auth_attempts` are analyzer heuristics, not decrypted ground truth. No credentials, usernames, commands, command output or file contents are available.
- No host/endpoint evidence, auth logs, shell history or process telemetry: login success/failure and any host-side effects remain Likely at most.
- Tool identity is unknown: `libssh` indicates a library, not a specific program. No claim of Hydra or any named automation tool is supported.
- The capture contains no port scan and no burst of many short sessions; no such activity is present in these 107 frames.
- Short capture (34.385135 s, three sessions); absence of other activity outside this window cannot be established.
- Zeek TSV and JSON UIDs differ between runs; compare by timestamp/port/size. Timeline `evidence_ref` values use the TSV UIDs.
