# Case 01 — cross-tool verification (claim by claim)

`Zeek evidence` uses the regenerated TSV logs (`zeek/tsv/`); the `second tool`
column uses tshark/tcpdump/capinfos or the JSON Zeek run. Commands were run from
`cases/case01_ssh_bruteforce/` with `export TZ=UTC`. Raw outputs are saved in
`tshark/`, `tcpdump/` and `zeek/queries.md`. UIDs in TSV and JSON differ because
`run_zeek.sh` runs Zeek twice; comparisons are by time/port/size.

| # | Claim | Zeek evidence | Second-tool command → result | Status | Delta explanation |
|---:|---|---|---|---|---|
| V1 | Pcap integrity / hash | `run_zeek.sh` aborts unless the sidecar verifies | `cd raw && sha256sum -c case01.pcap.sha256` → `case01.pcap: OK`; `capinfos case01.pcap` → SHA256 `771e90d7…0c99` | CONFIRMED | none |
| V2 | 107 packets total | `conn.log` `orig_pkts+resp_pkts` = 13+12+18+24+17+23 = **107** | `capinfos` → 107; `tshark -r raw/case01.pcap` frame count → 107 | CONFIRMED | none |
| V3 | Exactly three TCP conversations, all SSH to `127.0.0.1:22` | 3 `conn.log` rows, `service=ssh`, `id.resp_h=127.0.0.1`, `id.resp_p=22` | `tshark -r raw/case01.pcap -q -z conv,tcp` → 3 streams (34416/34430/54844 ↔ 22) | CONFIRMED | none |
| V4 | First/last UTC times, capture span | first `ts=1794846054.608130` (16:20:54.608130Z); last connection starts `1794846074.796806` + 14.196392 s | `tshark -r raw/case01.pcap -T fields -e frame.time_epoch` → first `1794846054.608130`, last `1794846088.993265`; `capinfos` span **34.385135 s** | CONFIRMED | capinfos/tshark span includes the final ACK; Zeek's last connection ends at the server FIN, 67 µs earlier |
| V5 | Banners: libssh ×3, OpenSSH ×3 | `ssh.log` 3× `SSH-2.0-libssh_0.12.2`, 3× `SSH-2.0-OpenSSH_10.6p1 Debian-1`; `software.log` libssh 0.12.2 / OpenSSH 10.6p1 | `tshark -r raw/case01.pcap -Y ssh.protocol -T fields -e ssh.protocol | sort | uniq -c` → `3` and `3` (`tshark/ssh_banners.txt`) | CONFIRMED | none |
| V6 | Per-stream packets and bytes | `conn.log` per uid: 13/12 & 1227/1741; 18/24 & 1679/2077; 17/23 & 1603/1977; IP bytes 1911/2373, 2623/3333, 2495/3181 | sums of `tcp.len` and `frame.len - 14` by `tcp.stream`/direction → **all 18 counters match** (`tshark/stream_bytes_diff.txt`) | CONFIRMED | none |
| V7 | Connection durations | `conn.log`: 0.120797 / 19.858788 / 14.196392 s | first-to-last frame per `tcp.stream`: 0.120826 / 19.858827 / 14.196459 s | DISCREPANT-EXPLAINED | Zeek ends at server FIN (frames 24, 71, 106); tshark includes trailing ACK (frames 25, 72, 107): +29/+39/+67 µs |
| V8 | Auth heuristic (`auth_success`, `auth_attempts`) | `ssh.log`: unset/0 for stream 0, `F`/5 for stream 1, `T`/5 for stream 2 | `jq -r '[.ts,.uid,.auth_success,.auth_attempts]|@tsv' zeek/json/ssh.log` → unset/0, `false`/5, `true`/5; tshark shows six 52→84 B pairs in stream 1 and five in stream 2 | DISCREPANT-EXPLAINED | Zeek's counters are analyzer heuristics on encrypted packets; 52/84 B pairs are not a 1:1 mapping to `auth_attempts`; no decryption is possible |
| V9 | No port scan / no RSTs | only 3 `conn.log` rows, all `port=22`, `state=SF`, history `ShADadFf` | `tshark -r raw/case01.pcap -Y 'tcp.flags.syn==True'` → 6 SYN flags (3 from client + 3 SYN/ACK); `-Y 'tcp.flags.reset==True'` → **0** | CONFIRMED | none; the synthetic 13-port scan is not in this file |
| V10 | No 36-attempt brute-force burst | max `auth_attempts=5`, 3 connections total | `tshark -q -z conv,tcp` → 3 streams; `tshark/frame_detail.txt` → 107 frames, no burst of short sessions | CONFIRMED | absence verified against the complete 107-frame capture |
| V11 | IP bytes and Ethernet header identity | sum `orig_ip_bytes+resp_ip_bytes` = **15,916** | `tshark -T fields -e frame.len -e ip.len` → frame bytes **17,414**, IP bytes **15,916**; 17,414 − 14 × 107 = 15,916 | CONFIRMED | exactly 14 B of Ethernet header per frame; no VLAN/padding |
| V12 | SSH payload encrypted; no command names recoverable | `ssh.log` contains only banner/algorithm metadata; no file or command logs | `tcpdump -nn -tttt -r raw/case01.pcap` (`tcpdump/full_text_dump.txt`) → all post-KEX frames shown as SSH encrypted records; no cleartext commands | CONFIRMED | command names/content are out of scope; any mapping would be Inferred |
| V13 | Same host-key fingerprint in all sessions | `ssh.log` `host_key_fingerprint=SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn` (3 rows) | `tshark -r raw/case01.pcap -Y ssh.protocol -T fields -e ssh.protocol` → identical OpenSSH banner 3 times; no second server identity | CONFIRMED | none |
| V14 | Loopback-only traffic | `conn.log` `id.orig_h = id.resp_h = 127.0.0.1` for all rows | `tshark -T fields -e ip.src -e ip.dst | sort -u` → only `127.0.0.1` | CONFIRMED | none |

## Reconciliation summary

`report/verify_counts.md`:

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows | 3 | 3 | 0 | CONFIRMED |
| Packets | 107 | 107 | 0 | CONFIRMED |
| IP bytes | 15,916 | 15,916 | 0 | CONFIRMED |

Sanity: 17,414 frame bytes − 14 × 107 packets = 15,916 IP bytes — the standard
14-byte Ethernet II header accounts for every byte of difference.
