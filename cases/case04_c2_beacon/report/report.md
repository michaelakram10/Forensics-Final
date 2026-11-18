# Case 04 — Periodic C2 Beaconing over TLS on a Non-Standard Port

## 6.1 Summary

From 14:00:00Z host 192.168.56.40 made 46 connection attempts to port 8443: 20 answered sessions to 203.0.113.50, two unanswered attempts, then 24 sessions to 203.0.113.51 after 14:21:04.997Z. All 44 TLS sessions use TLS 1.2 with SNI `updates.cdn-lab.test` on both IPs and near-constant payloads at ~57 s intervals. Beacon 8 received a 4,219 B response and produced a 2,302 B upload 6 s later; beacon 33 uploaded 86,263 B. Six unrelated HTTPS sessions to 198.51.100.20 use a different SNI and large downloads. Figures: `../viz/case04_c2_beacon_timeline.png`, `../../report/figures/case04.mmd`.

## 6.2 Evidence inventory

| File | Note |
|---|---|
| `raw/case04.pcap` | SHA-256 `eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675`, 2032 packets |
| `zeek/tsv/{conn,ssl}.log` | 52 / 50 rows |
| `tshark/beacon_stats.txt`, `c2_syn_times.txt`, `client_bytes_*.txt` | derived statistics and byte checks |

## 6.3 Reconstructed timeline

`../timeline/timeline.csv` (14 rows). Beacon statistics:

| Group | n | median interval | MAD | S0 | med orig B | med resp B |
|---|---:|---:|---:|---:|---:|---:|
| .50:8443 | 22 | 56.6 s | 3.5 s | 2 | 578 | 227 |
| .51:8443 | 24 | 57.1 s | 2.4 s | 0 | 594 | 227 |
| benign :443 | 6 | 465.6 s | 20.7 s | 0 | 793 | 99855 |

The timeline builder's "periodic" label on the benign group is a heuristic artefact of MAD/median being small for long absolute intervals; the report treats it as benign based on SNI, port and byte asymmetry.

## 6.4 Findings

F4.1–F4.8 in `../../report/confidence_matrix.md`: F4.1, F4.3, F4.4, F4.5(volume), F4.7 Certain for observations; F4.2 (classification), F4.5 (single implant), F4.8 Likely; F4.6 and F4.7's exfiltration purpose Inferred. ATT&CK T1071.001, T1571/T1573, T1008 (fallback, Likely), T1041 (volume Certain / purpose Inferred), T1029 and T1105 consistent with.

## 6.5 Cross-tool verification

`verification.md`: 7 CONFIRMED claims; reconciliation rows all CONFIRMED. Per-stream client bytes match for all 44 streams; first-SYN intervals agree with Zeek medians.

## 6.6 Data moved

Typical beacon ≈578–594 B up / 227 B down. Outliers: 4,219 B down (14:06:59Z), 2,302 B up 6 s later, and 86,263 B up to .51 at 14:31:37Z. TLS payload content is not determinable; only direction and volume are facts.

## 6.7 Limitations

Encrypted payload; synthetic TLS omits the Certificate message (Zeek 9.0.1 nevertheless reports `established=T`, no chain fingerprints); primary-group CV inflated by the follow-up session and outage; no host evidence for tasking or exfiltration intent.
