# Case 04 — packet-level notes (Log/pcap analyst)

## Evidence

| Item | Value |
|---|---|
| File | `raw/case04.pcap` |
| SHA-256 | `eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675` |
| Packets | 2,032 |
| First / last packet | 2026-11-04 14:00:00.000Z / 14:44:11.364Z |
| Hosts | 192.168.56.40 → 203.0.113.50:8443 (primary), 203.0.113.51:8443 (backup), 198.51.100.20:443 (benign) |

## Beacon pattern

- 46 connection attempts to port 8443: 44 SF (20 to primary, 24 to backup) and 2 S0 to primary.
- All 44 TLS sessions use TLS 1.2, cipher `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and SNI `updates.cdn-lab.test` on both C2 IPs.
- Small, near-constant payloads: median 578 B up / 227 B down (primary), 594 B up / 227 B down (backup). Intervals: primary median 56.6 s (MAD 3.5 s), backup median 57.1 s (MAD 2.4 s). 45 intervals from 46 first-SYN timestamps: mean 57.58 s, median 56.91 s, min 6.00 s, max 71.37 s. The 6.00 s minimum is the follow-up session to beacon 8, not a beacon period; excluding it gives n=44, mean 58.75 s, median 57.02 s, min 49.02 s.
- Application Data records are random synthetic bytes; payload content is not determinable.

## Outliers and events

- 14:06:59.317Z — beacon 8 response 4,219 B down (tasking-sized).
- 14:07:05.317Z — 6 s later, 2,302 B up (task-result-sized, inferred).
- 14:19:20.508Z and 14:20:15.456Z — two unanswered primary attempts (SYN + 2 retransmits each, `orig_pkts=3`, Zeek S0).
- 14:21:04.997Z — first session to backup .51, same SNI and byte pattern (failover, Likely).
- 14:31:37.763Z — 86,263 B upload to .51 in a 2.0 s session (volume Certain, exfiltration Inferred).
- Six sessions to 198.51.100.20:443, SNI `www.example.test`, downloads ~100 KB median (e.g. 149,555 B at 14:35:05.067Z), irregular absolute timing — benign-looking.

## Cross-check

Per-stream client payload bytes match for all 44 C2 streams (`tshark/client_bytes_zeek.txt` vs `client_bytes_tshark.txt`, diff empty after restricting both sides to port 8443 and normalising field separators). SYN counts: 50 SYNs to 8443, 22 streams to primary, 20 SYN/ACKs from primary — all reproduced by tshark.
