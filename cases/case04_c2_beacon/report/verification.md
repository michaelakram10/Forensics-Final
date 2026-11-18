# Case 04 — cross-tool verification (tshark & tcpdump)

Setup: `PCAP=$PWD/cases/case04_c2_beacon/raw/case04.pcap`; hash verified (`case04.pcap: OK`).

## Automated reconciliation

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows | 52 | 52 | 0 | CONFIRMED |
| Packets | 2032 | 2032 | 0 | CONFIRMED |
| IP bytes | 849392 | 849392 | 0 | CONFIRMED |

Sanity: `877840 − 14×2032 = 849392`.

## Claim-by-claim table

| # | Claim | Zeek evidence | Second-tool command → result | Status | Δ / explanation |
|---|---|---|---|---|---|
| V-01 | 50 SYNs to port 8443, 46 streams (22 primary, 24 backup) | 46 `conn.log` rows to 8443 | `tshark -r $PCAP -Y 'tcp.dstport==8443 && tcp.flags.syn==1 && tcp.flags.ack==0' \| wc -l` → 50; primary streams → 22 | CONFIRMED | none (50 = 44 sessions + 2 failed × 3 SYNs) |
| V-02 | 20 SYN/ACKs from primary | 20 SF rows to .50 | tshark `ip.src==203.0.113.50 && tcp.flags.syn==1 && tcp.flags.ack==1` → 20 | CONFIRMED | none |
| V-03 | SNI `updates.cdn-lab.test` on both C2 IPs, 44 sessions | 44 `ssl.log` rows | tshark `tls.handshake.type==1` ClientHello fields show the same SNI on .50 and .51 | CONFIRMED | none |
| V-04 | Beacon interval median ≈57 s | `beacon_stats.py`: 56.6 s (primary), 57.1 s (backup) | first-SYN extraction (`c2_syn_times.txt`, 46 timestamps → 45 intervals) → mean 57.58 s, median 56.91 s, min 6.00 s, max 71.37 s; excluding the 6 s follow-up n=44, mean 58.75 s, median 57.02 s | CONFIRMED | same first-SYN timestamps; 6.00 s is a follow-up session, not a beacon period |
| V-05 | Per-stream client bytes | Zeek `orig_bytes` per 8443 flow | `tshark ... tcp.len` per client port vs `zeek-cut id.resp_p id.orig_p orig_bytes \| awk '$1==8443'` → diff empty for 44 streams (`client_bytes_*.txt`) | CONFIRMED | initial mismatch in the guide's command was a field-separator/port-filter issue, corrected here |
| V-06 | 86,263 B upload at 14:31:37.763Z | `conn.log orig_bytes=86263` | tshark per-port sum: 86263 on client port 49534 | CONFIRMED | none |
| V-07 | Two unanswered primary attempts, then failover | 2 S0 rows, `orig_pkts=3` | tshark SYN-only count for .50 = 26 (20 sessions + 2×3 retransmitted SYNs); first .51 session at 14:21:04.997Z | CONFIRMED | none |

Saved outputs: `tshark/beacon_stats.txt`, `tshark/c2_syn_times.txt`, `tshark/client_bytes_zeek.txt`, `tshark/client_bytes_tshark.txt`, `tshark/capinfos.txt`, `tcpdump/full_text_dump.txt`.

No CHALLENGED findings; all differences were definitional (Ethernet header, port filter, tshark 4.6 printing `True`/`False` for flag fields) and are documented here.
