# Case 03 — cross-tool verification (tshark & tcpdump)

Setup: `PCAP=$PWD/cases/case03_dns_tunnel/raw/case03.pcap`; hash verified (`case03.pcap: OK`).

## Automated reconciliation

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows (conn.log rows vs streams) | 242 | 242 | 0 | CONFIRMED |
| Packets | 484 | 484 | 0 | CONFIRMED |
| IP bytes | 82351 | 82351 | 0 | CONFIRMED |

Sanity: `89127 − 14×484 = 82351`.

## Claim-by-claim table

| # | Claim | Zeek evidence | Second-tool command → result | Status | Δ / explanation |
|---|---|---|---|---|---|
| V-01 | 242 DNS queries (40 A + 202 TXT) | 242 rows in `dns.log`; `qtype_name` counts | `tshark -r $PCAP -Y 'dns.flags.response==0' \| wc -l` → 242; type counts 40/202 | CONFIRMED | none |
| V-02 | 202 queries to exfil-lab.test | 202 `dns.log` rows | tshark `dns.qry.name contains "exfil-lab.test"` → 202; tcpdump `udp dst port 53 \| grep -c exfil-lab.test` → 202 | CONFIRMED | none |
| V-03 | Query length ≈136 chars for tunnel, ~17 for baseline | `dns_stats.py` output | tshark `dns.qry.name` length histogram dominated by 200 × 136 | CONFIRMED | none |
| V-04 | Outbound frame bytes 39367 / 202 frames | Zeek `orig_ip_bytes=36539` for the 202 uids | `tshark ... -T fields -e frame.len \| awk '{s+=$1} END{print s,NR}'` → 39367 202 | DISCREPANT-EXPLAINED | Δ = 39367 − 14×202 = 36539 = Zeek IP bytes (Ethernet header) |
| V-05 | Decoded payload hash | `decode_dns_tunnel.py` on Zeek `query` → 14000 B, sha256 `8d8b129b…2f97` | same decoder on tshark `dns.qry.name` → 14000 B, identical sha256 | CONFIRMED | none |
| V-06 | Tunnel timing 10:10:00.000Z → 10:10:47.848Z | first/last `dns.log` timestamps | tshark `frame.time_epoch` first/last + `date -u -d @…` agree | CONFIRMED | none |

Saved outputs: `tshark/dns_stats.txt`, `tshark/recovered_from_tshark.bin`, `tshark/recovered_from_zeek.bin`, `tshark/capinfos.txt`, `tcpdump/full_text_dump.txt`.

No CHALLENGED findings. The byte delta in V-04 is the documented Ethernet-header definition difference, not a disagreement about packet content.
