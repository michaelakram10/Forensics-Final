# Case 01 — cross-tool verification (tshark & tcpdump)

Common setup: `export TZ=UTC`; `PCAP=$PWD/cases/case01_ssh_bruteforce/raw/case01.pcap`. Hash verified before every command (`sha256sum -c case01.pcap.sha256` → OK).

## Automated reconciliation

`report/verify_counts.md` (output of `tools/verify_counts.py case01_ssh_bruteforce case01`):

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows (conn.log rows vs tcp/udp streams) | 50 | 50 | 0 | CONFIRMED |
| Packets (orig+resp pkts vs frames) | 1401 | 1401 | 0 | CONFIRMED |
| IP bytes (`*_ip_bytes` vs `ip.len`) | 171830 | 171830 | 0 | CONFIRMED |

Sanity: `191444 − 14×1401 = 171830` = tshark IP bytes.

## Claim-by-claim table

| # | Claim | Zeek evidence | Second-tool command → result | Status | Δ / explanation |
|---|---|---|---|---|---|
| V-01 | 13 ports probed in 0.600 s from source port 51234 | 13 `conn.log` rows, `id.orig_p=51234`, histories `Sr`/`ShR` | `tshark -r $PCAP -Y 'ip.src==192.168.56.10 && tcp.srcport==51234 && tcp.flags.syn==1 && tcp.flags.ack==0' \| wc -l` → 13 | CONFIRMED | none |
| V-02 | Ports 22 and 80 open; 11 closed | `history=ShR` vs `history=Sr` | `tshark -r $PCAP -Y 'ip.src==192.168.56.20 && tcp.flags.syn==1 && tcp.flags.ack==1 && tcp.dstport==51234' -T fields -e tcp.srcport` → 22, 80; RST list → 11 ports | CONFIRMED | none |
| V-03 | Half-open scan (scanner RST after SYN/ACK) | 2 rows state RSTO | `tshark -r $PCAP -Y 'ip.src==192.168.56.10 && tcp.flags.reset==1 && tcp.srcport==51234' -T fields -e tcp.dstport` → 22, 80 | CONFIRMED | none |
| V-04 | 38 SYNs to port 22 (1 scan + 37 sessions) | 38 `conn.log` rows with `id.resp_p=22` | `tshark -r $PCAP -Y 'tcp.dstport==22 && tcp.flags.syn==1 && tcp.flags.ack==0' \| wc -l` → 38 | CONFIRMED | none |
| V-05 | Client banners: 36 libssh, 1 OpenSSH_9.9, server 37× OpenSSH_8.9 | `ssh.log client/server` counts | `tshark -r $PCAP -Y ssh.protocol -T fields -e ip.src -e ssh.protocol \| sort \| uniq -c` → 36 / 1 / 37 (`tshark/ssh_banners.txt`) | CONFIRMED | none |
| V-06 | Per-stream SSH payload bytes | `conn.log orig_bytes/resp_bytes` | `stream_bytes_zeek.txt` vs `stream_bytes_tshark.txt` diff → empty | CONFIRMED | all 37 streams match exactly |
| V-07 | Interactive session has 36-byte keystroke/echo packets | long conn 165/164 pkts, 4020/25110 B | `tshark -r $PCAP -Y 'tcp.port==49302 && tcp.len>0' -T fields -e ip.src -e tcp.len \| ... uniq -c` → 67×36 B client, 60×36 B server, 13×1400 B server (`tshark/interactive_pkt_sizes.txt`) | CONFIRMED | new detail from tshark; Zeek had only aggregate counts |
| V-08 | Zeek `resp_ip_bytes` vs tshark `frame.len` totals | 171830 total IP bytes | 191444 frame bytes − 14×1401 = 171830 | DISCREPANT-EXPLAINED | Δ = 14 B/frame Ethernet header counted by tshark, not Zeek |

Saved raw evidence: `tshark/capinfos.txt`, `tshark/conv_tcp.txt`, `tshark/stream_bytes_*.txt`, `tshark/interactive_pkt_sizes.txt`, `tshark/ssh_banners.txt`, `tcpdump/full_text_dump.txt`.

## Note on authentication outcome

Zeek's SSH heuristic reports `auth_success=T, auth_attempts=1` for the long session but leaves the 36 short sessions unset. This is a second artifact in addition to timing/size, but because SSH is encrypted and the decisive payload is not visible, the "failed logins" finding stays **Likely** in the confidence matrix rather than being promoted to Certain.
