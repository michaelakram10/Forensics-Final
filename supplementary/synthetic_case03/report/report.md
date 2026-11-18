# Synthetic Case 03 (superseded) — DNS Tunneling / Covert Exfiltration

## 5.1 Summary

From 10:00:19Z workstation 192.168.56.40 made 40 ordinary A queries through resolver 192.168.56.53, then at 10:10:00.000Z began 202 TXT queries to `*.t.exfil-lab.test` with 202/202 unique, ~135-character base32 names (entropy 4.35 vs ~2.5 for baseline). The last query was at 10:10:47.848Z. Reassembling the labels with `tools/decode_dns_tunnel.py` from both Zeek and tshark query names produced byte-identical 14,000-byte files (SHA-256 `8d8b129b78610da1d7dad75ca2375c25be120b2cdc1f7a3869b974d1b6b32f97`) of synthetic records. Figures: `../viz/case03_dns_tunnel_timeline.png`, `../../../report/figures/case03.mmd`.

## 5.2 Evidence inventory

| File | Note |
|---|---|
| `raw/case03.pcap` | SHA-256 `00dbcc9650c4f4a85e7296b5a26127d0f35763db1eaddc5b488ed47b45e6908c`, 484 packets |
| `zeek/tsv/dns.log` | 242 rows |
| `tshark/recovered_from_tshark.bin`, `recovered_from_zeek.bin` | 14,000 B each, identical SHA-256 |
| `tshark/dns_stats.txt` | domain statistics |

## 5.3 Reconstructed timeline

`../timeline/timeline.csv` (4 rows): baseline corp.test/example.test at 10:00:19.899 / 10:01:34.708; tunnel begins 10:10:00.000 (`init.t.exfil-lab.test`); ends 10:10:47.848 (202 queries, 202 unique, mean length 135).

## 5.4 Findings

F3.1–F3.8 in `../../../report/confidence_matrix.md`: F3.1, F3.2 (statistics), F3.3, F3.4, F3.5, F3.6 Certain; F3.7 and F3.8 Inferred. The statistical tunnel indicator is Certain as a measurement but was Inferred as a classification until F3.3 decoded the payload. ATT&CK T1071.004 (DNS), T1132.001 (data encoding), T1048 (exfiltration).

## 5.5 Cross-tool verification

`verification.md`: 6 claims — 5 CONFIRMED, 1 DISCREPANT-EXPLAINED (39,367 frame bytes − 14×202 = 36,539 Zeek IP bytes). All reconciliation rows CONFIRMED.

## 5.6 Data moved

14,000 bytes recovered, beginning `SYNTHETIC-LAB-RECORD 0001 emp=E74697 salary=19690 note=NOT-REAL-DATA`. Outbound tunnel traffic: 202 packets, 39,367 frame bytes, 36,539 IP bytes, 30,883 DNS payload bytes.

## 5.7 Limitations

Only the client↔resolver leg is visible; the authoritative server and any recursive resolution are outside the capture. The `sNNNN.<base32>` encoding is custom — no known tunnel tool could be identified. The data is synthetic.
