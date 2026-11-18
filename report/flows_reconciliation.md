# Flow-export reconciliation

Because `nfpcapd`/`nfdump` are unavailable, the flow CSVs under `cases/*/flows/` are exports of Zeek `conn.log` (a bidirectional flow log), not independent NetFlow exports. They are included to give a flow-oriented view. The independent column below is tshark's TCP/UDP stream count from the sealed pcap.

| Case | Zeek conn.log rows | Flow CSV rows | tshark streams | Status |
|---|---:|---:|---:|---|
| case01_ssh_bruteforce | 3 | 3 | 3 | CONFIRMED |
| case02_web_sqli | 3 | 3 | 3 | CONFIRMED |
| case03_dns_tunnel | 1 | 1 | 1 | CONFIRMED |
| case04_c2_beacon | 52 | 52 | 52 | CONFIRMED |

Status compares the flow CSV row count to tshark's stream count. A mismatch would indicate a flow-logging or stream-tracking difference; see each case's `report/verification.md` for the byte-level reconciliation.
