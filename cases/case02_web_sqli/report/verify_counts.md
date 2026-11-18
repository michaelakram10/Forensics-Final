### Reconciliation for case02_web_sqli

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 3 | 3 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 203 | 203 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 105459 | 105459 | 0 | CONFIRMED |

Sanity: tshark frame bytes 108301 - 14 x 203 packets = 105459 (must equal tshark IP bytes 105459).
