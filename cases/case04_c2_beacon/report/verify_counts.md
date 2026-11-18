### Reconciliation for case04_c2_beacon

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 52 | 52 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 2032 | 2032 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 849392 | 849392 | 0 | CONFIRMED |

Sanity: tshark frame bytes 877840 - 14 x 2032 packets = 849392 (must equal tshark IP bytes 849392).
