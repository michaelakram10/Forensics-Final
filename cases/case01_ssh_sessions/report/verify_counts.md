### Reconciliation for case01_ssh_sessions

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 3 | 3 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 107 | 107 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 15916 | 15916 | 0 | CONFIRMED |

Sanity: tshark frame bytes 17414 - 14 x 107 packets = 15916 (must equal tshark IP bytes 15916).
