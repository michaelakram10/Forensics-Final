### Reconciliation for case03_dns_tunnel

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 1 | 1 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 890 | 890 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 104305 | 104305 | 0 | CONFIRMED |

Sanity: tshark frame bytes 116765 - 14 x 890 packets = 104305 (must equal tshark IP bytes 104305).
