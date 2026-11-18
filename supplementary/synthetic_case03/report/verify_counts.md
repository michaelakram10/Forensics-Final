### Reconciliation for case03_dns_tunnel

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 242 | 242 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 484 | 484 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 82351 | 82351 | 0 | CONFIRMED |

Sanity: tshark frame bytes 89127 - 14 x 484 packets = 82351 (must equal tshark IP bytes 82351).
