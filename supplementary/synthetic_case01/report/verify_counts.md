### Reconciliation for case01_ssh_bruteforce

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows: Zeek conn.log rows vs tshark tcp/udp streams | 50 | 50 | 0 | CONFIRMED |
| Packets: Zeek orig_pkts+resp_pkts vs tshark frames | 1401 | 1401 | 0 | CONFIRMED |
| IP bytes: Zeek *_ip_bytes vs tshark ip.len | 171830 | 171830 | 0 | CONFIRMED |

Sanity: tshark frame bytes 191444 - 14 x 1401 packets = 171830 (must equal tshark IP bytes 171830).
