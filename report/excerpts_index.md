# Focused pcap excerpts

Created from the sealed originals with `tshark -r <pcap> -Y <filter> -w <out>`. Each excerpt directory contains a `SHA256SUMS.txt`. The sealed full pcap in `raw/` remains authoritative.

| Case | Excerpt | Filter | What it shows |
|---|---|---|---|
| case01_ssh_bruteforce | `case01_ssh_22.pcap` | `tcp.port == 22` | all SSH traffic on port 22 |
| case02_web_sqli | `case02_http.pcap` | `http` | all HTTP request/response traffic |
| case02_web_sqli | `case02_outfile.pcap` | `http.request.uri contains "OUTFILE"` | INTO OUTFILE staging request |
| case02_web_sqli | `case02_csv_download.pcap` | `http.request.uri contains "customers.csv"` | customers.csv download |
| case03_dns_tunnel | `case03_dns_tunnel.pcap` | `udp.port == 53` | all DNS traffic to/from the resolver |
| case03_dns_tunnel | `case03_dnscat_queries.pcap` | `dns.qry.name contains "dnscat"` | dnscat2-tagged DNS queries |
| case04_c2_beacon | `case04_c2_8443.pcap` | `tcp.port == 8443` | all C2-port traffic |
| case04_c2_beacon | `case04_large_upload.pcap` | `tcp.port == 8443 && tcp.len > 1000` | large upload/task packets on port 8443 |

Note: for Case 03 the two excerpts are byte-identical because every DNS query in that capture carries the `dnscat.` signature — the full DNS excerpt is already tunnel-only. Case 01's excerpt contains all 107 frames because every connection is to port 22.

