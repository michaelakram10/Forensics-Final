# Case 02 — cross-tool verification (tshark & tcpdump)

Setup: `PCAP=$PWD/cases/case02_web_sqli/raw/case02.pcap`; hash verified (`case02.pcap: OK`).

## Automated reconciliation

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows | 3 | 3 | 0 | CONFIRMED |
| Packets | 203 | 203 | 0 | CONFIRMED |
| IP bytes | 105459 | 105459 | 0 | CONFIRMED |

Sanity: `108301 − 14×203 = 105459`.

## Claim-by-claim table

| # | Claim | Zeek evidence | Second-tool command → result | Status | Δ / explanation |
|---|---|---|---|---|---|
| V-01 | 3 TCP handshakes / connections | 3 `conn.log` rows (52110, 52112, 52140) | `tshark -r $PCAP -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.srcport` → 52110, 52112, 52140 | CONFIRMED | none |
| V-02 | 17 HTTP requests | 17 `http.log` rows | `tshark -r $PCAP -Y http.request \| wc -l` → 17 | CONFIRMED | none |
| V-03 | Cleartext credentials | `request_body_len=44` on POST | `tshark -r $PCAP -Y 'http.request.method=="POST"' -T fields -e urlencoded-form.key -e urlencoded-form.value` → `username,password,Login` / `admin,password,Login` | CONFIRMED | Zeek sees length only; tshark supplies content |
| V-04 | 11 injection requests | 11 URIs matching `%27`/UNION/ORDER/OUTFILE | `tshark -r $PCAP -Y 'http.request.uri contains "%27"' \| wc -l` → 11 | CONFIRMED | none |
| V-05 | Downloaded CSV identical in both tools | Zeek `files.log` md5 `98e5d93b…3dfe`, sha256 `9b44747e…ca4c6`, 28370 B | `tshark --export-objects http,...` + `sha256sum` → same sha256 and md5; `wc -l` → 501 | CONFIRMED | none |
| V-06 | MIME type | `files.log mime_type=text/plain` | `http.content_type=text/csv` | DISCREPANT-EXPLAINED | Zeek sniffs content (CSV has no magic number); tshark reads the HTTP header. Both are correct for what they measure. |
| V-07 | Response body size of the download | `response_body_len=28370` | tshark `http.content_length_header` → 28370 | CONFIRMED | none |

Saved outputs: `tshark/http_objects/customers.csv`, `tshark/customers_tshark.sha256`, `tshark/customers_zeek.sha256`, `tshark/capinfos.txt`, `tcpdump/full_text_dump.txt`.

No CHALLENGED findings: every quantitative Zeek claim was reproduced by tshark. The only apparent mismatch (MIME type) is explained by the different measurement layer and documented rather than hidden.
