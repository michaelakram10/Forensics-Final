# Case 02 — SQL Injection and Database Dump Exfiltration over HTTP

## 4.1 Summary

On 2026-11-03, 192.168.56.10 used a Firefox UA to log in to 192.168.56.30:80 with `admin/password` in cleartext (44-byte POST body recovered by tshark), then at 13:21:35Z a sqlmap-UA session issued 11 injection requests against `/vulnerabilities/sqli/?id`, enumerating the schema and five password hashes and staging `customers.csv` with `INTO OUTFILE`. At 13:22:12.874Z a curl-UA session downloaded the 28,370-byte file (500 synthetic rows plus header); Zeek and tshark extracted byte-identical copies (SHA-256 `9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6`). Figures: `../viz/case02_web_sqli_timeline.png`, `../../report/figures/case02.mmd`.

## 4.2 Evidence inventory

| File | SHA-256 / note |
|---|---|
| `raw/case02.pcap` | `e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9` (203 packets) |
| `zeek/tsv/{conn,http,files}.log` | 3 / 17 / many rows |
| `tshark/http_objects/customers.csv` | SHA-256 `9b44747e…ca4c6`, MD5 `98e5d93b…3dfe`, 501 lines |
| `zeek/tsv/extract_files/extract-1793712132.879703-HTTP-FkBLUu28jFlfXZkM2d` | same SHA-256 |

## 4.3 Reconstructed timeline

`../timeline/timeline.csv` has 17 rows. Key events: 13:20:04.205 login POST (302 + cookie); 13:21:35.455 first probe; 13:21:38.240 ORDER BY 3 error; 13:21:40 information_schema enumeration; 13:21:41.321 users dump; 13:21:42.067 INTO OUTFILE; 13:22:12.874 CSV download.

## 4.4 Findings

F2.1–F2.10 in `../../report/confidence_matrix.md`: 6 Certain, 3 Likely, 1 mixed (F2.7). ATT&CK T1190 (exploit), T1078.001 (valid credentials), T1074.001 (local data staging, Likely), T1048.003 (exfiltration over alternative protocol — HTTP here; Certain for the transfer), T1213 consistent with for data from information repositories.

## 4.5 Cross-tool verification

`verification.md` + `verify_counts.md`: all quantitative claims CONFIRMED; one DISCREPANT-EXPLAINED for MIME type (Zeek sniffs `text/plain`; HTTP header says `text/csv`). All three reconciliation rows CONFIRMED.

## 4.6 Data moved

`customers.csv`: 28,370 B, 501 lines, fields `id,first_name,last_name,email,phone,card_last4`, synthetic `userNNNN@example.test` records. Both extraction tools agree on SHA-256 and MD5.

## 4.7 Limitations

No server-side evidence: cookie validity, INTO OUTFILE write success and actual tool identity are inferred. The User-Agent is spoofable. All HTTP content is cleartext, which is why this case has the highest proportion of Certain findings.
