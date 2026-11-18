# Case 02 — SQL Injection and Database Dump Exfiltration over HTTP

**Provenance:** synthetic Scapy reconstruction; all times UTC (`export TZ=UTC`).
Figures: `../viz/case02_web_sqli_timeline.png`, `../../report/figures/case02.mmd`.

## Summary

On 2026-11-03, 192.168.56.10 used a Firefox user-agent session to log in to
192.168.56.30:80 with `admin/password` in cleartext; the POST body was 44 bytes and
its form keys/values were recovered by tshark (`username,password,Login` /
`admin,password,Login`). The response was a 302 to `index.php` with a
`PHPSESSID` cookie and `security=low`; the cookie is reused by the 15 later
requests.

At 13:21:35Z a sqlmap-user-agent session issued 11 injection requests against
`/vulnerabilities/sqli/?id` between 13:21:35.455Z and 13:21:42.067Z. The cleartext
responses show a SQL syntax error, differentiated `ORDER BY` responses,
schema/column enumeration, five password hashes from `users`, and staging of
`/var/www/html/dump/customers.csv` with `INTO OUTFILE`. At 13:22:12.874Z a
curl-user-agent session downloaded the staged file. HTTP content is cleartext,
which is why this synthetic case has the highest proportion of Certain findings.

## Evidence inventory

| Evidence | Location | Key facts |
|---|---|---|
| Sealed pcap | `raw/case02.pcap`, `raw/case02.pcap.sha256` | SHA-256 `e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9`; sidecar `OK`; 203 packets |
| Capture metadata | `tshark/capinfos.txt` | 203 packets; 108,301 frame bytes; `108301 − 14×203 = 105459` IP bytes |
| Zeek logs | `zeek/tsv/{conn,http,files}.log` | 3 TCP connections, 17 HTTP requests, file-tracking rows |
| Extracted CSV (tshark) | `tshark/http_objects/customers.csv` | 28,370 B; 501 lines; SHA-256 `9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6`; MD5 `98e5d93bc6b74b21df42629bb7b03dfe` |
| Extracted CSV (Zeek) | `zeek/tsv/extract_files/extract-1793712132.879703-HTTP-FkBLUu28jFlfXZkM2d` | Same SHA-256 as the tshark export |
| Human-readable dump | `tcpdump/full_text_dump.txt` | tcpdump rendering of the sealed pcap |
| Reconciliation | `report/verify_counts.md`, `report/verification.md` | 3/3 flows, 203/203 packets, 105,459/105,459 IP bytes; 7 claim checks |
| Timeline | `timeline/timeline.csv` | 17 UTC rows with `http.log` uid/depth evidence refs |

## Reconstructed timeline (from timeline/timeline.csv)

The CSV contains 17 rows; the key reconstruction is:

| UTC | Event | Evidence |
|---|---|---|
| 13:20:04.205 | `POST /login.php` → 302; cleartext credentials in the 44-byte body | `CrducnvRNv7KuzKrl` depth=2 |
| 13:21:35.455 | First SQLi-pattern request: `id=1'` → 200 (4,095 B body) | `CvcBkIXeguzV9SJS4` depth=1 |
| 13:21:38.240 | `ORDER BY 3` → 200 (3,979 B body) | `CvcBkIXeguzV9SJS4` depth=5 |
| 13:21:39.342 | `UNION SELECT user(),database()` → 200 (4,031 B body) | `CvcBkIXeguzV9SJS4` depth=7 |
| 13:21:40.199 | `information_schema.tables` enumeration → 200 (4,121 B body) | `CvcBkIXeguzV9SJS4` depth=8 |
| 13:21:40.611 | `information_schema.columns` enumeration → 200 (4,241 B body) | `CvcBkIXeguzV9SJS4` depth=9 |
| 13:21:41.321 | `UNION SELECT user,password FROM users` → 200 (4,345 B body) | `CvcBkIXeguzV9SJS4` depth=10 |
| 13:21:42.067 | `INTO OUTFILE '/var/www/html/dump/customers.csv'` staging via `CONCAT_WS(...)` → 200 (3,978 B body) | `CvcBkIXeguzV9SJS4` depth=11 |
| 13:22:12.874 | `GET /dump/customers.csv` → 200 (28,370 B body) | `CkvyuC85Qc7Avk4ak` depth=1 |

## Findings with ratings

The full finding rows below are copied from `../../report/confidence_matrix.md`.
F2.7 is split into the observation (7a) and the inferred use (7b).

| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F2.1 | Target is 192.168.56.30:80, Apache/2.4.58 (Debian) | T1190 | **Certain** | Cleartext `Server:` header; `conn.log` service=http | Header visible in Zeek HTTP metadata and tshark. |
| F2.2 | Credentials `admin` / `password` sent in cleartext to /login.php | T1078.001 | **Certain** | tshark `urlencoded-form.key/value` → `username,password,Login` = `admin,password,Login`; Zeek `request_body_len=44` | Body content visible in tshark; Zeek independently confirms the 44-byte body. |
| F2.3 | The login succeeded and a session cookie was issued | T1078.001 | **Likely** | 302 to index.php with Set-Cookie PHPSESSID/security=low; 15 later requests carry the cookie | Redirect + reuse strongly imply success; server-side state is not visible. |
| F2.4 | The `id` parameter of /vulnerabilities/sqli/ was injected 11 times | T1190 | **Certain** | 11 decoded URIs in `http.log` (depths 1–11); tshark count of URIs containing `%27` = 11 | Payload strings are cleartext and reproduced by both tools. |
| F2.5 | The injection worked: SQL syntax error, extra rows and differentiated ORDER BY responses | T1190 | **Certain** | response bodies 4095–4345 B; ORDER BY 3 (3979 B) differs from ORDER BY 2 (3978 B); error text in cleartext responses | Response content visible in the artifacts. |
| F2.6 | The attacker determined the column count is 2 | T1190 | **Likely** | ORDER BY 2 normal, ORDER BY 3 error, UNION SELECT 1,2 succeeds | Responses observed; the inference about attacker knowledge is an interpretation. |
| F2.7a | Schema names and five password hashes were returned to the attacker | T1213 *(consistent with)* | **Certain** | 4345 B response to `UNION SELECT user,password FROM users`; 4121/4241 B information_schema responses | Response bodies contain the data in cleartext. |
| F2.7b | That returned data was actually used by the attacker | T1213 *(consistent with)* | **Likely** | Subsequent enumeration and staged dump requests | Sequence is suggestive; no host-side evidence of use. |
| F2.8 | An automated tool consistent with sqlmap was in use | n/a | **Likely** | `User-Agent: sqlmap/1.7.11#stable (https://sqlmap.org)`; 0.4–0.9 s cadence | UA can be forged; timing is consistent but not conclusive. |
| F2.9 | A dump file was written to the web root via INTO OUTFILE | T1074.001 | **Likely** | URI contains `INTO OUTFILE '/var/www/html/dump/customers.csv'`; 30 s later GET of that path returns 200 | Write success is not directly visible; availability strongly implies it. |
| F2.10 | customers.csv (28,370 B, 500 rows + header) was downloaded by 192.168.56.10 | T1048.003 | **Certain** | `http.log`, `files.log`, Zeek extraction and tshark HTTP export; both SHA-256 = `9b44747e…ca4c6`, MD5 = `98e5d93b…3dfe` | File reassembled by two tools with identical hashes; 501 lines counted. |

**Confidence counts:** Certain 6 (F2.1, F2.2, F2.4, F2.5, F2.7a, F2.10);
Likely 5 (F2.3, F2.6, F2.7b, F2.8, F2.9); Inferred 0.

## Cross-tool verification (from verification.md)

`report/verify_counts.py` reconciles Zeek and tshark with zero deltas:

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows | 3 | 3 | 0 | CONFIRMED |
| Packets | 203 | 203 | 0 | CONFIRMED |
| IP bytes | 105459 | 105459 | 0 | CONFIRMED |

The claim-by-claim checks in `report/verification.md` cover 7 claims: V-01 three
TCP handshakes; V-02 17 HTTP requests; V-03 cleartext credentials (Zeek supplies
the 44-byte body length, tshark the content); V-04 11 injection URIs containing
`%27`; V-05 byte-identical CSV from both extraction tools; V-07 the 28,370-byte
download response. V-06 is DISCREPANT-EXPLAINED: Zeek sniffs `text/plain` while
the HTTP header says `text/csv`; both are correct for what they measure. No
CHALLENGED findings remain.

## Data moved

- Login: a 44-byte cleartext form body containing `admin`, `password` and
  `Login`; a 302 to `index.php` with `PHPSESSID`/`security=low` cookie.
- Injection responses: 4,095–4,345 B bodies for the data-returning requests;
  `ORDER BY 2` (3,978 B) differs from `ORDER BY 3` (3,979 B), and
  `UNION SELECT 1,2` succeeds (4,016 B).
- Exfiltrated file: `customers.csv`, 28,370 B, 501 lines, fields
  `id,first_name,last_name,email,phone,card_last4`, synthetic
  `userNNNN@example.test` records. The Zeek and tshark copies have identical
  SHA-256 and MD5 values.

## Limitations

- **No server-side evidence:** cookie validity and `INTO OUTFILE` write success
  are inferred from subsequent requests, not observed server state; actual use
  of the returned schema/password data is likewise inferred (F2.7b).
- **Tool identity is not Certain:** the `sqlmap/1.7.11#stable` User-Agent can be
  forged; the 0.4–0.9 s cadence is consistent with automation but not conclusive
  (F2.8).
- **Cleartext only:** all claims here come from HTTP headers/bodies and Zeek
  metadata; no endpoint, disk or process evidence accompanies the pcap.
- **Synthetic capture:** this is a Scapy reconstruction, not a capture of a real
  victim; it must not be described as real tool traffic.
- **No `weird.log`:** Zeek 9.0.1 produced none on this synthetic case; the
  absence is recorded rather than hidden.
- **Manual-guided analysis:** the exercise material was available to the
  analyst; no blind or "frozen before unsealing" claim is made.
