# Case 02 — Zeek queries (TSV via `zeek-cut`, JSON via `jq`)

Working directory for TSV: `cases/case02_web_sqli/zeek/tsv`.

## Q2.1 Connections

```bash
zeek-cut -d ts id.orig_h id.orig_p id.resp_h id.resp_p service duration orig_bytes resp_bytes conn_state < conn.log
```

Output — exactly 3 rows:

```
2026-11-03T13:20:00+0000  192.168.56.10  52110  192.168.56.30  80  http  10.127434  1200  16867  SF
2026-11-03T13:21:35+0000  192.168.56.10  52112  192.168.56.30  80  http   7.074153  3305  47176  SF
2026-11-03T13:22:12+0000  192.168.56.10  52140  192.168.56.30  80  http   0.814951   184  28607  SF
```

## Q2.2 All requests in order, decoded

```bash
zeek-cut -d ts id.orig_p trans_depth method uri status_code response_body_len user_agent < http.log \
 | python3 -c "
import sys, urllib.parse as u
for l in sys.stdin:
    f = l.rstrip('\n').split('\t'); f[4] = u.unquote(f[4]); print(' | '.join(f))"
```

Output: 17 lines. Key rows (full list in `timeline/timeline.csv`):

```
13:20:01 | 52110 | 1 | GET  | /login.php | 200 | 3927 | Mozilla/5.0 ... Firefox/128.0
13:20:04 | 52110 | 2 | POST | /login.php | 302 | 0    | Mozilla/5.0 ... Firefox/128.0
13:21:35 | 52112 | 1 | GET | /vulnerabilities/sqli/?id=1' | 200 | 4095 | sqlmap/1.7.11#stable
13:21:37 | 52112 | 4 | GET | ... ORDER BY 2-- - | 200 | 3978 | sqlmap/1.7.11#stable
13:21:38 | 52112 | 5 | GET | ... ORDER BY 3-- - | 200 | 3979 | sqlmap/1.7.11#stable
13:21:41 | 52112 | 10| GET | ... UNION SELECT user,password FROM users | 200 | 4345 | sqlmap/1.7.11#stable
13:21:42 | 52112 | 11| GET | ... INTO OUTFILE '/var/www/html/dump/customers.csv' | 200 | 3978 | sqlmap/1.7.11#stable
13:22:12 | 52140 | 1 | GET | /dump/customers.csv | 200 | 28370 | curl/8.5.0
```

## Q2.3 Response-size profile of the injection session

```bash
zeek-cut id.orig_p response_body_len uri < http.log | awk '$1==52112' | sort -k2,2n | awk '{print $2}' | uniq -c
```

Observed 11 response sizes: 3978 (×3, includes ORDER BY 2 and the INTO OUTFILE response), 3979 (ORDER BY 3 error), 4016, 4031, 4095, 4121, 4159, 4241, 4345.

## Q2.4 POST body length

```bash
zeek-cut method uri request_body_len status_code < http.log | awk '$1=="POST"'
```

Output: `POST /login.php 44 302` (the guide's 43 B estimate is superseded by the measured 44 B).

## Q2.5 Extracted file

```bash
zeek-cut -d ts fuid source mime_type total_bytes md5 sha1 extracted < files.log | sort -k5,5nr | head -n 3
ls -lS extract_files | head
sha256sum extract_files/* | sort | head -n 3
```

Largest file: `total_bytes=28370`, `md5=98e5d93bc6b74b21df42629bb7b03dfe`, `sha1=7ee150370ffa4774e5255b298e293f73e5fb09be`, `mime_type=text/plain` (sniffed), extracted as `extract-1793712132.879703-HTTP-FkBLUu28jFlfXZkM2d`. Its SHA-256 equals tshark's exported `customers.csv` (`9b44747e…ca4c6`).

## Q2.6 JSON equivalents

```bash
jq -r '[(.ts|todate), .["id.orig_p"], .method, .uri, .status_code, .response_body_len, .user_agent] | @tsv' http.log
jq -r 'select(.uri|test("%27|UNION|ORDER|OUTFILE|information_schema";"i")) | .uri' http.log | wc -l
jq -r '.user_agent' http.log | sort | uniq -c
```

Output: injection-pattern count = **11**; user agents: 5× Firefox/128.0, 11× sqlmap/1.7.11#stable, 1× curl/8.5.0.
