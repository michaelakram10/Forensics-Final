# Case 02 — packet-level notes (Log/pcap analyst)

## Evidence

| Item | Value |
|---|---|
| File | `raw/case02.pcap` |
| SHA-256 | `e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9` |
| Packets | 203 |
| First / last packet | 2026-11-03 13:20:00.000Z / 13:22:12.874Z |
| HTTP requests / TCP connections | 17 / 3 (client ports 52110, 52112, 52140) |

## Session A — browser login (13:20:00Z, port 52110)

- Five requests on one keep-alive connection with Firefox/128.0 UA.
- `POST /login.php` carries a 44-byte cleartext body; tshark field extraction recovers `username=admin`, `password=password`, `Login=Login`.
- Response: 302 to index.php with `Set-Cookie: PHPSESSID=7f3a9c1e5b2d4a6f8e0c1b3d5a7f9e21; path=/` and `security=low`; all later requests carry the cookie.
- Zeek knows the body length (44 B) but not its content — the exact gap tshark fills.

## Session B — injection (13:21:35Z, port 52112)

- Eleven GET requests on one keep-alive connection, UA `sqlmap/1.7.11#stable (https://sqlmap.org)`.
- Progression: `id=1'` (SQL error, 4095 B response) → `OR '1'='1` (5 rows, 4159 B) → `ORDER BY 1/2/3` (3978/3978/3979 B, error on 3 ⇒ two columns) → `UNION SELECT 1,2` and `user(),database()` → `information_schema.tables` (4121 B) and `.columns` (4241 B) → `users` password hashes (4345 B) → `INTO OUTFILE '/var/www/html/dump/customers.csv'` (3978 B).
- The `INTO OUTFILE` request is visible as a URI only; its success is inferred from Session C.

## Session C — staged file download (13:22:12.874Z, port 52140)

- `GET /dump/customers.csv` with UA `curl/8.5.0` → 200, `Content-Type: text/csv`, 28,370 B.
- Zeek extracted the largest file (28,370 B) with sniffed `mime_type=text/plain`; tshark's HTTP export gives the same bytes.
- SHA-256 (both tools): `9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6`; MD5: `98e5d93bc6b74b21df42629bb7b03dfe`.
- `wc -l` = 501 (header + 500 synthetic customer rows); first line `id,first_name,last_name,email,phone,card_last4`.

## Notes

- Zeek `resp_bytes` for port 52140 is 28,607 B (payload incl. headers beyond body); HTTP body length is 28,370 B. tshark's stream byte total for the download matches Zeek's `resp_bytes`, not the body length — different measurement layers.
- No host evidence is available: cookie validity, INTO OUTFILE write and tool identity remain interpretations.
