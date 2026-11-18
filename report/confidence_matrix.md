# Forensic Confidence Rating Matrix — Project 09

**Committed:** 2026-11-18. Ratings are based solely on artifacts: pcap bytes, Zeek logs,
tshark/tcpdump output and derived timelines, recorded under `cases/*/`. The exercise was
**manual-guided** (`project.md` was available to the analyst); no claim that these
ratings were "frozen before unsealing" or that ground-truth agreement proves blind
accuracy is made. Rubric and downgrade rules: `report/methodology.md` §5.

Mixed ratings have been split into separate observation/interpretation rows so every
row carries exactly one rating.

## Case 01 — SSH sessions on loopback (REAL capture)

| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F1.1 | Three completed TCP SSH sessions from loopback to `127.0.0.1:22`; all `SF`, 107 frames, 15,916 IP bytes | n/a | **Certain** | `conn.log` 3 rows; `tshark/conv_tcp.txt`; `report/verify_counts.md` | Addresses, ports, states and counts directly visible and reproduced by both tools (3/3 flows, 107/107 packets, 15,916/15,916 IP bytes). |
| F1.2 | Identical plaintext banners in all sessions: client `SSH-2.0-libssh_0.12.2` ×3, server `SSH-2.0-OpenSSH_10.6p1 Debian-1` ×3; same algorithms and host key `SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn` | n/a | **Certain** | `ssh.log`, `software.log`, `tshark/ssh_banners.txt` | Banners/algorithms are cleartext and identical in Zeek and tshark. |
| F1.3 | Short session (client port 34416): 0.120797 s, 13/12 pkts, 1,227/1,741 B payload, one encrypted exchange then client FIN; Zeek `auth_attempts=0`, `auth_success` unset | n/a | **Certain** | `conn.log` uid `CF3dQ73otQFUMGzMMi`, `ssh.log`, frames 1–25 | Timing, counters and logged heuristic values are measured; payload not interpreted. |
| F1.4 | Two long sessions (34430, 54844): 19.858788 / 14.196392 s, 18/24 and 17/23 pkts, 1,679/2,077 and 1,603/1,977 B payload | n/a | **Certain** | `conn.log`, `tshark/stream_bytes_diff.txt`, `packet_histogram_long.txt` | Sizes and durations measured and cross-tool identical (18/18 per-stream counters match). |
| F1.5 | Both long sessions contain repeated encrypted authentication-like exchanges; Zeek records `auth_attempts=5` for each | T1110.001 *(consistent with)* | **Likely** | `ssh.log` 5/5; tshark 52→84 B pairs (6 and 5) | Zeek's counter is a heuristic over encrypted packets; pairs do not map 1:1. Not a burst of many short sessions. |
| F1.6 | First long session ends with `auth_success=F` and client FIN after a final 76 B server packet — consistent with failed authentication | T1110.001 *(consistent with)* | **Likely** | `ssh.log` uid `CPbK9Z6ezH8vbIQn1`; frames 64, 65, 71 | Failure indication is heuristic + teardown; encrypted payload cannot confirm the reason. |
| F1.7 | Second long session ends with `auth_success=T`, final 92 B client / 28 B server exchange and orderly FINs — consistent with successful SSH login | T1021.004, T1078 *(consistent with)* | **Likely** | `ssh.log` uid `CIkYPK3CLHxdbW23vh`; frames 101–107 | Strong metadata/heuristic indicators; no credential, user or host-side evidence. |
| F1.8 | Specific automation tool, credentials, command names and host effects cannot be determined; `libssh` is a library, not a tool identity | n/a | **Inferred** | `ssh.log` banners; `tcpdump/full_text_dump.txt` encrypted records | Only the library banner is visible; naming a tool or decrypting commands exceeds the artifacts. |
| F1.9 | No port scan, no RSTs, no non-22 destination and no burst of many short sessions in this capture | n/a | **Certain** | 3 `conn.log` rows, all `SF`; `tshark/tcp_flags.txt` 0 RST / 3 client SYNs | The 107-frame file is complete; no such burst is present. |

## Case 02 — SQL injection and CSV exfiltration over HTTP (synthetic)

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

## Case 03 — dnscat2 DNS tunnel on loopback (REAL capture)

| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F3.1 | dnscat2 C2 tool identified from the `dnscat.` protocol signature | T1071.004, T1572 | **Certain** | 445/445 Zeek `dns.log` queries begin `dnscat.`; `tshark -e dns.qry.name`; `report/decode_dnscat2.py` (0 non-hex labels) | Direct signature match in every query is stronger than generic statistics, which only support the finding. |
| F3.2 | One persistent loopback UDP flow (127.0.0.1:44651→127.0.0.1:53) for 298.506573 s | T1071.004 | **Certain** | Zeek `conn.log` uid `Chubce1wik6p4KDZeg`, 445/445 pkts, duration 298.506573; tshark `udp.stream`=0 only | Directly measured by both tools with zero deltas. |
| F3.3 | Covert channel carried in CNAME/MX/TXT records with hex labels | T1572 | **Certain** | qtypes CNAME 164 / MX 150 / TXT 131 (Zeek and tshark agree); 445 unique names; name length 41–240 | Unusual RR types plus hex-only labels observed directly; 274 type transitions show mixed rotation. |
| F3.4a | Two distinct session-marker byte values present in first labels | T1572 | **Certain** | `decode_dnscat2.py`: bytes[3:5] `0xbb73`×263 (frames 1–803), `0x9658`×182 (frames 241–889) | Direct byte-level measurement from tshark-derived extraction. |
| F3.4b | Overlapping markers suggest two concurrent logical channels | T1572 | **Likely** | Same markers coexist across frames 241–803 | Interpretation of F3.4a; encryption prevents confirming two independent sessions. |
| F3.5 | Regular automated beaconing cadence | T1071.004 | **Likely** | 445 queries / 298.5 s ≈1.49/s; intervals mean 0.672 s, median 0.554 s; 160/444 in 0.9–1.1 s | Machine-like periodicity consistent with an automated tunnel client, not a direct artifact. |
| F3.6 | Maximum-length name burst suggests batched data flush | T1048 | **Likely** | Frames 281/283 = 240-char names (115 bytes), frame 285 = 181 chars, all within ~104 ms at 18:27:31Z | Size spike consistent with data/key-exchange-sized messages; content unconfirmable. |
| F3.7 | Encrypted dnscat2 payload; only structure recoverable | T1573, T1027 | **Certain** | Structured framing (varying nonce bytes, byte[2]=0x01×439, two session markers); no key in pcap; plaintext absent | Encryption and absence of key material are directly established limits; no content claimed. |
| F3.8 | Bidirectional volume pattern indicates interactive C2 rather than bulk one-way exfiltration | T1071.004 | **Inferred** | resp/orig L7 = 52,063/27,322 ≈1.9; hex-derived query/answer 8,090/8,067 bytes near-symmetric | Encrypted content prevents definitive data-movement classification. |
| F3.9 | Tunnel still open when capture ended | T1071.004 | **Inferred** | Last pair frames 889/890 at 18:30:23.513/.514; `conn_state=SF`, duration matches capture; no distinguishable close marker | Absence of teardown plus capture boundary suggests active tunnel at stop. |
| F3.10 | Polling rate rises from ≈1.01 to ≈2.06 queries/s at t=118.8 s and returns to ≈1.01 queries/s at t=256.0 s; likely two dnscat2 sessions polling rather than one client speeding up | T1071.004, T1572 | **Likely** | Zeek `dns.log`: 120 queries / 118.8 s, 282 / 137.2 s, 43 / 42.5 s; second marker `0x9658` at frame 241, t=118.813 s (18:27:23.821Z) | Rates and the new marker are measured; the one→two→one session count is inferred from the doubling. No console log was retained to confirm. |

## Case 04 — periodic TLS beaconing (synthetic)

| ID | Finding | ATT&CK | Rating | Evidence | Justification |
|---|---|---|---|---|---|
| F4.1 | 192.168.56.40 connected to 203.0.113.50:8443 22 times (20 answered, 2 unanswered) and to 203.0.113.51:8443 24 times | T1071.001 | **Certain** | `conn.log` groups 20+2 SF/S0 and 24 SF; tshark 50 SYNs to 8443, 22 streams to .50, 20 SYN/ACKs | Counts reproduced by both tools. |
| F4.2a | Connections are periodic: primary median 56.6 s (MAD 3.5 s), backup median 57.1 s (MAD 2.4 s) | n/a | **Certain** | `beacon_stats.py`; 45 intervals from 46 first-SYN timestamps: mean 57.58 s, median 56.91 s (excluding the 6.00 s follow-up: n=44, mean 58.75 s, median 57.02 s) | Regularity measured twice; this row records the measurement only. |
| F4.2b | The periodic pattern is consistent with C2 beaconing | T1029 *(consistent with)* | **Likely** | Same statistics plus fixed sizes and non-standard port | Classification rests on regularity + metadata, not on readable payload. |
| F4.3 | Traffic is TLS 1.2 on non-standard port 8443 with SNI `updates.cdn-lab.test` | T1571, T1573 | **Certain** | `ssl.log` 44 rows: TLSv12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, that SNI; tshark ClientHello fields | Plaintext handshake fields, both tools. |
| F4.4 | Payload content is not determinable | T1573 | **Certain** | only Application Data records after handshake; random synthetic ciphertext | By definition outside the artifacts. Note: synthetic TLS omits Certificate; Zeek 9.0.1 reports `established=T` here. |
| F4.5 | After two unanswered primary attempts, the host switched to .51 with the same SNI and byte pattern | T1008 | **Likely** | S0 rows at 14:19:20.508Z and 14:20:15.456Z with `orig_pkts=3`; first .51 session at 14:21:04.997Z; identical SNI/sizes | Identical metadata suggests one implant; another host could imitate the pattern. |
| F4.6 | Beacon 8 delivered a ~4.2 KB server→client response and a ~2.3 KB upload followed 6 s later | T1105 *(consistent with)* | **Inferred** | 14:06:59.317Z resp_bytes=4219; 14:07:05.317Z orig_bytes=2302 | Direction and size asymmetry suggest tasking/result, but contents are unknown. |
| F4.7a | 86,263 B left the host in one session to .51 | n/a | **Certain** | `conn.log` orig_bytes=86263 at 14:31:37.763Z; tshark client-byte diff matches for all 44 streams | Volume measured twice; this row records the measurement only. |
| F4.7b | That upload was exfiltration | T1041 | **Inferred** | Same volume plus regular beacon timing | Purpose is not visible in encrypted traffic. |
| F4.8 | The six sessions to 198.51.100.20:443 (SNI `www.example.test`) are unrelated to the C2 | n/a | **Likely** | 6 sessions, different SNI/IP/port, large downloads (~100 KB median), irregular absolute timing | Differences are clear, but unrelatedness cannot be proven. |

## Consolidated counts

| Case | Certain | Likely | Inferred | Total |
|---|---:|---:|---:|---:|
| 01 (real) | 5 | 3 | 1 | 9 |
| 02 (synthetic) | 6 | 5 | 0 | 11 |
| 03 (real) | 5 | 4 | 2 | 11 |
| 04 (synthetic) | 5 | 3 | 2 | 10 |
| **Total** | **21** | **15** | **5** | **41** |
