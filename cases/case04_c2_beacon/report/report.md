# Case 04 — Periodic C2 Beaconing over TLS on a Non-Standard Port

**Provenance:** synthetic Scapy reconstruction; all times UTC (`export TZ=UTC`).
Figures: `../viz/case04_c2_beacon_timeline.png`, `../../report/figures/case04.mmd`.

## Summary

Between 14:00:00Z and 14:43:11Z, 192.168.56.40 made 46 connection attempts to
port 8443: 20 answered sessions to 203.0.113.50, two unanswered attempts, then
24 sessions to 203.0.113.51 beginning at 14:21:04.997Z. All 44 completed TLS
sessions use TLS 1.2, cipher `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and SNI
`updates.cdn-lab.test` on both IPs. The first-SYN intervals give 45 intervals
from 46 timestamps: mean 57.58 s, median 56.91 s, min 6.00 s, max 71.37 s; the
6.00 s minimum is a follow-up session, not a beacon period. Outliers are a
4,219 B response at 14:06:59.317Z, a 2,302 B upload 6 s later, and an 86,263 B
upload at 14:31:37.763Z. Six HTTPS sessions to 198.51.100.20 use a different SNI
(`www.example.test`) and large downloads.

## Evidence inventory

| Evidence | Location | Key facts |
|---|---|---|
| Sealed pcap | `raw/case04.pcap`, `raw/case04.pcap.sha256` | SHA-256 `eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675`; sidecar `OK`; 2,032 packets |
| Capture metadata | `tshark/capinfos.txt` | 2,032 packets; 877,840 frame bytes; `877840 − 14×2032 = 849392` IP bytes |
| Zeek logs | `zeek/tsv/{conn,ssl}.log` | 52 connection rows (46 to 8443 + 6 to 443); 50 SSL rows (44 C2 + 6 benign) |
| Beacon statistics | `tshark/beacon_stats.txt`, `tshark/c2_syn_times.txt` | group medians/MADs; 46 first-SYN timestamps and 45 intervals |
| Byte checks | `tshark/client_bytes_zeek.txt`, `tshark/client_bytes_tshark.txt` | per-stream client-byte diff empty for all 44 C2 streams |
| Human-readable dump | `tcpdump/full_text_dump.txt` | tcpdump rendering of the sealed pcap |
| Reconciliation | `report/verify_counts.md`, `report/verification.md` | 52/52 flows, 2,032/2,032 packets, 849,392/849,392 IP bytes; 7 claim checks |
| Timeline | `timeline/timeline.csv` | 14 UTC rows with `conn.log` uid evidence refs |

## Reconstructed timeline (from timeline/timeline.csv)

The full 14-row CSV is reproduced here with its evidence references:

| UTC | Event | Evidence |
|---|---|---|
| 14:00:00.000 | Periodic connections to 203.0.113.50:8443 begin (n=22, median 56.6 s, MAD 3.5 s) | `CdV56y1Jj5T9xaZRui` |
| 14:01:00.012 | Periodic connections to 198.51.100.20:443 begin (n=6, median 465.6 s, MAD 20.7 s) | `CfI58m13zCmEGw7Bk9` |
| 14:06:59.317 | Largest download in primary C2 group: 4,219 B | `C5gqpz4Aa2kXNo4dOh` |
| 14:07:05.317 | Largest upload in primary C2 group: 2,302 B | `CZcCOt32SubuNDwVKb` |
| 14:08:27.849 | Largest upload in benign :443 group: 981 B | `CEqWla2Lf8XswUXSpi` |
| 14:19:20.508 | Unanswered connection attempt (S0) to 203.0.113.50 | `Ck89e7W7UPPRw8Ysg` |
| 14:20:15.456 | Last periodic connection to 203.0.113.50:8443 | `Cz2UNp1sLKGWIIdHA9` |
| 14:20:15.456 | Unanswered connection attempt (S0) to 203.0.113.50 | `Cz2UNp1sLKGWIIdHA9` |
| 14:21:04.997 | Connections to 203.0.113.51:8443 begin (n=24, median 57.1 s, MAD 2.4 s) | `CM7JGD2eItvzXA2eNf` |
| 14:21:04.997 | Largest download in backup C2 group: 227 B | `CM7JGD2eItvzXA2eNf` |
| 14:31:37.763 | Largest upload in backup C2 group: 86,263 B | `CFT1n63MPYbNI0Whnl` |
| 14:35:05.067 | Largest download in benign :443 group: 149,555 B | `CbLT901ANVTfCYeqj9` |
| 14:43:10.951 | Last periodic connection to 203.0.113.51:8443 | `CUay7R2A7Ksx0nhEDc` |
| 14:43:11.364 | Last periodic connection to 198.51.100.20:443 | `CBiDz02H2OjCR6O9J3` |

Timing summary by group:

| Group | n | mean | median | stdev | CV | MAD | S0 | med orig B | med resp B |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| .50:8443 | 22 | 57.9 | 56.6 | 13.2 | 0.23 | 3.5 | 2 | 578 | 227 |
| .51:8443 | 24 | 57.7 | 57.1 | 4.9 | 0.09 | 2.4 | 0 | 594 | 227 |
| benign :443 | 6 | 506.3 | 465.6 | 157.6 | 0.31 | 20.7 | 0 | 793 | 99855 |

## Findings with ratings

The full finding rows below are copied from `../../report/confidence_matrix.md`.
F4.2 and F4.7 are split into observation/interpretation rows.

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

**Confidence counts:** Certain 5 (F4.1, F4.2a, F4.3, F4.4, F4.7a);
Likely 3 (F4.2b, F4.5, F4.8); Inferred 2 (F4.6, F4.7b).

## Cross-tool verification (from verification.md)

`tools/verify_counts.py` reconciles Zeek and tshark (output: `report/verify_counts.md`) with zero deltas:

| Metric | Zeek | tshark | Delta | Status |
|---|---:|---:|---:|---|
| Flows | 52 | 52 | 0 | CONFIRMED |
| Packets | 2032 | 2032 | 0 | CONFIRMED |
| IP bytes | 849392 | 849392 | 0 | CONFIRMED |

The 7 claim checks in `report/verification.md` are all CONFIRMED: V-01 50 SYNs
to 8443 (44 sessions + 2 failed attempts × 3 SYNs) and 22 primary/24 backup
streams; V-02 20 SYN/ACKs from the primary; V-03 the same SNI on 44 TLS
sessions; V-04 the first-SYN interval statistics; V-05 empty per-stream client
byte diffs for all 44 C2 streams; V-06 86,263 B on client port 49534;
V-07 two S0 attempts before the first .51 session at 14:21:04.997Z. Differences
were definitional (Ethernet header, port filter, tshark 4.6 flag formatting),
not contradictions.

## Data moved

- Typical C2 beacon: 578–594 B client→server and 227 B server→client.
- Tasking/response outlier: 4,219 B down at 14:06:59.317Z followed by 2,302 B
  up 6 s later.
- Largest upload: 86,263 B from 192.168.56.40 to 203.0.113.51 at
  14:31:37.763Z; byte volume is Certain, its classification as exfiltration is
  Inferred.
- Six benign :443 sessions have a median 99,855 B response and a different SNI;
  they are treated as unrelated (Likely), not as C2.
- TLS Application Data is unreadable; no content, command, file or tasking
  purpose can be recovered from the capture.

## Limitations

- **Encrypted payload:** only handshake fields, sizes and timing are visible.
  The synthetic TLS omits a Certificate message; Zeek 9.0.1 nevertheless
  reports `established=T`, and no chain fingerprints are available.
- **No host evidence:** there are no process, disk or user artifacts, so a
  single implant identity (F4.5), tasking (F4.6) and exfiltration purpose
  (F4.7b) remain Likely/Inferred.
- **Timing outliers:** the primary group CV is inflated by the 6.00 s follow-up
  and the two S0 outage attempts; excluding the follow-up gives n=44, mean
  58.75 s, median 57.02 s.
- **Heuristic label:** the timeline builder labels the six benign HTTPS sessions
  "periodic" because MAD/median is small relative to their long absolute
  intervals; they are treated as benign based on SNI, port, byte asymmetry and
  absolute irregularity.
- **No `weird.log`:** Zeek 9.0.1 produced none on this synthetic case; the
  absence is recorded rather than hidden.
- **Synthetic capture:** this is a Scapy reconstruction, not a real C2 capture;
  its payload is synthetic ciphertext and must not be described as decrypted
  real traffic.
- **Manual-guided analysis:** the exercise material was available to the
  analyst; no blind or "frozen before unsealing" claim is made.
