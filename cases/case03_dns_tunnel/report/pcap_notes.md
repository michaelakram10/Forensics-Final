# Case 03 — PCAP notes (real dnscat2 capture)

## Evidence table

| Item | Value | Source |
|---|---|---|
| File | `raw/case03.pcap` | case dir |
| SHA-256 | `e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb` | `sha256sum -c case03.pcap.sha256` → `OK` |
| Size | 131,029 bytes (131 kB) | `stat` / `capinfos` |
| Encapsulation | Ethernet, microsecond precision, snaplen 262144 | `capinfos` |
| Packets | 890 (445 queries + 445 responses) | `capinfos`, tshark, Zeek |
| First packet (UTC) | 1795026325.008145 → **2026-11-18 18:25:25.008145 UTC** | `capinfos` (TZ=UTC) |
| Last packet (UTC) | 1795026623.514718 → **2026-11-18 18:30:23.514718 UTC** | `capinfos` (TZ=UTC) |
| Duration | 298.506573 s (≈4 min 58.5 s) | `capinfos`, Zeek `conn.log` |
| Flow | 1 × UDP, 127.0.0.1:44651 ↔ 127.0.0.1:53, `udp.stream=0` | tshark, Zeek `conn.log` |
| Zeek uid | `Chubce1wik6p4KDZeg` | `conn.log` / `dns.log` |
| Query types | CNAME 164, MX 150, TXT 131 | tshark, Zeek |
| Query names | 445 total / 445 unique; `dnscat.<hex>` | tshark, Zeek |
| Name length | min 41, max 240, mean 43.398, median 41 | tshark |
| Entropy (name chars) | mean 3.967 bits/char (hex alphabet) | `dns_stats.txt` |
| Capture loss | 0 gaps / 0.0% reported; notice is TCP-ACK heuristic false positive on UDP-only capture | Zeek `capture_loss.log`, `notice.log` |

**Timezone note.** All times in this handoff are UTC (`export TZ=UTC`). With
`TZ` unset, `capinfos` and Zeek's `#open` banner render VM-local time UTC-5
(13:25–13:30 local), which is the *same* instants. The Zeek log *data* column
`ts` is a Unix epoch and is timezone-independent. The earlier `verify_counts`
note referred to those local-time renderings; they are not a different capture.

**Loopback caveat.** Both endpoints are 127.0.0.1. This is an isolated lab
capture on the loopback interface: there are no real client/server IP addresses,
no MAC-level topology, and the authoritative DNS server is not separately
visible. Attribution to a host, user or external domain is therefore impossible
from this pcap alone.

## Acquisition note (operator-reported; public-safe)

- **Who / where:** run by the `kali` operator on the isolated lab VM (the VM name
  was not recorded in the retained notes; the custody-log host is `kali`).
  Interface: `lo` (loopback).
- **Capture command:** the exact `tcpdump` command line was **not retained** in
  the operator notes. The evidence is consistent with a loopback capture filtered
  to DNS (`sudo tcpdump -i lo udp port 53 -w raw/case03.pcap`), but this is a
  reconstruction, not a verbatim record, and is not presented as exact.
- **dnscat2 setup (operator-reported):** dnscat2 was run in direct DNS mode with
  `--dns server=127.0.0.1` on the loopback resolver. The pre-shared secret is
  **omitted** (not pasted into this public repo; no secret hash was retained).
  The exact full command line was not retained. Console commands typed during
  the session were `windows`, `window -i 1`, `shell`, `ping` and `exit`; the
  second session marker at t = 118.81 s is consistent with the window/session
  switch but cannot be confirmed without console output.
- **Clock:** the VM clock was UTC−5. With `TZ` unset, tools render the capture as
  13:25–13:30 local; adding 5 h gives the authoritative UTC window 18:25–18:30
  used throughout this report.

## Phase reconstruction

| Phase | Frames | UTC window | Observation |
|---|---|---|---|
| 1. Session establishment | 1–6 | 18:25:25.008145 – 18:25:27.061236 | First query (frame 1, TXT, 155-char name, 73-byte decoded frame) carries `03 bb 73 00 00 00 00` after the 2-byte nonce — a setup/SYN-like message with zero sequence. First response at frame 2 (rtt 0.136774 s, largest RTT in capture). qtypes TXT→MX→TXT as record types begin rotating. |
| 2. Steady-state tunneling | 7–888 | 18:25:27 – 18:30:22 | 445-query stream, mostly minimal 17-byte frames (median), qtypes mixed among CNAME/MX/TXT (274 type transitions), cadence median 0.554 s with a strong ~1 s component (160/444 intervals in 0.9–1.1 s). Second session id `0x9658` appears from frame 241 (18:27:23.820768) while `0xbb73` continues to frame 803 — two overlapping logical channels. |
| 3. Large data burst | 281–286 | 18:27:31.488949 – 18:27:31.592956 | Frames 281 and 283 are the two 240-char maximum-length names (115 decoded bytes each); frame 285 is 181 chars (86 bytes). These are the largest payload frames, consistent with a data flush / key-exchange-sized messages, answered within ~1 ms. |
| 4. Termination | 889–890 | 18:30:23.513247 – 18:30:23.514718 | Last query (frame 889, MX, session `0x9658`) and last response (frame 890). Zeek `conn_state=SF` and `duration=298.506573` exactly span the capture. No explicit dnscat2 FIN/close message is distinguishable in the hex framing; the tunnel simply stops at the end of capture. |

### Polling-rate phases (queries only, relative to first query)

| Phase | Window (s) | UTC | Queries | Rate | Reading |
|---|---|---|---:|---:|---|
| 1 | 0.0 – 118.8 | 18:25:25 → 18:27:23 | 120 | 1.01 /s | one session polling |
| 2 | 118.8 – 256.0 | 18:27:23 → 18:29:41 | 282 | 2.06 /s | two sessions polling; second handshake at t = 118.81 s (frame 241) |
| 3 | 256.0 – 298.5 | 18:29:41 → 18:30:23 | 43 | 1.01 /s | back to one session |

Tool identity uses the **first label `dnscat`** of `dnscat.<hex>` (direct-mode
dnscat2 signature), not the last two labels. The typical query name is 41
characters; long names (up to 240) appear only in the short burst at frames
281/283/285. No ground-truth console log was kept, so session-count readings are
Likely, not Certain.

## Byte accounting

| Measure | Value | Derivation |
|---|---|---|
| Total frame bytes (tshark `frame.len`) | 116,765 | sum over 890 frames (`capinfos` Data size 116 kB) |
| Ethernet overhead | 12,460 | 14 bytes × 890 frames |
| Total IP bytes (tshark `ip.len`) | 104,305 | 116,765 − 12,460 = Zeek `orig_ip_bytes`+`resp_ip_bytes` (39,782 + 64,523) — delta 0 |
| Zeek L7 payload | 79,385 | `orig_bytes` 27,322 + `resp_bytes` 52,063 |
| Query-side hex payload | 8,090 bytes | 16,180 hex chars from `dnscat.` labels (445 queries) |
| Answer-side hex payload | 8,067 bytes | hex from TXT/CNAME/MX answer records (445 responses) |
| UDP+IP headers | 24,920 | 104,305 − 79,385 = 28 bytes × 890 frames |

The returned (server→client) byte volume (52,063 L7) is about 1.9× the sent
volume (27,322 L7), consistent with a tunnel carrying responses/data downstream
as well as query-side control traffic; exact content is encrypted.

## Cross-check
`tools/verify_counts.py` (saved to `report/verify_counts.md`) reconciles Zeek vs
tshark with zero deltas on flows (1/1), packets (890/890) and IP bytes
(104,305/104,305), and prints the 14-byte-per-frame identity
`116765 − 14×890 = 104305`. See `report/verification.md` for the claim-by-claim
table. The two tools used are **Zeek 9.0.1** and **TShark (Wireshark) 4.6.9**;
tcpdump is used only for the human-readable packet dump.
