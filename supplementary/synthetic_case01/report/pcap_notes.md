# Case 01 — packet-level notes (Log/pcap analyst)

## Evidence

| Item | Value |
|---|---|
| File | `raw/case01.pcap` |
| SHA-256 | `09e1de1777d611debc7bbee5cbb63478c5a6c7a5aec04edccc086bcbc90b6d8e` |
| Size / packets | 213 kB / 1,401 |
| Capture duration | 131.105910 s |
| First / last packet | 2026-11-02 09:00:00.000Z / 09:02:11.105Z |
| Verified before every session | `cd raw && sha256sum -c case01.pcap.sha256` → `case01.pcap: OK` |

`capinfos` output: `tshark/capinfos.txt`; full text dump: `tcpdump/full_text_dump.txt`; conversation table: `tshark/conv_tcp.txt`.

## Stage 1 — SYN scan (09:00:00.000Z – 09:00:00.600Z)

- 13 SYNs from `192.168.56.10:51234` to 13 ports on `192.168.56.20`, fixed source port in 0.600 s.
- `192.168.56.20` answered ports 22 and 80 with SYN/ACK; scanner replied RST (half-open signature, Zeek `RSTO`/`ShR`).
- Other 11 ports answered RST/ACK (Zeek `REJ`/`Sr`).

## Stage 2 — SSH guessing burst (09:01:00.046Z – 09:01:19.420Z)

- 37 additional SYNs to port 22 (plus the scan SYN = 38 SYNs to :22).
- 36 complete SSH sessions, ~1–2 s each, four started in parallel per ~2.4 s group; mean 917 B up / 1490 B down / 15 orig pkts.
- 36 client banners `SSH-2.0-libssh_0.10.6`, server `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`.
- One encrypted auth-looking exchange per session followed by an immediate client close; individual failures are not visible (encrypted).

## Stage 3 — interactive session (09:01:22.420Z – 09:02:11.105Z)

- Client port 49302, client banner `SSH-2.0-OpenSSH_9.9p1 Debian-3` — a different client.
- 48.685 s, 165/164 packets, 4,020 B up / 25,110 B down, Zeek `auth_success=T`, `auth_attempts=1`.
- 67 client→server and 60 server→client packets of exactly 36 B (keystrokes/echoes); 13 server→client segments of 1400 B plus 612/742/910/324/250 B bursts (`tshark/interactive_pkt_sizes.txt`).
- Human-like gaps of 3–8 s between command groups. Content of commands and replies is encrypted; sizes only.

## Cross-check

`tshark/stream_bytes_zeek.txt` and `tshark/stream_bytes_tshark.txt` are byte-identical for all 37 SSH streams with payload (`diff` empty). This is the strongest independent confirmation of the Zeek byte accounting.
