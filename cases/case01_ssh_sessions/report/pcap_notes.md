# Case 01 — pcap notes (real lab capture)

All times are **UTC** (`export TZ=UTC`). The pcap is a real tcpdump capture from
an isolated lab on **loopback**: every frame is `127.0.0.1 → 127.0.0.1`. There is
no port scan and no 36-attempt brute-force burst in this file; those claims
belong to the preserved synthetic case under `supplementary/synthetic_case01/`
and are **not** evidence here.

## Acquisition note (operator-reported; public-safe)

- **Who / where:** run by the `kali` operator on the isolated lab VM (the VM name
  was not recorded in the retained notes; the custody-log host is `kali`).
  Interface: `lo` (loopback).
- **Exact capture command** recorded in the setup notes, with the output filename
  normalised to the sealed evidence name:

  ```bash
  sudo tcpdump -i lo port 22 -w raw/case01.pcap
  ```

  It was started in the background and stopped with `sudo kill $TCPDUMP_PID`.
- **What generated the sessions:** a local OpenSSH server on `127.0.0.1:22` and
  Hydra v9.7 against the same loopback address (`ssh://127.0.0.1`, `-t 1 -I`)
  with a short wordlist. Account names and wordlist contents are omitted. The
  sealed pcap itself shows only three completed sessions; the original synthetic
  exercise's 36-attempt count is **not** evidence in this capture.
- **Clock:** the VM clock was UTC−5. The local display 11:20:54–11:21:28 becomes
  16:20:54–16:21:28 UTC by adding 5 h; packet epochs and all reported times are
  UTC.

## Evidence table

| Item | Measured value | Source |
|---|---|---|
| File | `raw/case01.pcap` (19,150 bytes on disk) | `ls -l`, `capinfos` |
| SHA-256 | `771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99` | `sha256sum -c raw/case01.pcap.sha256` → `OK` |
| Packets | **107** | `capinfos`, Zeek `conn.log` sum (13+12+18+24+17+23), tshark frame count |
| Frame bytes | **17,414** | `tshark frame.len` sum (`tshark/capinfos.txt`, `verify_counts.md`) |
| IP bytes | **15,916** | `tshark ip.len` sum = Zeek `*_ip_bytes` sum |
| Ethernet identity | 17,414 − 14 × 107 = **15,916** | `verify_counts.md` sanity check |
| Capture span (capinfos) | **34.385135 s**, 2026-11-16 16:20:54.608130 → 16:21:28.993265 | `capinfos` / `tshark/frame_detail.txt` |
| First frame (epoch / UTC) | `1794846054.608130` / **2026-11-16T16:20:54.608130Z** | frame 1, `conn.log` uid `CF3dQ73otQFUMGzMMi` |
| Last frame (epoch / UTC) | `1794846088.993265` / **2026-11-16T16:21:28.993265Z** | frame 107, `conn.log` uid `CIkYPK3CLHxdbW23vh` |
| TCP conversations | **3** streams (0, 1, 2), all `127.0.0.1:ephemeral → 127.0.0.1:22` | Zeek `conn.log`, `tshark/conv_tcp.txt` |
| Connection durations (Zeek) | **0.120797 s**, **19.858788 s**, **14.196392 s** | `conn.log` |
| Host-local wall time | 11:20:54–11:21:28 (UTC−5) | `capinfos` local display; equals the UTC epochs above |
| Banners | `SSH-2.0-libssh_0.12.2` ×3; `SSH-2.0-OpenSSH_10.6p1 Debian-1` ×3 | `ssh.log`, `tshark/ssh_banners.txt` |
| TCP flags | 3 SYN, 3 SYN/ACK, 6 FIN, **0 RST** | `tshark/tcp_flags.txt` (`tcp.flags.* == True/False`) |

The "≈19.9 s" figure is the **longest connection**, not the capture span. The
whole file spans **34.385135 s**; the user-supplied "3 clusters" are the three
connection starts at 16:20:54.608130Z, 16:20:54.939960Z and 16:21:14.796806Z.

## Per-connection table

| tcp.stream | conn.log uid | client port | bytes orig/resp (TCP payload) | packets orig/resp | Zeek duration | Zeek state / history | auth_success / auth_attempts |
|---:|---|---:|---:|---:|---:|---|---|
| 0 | `CF3dQ73otQFUMGzMMi` | 34416 | 1227 / 1741 | 13 / 12 | 0.120797 s | SF / `ShADadFf` | unset (`-`) / 0 |
| 1 | `CPbK9Z6ezH8vbIQn1` | 34430 | 1679 / 2077 | 18 / 24 | 19.858788 s | SF / `ShADadFf` | `F` / 5 |
| 2 | `CIkYPK3CLHxdbW23vh` | 54844 | 1603 / 1977 | 17 / 23 | 14.196392 s | SF / `ShADadFf` | `T` / 5 |

Totals: orig 48 packets / 4,509 payload bytes / 6,709 IP bytes; resp 59 packets
/ 5,795 payload bytes / 9,207 IP bytes.

## Stage-by-stage reconstruction

### Stage 0 — capture setup
A single Ethernet/loopback interface captured 107 frames in strict timestamp
order. Every conversation terminates at port 22 on 127.0.0.1; there are no DNS,
HTTP, ICMP or non-SSH frames and no frames to any other host.

### Stage 1 — short SSH session (stream 0, uid `CF3dQ73otQFUMGzMMi`)
- f1–f3: SYN / SYN-ACK / ACK (16:20:54.608130–54.608180Z).
- f4 (16:20:54.608280Z): client banner `SSH-2.0-libssh_0.12.2` (23 B).
- f6 (16:20:54.624584Z): server banner `SSH-2.0-OpenSSH_10.6p1 Debian-1` (33 B).
- f8/f10: server/client Key Exchange Init (1,040 / 976 B); f12: client ECDH init
  (48 B); f14: server ECDH reply + New Keys + one encrypted packet (572 B);
  f15: client New Keys (16 B).
- f17/f19: one 44 B encrypted client packet and 44 B server reply; f20: 68 B
  client packet; f21/f22: 52 B server and 52 B client packets.
- f23/f24/f25: client FIN (16:20:54.723511Z), server FIN (54.728927Z), final ACK
  (54.728956Z). Zeek records this as `SF`, 0.120797 s, `auth_attempts=0`,
  `auth_success=-`.

### Stage 2 — long SSH session A (stream 1, uid `CPbK9Z6ezH8vbIQn1`)
- Starts f26 at 16:20:54.939960Z, 0.331830 s after the first SYN.
- Identical banner/KEX sequence: client banner f29 (54.940122Z), server banner
  f31 (54.961098Z), KEX f33/f35, ECDH f37/f39, New Keys f40. Negotiated
  `chacha20-poly1305@openssh.com`, `hmac-sha2-256-etm@openssh.com`,
  `curve25519-sha256`, host key `ssh-ed25519` fingerprint
  `SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn`.
- Repeating encrypted 52 B server → 84 B client pairs at 16:20:55.059953,
  59.008241, 60.982183, 64.928468, 68.874557 and 70.848695Z; gaps between
  pair starts: 3.948288 / 1.973942 / 3.946285 / 3.946089 / 1.974138 s.
- f64 (16:21:14.795393Z): final 76 B encrypted server packet; f65: client FIN
  (14.796157Z); f71: server FIN (14.798748Z); f72: final ACK (14.798787Z).
- Zeek: `SF`, 19.858788 s, 18/24 packets, 1,679/2,077 payload bytes,
  `auth_success=F`, `auth_attempts=5`.

### Stage 3 — long SSH session B (stream 2, uid `CIkYPK3CLHxdbW23vh`)
- Starts f66 at 16:21:14.796806Z — **0.649 ms after** stream 1's client FIN
  (f65) and **1.942 ms before** stream 1's server FIN (f71): the two sessions
  overlap during TCP teardown, consistent with back-to-back automated setup.
- Identical banners (f69 at 14.796943Z, f73 at 14.818663Z), KEX (f75/f77),
  ECDH (f79/f81) and New Keys (f82), same algorithms and host-key fingerprint.
- Repeating encrypted 52 B server → 84 B client pairs at 16:21:14.912492,
  18.858082, 20.833689 and 24.779803Z (gaps 3.945590 / 1.975607 / 3.946114 s).
- f101 (16:21:28.726199Z): a 92 B encrypted client packet (the last exchange);
  f103 (28.791354Z): 28 B encrypted server packet; f104: client FIN
  (28.803411Z); f105: server ACK; f106: server FIN (28.993198Z); f107: final
  ACK (28.993265Z).
- Zeek: `SF`, 14.196392 s, 17/23 packets, 1,603/1,977 payload bytes,
  `auth_success=T`, `auth_attempts=5`.

### Stage 4 — after the capture
No further frames. The capture ends 67 µs after the final ACK of stream 2.

## Cross-check notes

- `tools/verify_counts.py` (`report/verify_counts.md`): flows 3 vs 3, packets
  107 vs 107, IP bytes 15,916 vs 15,916; all **CONFIRMED**.
- Ethernet identity: `frame.len` total 17,414 − 14 × 107 = 15,916 = sum of
  `ip.len`. No VLAN tags, no padding, no non-Ethernet encapsulation.
- `tshark/stream_bytes_diff.txt`: all **18** per-stream counters (6 counters ×
  3 streams) match `conn.log` exactly.
- `tshark/conv_tcp.txt` frame counts (25/42/40) equal Zeek
  `orig_pkts + resp_pkts` for each stream.
- Flag check (`tshark/tcp_flags.txt`): exactly 3 SYNs and 3 SYN/ACKs (one per
  connection), 6 FINs (two per connection), 0 RSTs. There is no half-open scan.
- Zeek durations are measured SYN → server FIN; tshark first-to-last frame
  spans add 29/39/67 µs for the trailing ACK. This is a convention difference,
  not a data discrepancy.
- Zeek `auth_attempts=5` is an analyzer heuristic over encrypted packets; the
  packet traces show six 52/84 B pairs in stream 1 and five in stream 2, so
  packet pairs cannot be mapped 1:1 to Zeek's counter. Authentication outcome,
  credentials, commands and host effects are **not** visible in this encrypted
  SSH traffic.
- Zeek TSV and JSON runs have different UIDs (generated per run); all other
  fields agree. `evidence_ref` values in the timeline use the **TSV** UIDs.
