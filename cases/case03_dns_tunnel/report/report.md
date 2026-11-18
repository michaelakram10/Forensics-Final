# Case 03 — DNS Tunneling (real dnscat2 capture)

## Summary

Case 03 contains a genuine dnscat2 DNS-tunnel capture. A single UDP flow on the
loopback interface (127.0.0.1:44651 → 127.0.0.1:53) carries 890 DNS packets over
298.506573 s: 445 queries and 445 matching responses. Every query name begins
with the `dnscat.` prefix and is composed solely of hexadecimal labels — the
dnscat2 signature, identified from the **first DNS label** `dnscat` (direct-mode
signature), not from the last two labels or generic statistics. The typical name
is 41 characters; the 240-character names occur only in short bursts. Record
types are mixed across CNAME (164), MX (150) and TXT (131), all 445 names are
unique, and the payload framing shows two overlapping session identifiers
(`0xbb73`, `0x9658`). Only structure, sizing, timing and record-type choice are
observable: dnscat2 encrypts the tunneled data, and the key is not present in the
capture, so message content is **not** recoverable.

The capture is an isolated lab recording on loopback: there are no real client or
server addresses, and no authoritative server is separately visible. All times
in this report are UTC (`export TZ=UTC`).

## Evidence inventory

| Artifact | Description | Key value |
|---|---|---|
| `raw/case03.pcap` | Primary sealed evidence | SHA-256 `e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb`; `sha256sum -c` → OK; 131,029 bytes |
| `tshark/capinfos.txt` | Capture metadata | 890 frames; 298.506573 s; 18:25:25.008145 → 18:30:23.514718 UTC |
| `tshark/dns_stats.txt` | DNS measurements | qtypes, uniqueness, length/entropy, structural extraction, no baseline |
| `tshark/dns_queries.tsv` | 445 query rows | epoch + frame number + full query name |
| `tshark/dns_answers.tsv` | 445 response rows | epoch + frame + name + qtype + answer record |
| `tshark/dnscat2_extract.txt` | Basic structural decode | 16,180 hex chars = 8,090 query bytes; 8,067 answer bytes |
| `tcpdump/full_text_dump.txt` | Human-readable packet dump | 890 packet lines (+ header) |
| `zeek/tsv/*`, `zeek/json/*` | Zeek 9.0.1 logs (regenerated) | `dns.log` 445 rows; `conn.log` 1 row |
| `zeek/queries.md` | Zeek commands and outputs | uids, qtypes, timestamps, byte join |
| `report/verify_counts.md` | Zeek ↔ tshark reconciliation | 1/1 flows, 890/890 packets, 104,305/104,305 IP bytes |
| `report/pcap_notes.md` | Evidence table, phases, byte accounting | 14-byte/frame identity |
| `report/verification.md` | Claim-by-claim verification | two tools only (Zeek + tshark) |
| `timeline/timeline.csv` | Custom 18-row evidence timeline | frame-number and dns.log evidence refs |
| `report/decode_dnscat2.py` | Structural extraction script (no decryption) | reproducible |

The synthetic former case is preserved under `supplementary/synthetic_case03/`
for reference only. Its base32 / 14,000-byte secret / `exfil-lab.test` / 202-query
claims do **not** apply to this real capture and are not repeated here.

## Reconstructed timeline

Full detail with per-row evidence refs is in `timeline/timeline.csv`.

| UTC | Event | Evidence |
|---|---|---|
| 18:25:25.008 | First query (TXT, 155 chars, 73-byte frame, marker `0xbb73`, zero sequence) | frame 1 |
| 18:25:25.144 | First response; rtt 0.136774 s (largest in capture) | frame 2 |
| 18:25:26.052 / 18:25:33.099 | First MX then first CNAME query — three record types in use | frames 3 / 19 |
| 18:27:23.820 | Second session id `0x9658` appears while `0xbb73` continues | frames 241–242 |
| 18:27:31.488–31.592 | Large burst: two 240-char names (115 bytes each) plus 181-char frame (86 bytes) | frames 281, 283, 285 |
| 18:28:11–18:28:28 | Representative steady-state middle queries | frames 445, 515 |
| 18:30:23.513 / 18:30:23.514 | Last query / last response; capture ends; `conn_state=SF` | frames 889 / 890 |

Phases: establishment (frames 1–6), steady-state tunneling with a large data
burst (7–888), and termination-by-capture-end (889–890). No explicit dnscat2
FIN/close message is distinguishable.

### Polling-rate phases (query counts from Zeek `dns.log`)

| Phase | Window (s since first query) | UTC | Queries | Rate | Reading |
|---|---|---|---:|---:|---|
| 1 | 0.0 – 118.8 | 18:25:25 → 18:27:23 | 120 | 1.01 /s | one session polling |
| 2 | 118.8 – 256.0 | 18:27:23 → 18:29:41 | 282 | 2.06 /s | two sessions polling; second handshake at t = 118.81 s (frame 241, 18:27:23.821Z) |
| 3 | 256.0 – 298.5 | 18:29:41 → 18:30:23 | 43 | 1.01 /s | back to one session |

The overall mean of ≈1.49 queries/s is therefore misleading if read as a single
client rate: each session contributes approximately **1 query/s**, and the
middle phase is consistent with two sessions polling concurrently. This is a
Likely interpretation — the rate and the second marker are measured; the session
count is inferred because no console log was retained.

## Findings

### F3.1 — dnscat2 C2 tool identified from protocol signature (Certain)
All 445/445 query names start with `dnscat.` followed by hex labels
(`report/decode_dnscat2.py`: 0 non-hex labels, 16,180 hex chars). The `dnscat.`
prefix is the dnscat2 protocol signature: this is a direct artifact match, which
is stronger evidence than generic statistics such as record-type mix or entropy.
ATT&CK: T1071.004 (Application Layer Protocol: DNS), T1572 (Protocol Tunneling).

### F3.2 — Single persistent UDP flow over loopback (Certain)
One UDP flow only, 127.0.0.1:44651 ↔ 127.0.0.1:53, uid `Chubce1wik6p4KDZeg`,
445 packets each direction, duration 298.506573 s. Confirmed by Zeek `conn.log`
and tshark `udp.stream`. ATT&CK: T1071.004.

### F3.3 — Covert channel encoded in DNS resource records (Certain)
Queries use CNAME (164), MX (150) and TXT (131) records whose names and answers
carry hex-encoded data rather than normal hostnames. All 445 names are unique;
name length 41–240 chars, mean 43.398, median 41, near-uniform hex entropy
(mean 3.967 bits/char). ATT&CK: T1572.

### F3.4a — Two distinct session-marker byte values observed (Certain)
First-label bytes[3:5] take only two values: `0xbb73` (263 queries, frames
1–803) and `0x9658` (182 queries, frames 241–889). This is a direct, measured
byte-pattern observation. ATT&CK: T1572.

### F3.4b — Markers overlap, suggesting concurrent channels (Likely)
The two markers coexist across frames 241–803, which is consistent with two
concurrent logical channels multiplexed on the one UDP flow. This is an
interpretation of the F3.4a observation, not a directly observed fact.
ATT&CK: T1572.

### F3.5 — Automated per-session polling cadence (Likely)
445 queries over 298.5 s (≈1.49/s overall), inter-query intervals mean 0.672 s /
median 0.554 s, with 160 of 444 intervals in the 0.9–1.1 s band. Read with the
phase table above, this is approximately **1 query/s per active dnscat2 session**
(≈1.01/s in phases 1 and 3, ≈2.06/s in phase 2) rather than one client changing
speed. Human DNS activity would not sustain this regularity. ATT&CK: T1071.004.

### F3.6 — Large maximum-length name burst suggests a data flush (Likely)
Frames 281 and 283 are both 240-character names (115 decoded bytes) and frame
285 is 181 characters (86 bytes), all within ~104 ms at 18:27:31 UTC and
answered in ~1 ms. The size spike is consistent with a batched data or
key-exchange-sized message, but content cannot be confirmed. ATT&CK: T1048.

### F3.7 — Encrypted payload; plaintext not recoverable (Certain)
Recovered framing shows structured fields (varying nonce/id bytes, message-type
byte 0x01 in 439 queries, session markers), but dnscat2 encrypts tunnel data
with a pre-shared secret that is absent from the pcap. Only structure — not
content — is recoverable. ATT&CK: T1573 (Encrypted Channel) / T1027.

### F3.8 — Bidirectional byte volumes indicate interactive C2 (Inferred)
Server→client L7 bytes (52,063) are about 1.9× client→server (27,322), and
hex-derived query/answer payload volumes are nearly symmetric (8,090 vs 8,067
bytes). This pattern is more consistent with an interactive remote-control
channel than a one-way bulk exfiltration stream, but encrypted content prevents
a definitive data-movement classification. ATT&CK: T1071.004.

### F3.9 — Tunnel still open at capture end (Inferred)
The final query/response pair (frames 889/890) is followed immediately by the
capture boundary; no distinguishable dnscat2 close message appears and Zeek
records `conn_state=SF` with duration exactly matching the capture. This
suggests recording stopped while the tunnel was still active, rather than a
clean session teardown being observed. ATT&CK: T1071.004.

### F3.10 — Polling rate indicates one → two → one sessions (Likely)
The measured query rate doubles at t = 118.8 s (120 queries in 118.8 s → 282 in
137.2 s, 1.01/s → 2.06/s) and returns to ≈1.01/s at t = 256.0 s (43 queries in
42.5 s). The new session marker `0x9658` first appears at t = 118.813 s
(18:27:23.821Z, frame 241), supporting the interpretation that a second session
started and later stopped. ATT&CK: T1071.004, T1572.

**Confidence counts:** Certain 5 (F3.1, F3.2, F3.3, F3.4a, F3.7) · Likely 4
(F3.4b, F3.5, F3.6, F3.10) · Inferred 2 (F3.8, F3.9). Total 11 findings
(mixed-rating observation and interpretation are kept in separate rows).

## Cross-tool verification

Exactly two measurement tools were used: **Zeek 9.0.1** and **TShark (Wireshark)
4.6.9**. (tcpdump produced only a readable dump; it is not a third measurement
tool — do not state that three tools agree.) `tools/verify_counts.py` reconciles
them with zero deltas:

| Metric | Zeek | tshark | Delta |
|---|---:|---:|---:|
| Flows | 1 | 1 | 0 |
| Packets | 890 | 890 | 0 |
| IP bytes | 104,305 | 104,305 | 0 |

14-byte/frame identity: `frame.len` total 116,765 − (14 × 890) = 104,305 =
tshark `ip.len` total = Zeek `orig_ip_bytes`+`resp_ip_bytes`. Two apparent
discrepancies are explained in `report/verification.md`: (a) `capinfos`/Zeek
banner render VM-local UTC-5 (13:25–13:30) when `TZ` is unset, while packet
epochs are UTC (18:25–18:30) — same capture; (b) Zeek's TCP-ACK-based capture-
loss notice is a benign false positive on a UDP-only flow (0.0% loss reported).

## Data moved

- Total frame bytes: 116,765; Ethernet overhead 12,460 (14 × 890); IP bytes
  104,305; IP+UDP headers 24,920 (28 × 890); L7 payload 79,385.
- Client→server (orig): 445 packets, 27,322 L7 bytes (39,782 IP bytes).
- Server→client (resp): 445 packets, 52,063 L7 bytes (64,523 IP bytes).
- Hex payload derived from query names: 8,090 bytes; from answer records: 8,067
  bytes. These are the on-the-wire encoded tunnel frames, **not** decrypted
  application data.
- No plaintext volume, file, secret or command can be attributed; any
  exfiltration quantity remains unmeasurable from this capture.

## Limitations

1. **Loopback capture:** both endpoints are 127.0.0.1; no real client/server IPs,
   MAC topology or host identity are available. No host-level attribution.
2. **UTC vs local time:** all times here are UTC with `export TZ=UTC`; tools
   with the VM's default UTC-5 rendering show 13:25–13:30 local for the same
   instants. Epoch values are authoritative.
3. **Encrypted dnscat2 payload:** the pre-shared key is absent. Only framing,
   session markers, record-type selection, sizing and timing are recoverable —
   message content, commands and any transferred files are not.
4. **No host evidence:** no process, disk, memory or user artifact accompanies
   the pcap; findings are artifact-only from network observation.
5. **Authoritative server not separately visible:** the `127.0.0.1:53` responder
   is only observed on loopback; no upstream resolver or external infrastructure
   is captured, so no domain or infrastructure attribution is possible.
6. **No baseline:** this is a single isolated flow with no legitimate DNS
   baseline; comparisons to normal DNS are qualitative only.
7. **No ground-truth console log was kept:** interpretations of the bursts and
   the one → two → one session-count change rely on traffic patterns only; no
   terminal scrollback was available to convert and compare against 18:27:23 and
   18:29:41 UTC.
