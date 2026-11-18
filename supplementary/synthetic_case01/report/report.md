# Case 01 — Scan, SSH Brute Force and Interactive Session

## 3.1 Summary

On 2026-11-02 09:00:00Z, 192.168.56.10 probed 13 TCP ports on 192.168.56.20 from a single source port (51234) in 0.600 s; 22 and 80 answered, the other 11 rejected. At 09:01:00Z the same source opened 36 near-identical short SSH sessions with a libssh client banner (mean 917 B up / 1490 B down, 15 packets each), consistent with failed password guessing (Likely). At 09:01:22.420Z a session with a different client banner (OpenSSH_9.9p1 Debian-3) lasted 48.7 s with 165/164 packets and 25,110 B down — an interactive login (Likely). Only reply sizes are visible; command content is encrypted. Figures: `../viz/case01_ssh_bruteforce_timeline.png`, `../../report/figures/case01.mmd`.

## 3.2 Evidence inventory

| File | SHA-256 / note | Packets |
|---|---|---|
| `raw/case01.pcap` | `09e1de1777d611debc7bbee5cbb63478c5a6c7a5aec04edccc086bcbc90b6d8e` | 1401 |
| `zeek/tsv/conn.log`, `ssh.log` | 50 / 37 rows | — |
| `zeek/json/conn.log`, `ssh.log` | JSON equivalents used by jq | — |
| `tshark/stream_bytes_zeek.txt`, `stream_bytes_tshark.txt` | byte-identical, 37 streams | — |

## 3.3 Reconstructed timeline

See `../timeline/timeline.csv` (6 events). Key rows:

| Time (UTC) | Event | Evidence ref |
|---|---|---|
| 09:00:00.000 | Port scan begins: 13 ports from 51234 | conn.log uid=CNwDExWxxjJWEYX36 |
| 09:00:00.599 | Scan ends; open ports 22, 80 | conn.log uid=CgOwCB45EuBZsO13Ul |
| 09:01:00.046 | SSH burst begins: 36 short sessions | conn.log uid=CsLr113uJrfHWq9o8g .. CEt7Tu3MaruhPrS1Qc |
| 09:01:22.420 | Long session starts (48.7 s, 4020/25110 B) | conn.log uid=CNBPHlk56QfmtoJcc |
| 09:02:11.105 | Long session ends | same uid |

## 3.4 Findings

Full table with justifications: `../../report/confidence_matrix.md` (F1.1–F1.10). Summary: F1.1, F1.2, F1.4, F1.8 Certain; F1.3, F1.5, F1.7 Likely; F1.6, F1.9, F1.10 Inferred. ATT&CK: T1046 (scan), T1110.001 (consistent with, password guessing), T1021.004/T1078 (interactive login), T1087/T1057/T1049/T1005 consistent with but unproven from encrypted sizes.

## 3.5 Cross-tool verification

See `verification.md` and `verify_counts.md`: 8 claims, 7 CONFIRMED and 1 DISCREPANT-EXPLAINED (14 B/frame Ethernet header). All three reconciliation rows CONFIRMED.

## 3.6 Data moved

36 short sessions carry ~917 B up / 1490 B down each (encrypted auth attempts). The interactive session carries 4,020 B up and 25,110 B down, including 36-byte keystroke/echo packets and 13 server bursts of 1400 B. A ~2.3 KB reply is consistent with a passwd-style file but its content is not determinable.

## 3.7 Limitations

Encrypted SSH payload; Zeek's heuristic marks only the long session `auth_success=T`; synthetic KEXINIT/random ciphertext; no `weird.log` produced by Zeek 9.0.1; no host evidence.
