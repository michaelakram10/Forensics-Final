# Independent NetFlow reconciliation

**Tool:** `nfpcapd` / `nfdump` 1.7.10-release (apt package `nfdump` 1.7.10-1),
installed on 2026-11-18. Exact version output:

```text
nfdump: Version: 1.7.10-release options: LZ4 ZSTD BZIP2 date: Mon Sep 7 17:39:23 CEST 2026
nfpcapd: Version: 1.7.10-release options: LZ4 ZSTD BZIP2 date: Mon Sep 7 17:39:23 CEST 2026
```

The four sealed pcaps were read **read-only**; no `raw/` or `supplementary/`
file was changed. New output is under `cases/<case>/netflow/`:

- `nfcapd.*` — flow records written by `nfpcapd -r <pcap> -w cases/<case>/netflow -I <caseNN>`.
- `export/<nfcapd-file>.csv` — `nfdump -r <file> -o csv -N` text export.
- `export/<nfcapd-file>.summary.txt` — `nfdump -r <file> -o null -N` summary.

`nfpcapd` rotates output files every five minutes, so Case 03 produced 2
`nfcapd.*` files and Case 04 produced 9; Cases 01 and 02 produced 1 each. All
exports were generated with `TZ=UTC`, so `firstSeen` values are UTC. Totals below
are the sums of the per-file CSV exports (each `nfcapd.*` file was read with a
single `-r` argument).

## Reconciliation

Zeek and tshark figures come from each case's existing
`report/verify_counts.md`; nfdump figures come from the new export CSVs.

| Case | Zeek conn.log rows | nfdump flow records | Zeek/tshark packets | nfdump packets | Δ packets | Zeek/tshark IP bytes | nfdump bytes | Δ bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| case01_ssh_sessions | 3 | 9 | 107 | 107 | 0 | 15,916 | 15,916 | 0 |
| case02_web_sqli | 3 | 9 | 203 | 203 | 0 | 105,459 | 105,459 | 0 |
| case03_dns_tunnel | 1 | 890 | 890 | 890 | 0 | 104,305 | 104,305 | 0 |
| case04_c2_beacon | 52 | 152 | 2,032 | 2,032 | 0 | 849,392 | 849,392 | 0 |

Packet and byte totals agree exactly for all four cases. This is a genuine
third-tool check: the independent exporter sees the same packets and the same
IP-layer byte volume as Zeek and tshark.

## Why the flow counts differ

- **Direction:** NetFlow records are unidirectional; Zeek `conn.log` is one
  bidirectional record per TCP connection. Cases 01 and 02 show 9 exporter
  records for 3 Zeek connections: two directions per connection plus a short
  trailing one-packet record for each (visible in the new CSVs).
- **UDP DNS:** Case 03 has 890 exporter records for 1 Zeek connection because
  each DNS query/response packet becomes its own unidirectional record; 890
  records for 890 packets.
- **Rotation / expiry:** Case 04 has 152 exporter records for 52 Zeek
  connections. Direction splitting, trailing short records and the five-minute
  `nfcapd` rotation (9 output files) account for the larger exporter count;
  the packet and byte totals still match exactly.
- **Byte definition:** nfdump `bytes` counts IP-layer bytes, matching
  `tshark ip.len` and Zeek `orig_ip_bytes + resp_ip_bytes`. It does **not**
  include the 14-byte Ethernet header; `nfpcapd`'s own "Processed bytes" line
  refers to frame bytes (e.g. 17,414 for Case 01) and differs by 14 × packets.

The Zeek-derived CSVs under `cases/*/flows/` remain in place as a convenient
one-row-per-connection view; they are still **not** NetFlow exporter records.
The records under `cases/*/netflow/` are the independent exporter output.

This check does not change the confidence ratings or the "manual-guided, not
blind" statement in the repository.
