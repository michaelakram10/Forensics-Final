# Flow-export reconciliation

An independent NetFlow export was initially unavailable (`nfpcapd`/`nfdump`,
`softflowd` and `argus` absent; no passwordless sudo at the time), but `nfdump`
1.7.10-1 was later installed and `nfpcapd`/`nfdump` 1.7.10-release produced real
exporter records from all four sealed pcaps under `cases/*/netflow/`. The flow CSVs
under `cases/*/flows/` therefore remain exports of Zeek `conn.log` (a bidirectional
flow log), **not** NetFlow exporter records. The independent records and their
reconciliation are in `report/netflow_reconciliation.md`. The independent column
below is tshark's TCP/UDP stream count from the sealed pcap, so this comparison is
still a genuine cross-tool check.

| Case | Zeek conn.log rows | Flow CSV rows | tshark streams | Status |
|---|---:|---:|---:|---|
| case01_ssh_sessions | 3 | 3 | 3 | CONFIRMED |
| case02_web_sqli | 3 | 3 | 3 | CONFIRMED |
| case03_dns_tunnel | 1 | 1 | 1 | CONFIRMED |
| case04_c2_beacon | 52 | 52 | 52 | CONFIRMED |

Status compares the flow CSV row count to tshark's stream count. A mismatch would indicate a flow-logging or stream-tracking difference; see each case's `report/verification.md` for the byte-level reconciliation.

## Update (2026-11-18T21:07:05Z)

Re-checked the second review's A2 requirement. Exact commands run:

```console
$ which nfpcapd nfdump softflowd argus ra
nfpcapd not found
nfdump not found
softflowd not found
argus not found
ra not found

$ sudo -n true
sudo: a password is required

$ sudo -n apt-get install -y nfdump
sudo: a password is required
```

Exit code of the last command: 1. No independent flow exporter could be run,
so no `cases/<case>/netflow/` folder and no `report/netflow_reconciliation.md`
were created; no flow output was fabricated. The "Zeek-derived, not NetFlow"
wording in this file, in `report/methodology.md` Sections 2 and 4.4, and in
Appendix E of `report/FINAL_REPORT.md` remained accurate at that time. This
attempt was later superseded by the successful install and export described below.

## Independent nfdump export (2026-11-18T21:21:08Z)

`sudo apt install nfdump` succeeded with the operator's password; apt installed
`nfdump_1.7.10-1`, providing `/usr/bin/nfpcapd`, `/usr/bin/nfdump` and
`/usr/bin/nfcapd`, all version 1.7.10-release. Each sealed pcap was read with
`nfpcapd -r <pcap> -w cases/<case>/netflow -I <caseNN>`; each resulting
`nfcapd.*` file was exported with `nfdump -r <file> -o csv -N` and
`nfdump -r <file> -o null -N` into `cases/<case>/netflow/export/`.

Packet and byte totals match Zeek and tshark exactly for all four cases; flow
counts differ because NetFlow records are unidirectional. Full table, commands
and explanations: `report/netflow_reconciliation.md`. The version output is
recorded in `report/tool_versions.md`.
