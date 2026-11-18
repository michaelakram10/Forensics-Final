# Flow-export reconciliation

An independent NetFlow export was attempted but could not be produced: `nfpcapd`/`nfdump`, `softflowd` and `argus` are not installed, and `sudo apt install nfdump` is not possible here (no passwordless sudo). The flow CSVs under `cases/*/flows/` therefore remain exports of Zeek `conn.log` (a bidirectional flow log), **not** independent NetFlow exporter records. They give a flow-oriented view; the independent column below is tshark's TCP/UDP stream count from the sealed pcap, so the comparison is still a genuine cross-tool check.

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
Appendix E of `report/FINAL_REPORT.md` remains accurate and unchanged.
