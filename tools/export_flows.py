#!/usr/bin/env python3
"""export_flows.py [case ...] -> cases/<case>/flows/caseNN_flows.csv + report/flows_reconciliation.md

These CSVs are NOT NetFlow records from a flow exporter: they are a tabular
FLOW EXPORT derived from Zeek's conn.log (itself a bidirectional flow log),
emitted in a NetFlow-like shape so the flow view can be read and reconciled
separately. Independent exporter records produced with `nfpcapd`/`nfdump`
1.7.10-release are under `cases/<case>/netflow/` and are reconciled in
`report/netflow_reconciliation.md`. Provenance is stated in each case's
flows/README.md. tshark stream counts provide the third-column reconciliation.
"""
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ["case01_ssh_sessions", "case02_web_sqli", "case03_dns_tunnel", "case04_c2_beacon"]
BASE = {"case01_ssh_sessions": "case01", "case02_web_sqli": "case02",
        "case03_dns_tunnel": "case03", "case04_c2_beacon": "case04"}
COLS = ["flow_id", "start_time_utc", "end_time_utc", "src_ip", "src_port", "dst_ip", "dst_port",
        "proto", "service", "conn_state", "orig_pkts", "resp_pkts", "orig_bytes", "resp_bytes",
        "orig_ip_bytes", "resp_ip_bytes", "duration_s"]

README_TEMPLATE = (
    "# Flow export — {case}\n\n"
    "`{base}_flows.csv` is a **tabular flow export derived from Zeek `conn.log`**. "
    "Independent NetFlow exporter records from `nfpcapd`/`nfdump` 1.7.10-release "
    "are now under `cases/<case>/netflow/` (see `report/netflow_reconciliation.md`); "
    "this CSV is still a Zeek-derived view, not a NetFlow record. Zeek `conn.log` "
    "is itself a bidirectional flow log; this CSV simply presents each connection "
    "as one flow record for readers who want a flow-oriented view. It is "
    "reconciled against tshark TCP/UDP stream counts in "
    "`report/flows_reconciliation.md`. Provenance: Zeek 9.0.1 JSON `conn.log`, "
    "generated from the sealed pcap with `tools/run_zeek.sh`.\n"
)

RECON_INTRO = """An independent NetFlow export was initially unavailable (`nfpcapd`/`nfdump`,
`softflowd` and `argus` absent; no passwordless sudo at the time), but `nfdump`
1.7.10-1 was later installed and `nfpcapd`/`nfdump` 1.7.10-release produced real
exporter records from all four sealed pcaps under `cases/*/netflow/`. The flow CSVs
under `cases/*/flows/` therefore remain exports of Zeek `conn.log` (a bidirectional
flow log), **not** NetFlow exporter records. The independent records and their
reconciliation are in `report/netflow_reconciliation.md`. The independent column
below is tshark's TCP/UDP stream count from the sealed pcap, so this comparison is
still a genuine cross-tool check."""

STATUS_LINE = ("Status compares the flow CSV row count to tshark's stream count. A mismatch "
               "would indicate a flow-logging or stream-tracking difference; see each case's "
               "`report/verification.md` for the byte-level reconciliation.")

HISTORY = """## Update (2026-11-18T21:07:05Z)

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
recorded in `report/tool_versions.md`."""


def iso(ts):
    return datetime.fromtimestamp(float(ts), timezone.utc).isoformat(timespec="milliseconds")


def tshark_streams(pcap):
    cmd = ["tshark", "-r", str(pcap), "-Y", "tcp || udp", "-T", "fields",
           "-e", "tcp.stream", "-e", "udp.stream"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    streams = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 1 and parts[0]:
            streams.add(("tcp", parts[0]))
        if len(parts) >= 2 and parts[1]:
            streams.add(("udp", parts[1]))
    return len(streams)


def export(case):
    cdir = ROOT / "cases" / case
    conn = [json.loads(l) for l in (cdir / "zeek/json/conn.log").open()]
    out = cdir / "flows" / f"{BASE[case]}_flows.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for i, c in enumerate(sorted(conn, key=lambda r: r["ts"]), 1):
            dur = float(c.get("duration", 0))
            w.writerow({
                "flow_id": f"{BASE[case]}-{i:04d}",
                "start_time_utc": iso(c["ts"]),
                "end_time_utc": iso(float(c["ts"]) + dur),
                "src_ip": c.get("id.orig_h", ""),
                "src_port": c.get("id.orig_p", ""),
                "dst_ip": c.get("id.resp_h", ""),
                "dst_port": c.get("id.resp_p", ""),
                "proto": c.get("proto", ""),
                "service": c.get("service", "-"),
                "conn_state": c.get("conn_state", ""),
                "orig_pkts": c.get("orig_pkts", 0),
                "resp_pkts": c.get("resp_pkts", 0),
                "orig_bytes": c.get("orig_bytes", 0),
                "resp_bytes": c.get("resp_bytes", 0),
                "orig_ip_bytes": c.get("orig_ip_bytes", 0),
                "resp_ip_bytes": c.get("resp_ip_bytes", 0),
                "duration_s": f"{dur:.6f}",
            })
    (cdir / "flows" / "README.md").write_text(
        README_TEMPLATE.format(case=case, base=BASE[case]))
    pcap = cdir / "raw" / f"{BASE[case]}.pcap"
    return len(conn), tshark_streams(pcap)


if __name__ == "__main__":
    rows = []
    for case in (sys.argv[1:] or CASES):
        z, t = export(case)
        rows.append((case, z, t))
        print(f"{case}: {z} Zeek flows -> flow CSV; {t} tshark streams")
    out = ["# Flow-export reconciliation", "", RECON_INTRO, "",
           "| Case | Zeek conn.log rows | Flow CSV rows | tshark streams | Status |",
           "|---|---:|---:|---:|---|"]
    for case, z, t in rows:
        out.append(f"| {case} | {z} | {z} | {t} | {'CONFIRMED' if z == t else 'DISCREPANT - explain'} |")
    out += ["", STATUS_LINE, "", HISTORY]
    (ROOT / "report/flows_reconciliation.md").write_text("\n".join(out) + "\n")
    print("wrote report/flows_reconciliation.md")
