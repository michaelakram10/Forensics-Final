#!/usr/bin/env python3
"""verify_counts.py <case_dir_name> <pcap_basename> -> Zeek-vs-tshark reconciliation table (Markdown)."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
case, base = sys.argv[1], sys.argv[2]
cdir = ROOT / "cases" / case
pcap = cdir / "raw" / f"{base}.pcap"
conn = [json.loads(l) for l in (cdir / "zeek/json/conn.log").open()]


def tshark(flt, *fields):
    cmd = ["tshark", "-r", str(pcap), "-Y", flt, "-T", "fields"] + [x for f in fields for x in ("-e", f)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [l.split("\t") for l in out.splitlines()]


rows = tshark("tcp || udp", "frame.len", "ip.len", "tcp.stream", "udp.stream")
t_pkts = len(rows)
t_ip = sum(int(r[1]) for r in rows)
t_frame = sum(int(r[0]) for r in rows)
t_flows = len({("t", r[2]) for r in rows if r[2]} | {("u", r[3]) for r in rows if len(r) > 3 and r[3]})
z_pkts = sum(c.get("orig_pkts", 0) + c.get("resp_pkts", 0) for c in conn)
z_ip = sum(c.get("orig_ip_bytes", 0) + c.get("resp_ip_bytes", 0) for c in conn)

checks = [("Flows: Zeek conn.log rows vs tshark tcp/udp streams", len(conn), t_flows),
          ("Packets: Zeek orig_pkts+resp_pkts vs tshark frames", z_pkts, t_pkts),
          ("IP bytes: Zeek *_ip_bytes vs tshark ip.len", z_ip, t_ip)]
print(f"### Reconciliation for {case}\n")
print("| Metric | Zeek | tshark | Delta | Status |\n|---|---:|---:|---:|---|")
bad = 0
for name, z, t in checks:
    status = "CONFIRMED" if z == t else "DISCREPANT - explain"
    bad += z != t
    print(f"| {name} | {z} | {t} | {z - t} | {status} |")
print(f"\nSanity: tshark frame bytes {t_frame} - 14 x {t_pkts} packets = {t_frame - 14 * t_pkts} (must equal tshark IP bytes {t_ip}).")
sys.exit(1 if bad else 0)
