#!/usr/bin/env python3
"""Per (src,dst,port) inter-connection interval statistics from Zeek JSON conn.log."""
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
case = sys.argv[1] if len(sys.argv) > 1 else "case04_c2_beacon"
conn = [json.loads(l) for l in open(ROOT / "cases" / case / "zeek/json/conn.log")]
groups = {}
for c in conn:
    groups.setdefault((c["id.orig_h"], c["id.resp_h"], c["id.resp_p"]), []).append(c)
print(f"{'src':<15}{'dst':<15}{'port':>5}{'n':>4}{'mean_s':>8}{'median':>8}{'stdev':>7}{'CV':>6}{'MAD':>6}{'S0':>4}{'med_orig_B':>11}{'med_resp_B':>11}")
for (s, d, p), rows in sorted(groups.items()):
    ts = sorted(r["ts"] for r in rows)
    if len(ts) < 5:
        continue
    iv = [b - a for a, b in zip(ts, ts[1:])]
    med = st.median(iv)
    mad = st.median([abs(x - med) for x in iv])
    ok = [r for r in rows if r["conn_state"] == "SF"]
    mo = st.median([r.get("orig_bytes", 0) for r in ok]) if ok else 0
    mr = st.median([r.get("resp_bytes", 0) for r in ok]) if ok else 0
    s0 = sum(1 for r in rows if r["conn_state"] == "S0")
    print(f"{s:<15}{d:<15}{p:>5}{len(ts):>4}{st.mean(iv):>8.1f}{med:>8.1f}{st.pstdev(iv):>7.1f}{st.pstdev(iv)/st.mean(iv):>6.2f}{mad:>6.1f}{s0:>4}{mo:>11.0f}{mr:>11.0f}")
