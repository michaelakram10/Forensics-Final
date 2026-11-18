#!/usr/bin/env python3
"""build_timeline.py <case_dir_name> -> cases/<case>/timeline/timeline.csv. Uses ONLY Zeek JSON logs (no ground truth)."""
import csv
import json
import re
import statistics as st
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
case = sys.argv[1]


def load(name):
    p = ROOT / "cases" / case / "zeek/json" / f"{name}.log"
    return [json.loads(l) for l in p.open()] if p.exists() else []


iso = lambda ts: datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")
ev = []   # (ts, src, dst, event, evidence_ref)

conn = load("conn")
if case.startswith("case01"):
    by = {}
    for c in conn:
        by.setdefault((c["id.orig_h"], c["id.resp_h"]), []).append(c)
    for (s, d), rows in by.items():
        empty = [r for r in rows if r.get("orig_bytes", 0) == 0 and r.get("resp_bytes", 0) == 0]
        ports = {r["id.resp_p"] for r in empty}
        if len(ports) >= 10:
            empty.sort(key=lambda r: r["ts"])
            opened = sorted({r["id.resp_p"] for r in empty if r["conn_state"] not in ("REJ", "S0")})
            ev.append((empty[0]["ts"], s, d, f"Port scan begins: {len(ports)} ports probed from source port(s) {sorted({r['id.orig_p'] for r in empty})}", f"conn.log uid={empty[0]['uid']}"))
            ev.append((empty[-1]["ts"], d, s, f"Scan ends; answered (open) ports: {opened}", f"conn.log uid={empty[-1]['uid']}"))
        ssh = sorted([r for r in rows if r["id.resp_p"] == 22 and r.get("orig_bytes", 0) > 0], key=lambda r: r["ts"])
        short = [r for r in ssh if r["duration"] < 5]
        long_ = [r for r in ssh if r["duration"] >= 30]
        if short:
            ev.append((short[0]["ts"], s, d, f"SSH connection burst begins: {len(short)} short sessions to port 22", f"conn.log uid={short[0]['uid']} .. {short[-1]['uid']}"))
            ev.append((short[-1]["ts"], s, d, "Last short SSH session", f"conn.log uid={short[-1]['uid']}"))
        for r in long_:
            ev.append((r["ts"], s, d, f"Long SSH session starts (duration {r['duration']:.1f} s, orig {r['orig_bytes']} B, resp {r['resp_bytes']} B)", f"conn.log uid={r['uid']}"))
            ev.append((r["ts"] + r["duration"], d, s, "Long SSH session ends", f"conn.log uid={r['uid']}"))
elif case.startswith("case02"):
    for h in load("http"):
        uri = unquote(h.get("uri", ""))
        tag = "SQLi-pattern request" if re.search(r"'|UNION|ORDER BY|OUTFILE|information_schema", uri, re.I) else "HTTP request"
        ev.append((h["ts"], h["id.orig_h"], h["id.resp_h"], f"{tag}: {h['method']} {uri[:110]} -> {h.get('status_code')} ({h.get('response_body_len', 0)} B body)", f"http.log uid={h['uid']} depth={h.get('trans_depth')}"))
elif case.startswith("case03"):
    dns = load("dns")
    dom = {}
    for d in dns:
        dom.setdefault(".".join(d["query"].lower().rstrip(".").split(".")[-2:]), []).append(d)
    for name, rows in dom.items():
        uniq = len({r["query"] for r in rows})
        mean_len = sum(len(r["query"]) for r in rows) / len(rows)
        rows.sort(key=lambda r: r["ts"])
        if len(rows) >= 50 and uniq / len(rows) >= 0.9 and mean_len > 60:
            ev.append((rows[0]["ts"], rows[0]["id.orig_h"], rows[0]["id.resp_h"], f"Tunnel-like DNS activity to {name} begins (first query {rows[0]['query'][:40]})", f"dns.log uid={rows[0]['uid']}"))
            ev.append((rows[-1]["ts"], rows[-1]["id.orig_h"], rows[-1]["id.resp_h"], f"Tunnel-like DNS activity ends: {len(rows)} queries, {uniq} unique, mean length {mean_len:.0f}", f"dns.log uid={rows[-1]['uid']}"))
        else:
            ev.append((rows[0]["ts"], rows[0]["id.orig_h"], rows[0]["id.resp_h"], f"Ordinary DNS for {name}: {len(rows)} queries, {uniq} unique", f"dns.log uid={rows[0]['uid']}"))
elif case.startswith("case04"):
    groups = {}
    for c in conn:
        groups.setdefault((c["id.orig_h"], c["id.resp_h"], c["id.resp_p"]), []).append(c)
    for (s, d, p), rows in groups.items():
        rows.sort(key=lambda r: r["ts"])
        if len(rows) < 5:
            continue
        iv = [b["ts"] - a["ts"] for a, b in zip(rows, rows[1:])]
        med = st.median(iv)
        mad = st.median([abs(x - med) for x in iv])
        if mad / med < 0.25:
            ev.append((rows[0]["ts"], s, d, f"Periodic connections to {d}:{p} begin (n={len(rows)}, median interval {med:.1f}s, MAD {mad:.1f}s)", f"conn.log uid={rows[0]['uid']}"))
            ev.append((rows[-1]["ts"], s, d, f"Last periodic connection to {d}:{p}", f"conn.log uid={rows[-1]['uid']}"))
            for r in rows:
                if r["conn_state"] == "S0":
                    ev.append((r["ts"], s, d, "Unanswered connection attempt (S0)", f"conn.log uid={r['uid']}"))
            big = max(rows, key=lambda r: r.get("orig_bytes", 0))
            ev.append((big["ts"], s, d, f"Largest upload in group: {big.get('orig_bytes', 0)} B", f"conn.log uid={big['uid']}"))
            dn = max(rows, key=lambda r: r.get("resp_bytes", 0))
            ev.append((dn["ts"], d, s, f"Largest download in group: {dn.get('resp_bytes', 0)} B", f"conn.log uid={dn['uid']}"))

ev.sort(key=lambda e: e[0])
out = ROOT / "cases" / case / "timeline" / "timeline.csv"
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp_utc", "source", "destination", "event", "evidence_ref"])
    for ts, s, d, e, r in ev:
        w.writerow([iso(ts), s, d, e, r])
print(f"wrote {out} ({len(ev)} events)")
