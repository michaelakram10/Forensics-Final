#!/usr/bin/env python3
"""generate_timelines.py [case ...] -> cases/<case>/viz/<case>_timeline.png (220 dpi).

Reads ONLY Zeek JSON logs. Three panels:
  1. activity/swimlane view (per-case layout; sub-lanes for overlapping connections)
  2. payload bytes over time, spread across each connection's duration
  3. case-specific analytical view

All times are read from the data; nothing is hard-coded from the manual.
"""
import json
import sys
import urllib.parse as up
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "case01_ssh_bruteforce": "Case 01 - SSH session reconstruction (real loopback capture)",
    "case02_web_sqli": "Case 02 - SQL injection and CSV exfiltration over HTTP",
    "case03_dns_tunnel": "Case 03 - dnscat2 DNS tunnelling (real loopback capture)",
    "case04_c2_beacon": "Case 04 - Periodic TLS beaconing on a non-standard port",
}
STATE_COLORS = {"SF": "#2f9e44", "S0": "#e03131", "REJ": "#f76707",
                "RSTO": "#f59f00", "RSTR": "#f59f00", "OTH": "#868e96"}
LINEAR_BINS = np.array([-100000, -10000, -1000, -100, 0, 100, 1000, 10000, 100000], dtype=float)


def load(case, name):
    p = ROOT / "cases" / case / "zeek/json" / f"{name}.log"
    if not p.exists():
        return pd.DataFrame()
    return pd.DataFrame([json.loads(l) for l in p.open()])


def prep_conn(df):
    for c in ("duration", "orig_bytes", "resp_bytes", "ts"):
        if c not in df:
            df[c] = 0.0
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    if "id.orig_h" not in df:
        df["id.orig_h"] = "?"
    if "id.resp_h" not in df:
        df["id.resp_h"] = "?"
    if "id.resp_p" not in df:
        df["id.resp_p"] = 0
    df["lane"] = df["id.orig_h"].astype(str) + " -> " + df["id.resp_h"].astype(str) + ":" + df["id.resp_p"].astype(str)
    return df


def assign_sublanes(conn):
    """Greedy interval packing so overlapping connections get separate sub-lanes."""
    ends = []
    result = []
    for _, r in conn.sort_values("ts").iterrows():
        start, dur = float(r["ts"]), float(r["duration"])
        chosen = next((i for i, e in enumerate(ends) if e <= start + 1e-9), None)
        if chosen is None:
            chosen = len(ends)
            ends.append(start + dur)
        else:
            ends[chosen] = start + dur
        result.append(chosen)
    conn = conn.copy()
    conn["sublane"] = result
    return conn


def symlog_ticks(ax):
    ax.set_yscale("symlog", linthresh=100)
    ax.set_yticks(LINEAR_BINS)
    ax.set_yticklabels(["-100k", "-10k", "-1k", "-100", "0", "100", "1k", "10k", "100k"], fontsize=7)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: ""))
    # Re-apply explicit labels after the formatter (formatter suppresses auto text).
    ax.set_yticklabels(["-100k", "-10k", "-1k", "-100", "0", "100", "1k", "10k", "100k"], fontsize=7)


def swimlane(ax, conn, t0, span, case):
    if case == "case03_dns_tunnel":
        return dns_rate_panel(ax, case, t0, span)
    conn = assign_sublanes(conn)
    lanes = sorted(conn["lane"].unique(), key=lambda s: (str(s).rsplit(":", 1)[-1], s))
    lane_idx = {l: i for i, l in enumerate(lanes)}
    minw = max(span * 0.002, 0.05)
    for _, r in conn.iterrows():
        y = lane_idx[r["lane"]] * 1.0 + (r["sublane"] * 0.22)
        ax.barh(y, max(float(r["duration"]), minw), left=float(r["ts"]) - t0,
                height=0.20, color=STATE_COLORS.get(r["conn_state"], "#868e96"))
    ax.set_yticks([i + 0.35 for i in range(len(lanes))])
    ax.set_yticklabels(lanes, fontsize=6)
    ax.set_xlim(-span * 0.01, span * 1.01)
    ax.set_ylim(-0.5, len(lanes) + 0.2)
    n = len(conn)
    ax.set_title(f"Activity swimlane - {n} Zeek conn.log records, colour = conn_state, overlapping flows use sub-lanes",
                 fontsize=9, loc="left")
    ax.legend(handles=[Patch(color=c, label=s) for s, c in STATE_COLORS.items()], fontsize=6, ncol=6, loc="upper right")
    ax.grid(axis="x", alpha=0.25)
    if case == "case02_web_sqli":
        h = load(case, "http")
        if not h.empty:
            ax.scatter(pd.to_numeric(h["ts"], errors="coerce") - t0,
                       [-0.25] * len(h), marker="|", s=220, c="#1c7ed6", linewidths=1.2,
                       label="HTTP request markers", zorder=5)
            ax.legend(handles=[Patch(color=c, label=s) for s, c in STATE_COLORS.items()] +
                      [Patch(color="#1c7ed6", label=f"{len(h)} HTTP request markers")],
                      fontsize=6, ncol=5, loc="upper right")
        ax.set_title(f"Activity swimlane - {n} connections plus one marker per HTTP request", fontsize=9, loc="left")


def dns_rate_panel(ax, case, t0, span):
    d = load(case, "dns")
    if d.empty:
        ax.set_title("DNS activity", fontsize=9, loc="left")
        return
    ts = pd.to_numeric(d["ts"], errors="coerce")
    names = d["query"].astype(str)
    is_tunnel = names.str.startswith("dnscat.") | names.str.contains("exfil-lab.test", regex=False)
    step = 10 if span <= 600 else 30
    edges = np.arange(0, span + step, step)
    for mask, color, label in [(~is_tunnel.values, "#2f9e44", "ordinary DNS"),
                               (is_tunnel.values, "#e03131", "dnscat2 / tunnel DNS")]:
        counts, _ = np.histogram((ts[mask] - t0).dropna(), bins=edges)
        ax.bar(edges[:-1], counts, width=step * 0.9, align="edge", color=color, label=label)
    ax.set_ylabel(f"DNS queries per {step} s", fontsize=8)
    ax.set_xlim(-step, span + step)
    ax.set_title("DNS query-rate view (phase view: baseline vs tunnel)", fontsize=9, loc="left")
    ax.legend(fontsize=7, loc="upper right")
    ax.grid(axis="x", alpha=0.25)


def bytes_panel(ax, conn, t0, span):
    bs = 1 if span < 60 else 5 if span < 300 else 30 if span < 3600 else 60
    nbins = int(span // bs) + 2
    orig = np.zeros(nbins)
    resp = np.zeros(nbins)
    for _, r in conn.iterrows():
        start = float(r["ts"]) - t0
        dur = max(float(r["duration"]), 1e-6)
        i0 = max(0, int(start // bs))
        i1 = min(nbins, int(np.ceil((start + dur) / bs)))
        if i1 <= i0:
            i1 = i0 + 1
        overlap = np.minimum((np.arange(i0, i1) + 1) * bs, start + dur) - \
                  np.maximum(np.arange(i0, i1) * bs, start)
        weight = overlap / dur
        orig[i0:i1] += float(r["orig_bytes"]) * weight
        resp[i0:i1] += float(r["resp_bytes"]) * weight
    x = np.arange(nbins) * bs
    ax.bar(x, orig, width=bs * 0.9, align="edge", color="#1c7ed6", label="originator -> responder (orig_bytes)")
    ax.bar(x, -resp, width=bs * 0.9, align="edge", color="#ae3ec9", label="responder -> originator (resp_bytes)")
    ax.axhline(0, color="black", lw=0.6)
    symlog_ticks(ax)
    ax.set_ylabel(f"bytes per {bs} s bin (symlog)", fontsize=8)
    ax.set_title("Payload bytes over time (each connection's bytes spread over its duration)", fontsize=9, loc="left")
    ax.legend(fontsize=7, loc="upper right")
    ax.set_xlim(-span * 0.01, span * 1.01)
    ax.grid(axis="x", alpha=0.25)


def panel_case01(ax, case, conn, t0, span):
    ssh = conn[conn["id.resp_p"] == 22]
    scan = conn[(conn["orig_bytes"] == 0) & (conn["resp_bytes"] == 0) & (conn["duration"] < 1)]
    burst = ssh[(ssh["duration"] < 5) & (ssh["orig_bytes"] > 0)]
    longs = ssh[ssh["duration"] >= 5]
    ax.scatter(ssh["ts"] - t0, np.ones(len(ssh)), marker="|", s=420, c="#e03131", linewidths=2,
               label=f"TCP/22 connections (n={len(ssh)})")
    if len(scan):
        ax.axvspan((scan["ts"] - t0).min(), (scan["ts"] - t0).max() + 0.5,
                   color="#f59f00", alpha=0.30, label=f"short/empty scan-like flows (n={len(scan)})")
    if len(burst):
        ax.axvspan((burst["ts"] - t0).min(), (burst["ts"] - t0).max() + 0.5,
                   color="#e03131", alpha=0.18, label=f"short SSH sessions (n={len(burst)})")
    for _, r in longs.iterrows():
        ax.axvspan(float(r["ts"]) - t0, float(r["ts"]) - t0 + float(r["duration"]),
                   color="#1c7ed6", alpha=0.20, label="long interactive session")
    ax.set_yticks([])
    ax.set_title(f"Connection-rate view: {len(scan)} scan-like / {len(burst)} short SSH / {len(longs)} long SSH",
                 fontsize=9, loc="left")
    ax.legend(fontsize=7, loc="upper right")
    ax.set_xlim(-span * 0.01, span * 1.01)


def panel_case02(ax, case, conn, t0, span):
    h = load(case, "http")
    if h.empty:
        return
    h["response_body_len"] = pd.to_numeric(h.get("response_body_len", 0), errors="coerce").fillna(0)
    uris = h["uri"].astype(str).map(lambda s: up.unquote(s))
    sus = uris.str.contains(r"%27|UNION|ORDER|OUTFILE|information_schema|'", case=False, regex=True)
    ax.scatter(h.loc[~sus, "ts"] - t0, h.loc[~sus, "response_body_len"] + 1,
               c="#2f9e44", label="ordinary request")
    ax.scatter(h.loc[sus, "ts"] - t0, h.loc[sus, "response_body_len"] + 1,
               c="#e03131", label="SQLi-pattern URI")
    for _, r in h.iterrows():
        uri = up.unquote(str(r["uri"]))
        if "INTO OUTFILE" in uri.upper() or "OUTFILE" in uri.upper():
            ax.annotate("INTO OUTFILE staging request", (r["ts"] - t0, r["response_body_len"] + 1),
                        xytext=(-170, 30), textcoords="offset points", arrowprops=dict(arrowstyle="->"), fontsize=7, c="#e03131")
        if "customers.csv" in uri and "OUTFILE" not in uri.upper():
            ax.annotate("customers.csv download", (r["ts"] - t0, r["response_body_len"] + 1),
                        xytext=(-150, -30), textcoords="offset points", arrowprops=dict(arrowstyle="->"), fontsize=7, c="#1c7ed6")
    ax.set_yscale("log")
    ax.set_ylabel("response body bytes", fontsize=8)
    ax.set_title("HTTP requests: response size vs time (OUTFILE request vs file download distinguished)",
                 fontsize=9, loc="left")
    ax.legend(fontsize=7, loc="upper left")
    ax.set_xlim(-span * 0.01, span * 1.01)


def panel_case03(ax, case, conn, t0, span):
    d = load(case, "dns")
    if d.empty:
        return
    d["qlen"] = d["query"].astype(str).str.len()
    tun = d["query"].astype(str).str.startswith("dnscat.") | d["query"].astype(str).str.contains("exfil-lab.test", regex=False)
    ax.scatter(d.loc[~tun, "ts"] - t0, d.loc[~tun, "qlen"], c="#2f9e44", s=10, alpha=0.7, label="ordinary DNS")
    ax.scatter(d.loc[tun, "ts"] - t0, d.loc[tun, "qlen"], c="#e03131", s=10, alpha=0.7, label="dnscat2 / tunnel DNS")
    ax.set_ylabel("query name length (chars)", fontsize=8)
    ax.set_title(f"DNS query length vs time ({int(tun.sum())} tunnel / {int((~tun).sum())} ordinary)", fontsize=9, loc="left")
    ax.legend(fontsize=7, loc="upper left")
    ax.set_xlim(-span * 0.01, span * 1.01)


def panel_case04(ax, case, conn, t0, span):
    c2 = conn[conn["id.resp_p"] == 8443].sort_values("ts")
    if c2.empty:
        return
    iv = c2["ts"].diff()
    mask = iv.notna()
    ax.stem((c2["ts"] - t0)[mask], iv[mask], basefmt=" ")
    ax.axhline(iv.mean(), color="#1c7ed6", ls="--", lw=1,
               label=f"mean of {int(mask.sum())} intervals {iv.mean():.1f} s")
    s0 = c2[c2["conn_state"] == "S0"]
    ax.scatter(s0["ts"] - t0, np.zeros(len(s0)), marker="x", color="#e03131", s=60, label="unanswered SYN (S0)")
    ax.set_ylabel("seconds since previous C2 connection", fontsize=8)
    ax.set_title("Beacon intervals (all connections to port 8443)", fontsize=9, loc="left")
    ax.legend(fontsize=7, loc="upper right")
    ax.set_xlim(-span * 0.01, span * 1.01)


PANELS = {"case01_ssh_bruteforce": panel_case01, "case02_web_sqli": panel_case02,
          "case03_dns_tunnel": panel_case03, "case04_c2_beacon": panel_case04}


def build(case):
    conn = prep_conn(load(case, "conn"))
    if conn.empty:
        print("skip", case, "(no conn.log)")
        return
    t0 = conn["ts"].min()
    span = float((conn["ts"] + conn["duration"]).max() - t0)
    fig, axes = plt.subplots(3, 1, figsize=(14, 10), constrained_layout=True)
    swimlane(axes[0], conn, t0, span, case)
    bytes_panel(axes[1], conn, t0, span)
    PANELS[case](axes[2], case, conn, t0, span)
    axes[2].set_xlabel("seconds since first packet", fontsize=9)
    start = datetime.fromtimestamp(t0, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    fig.suptitle(f"{CASES[case]}\nfirst packet {start} UTC  |  source: Zeek JSON logs", fontsize=11)
    out = ROOT / "cases" / case / "viz" / f"{case}_timeline.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=220)
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    for c in (sys.argv[1:] or list(CASES)):
        build(c)
