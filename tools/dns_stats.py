#!/usr/bin/env python3
"""Reads DNS query names on stdin; prints per-registered-domain tunnel indicators."""
import collections
import math
import sys


def H(s):
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


dom = collections.defaultdict(list)
for line in sys.stdin:
    q = line.strip().lower().rstrip(".")
    if q:
        dom[".".join(q.split(".")[-2:])].append(q)
print(f"{'registered_domain':<22}{'queries':>8}{'unique':>8}{'mean_len':>10}{'max_len':>9}{'mean_H(longest_label)':>24}")
for d, qs in sorted(dom.items(), key=lambda kv: -len(kv[1])):
    lens = [len(q) for q in qs]
    h = [H(max(q.split("."), key=len)) for q in qs]
    print(f"{d:<22}{len(qs):>8}{len(set(qs)):>8}{sum(lens)/len(lens):>10.1f}{max(lens):>9}{sum(h)/len(h):>24.2f}")
