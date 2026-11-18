#!/usr/bin/env python3
"""Reads DNS query names on stdin, reassembles sNNNN.<b32>.<b32>.t.exfil-lab.test chunks, writes decoded bytes to stdout."""
import base64
import re
import sys

chunks = set()
for line in sys.stdin:
    m = re.match(r"^s(\d{4})\.([a-z2-7]+)(?:\.([a-z2-7]+))?\.t\.exfil-lab\.test$", line.strip().lower())
    if m:
        chunks.add((int(m.group(1)), m.group(2) + (m.group(3) or "")))
out = b""
for seq, s in sorted(chunks):                      # sorted + set() = ordered and de-duplicated
    s = s.upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    out += base64.b32decode(s)
sys.stdout.buffer.write(out)
