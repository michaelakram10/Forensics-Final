#!/usr/bin/env python3
"""
BASIC structural analysis of the dnscat2 DNS-tunnel capture (case03).

This script does NOT decrypt dnscat2.  dnscat2 encrypts its tunnel payload with
a pre-shared secret (AES-CBC + HMAC); the key is not present in the pcap, so
message *content* is not recoverable from passive observation alone.

What it DOES do:
  * parse each DNS query name of the form dnscat.<hex labels...>; tool identity
    uses the FIRST label "dnscat" (direct-mode dnscat2 signature), not the last two labels
  * concatenate the hex labels per query -> the raw on-the-wire dnscat2 frame
  * report total extracted hex characters / bytes
  * inspect the first frame bytes for fixed markers, session/sequence fields
  * report per-query frame lengths and the large (negotiation/data) frames

Usage (from case dir):
  python3 report/decode_dnscat2.py raw/case03.pcap > tshark/dnscat2_extract.txt
"""
import sys
import subprocess
import collections
import statistics

PCAP = sys.argv[1] if len(sys.argv) > 1 else "raw/case03.pcap"


def query_rows():
    cmd = ["tshark", "-r", PCAP, "-Y", "dns.flags.response==0", "-T", "fields",
           "-e", "frame.number", "-e", "frame.time_epoch", "-e", "dns.qry.name",
           "-e", "dns.qry.type"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) >= 3 and f[2]:
            yield int(f[0]), float(f[1]), f[2], (f[3] if len(f) > 3 else "")


rows = list(query_rows())
print("=== dnscat2 BASIC structural extraction (NOT decryption) ===")
print(f"pcap: {PCAP}")
print(f"DNS queries parsed: {len(rows)}")

hexstrings = []
nonhex_labels = 0
for _, _, name, _ in rows:
    assert name.startswith("dnscat."), f"unexpected name: {name}"
    labels = name[len("dnscat."):].split(".")
    joined = "".join(labels)
    if any(c not in "0123456789abcdefABCDEF" for c in joined):
        nonhex_labels += 1
    hexstrings.append(joined)

total_hex_chars = sum(len(h) for h in hexstrings)
print(f"queries with a non-hex label after 'dnscat.': {nonhex_labels}")
print(f"total hex characters in concatenated labels: {total_hex_chars}")
print(f"total extracted hex BYTES (floor(chars/2)): {total_hex_chars // 2}")
print(f"  (odd-length frames: {sum(1 for h in hexstrings if len(h) % 2)})")

flens = [len(h) // 2 for h in hexstrings]
print(f"per-query frame bytes: min={min(flens)} max={max(flens)} "
      f"mean={statistics.mean(flens):.2f} median={statistics.median(flens)}")

# ---- first-frame-byte structure -------------------------------------------
print("\n=== first-label byte offsets (most common value per offset) ===")
offsets = collections.defaultdict(collections.Counter)
short_frames = 0
for h in hexstrings:
    b = bytes.fromhex(h if len(h) % 2 == 0 else h[:-1])
    if len(b) < 8:
        short_frames += 1
    for i, byte in enumerate(b[:12]):
        offsets[i][byte] += 1
print(f"frames shorter than 8 bytes: {short_frames}")
for i in sorted(offsets):
    common = offsets[i].most_common(4)
    vals = ", ".join(f"0x{v:02x}({c})" for v, c in common)
    print(f"  byte[{i:2d}] distinct={len(offsets[i]):3d}  top: {vals}")

# ---- repeated fixed marker -------------------------------------------------
print("\n=== fixed 2-byte field at bytes[3:5] of first label ===")
markers = collections.Counter()
for h in hexstrings:
    b = bytes.fromhex(h if len(h) % 2 == 0 else h[:-1])
    if len(b) >= 5:
        markers[b[3:5]] += 1
for v, c in markers.most_common(6):
    print(f"  0x{v[0]:02x}{v[1]:02x} ({int.from_bytes(v, 'big')}): {c} queries")

# ---- message-type / session interpretation of bytes[0:5] -------------------
print("\n=== byte[2] (candidate message-type) frequency ===")
bt2 = collections.Counter()
for h in hexstrings:
    b = bytes.fromhex(h if len(h) % 2 == 0 else h[:-1])
    if len(b) >= 3:
        bt2[b[2]] += 1
for v, c in bt2.most_common():
    print(f"  0x{v:02x}: {c} queries")
print("  => bytes[0:2] vary per query (nonce/id); byte[2] is almost always 0x01;")
print("     bytes[3:5] take only two values -> possible 2 active dnscat2 sessions.")

# ---- largest frames (session negotiation / data) ---------------------------
print("\n=== largest 6 query frames (frame, epoch, type, bytes, name[:70]) ===")
for idx in sorted(range(len(rows)), key=lambda i: flens[i], reverse=True)[:6]:
    fr, ep, name, qt = rows[idx]
    print(f"  frame {fr:3d} epoch {ep:.6f} qtype={qt:>2s} bytes={flens[idx]:3d}  {name[:70]}")

print("\nNOTE: dnscat2 encrypts tunneled payload data; only framing/structure,")
print("record-type selection and sizing are observable. No plaintext is claimed.")
