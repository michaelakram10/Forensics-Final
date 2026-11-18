#!/usr/bin/env python3
"""make_excerpts.py -> focused pcap excerpts under cases/<case>/excerpts/, each hashed.

Excerpts are taken from the sealed originals with tshark display filters. They are
convenience copies for reviewers; the sealed full pcaps remain authoritative.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = {"case01_ssh_bruteforce": "case01", "case02_web_sqli": "case02",
        "case03_dns_tunnel": "case03", "case04_c2_beacon": "case04"}
EXCERPTS = {
    "case01_ssh_bruteforce": [
        ("case01_ssh_22.pcap", "tcp.port == 22", "all SSH traffic on port 22"),
    ],
    "case02_web_sqli": [
        ("case02_http.pcap", "http", "all HTTP request/response traffic"),
        ("case02_outfile.pcap", 'http.request.uri contains "OUTFILE"', "INTO OUTFILE staging request"),
        ("case02_csv_download.pcap", 'http.request.uri contains "customers.csv"', "customers.csv download"),
    ],
    "case03_dns_tunnel": [
        ("case03_dns_tunnel.pcap", "udp.port == 53", "all DNS traffic to/from the resolver"),
        ('case03_dnscat_queries.pcap', 'dns.qry.name contains "dnscat"', "dnscat2-tagged DNS queries"),
    ],
    "case04_c2_beacon": [
        ("case04_c2_8443.pcap", "tcp.port == 8443", "all C2-port traffic"),
        ("case04_large_upload.pcap", "tcp.port == 8443 && tcp.len > 1000", "large upload/task packets on port 8443"),
    ],
}


def run(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def main():
    index = ["# Focused pcap excerpts", "",
             "Created from the sealed originals with `tshark -r <pcap> -Y <filter> -w <out>`. "
             "Each excerpt directory contains a `SHA256SUMS.txt`. The sealed full pcap in "
             "`raw/` remains authoritative.", "",
             "| Case | Excerpt | Filter | What it shows |", "|---|---|---|---|"]
    for case, items in EXCERPTS.items():
        cdir = ROOT / "cases" / case
        src = cdir / "raw" / f"{BASE[case]}.pcap"
        out_dir = cdir / "excerpts"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "SHA256SUMS.txt").unlink(missing_ok=True)
        for name, flt, desc in items:
            dst = out_dir / name
            run(["tshark", "-r", str(src), "-Y", flt, "-w", str(dst)])
            digest = subprocess.run(["sha256sum", str(dst)], capture_output=True,
                                    text=True, check=True).stdout.split()[0]
            with (out_dir / "SHA256SUMS.txt").open("a") as f:
                f.write(f"{digest}  {name}\n")
            index.append(f"| {case} | `{name}` | `{flt}` | {desc} |")
            print(f"wrote {dst.relative_to(ROOT)} ({digest[:12]}...)")
    index += ["", "Note: for Case 03 the two excerpts are byte-identical because every DNS "
              "query in that capture carries the `dnscat.` signature — the full DNS excerpt "
              "is already tunnel-only. Case 01's excerpt contains all 107 frames because "
              "every connection is to port 22.", ""]
    (ROOT / "report/excerpts_index.md").write_text("\n".join(index) + "\n")
    print("wrote report/excerpts_index.md")


if __name__ == "__main__":
    main()
