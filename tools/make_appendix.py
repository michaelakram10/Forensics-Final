#!/usr/bin/env python3
"""Build report/APPENDIX_A_raw_evidence.md and report/hash_manifest.md.

Runs from any working directory. Every project file is hashed except the manifest
itself, bytecode caches and Git internals. Private exercise material (project.md,
lab/, ground_truth/) is excluded from the public submission tree, so it is not
hashed here either.
"""
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGS = {
    "case01_ssh_sessions": ["conn.log", "ssh.log"],
    "case02_web_sqli": ["conn.log", "http.log", "files.log"],
    "case03_dns_tunnel": ["conn.log", "dns.log"],
    "case04_c2_beacon": ["conn.log", "ssl.log"],
}

out = ["# Appendix A — Raw evidence preserved (verbatim excerpts)", "",
       "Full raw outputs are preserved under `cases/*/tshark/`, `cases/*/tcpdump/` and `cases/*/zeek/{tsv,json}/`. "
       "The blocks below are verbatim `head -n 28` / `tail -n 12` excerpts and complete `capinfos` outputs."]
for case, logs in LOGS.items():
    out += ["", f"## {case}", "", "### capinfos", "```"]
    out += (ROOT / "cases" / case / "tshark" / "capinfos.txt").read_text().splitlines()
    out += ["```", ""]
    for name in logs:
        lines = (ROOT / "cases" / case / "zeek" / "tsv" / name).read_text().splitlines()
        out += [f"### zeek/tsv/{name} — head -n 28", "```"] + lines[:28] + ["```", ""]
        out += [f"### zeek/tsv/{name} — tail -n 12", "```"] + lines[-12:] + ["```", ""]
(ROOT / "report" / "APPENDIX_A_raw_evidence.md").write_text("\n".join(out) + "\n")
print("wrote report/APPENDIX_A_raw_evidence.md")

files = [p for p in ROOT.rglob("*")
         if p.is_file()
         and ".git" not in p.parts
         and "__pycache__" not in p.parts
         and p.suffix != ".pyc"
         and p.name != "hash_manifest.md"]
files.sort(key=lambda p: str(p.relative_to(ROOT)))
lines = ["# Appendix B — Hash manifest", "",
         f"Generated with `sha256sum` on {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}. "
         "Sealed pcaps and their `.sha256` files are read-only; analysis outputs are writable.", "",
         "**Scope:** every file in the submission tree is listed except this manifest itself (a file "
         "cannot hash itself), Python bytecode caches (`__pycache__/`, `*.pyc`) and Git internals "
         "under `.git/`. Root Markdown files, `.gitignore`, case artifacts, supplementary material, "
         "custody records, reports, PDFs and scripts are all included. Private exercise material "
         "(`project.md`, `lab/`, `ground_truth/`) is excluded from this public tree.", "", "```"]
for p in files:
    digest = subprocess.run(["sha256sum", str(p)], capture_output=True, text=True, check=True).stdout.split()[0]
    lines.append(f"{digest}  {p.relative_to(ROOT)}")
lines += ["```", ""]
(ROOT / "report" / "hash_manifest.md").write_text("\n".join(lines) + "\n")
print(f"wrote report/hash_manifest.md ({len(files)} files)")
