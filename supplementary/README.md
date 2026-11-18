# Supplementary material — synthetic reconstructions

These two directories are the **original Scapy-generated synthetic pcaps and their
analysis**, preserved for reproducibility and comparison:

- `synthetic_case01/` — synthetic port scan + 36-session SSH brute force + interactive session
- `synthetic_case03/` — synthetic base32 DNS tunnel (`exfil-lab.test`, 14,000-byte recovered payload)

They are **not** the primary cases. The primary `cases/case01_ssh_bruteforce/` and
`cases/case03_dns_tunnel/` now use **real lab captures** (loopback captures from an
isolated exercise VM). See `report/data_provenance.md` for the full provenance table.

## Honesty note

The traffic in these directories was generated with `lab/gen_case01.py` and
`lab/gen_case03.py` (Scapy). It is realistic at the protocol level but is **not** a
capture of real Hydra/sqlmap/dnscat2/implant traffic. Do not describe it as such.
Reports inside these directories still say "Case 01"/"Case 03" because they were
written before the swap; read them as documentation of the synthetic exercise only.

Path note: because these folders moved out of `cases/`, relative links of the form
`../../report/...` inside them now point one level too high. The authoritative
final report is `report/FINAL_REPORT.md` at the project root.
