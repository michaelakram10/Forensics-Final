# Data provenance — which captures are real and which are synthetic

| Case | Primary pcap | SHA-256 | Packets | UTC span | Provenance |
|---|---|---|---:|---|---|
| 01 | `cases/case01_ssh_bruteforce/raw/case01.pcap` | `771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99` | 107 | 2026-11-16 16:20:54 – 16:21:28 | **Real** isolated-lab tcpdump capture, loopback (`127.0.0.1`) SSH exercise |
| 02 | `cases/case02_web_sqli/raw/case02.pcap` | `e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9` | 203 | 2026-11-03 13:20:00 – 13:22:12 | Synthetic (Scapy, `lab/gen_case02.py`) |
| 03 | `cases/case03_dns_tunnel/raw/case03.pcap` | `e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb` | 890 | 2026-11-18 18:25:25 – 18:30:23 | **Real** isolated-lab capture of a dnscat2 session, loopback (`127.0.0.1`) |
| 04 | `cases/case04_c2_beacon/raw/case04.pcap` | `eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675` | 2032 | 2026-11-04 14:00:00 – 14:43:13 | Synthetic (Scapy, `lab/gen_case04.py`) |

## Notes

- The real captures were produced on an isolated lab VM; both use `127.0.0.1` for
  client and server. They therefore demonstrate protocol-level reconstruction but do
  not provide distinct attacker/victim addresses or a separately visible authoritative
  DNS server.
- `capinfos` on the VM prints local time (UTC−5): the real Case 01 capture appears as
  11:20–11:21 and the real Case 03 capture as 13:25–13:30. All analysis timestamps in
  this repository are UTC (16:20–16:21 and 18:25–18:30 respectively).
- The replaced synthetic reconstructions are preserved under
  `supplementary/synthetic_case01/` and `supplementary/synthetic_case03/`. They are
  clearly labelled as synthetic and are not used as evidence in the primary cases.
- No capture in this repository is presented as traffic from a real victim or a real
  malicious campaign. The synthetic cases are modelled on the corresponding attack
  types; the real cases are lab exercises on loopback.
- Chain-of-custody entries for the capture swap are in `custody/custody_log.csv`.

## Analysis honesty

The analysis was **manual-guided, not blind**: `project.md`, `lab/` and `ground_truth/`
were available to the analyst during the exercise. They are therefore excluded from
the public submission repository. No claim that confidence ratings were frozen before
ground truth was available is made. Findings are derived from pcap/Zeek/tshark
artifacts and rated under the rubric in `report/methodology.md` §5.
