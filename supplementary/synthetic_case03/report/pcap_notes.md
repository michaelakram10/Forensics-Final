# Case 03 — packet-level notes (Log/pcap analyst)

## Evidence

| Item | Value |
|---|---|
| File | `raw/case03.pcap` |
| SHA-256 | `00dbcc9650c4f4a85e7296b5a26127d0f35763db1eaddc5b488ed47b45e6908c` |
| Packets | 484 (242 DNS transactions × query+response) |
| First / last packet | 2026-11-05 10:00:19.899Z / 10:10:47.848Z |
| Participants | 192.168.56.40 → resolver 192.168.56.53:53/udp |

## Baseline (10:00:19.899Z – 10:09:56.205Z)

- 40 A queries: 22 to corp.test, 18 to example.test; short (mean ~16–17 chars), repeated names, TTL 300, low entropy (~2.4–2.5). Answers are documentation-range addresses.

## Tunnel (10:10:00.000Z – 10:10:47.848Z)

- `init.t.exfil-lab.test` TXT → `ready`; 200 numbered data queries `sNNNN.<56 base32>.<56 base32>.t.exfil-lab.test` (136 chars), each carrying 70 raw bytes; `fin.s0200.t.exfil-lab.test` → `done`.
- Every one of the 202 names is unique; mean length 134.9, max 136, longest-label entropy 4.35 — clear statistical outlier versus baseline (`tshark/dns_stats.txt`).
- Responses are short TXT acknowledgements (`a0001`…`a0200`); TTL 0.
- Mean inter-query gap 0.238 s; the tunnel lasts ≈47.8 s.
- Frame bytes for tunnel queries: 39,367 over 202 frames; IP bytes 36,539; DNS payload 30,883 (identity Σframe − 14×202 = Σip verified).

## Decoded content

`tools/decode_dns_tunnel.py` reassembled the base32 labels from both tshark query names and Zeek `dns.log`:

- Both outputs: exactly 14,000 bytes, identical SHA-256 `8d8b129b78610da1d7dad75ca2375c25be120b2cdc1f7a3869b974d1b6b32f97`.
- First lines: `SYNTHETIC-LAB-RECORD 0001 emp=E74697 salary=19690 note=NOT-REAL-DATA` etc.

The content is synthetic but the extraction is deterministic and independently reproduced; this converts the statistical "tunnel" inference into a Certain finding.
