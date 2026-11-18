# Case 03 — Cross-tool verification

**Tools used: exactly two — Zeek 9.0.1 and TShark (Wireshark) 4.6.9.**
`tcpdump` was used only to produce a human-readable dump (`tcpdump/full_text_dump.txt`);
it is not a third independent measurement tool. Do not read the results below as
"three tools agree". Reconciliation is from `tools/verify_counts.py` →
`report/verify_counts.md`. All times UTC.

| # | Claim | Zeek evidence | Second-tool command → result | Status | Delta / explanation |
|---|---|---|---|---|---|
| 1 | 1 network flow, UDP 127.0.0.1:44651→127.0.0.1:53 | `conn.log`: 1 row, uid `Chubce1wik6p4KDZeg`, proto udp, service dns | `tshark -r raw/case03.pcap -T fields -e udp.stream \| sort -u` → single value `0` | CONFIRMED | 0 |
| 2 | 890 packets total | `conn.log orig_pkts 445 + resp_pkts 445 = 890` | `tshark ... -Y 'tcp \|\| udp'` frame count → `890` | CONFIRMED | 0 |
| 3 | 445 queries + 445 responses | `dns.log` 445 rows (1/row, response joined); `conn.log` 445/445 pkts | `tshark ... -e dns.flags.response \| sort \| uniq -c` → `445 False`, `445 True` | CONFIRMED | 0 (Zeek combines query+reply into one dns.log row) |
| 4 | IP byte total 104,305 | `conn.log orig_ip_bytes 39782 + resp_ip_bytes 64523 = 104305` | sum of tshark `ip.len` → `104305` | CONFIRMED | 0 |
| 5 | 14-byte/frame Ethernet identity | implied: Zeek IP bytes exclude L2 | `tshark frame.len total = 116765`; `116765 − 14×890 = 104305` = tshark IP bytes = Zeek IP bytes | CONFIRMED | 14 bytes/frame × 890 = 12,460 Ethernet header bytes; after subtracting, Zeek and tshark agree exactly (delta 0). This is why raw frame-byte sums must not be compared directly to Zeek `*_ip_bytes`. |
| 6 | L7 payload 27,322 out / 52,063 in | `conn.log orig_bytes 27322`, `resp_bytes 52063` | `tshark udp.length` minus UDP header, or `verify_counts` sanity → consistent with 104,305 IP − 24,920 IP+UDP headers | CONFIRMED | 79,385 L7 total; 104,305 − 79,385 = 24,920 = 28×890 (20-byte IPv4 + 8-byte UDP per frame) |
| 7 | qtype distribution CNAME 164 / MX 150 / TXT 131 | `zeek-cut qtype_name < zeek/tsv/dns.log \| sort \| uniq -c` → 164/150/131; `jq -r .qtype_name zeek/json/dns.log` → same | `tshark -Y 'dns.flags.response==0' -e dns.qry.type \| sort \| uniq -c` → `164` (5), `150` (15), `131` (16) | CONFIRMED | 0 across TSV, JSON and tshark |
| 8 | 445 unique `dnscat.` names | `zeek-cut query ... \| sort -u \| wc -l` → `445` | `tshark -Y 'dns.flags.response==0' -e dns.qry.name \| sort -u \| wc -l` → `445` | CONFIRMED | 0 |
| 9 | Duration 298.506573 s | `conn.log duration 298.506573` | `capinfos` Capture duration `298.506573 seconds` | CONFIRMED | 0 |
| 10 | First/last time — UTC vs local rendering | Zeek data `ts` first 1795026325.008145, last 1795026623.513247 (query); epoch is timezone-independent | `capinfos` with `TZ=UTC` → `2026-11-18 18:25:25.008145` / `18:30:23.514718`; with VM-local UTC-5 → `13:25:25` / `13:30:23` | DISCREPANT-EXPLAINED | *Apparent* 5-hour display delta only. `capinfos`/Zeek `#open` banner print local wall-clock (UTC-5) when `TZ` is unset; the packet epochs and `ts` values are UTC. Same capture, confirmed by the old `verify_counts` note. All handoff times use UTC. |
| 11 | Capture loss / TCP-ACK notice | `capture_loss.log`: 0 gaps, 0.0% lost; `notice.log` has `CaptureLoss::Too_Little_Traffic` ("0 TCP ACKs, expected ≥1") | tshark shows 100% UDP, zero TCP frames | DISCREPANT-EXPLAINED | Zeek's capture-loss heuristic expects TCP ACKs; a UDP-only tunnel triggers a benign notice. 0.0% packet loss reported; no evidence of missing packets. |
| 12 | dnscat2 identity from `dnscat.` prefix | 445/445 `dns.log` queries begin `dnscat.`; hex-only labels | `tshark -e dns.qry.name` → every name `dnscat.<hex...>`; `report/decode_dnscat2.py` → 0 non-hex labels, 16,180 hex chars | CONFIRMED | Signature-based identification (certain). Contrasted with generic statistics (record-type mix, entropy), which are only supporting/likely evidence. |
| 13 | Two session markers | byte[3:5] `0xbb73` in 263 queries, `0x9658` in 182 (decode script) | tshark first-label hex inspection, frames 1–803 vs 241–889 | CONFIRMED | Both markers seen by tshark-derived extraction; overlap frames 241–803 ⇒ two concurrent logical channels. |
| 14 | Query-name length max 240 | Zeek `query` longest via zeek-cut → 240 chars (2 names) | `tshark -e dns.qry.name` awk length → 240 (frames 281, 283) | CONFIRMED | 0 |

**Reconciliation summary:** 1/1 flows, 890/890 packets, 104,305/104,305 IP
bytes, all zero deltas. Two apparent discrepancies (#10 timezone rendering,
#11 TCP-ACK loss heuristic) are explained, not data conflicts. No claim relies
on a third tool.
