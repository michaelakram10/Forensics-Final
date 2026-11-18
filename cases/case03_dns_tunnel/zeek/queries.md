# Case 03 — Zeek query analysis (Zeek 9.0.1, `export TZ=UTC`)

All commands run from the case directory with `export PATH=/opt/zeek/bin:$PATH`.
TSV and JSON logs were regenerated from the sealed pcap with
`tools/run_zeek.sh case03_dns_tunnel case03` (hash check passed first).
Times printed by Zeek are Unix epochs; converting to UTC gives
2026-11-18 18:25:25.008145 → 18:30:23.514718 UTC (Zeek's own `#open` header
shows VM-local 2026-11-18-19-29-55 because the VM runs UTC-5; the log *data*
timestamps are epoch and therefore timezone-independent).

## Query count
```
export PATH=/opt/zeek/bin:$PATH; zeek-cut ts < zeek/tsv/dns.log | grep -vc '^#'
```
```
445
```
Zeek writes one `dns.log` row per query (the response is joined into `rtt` /
`answers`). 445 DNS query rows ↔ 445 tshark query frames ↔ 445 response frames.

## qtype distribution
```
zeek-cut qtype_name < zeek/tsv/dns.log | grep -v '^#' | sort | uniq -c
```
```
    164 CNAME
    150 MX
    131 TXT
```
Equivalent JSON command:
```
jq -r '.qtype_name' zeek/json/dns.log | sort | uniq -c
```
```
    164 CNAME
    150 MX
    131 TXT
```

## Unique names
```
zeek-cut query < zeek/tsv/dns.log | grep -v '^#' | sort -u | wc -l
```
```
445
```
All 445 query names are distinct — consistent with per-message sequence/nonce
data embedded in each `dnscat.<hex>` label set.

## First / last timestamps (epoch, UTC)
```
zeek-cut ts < zeek/tsv/dns.log | grep -v '^#' | sed -n '1p;$p'
```
```
1795026325.008145
1795026623.513247
```
= 2026-11-18 18:25:25.008145 UTC → 2026-11-18 18:30:23.513247 UTC (last *query*;
the last *response* frame is 1795026623.514718).
JSON equivalent:
```
jq -r '[.ts,.query]|@tsv' zeek/json/dns.log | sed -n '1p;$p'
```
```
1795026325.008145  dnscat.87ff03bb730000000005fa2769a17431349604b950c74cf27751cb... (truncated)
1795026623.513247  dnscat.dbb30196584ef82b8ed59a00b452340488
```

## Longest names
```
zeek-cut query < zeek/tsv/dns.log | grep -v '^#' | awk '{print length($0), $0}' | sort -rn | head -3
```
```
240 dnscat.cc5b01bb737b04a2880bef0083d4b705acaf72a6a7bb59bfd3f4b7841af0... (frame 283)
240 dnscat.827701bb73cf055c7f6b700082f7408497833f2a3858d9a8f1c1b9bd838e... (frame 281)
181 dnscat.846301bb7331360668e417008404997bf43d8002d4d57aff07805a5eb690... (frame 285)
```
Name length min 41, max 240, mean 43.398, median 41 characters (tshark cross-check).

## uid join for flow bytes (conn.log)
```
zeek-cut uid orig_bytes resp_bytes orig_pkts resp_pkts duration < zeek/tsv/conn.log | grep -v '^#'
```
```
Chubce1wik6p4KDZeg  27322  52063  445  445  298.506573
```
`uid = Chubce1wik6p4KDZeg` is the single UDP flow 127.0.0.1:44651 → 127.0.0.1:53,
`service=DNS`, `conn_state=SF`, `orig_ip_bytes=39782`, `resp_ip_bytes=64523`.
Every `dns.log` row carries this same uid, proving all DNS activity belongs to
that one flow. `orig_bytes`/`resp_bytes` are layer-7 payload; the 14-byte/frame
Ethernet overhead identity is verified in `report/verification.md`.
