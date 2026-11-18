# Case 03 — Zeek queries (TSV via `zeek-cut`, JSON via `jq`)

## Q3.1 Volume and rate

```bash
zeek-cut ts < dns.log | wc -l                     # 242
zeek-cut ts < dns.log | awk 'NR==1{a=$1} {b=$1} END{printf "span %.1f s\n", b-a}'   # 627.9 s
```

## Q3.2 Domain statistics

Script: `tools/dns_stats.py` (created from the guide). Run:

```bash
zeek-cut query < dns.log | "$P09/tools/dns_stats.py"
```

Output:

```
registered_domain      queries  unique  mean_len  max_len   mean_H(longest_label)
exfil-lab.test             202     202     134.9      136                    4.35
corp.test                   22       4      16.3       18                    2.43
example.test               18       6      16.7       19                    2.52
```

## Q3.3 Query types and answers

```bash
zeek-cut qtype_name rcode_name < dns.log | sort | uniq -c
```

Output: `40 A NOERROR`, `202 TXT NOERROR`. Tunnel answers are TXT strings `ready`, `a0001`…`a0200`, `done` (seen in `dns.log` `answers` field and in tshark's TXT field).

## Q3.4 Timing

```bash
zeek-cut -d ts query < dns.log | grep exfil-lab | sed -n '1p;$p'
zeek-cut ts query < dns.log | grep exfil-lab | awk 'NR>1{d=$1-p; s+=d; n++} {p=$1} END{printf "mean inter-query gap %.3f s over %d gaps\n", s/n, n}'
```

Output: first `2026-11-05T10:10:00+0000 init.t.exfil-lab.test`, last `2026-11-05T10:10:47+0000 fin.s0200.t.exfil-lab.test`; `mean inter-query gap 0.238 s over 201 gaps`.

## Q3.5 Outbound bytes via uid join (JSON)

```bash
jq -r 'select(.query|test("exfil-lab\\.test$")) | .uid' dns.log > /tmp/tunnel_uids.txt
jq -s --rawfile u /tmp/tunnel_uids.txt '
  ($u|split("\n")|map(select(length>0))) as $ids
  | map(select(.uid | IN($ids[])))
  | {conns: length, orig_bytes:(map(.orig_bytes)|add), orig_ip_bytes:(map(.orig_ip_bytes)|add), resp_ip_bytes:(map(.resp_ip_bytes)|add)}' conn.log
```

Output (Zeek JSON, case03):

```json
{
  "conns": 202,
  "orig_bytes": 30883,
  "orig_ip_bytes": 36539,
  "resp_ip_bytes": 40174
}
```
