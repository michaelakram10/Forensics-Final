# Case 04 — Zeek queries (TSV via `zeek-cut`, JSON via `jq`)

## Q4.1 Connection groups

```bash
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | sort | uniq -c | sort -rn
```

Output:

```
     24 192.168.56.40  203.0.113.51  8443  SF
     20 192.168.56.40  203.0.113.50  8443  SF
      6 192.168.56.40  198.51.100.20  443  SF
      2 192.168.56.40  203.0.113.50  8443  S0
```

## Q4.2 TLS metadata

```bash
zeek-cut -d ts id.resp_h id.resp_p version cipher server_name established < ssl.log | head -n 6
zeek-cut version cipher server_name established < ssl.log | sort | uniq -c
```

Output counts: 44 × `TLSv12 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 updates.cdn-lab.test T` (both C2 IPs) and 6 × same version/cipher with `www.example.test` (benign host). Same SNI on two different C2 IPs is itself a finding.

Note: synthetic TLS omits the Certificate message; `ssl.log` still shows `established=T` in Zeek 9.0.1 and no certificate chain fingerprints. This is recorded as a limitation rather than treated as proof of certificate validation.

## Q4.3 Beacon statistics

```bash
./tools/beacon_stats.py case04_c2_beacon
```

Output (`tshark/beacon_stats.txt`):

```
src            dst             port   n  mean_s  median  stdev   CV   MAD  S0 med_orig_B med_resp_B
192.168.56.40  198.51.100.20    443   6   506.3   465.6  157.6  0.31  20.7   0        793      99855
192.168.56.40  203.0.113.50   8443  22    57.9    56.6   13.2  0.23   3.5   2        578        227
192.168.56.40  203.0.113.51   8443  24    57.7    57.1    4.9  0.09   2.4   0        594        227
```

The primary group's CV is inflated by the 6-second follow-up session and the two failed attempts; median and MAD are used in the report. The benign HTTPS group has a small MAD/median ratio (0.04) purely because its absolute intervals are much longer; it is not treated as beaconing.

## Q4.4 Largest upload and download

```bash
zeek-cut -d ts id.resp_h orig_bytes resp_bytes duration < conn.log | grep -v 198.51.100.20 | sort -k3,3nr | head -n 2
zeek-cut -d ts id.resp_h orig_bytes resp_bytes duration < conn.log | grep -v 198.51.100.20 | sort -k4,4nr | head -n 2
```

Output: upload `2026-11-04T14:31:37+0000 203.0.113.51 86263 203 1.996045`; tasking response `14:06:59 Z 203.0.113.50 578 4219 0.587141` followed by `14:07:05 Z ... 2302 B up`.

## Q4.5 Unanswered attempts

```bash
zeek-cut -d ts id.orig_p id.resp_h id.resp_p conn_state history orig_pkts < conn.log | awk '$5=="S0"'
```

Output:

```
2026-11-04T14:19:20+0000  49521  203.0.113.50  8443  S0  S  3
2026-11-04T14:20:15+0000  49522  203.0.113.50  8443  S0  S  3
```

Each has `orig_pkts=3` (SYN + 2 retransmissions). The next successful beacon goes to 203.0.113.51 at 14:21:04.997Z.
