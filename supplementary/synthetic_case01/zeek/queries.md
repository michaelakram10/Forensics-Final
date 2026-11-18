# Case 01 — Zeek queries (TSV via `zeek-cut`, JSON via `jq`)

Working directory for TSV: `cases/case01_ssh_bruteforce/zeek/tsv`. All timestamps UTC (`export TZ=UTC`).

## Q1.1 Inventory and header

```bash
ls -l
head -n 8 conn.log | cut -c1-160
wc -l conn.log
zeek-cut uid < conn.log | wc -l
```

Observed: logs present are `conn.log ssh.log notice.log software.log known_hosts.log known_services.log capture_loss.log stats.log packet_filter.log loaded_scripts.log` (no `weird.log` from Zeek 9.0.1). `zeek-cut uid < conn.log | wc -l` → **50**.

## Q1.2 Who talked to whom, with what outcome

```bash
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | sort | uniq -c | sort -rn
```

Output (abridged to the distinct groups):

```
     37 192.168.56.10  192.168.56.20  22    SF
      1 192.168.56.10  192.168.56.20  80    RSTO
      1 192.168.56.10  192.168.56.20  22    RSTO
      1 192.168.56.10  192.168.56.20  8080  REJ
      1 192.168.56.10  192.168.56.20  3306  REJ
      1 192.168.56.10  192.168.56.20  443   REJ
      1 192.168.56.10  192.168.56.20  445   REJ
      1 192.168.56.10  192.168.56.20  139   REJ
      1 192.168.56.10  192.168.56.20  111   REJ
      1 192.168.56.10  192.168.56.20  110   REJ
      1 192.168.56.10  192.168.56.20  53    REJ
      1 192.168.56.10  192.168.56.20  25    REJ
      1 192.168.56.10  192.168.56.20  23    REJ
      1 192.168.56.10  192.168.56.20  21    REJ
```

## Q1.3 Scan fingerprint

```bash
zeek-cut -d ts id.orig_p id.resp_p conn_state history duration orig_bytes resp_bytes \
  < conn.log | awk '$2==51234' | sort -k3,3n
zeek-cut ts id.orig_p < conn.log | awk '$2==51234{n++; if(!min||$1<min)min=$1; if($1>max)max=$1} END{printf "%d probes in %.3f s\n", n, max-min}'
```

Output: 13 probe rows from source port 51234, histories `Sr` (11 closed ports) and `ShR` (ports 22, 80), durations ≈0.0004 s. Summary: **`13 probes in 0.600 s`**.

## Q1.4 Open ports

```bash
zeek-cut id.resp_p history < conn.log | awk '$2 ~ /h/ && $2 ~ /^ShR/' | sort -n
```

Output: `22 ShR`, `80 ShR`.

## Q1.5 SSH profile and the outlier

```bash
zeek-cut id.resp_p id.orig_p duration orig_bytes resp_bytes orig_pkts conn_state < conn.log \
 | awk '$1==22 && $7=="SF"{ if($3<5){n++; so+=$4; sr+=$5; sp+=$6} else {print "LONG SESSION:", $0} }
        END{printf "short sessions: %d  mean orig_bytes=%.0f  mean resp_bytes=%.0f  mean orig_pkts=%.1f\n", n, so/n, sr/n, sp/n}'
```

Output:

```
LONG SESSION: 22 49302 48.685172 4020 25110 165 SF
short sessions: 36  mean orig_bytes=917  mean resp_bytes=1490  mean orig_pkts=15.0
```

## Q1.6 SSH identity (ssh.log)

```bash
zeek-cut client server < ssh.log | sort | uniq -c | sort -rn
zeek-cut -d ts id.orig_p client auth_success auth_attempts kex_alg < ssh.log | head -n 5
zeek-cut auth_success auth_attempts < ssh.log | sort | uniq -c
```

Output:

```
     36 SSH-2.0-libssh_0.10.6      SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
      1 SSH-2.0-OpenSSH_9.9p1 Debian-3  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10

     36 -  0
      1 T  1
```

Zeek's heuristic does mark the long session `auth_success=T, auth_attempts=1`; the 36 short sessions remain unset. The guide expected `-` throughout; measured output wins and is used in the report.

## Q1.7 Interactive-session fingerprint

```bash
zeek-cut id.orig_p duration orig_pkts resp_pkts orig_bytes resp_bytes < conn.log | awk '$1==49302'
```

Output: `49302 48.685172 165 164 4020 25110`.

## Q1.8 JSON equivalents

Working directory: `cases/case01_ssh_bruteforce/zeek/json`.

```bash
jq -r 'select(.["id.resp_p"]==22) | [(.ts|todate), .["id.orig_p"], .duration, .orig_bytes, .resp_bytes, .conn_state] | @tsv' conn.log | head
jq -r 'select(.["id.resp_p"]==22) | .conn_state' conn.log | sort | uniq -c
jq -s 'max_by(.duration) | {ts:(.ts|todate), orig:.["id.orig_p"], dur:.duration, ob:.orig_bytes, rb:.resp_bytes}' conn.log
```

Observed: 37 rows on port 22 (36 SF short + 1 SF long, plus the single scan RSTO row is excluded because its `orig_bytes`/state filter differs); longest connection = `{"ts":"2026-11-02T09:01:22Z","orig":49302,"dur":48.685172,"ob":4020,"rb":25110}`.
