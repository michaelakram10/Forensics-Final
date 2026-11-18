# Project 09 — Network Session Reconstruction

## Presenter deck

**Project:** Digital Forensics — Network Session Reconstruction
**Date:** 2026-11-18  **Version:** 1.2

---

## Slide 1 — What we did

- Four cases reconstructed from sealed pcap + Zeek logs, cross-checked with tshark/tcpdump.
- **Two real lab captures** (Cases 01 and 03, loopback) and **two synthetic reconstructions** (Cases 02 and 04, Scapy).
- Deliverables: per-case reports, timelines, charts, confidence matrix, final report, raw-evidence appendix, hash manifest, flow exports, focused pcap excerpts, PDFs.
- All times UTC. Byte accounting identity verified in every case:
  `Σ frame.len − 14 × packets = Σ ip.len = Zeek Σ *_ip_bytes`.

---

## Slide 2 — Evidence and provenance

| Case | Provenance | Packets | UTC span |
|---|---|---:|---|
| 01 | **Real** lab SSH capture, loopback | 107 | 2026-11-16 16:20:54–16:21:28 |
| 02 | Synthetic (Scapy) SQLi / CSV exfil | 203 | 2026-11-03 13:20:00–13:22:12 |
| 03 | **Real** lab dnscat2 capture, loopback | 890 | 2026-11-18 18:25:25–18:30:23 |
| 04 | Synthetic (Scapy) TLS beaconing | 2032 | 2026-11-04 14:00:00–14:43:13 |

- Real captures use `127.0.0.1` for both ends — protocol-level reconstruction, no distinct attacker IP.
- `capinfos` prints VM local time (UTC−5); note the 5-hour offset, same packets.
- Full provenance: `report/data_provenance.md`.

---

## Slide 3 — Pipeline (reproducible)

1. `tools/seal_evidence.sh` → SHA-256 sidecars, read-only originals, custody log.
2. `tools/run_zeek.sh <case> <nn>` → Zeek TSV + JSON (hash check first).
3. `tools/verify_counts.py <case> <nn>` → Zeek vs tshark reconciliation.
4. `tools/build_timeline.py` / manual timelines → `timeline.csv` with evidence refs.
5. `tools/generate_timelines.py` → 220-dpi charts; Mermaid sequence diagrams.
6. `tools/export_flows.py`, `tools/make_excerpts.py`, `tools/export_pdf.py`.

All four reconciliations: **CONFIRMED** for flows, packets and IP bytes.

---

## Slide 4 — Case 01: real SSH lab capture

- 107 packets, 3 TCP conversations to `127.0.0.1:22`; 34.385 s total span, longest session 19.859 s.
- Client banners: `SSH-2.0-libssh_0.12.2`; server: `SSH-2.0-OpenSSH_10.6p1 Debian-1`.
- Two long sessions plus one short connection; sizes and timing are visible, payload is encrypted.
- Honest finding: **no port scan and no brute-force burst** are present in this real capture — those belonged to the synthetic version, preserved under `supplementary/`.

---

## Slide 5 — Case 02: SQL injection and CSV exfiltration (synthetic)

- 3 TCP connections, 17 HTTP requests, 11 SQLi-pattern requests on `/vulnerabilities/sqli/?id`.
- Cleartext `admin/password` POST body (44 B) recovered by tshark; Zeek saw only the length.
- `INTO OUTFILE '/var/www/html/dump/customers.csv'` then a download 30 s later.
- `customers.csv`: 28,370 B, 501 lines, SHA-256 `9b44747e…ca4c6` — **identical in Zeek and tshark extractions**.
- Explain the MIME delta: Zeek sniffed `text/plain`; HTTP header said `text/csv`.

---

## Slide 6 — Case 03: real dnscat2 DNS tunnel

- 890 packets, 445 DNS queries + 445 responses, one UDP flow `127.0.0.1:44651 ↔ 127.0.0.1:53`, ~298.5 s.
- Query names carry the `dnscat.` prefix — a dnscat2 signature on **all 445 queries** (tool identity Certain, not inferred from statistics).
- qtypes CNAME 164 / MX 150 / TXT 131; 445 unique hex names, 41–240 chars; two session markers `0xbb73`/`0x9658` overlap (likely two logical channels).
- Zeek ↔ tshark: 1/1 flows, 890/890 packets, 104,305/104,305 IP bytes; 116,765 frame bytes − 14×890 = 104,305.
- Polling-rate phases: 0–118.8 s 120 queries (≈1.01/s, 1 session); 118.8–256.0 s 282 (≈2.06/s, 2 sessions, second handshake at t=118.81 s); 256.0–298.5 s 43 (≈1.01/s, back to 1 session) — Likely.
- Honest limitation: dnscat2 payload is encrypted; only structure, timing and volume are recoverable — no plaintext, file or exfil quantity.

---

## Slide 7 — Case 04: periodic TLS beaconing (synthetic)

- 46 connection attempts to port 8443: 20 answered to `203.0.113.50`, 2 unanswered, 24 to `203.0.113.51`.
- All 44 TLS sessions: TLS 1.2, same cipher and SNI `updates.cdn-lab.test`.
- 45 intervals from 46 first-SYN timestamps: mean 57.58 s, median 56.91 s; the 6.00 s minimum is a follow-up session, not a beacon period.
- Outliers: 4,219 B down + 2,302 B up 6 s later; 86,263 B upload. Per-stream client bytes match for all 44 streams.

---

## Slide 8 — Confidence approach

| Rating | Meaning |
|---|---|
| **Certain** | Directly visible field/string, reproduced by a second tool, no plausible alternative. |
| **Likely** | Best-single-explanation, but decisive evidence (payload, intent, host outcome, identity) is absent. |
| **Inferred** | Statistics/timing/analogy, or confirmation would need unavailable data. |

- Observation and interpretation are **separate findings**.
- 41 findings: 21 Certain, 15 Likely, 5 Inferred.
- Tool identity, intent, host effects: at most Likely (usually Inferred).
- This was a **manual-guided** exercise, not a blind one — no claim of frozen-before-unsealing is made.

---

## Slide 9 — What the second tool added

- Case 02: cleartext POST credentials (tshark form fields) and an independently hashed file copy.
- Case 03: independent DNS counts, qtype distribution and timestamp verification.
- Cases 01/04: per-stream byte totals and packet-size details Zeek only reports in aggregate.
- Explained differences: 14 B/frame Ethernet header; Zeek MIME sniff vs HTTP `Content-Type`; tshark 4.6 boolean flags.

---

## Slide 10 — Limitations to state out loud

- Real captures are on loopback — no distinct attacker/victim addresses.
- SSH, dnscat2 and TLS payloads are encrypted: command names, credentials and file contents are not determinable.
- No host evidence: cookie validity, file-write success, tasking/exfiltration intent are inferences.
- Synthetic TLS omits a Certificate message (Zeek 9.0.1 still reports `established=T`).
- No ground-truth console log was kept; Case 03 burst/session interpretations rely on traffic patterns only.
- `nfpcapd`/`nfdump` install was attempted but no passwordless sudo is available; flow CSVs remain Zeek exports. `pandoc` is unavailable, so PDFs use WeasyPrint.

---

## Slide 11 — How to verify my work (60 seconds)

```bash
cd Forensics-Final
for f in cases/*/raw/*.sha256; do (cd "$(dirname "$f")" && sha256sum -c "$(basename "$f")"); done
zeek-cut uid query < cases/case03_dns_tunnel/zeek/tsv/dns.log | head -n 3
tshark -r cases/case02_web_sqli/raw/case02.pcap -Y 'http.request.method=="POST"' \
  -T fields -e urlencoded-form.key -e urlencoded-form.value
sha256sum cases/case02_web_sqli/tshark/http_objects/customers.csv
```

Expected: 4 × `OK`; dnscat2 query names; `username/password/Login` and `admin/password/Login`;
`9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6`.

---

## Slide 12 — Questions

- Full report: `report/FINAL_REPORT.md` (+ PDF)
- Raw evidence: `cases/*/{raw,zeek,tshark,tcpdump}/`
- Timeline charts: `cases/*/viz/*.png`; sequence diagrams: `report/figures/*.mmd`
- Hashes: `report/hash_manifest.md`; custody: `custody/custody_log.csv`
