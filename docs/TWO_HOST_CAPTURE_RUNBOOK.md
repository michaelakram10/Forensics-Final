# Two-host capture runbook — TEMPLATE (HUMAN ONLY)

> **Status: runbook only. No capture has been performed and no results are
> recorded here.** This is human-only work: the agent that created this file did
> not run a two-VM capture. Do not write invented timestamps, IP addresses,
> hashes or findings into this document.
>
> The existing analysis is **manual-guided, not blind**; that statement remains
> true. A new capture would be additional evidence, not a rewrite of the sealed
> originals. Follow `report/methodology.md` Section 5 for any new ratings.

## 1. Lab setup (fill in when performed)

- Host-only network / vSwitch: `<name>`
- Attacker VM: `<name>`, IP `<192.168.56.10 or actual>`
- Victim VM: `<name>`, IP `<192.168.56.30 or actual>`
- Optional sniffer / resolver VM: `<name>`, IP `<address>`
- Capture interface on the sniffing VM: `<iface>`
- VM clock offsets relative to UTC: attacker `<+/− hh:mm>`, victim `<+/− hh:mm>`,
  sniffer `<+/− hh:mm>`

## 2. Capture (run by a person, with exact commands recorded)

Start the capture on the victim or a third sniffer VM:

```bash
export TZ=UTC
sudo tcpdump -i <iface> -w case05.pcap
```

Perform one exercise, for example:

- SSH brute force with Hydra from attacker to victim; **or**
- DNS tunnelling with the resolver on a third VM so the authoritative server is
  visible in the capture.

Stop the capture and preserve the exact commands used:

```bash
sudo kill <TCPDUMP_PID>
```

Record in `cases/case05_<descriptive_name>/report/pcap_notes.md`:

- exact start/stop commands and their UTC times;
- exact exercise commands (omit secrets/wordlist contents);
- VM clock offsets and how UTC was derived;
- who ran it and on which VM;
- whether the capture is from two distinct hosts (not loopback).

## 3. Add the case using `docs/NEW_CASE_PIPELINE.md`

1. Move the sealed pcap and its `.sha256` into the new case's `raw/` directory.
2. Follow every step in `docs/NEW_CASE_PIPELINE.md` (scripts with hard-coded
   case lists must be edited first).
3. Add custody rows; do not edit existing rows.
4. Rate findings using `report/methodology.md` Section 5. Observation and
   interpretation stay separate; intent and tool identity are at most Likely.
5. Keep the manual-guided, not blind statement in all reports and the README.

## 4. Verification checklist

- [ ] `sha256sum -c` passes for the new pcap.
- [ ] Zeek ↔ tshark flow/packet/byte reconciliation is CONFIRMED (or explained).
- [ ] Timeline rows have `evidence_ref` values.
- [ ] Reports state the new capture's provenance truthfully.
- [ ] PDFs and `report/hash_manifest.md` regenerated last.
