# Custody log — companion notes

`custody_log.csv` is the chain-of-custody record for the sealed pcaps. The
`pcap_sha256` column holds the SHA-256 from each pcap's `.sha256` sidecar, or
`n/a` for documentation-only entries.

## Attribution

Every row's `user` (and usually `host`) is `kali` because that is the **shared
lab account** used for the acquisition and analysis sessions; it is not a
per-person identifier. Ownership of the files and areas of work is listed in
the roles table at the top of `report/FINAL_REPORT.md` (Michael Akram, Yousef
Basem, Mahgoub Hany, Mohamed Mohamed Fawzy and Yasser Yasser Mahmmoud).

Do not infer which individual performed a particular row from the `kali` value.
No per-person attribution has been invented. The `notes` column records
operator-reported context where it exists, including the explicitly labelled
Case 01 Hydra setup note in `cases/case01_ssh_sessions/report/pcap_notes.md`.
