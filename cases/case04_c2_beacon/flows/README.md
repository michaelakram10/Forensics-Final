# Flow export — case04_c2_beacon

`case04_flows.csv` is a **tabular flow export derived from Zeek `conn.log`**. `nfpcapd`/`nfdump` are not installed in this environment, so these are not NetFlow records captured by a flow exporter. Zeek `conn.log` is itself a bidirectional flow log; this CSV simply presents each connection as one flow record for readers who want a flow-oriented view. It is reconciled against tshark TCP/UDP stream counts in `report/flows_reconciliation.md`. Provenance: Zeek 9.0.1 JSON `conn.log`, generated from the sealed pcap with `tools/run_zeek.sh`.
