# SOC Lab Portfolio

A self-built Security Operations Center lab: SIEM detection engineering,
SOAR-driven threat intel correlation, and case management, built and
verified end-to-end on a two-node Proxmox homelab.

This repository is not a tutorial. It documents real decisions, real
bugs found and fixed, and real live-traffic verification — the goal is
to show how the system was reasoned about, not just that it runs.

## Scope

- **SIEM**: Wazuh (Sysmon-based endpoint telemetry, Suricata IDS/IPS
  network telemetry), tuned with the Olaf Hartong sysmon-modular
  community config plus custom correlation rules.
- **SOAR**: Shuffle workflows correlating Wazuh alerts (network, DNS,
  and process-hash indicators) against MISP threat intel, with
  deduplication and fail-closed error handling.
- **Case management**: TheHive + Cortex for incident triage.
- **Detection-as-code**: Sigma rules, version-controlled, CI-scanned
  for secrets before merge.

## Repository structure

tools/
blue-team/
wazuh/ — local detection rules + Sysmon config
shuffle/ — exported SOAR workflows (network/DNS/hash IOC correlation)
thehive/ — case-management integration notes
sigma/ — SIEM-agnostic detection rules (Sigma format)
docs/ — step-by-step build documentation (HTML)


## A note on secrets

All webhook UUIDs, API keys, and service credentials in this repo have
been redacted as `<REDACTED_TYPE>` placeholders. Lab-internal IP
addresses (RFC1918, `10.1.x.x`) are left intact — they're not usable
outside this network and are useful for explaining the VLAN
architecture. See `secret-scan.sh` for the manual literal-string scan
used alongside gitleaks CI.

## Status

Work in progress. See `docs/` for completed build steps.