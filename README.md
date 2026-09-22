# SOC Lab Portfolio

A self-built Security Operations Center Lab: SIEM detection engineering,
SOAR-driven threat intel correlation, case management, and adversary
emulation / detection validation, built and verified end-to-end on a
two-node Proxmox homelab.

This repository is not a tutorial. It documents real decisions, real
bugs found and fixed, and real live-traffic verification — the goal is
to show how the system was reasoned about, not just that it runs.

**📄 Live documentation: [k0zzi.github.io/soc-lab-portfolio](https://k0zzi.github.io/soc-lab-portfolio/)**

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
- **Adversary emulation & detection validation**: Atomic Red Team
  techniques run against live telemetry — each result (caught, missed,
  or prevented) traced to a specific root cause and cross-checked
  against MITRE ATT&CK, CISA, and major-vendor detection guidance,
  with fixes verified through genuine before/after comparisons rather
  than assumed.

## Repository structure

```
tools/
  blue-team/
    wazuh/     — local detection rules + Sysmon config
    shuffle/   — exported SOAR workflows (network/DNS/hash IOC correlation)
    thehive/   — case-management integration notes
    sigma/     — SIEM-agnostic detection rules (Sigma format)
  red-team/
    findings/  — Atomic Red Team per-technique results, root causes, sourcing,
                 plus the overall coverage summary and validation-cycle write-up
docs/ — step-by-step build documentation (HTML)
```

## A note on secrets

All webhook UUIDs, API keys, and service credentials in this repo have
been redacted as `<REDACTED_TYPE>` placeholders. Lab-internal IP
addresses (RFC1918, `10.1.x.x`) are left intact — they're not usable
outside this network and are useful for explaining the VLAN
architecture. See `secret-scan.sh` for the manual literal-string scan
used alongside gitleaks CI.

## Status

Work in progress. See the [live documentation](https://k0zzi.github.io/soc-lab-portfolio/) or the `docs/` folder for completed build steps.
