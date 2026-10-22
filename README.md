# SOC Lab Portfolio

A self-built Security Operations Center Lab: SIEM detection engineering,
SOAR-driven threat intel correlation, case management, and adversary
emulation / detection validation, built and verified end-to-end on a
two-node Proxmox homelab.

This repository is not a tutorial. It documents real decisions, real
bugs found and fixed, and real live-traffic verification — the goal is
to show how the system was reasoned about, not just that it runs.

**Live documentation: [k0zzi.github.io/soc-lab-portfolio](https://k0zzi.github.io/soc-lab-portfolio/)**<br>
**Atomic Red Team findings: [tools/red-team/findings/](tools/red-team/findings/)**

## Scope

- **SIEM**: Wazuh (Sysmon-based endpoint telemetry, Suricata IDS/IPS
  network telemetry), tuned with the Olaf Hartong sysmon-modular
  community config plus custom correlation rules.
- **Threat intelligence matching**: MISP indicators (IPv4 addresses and
  domain names) are exported by a script into Wazuh CDB lists and matched
  locally on the manager, so only matches leave the SIEM instead of every
  event being looked up in MISP. IPv4 indicators are matched on Sysmon
  network connections and on OPNsense firewall logs (both directions). DNS
  names are normalized (ASCII-only case folding, trailing dot, IDNA) and
  matched on label boundaries, including subdomains of domain-type
  indicators. See
  [tools/blue-team/wazuh/misp-ioc-sync/](tools/blue-team/wazuh/misp-ioc-sync/).
- **Alert layer (pilot)**: Wazuh Alerting monitors group the IOC alarms per
  indicator and keep the count, first/last seen and alert state in the
  engine. A Shuffle node mirrors the open alerts into TheHive, one alert per
  indicator, with the matched events summarised and MISP context (events,
  tags, decay score) added. The vendor comparison and the documented
  deviations are in
  [tools/blue-team/shuffle/ioc-alert-reader/](tools/blue-team/shuffle/ioc-alert-reader/);
  the monitor definitions are in
  [tools/blue-team/wazuh/alerting-monitors/](tools/blue-team/wazuh/alerting-monitors/).
- **Hash matching (pilot)**: file hashes do not use the CDB route, because Wazuh's decoders did not split
  the Sysmon hash string for Windows event-channel events in the lab. An ingest pipeline splits it into typed
  fields at index time, a script writes the last 30 days of published MISP hash indicators (SHA256, MD5,
  SHA1) into slot documents in the indexer, and three Alerting monitors compare the fields with those
  documents through terms lookups; the alert layer above mirrors the result into TheHive. Only events that
  Wazuh stores as alerts are searched, and IMPHASH is deliberately not matched. See
  [tools/blue-team/wazuh/misp-hash-slots/](tools/blue-team/wazuh/misp-hash-slots/),
  [tools/blue-team/wazuh/ingest/](tools/blue-team/wazuh/ingest/) and
  [tools/blue-team/wazuh/alerting-monitors/](tools/blue-team/wazuh/alerting-monitors/).
- **SOAR**: Shuffle workflows turn IOC matches into TheHive alerts (for
  domains, one alert per match; TheHive groups repeats by shared
  observable). The original per-event workflows, which query MISP for every
  network, DNS or process-hash event with deduplication and fail-closed
  error handling, remain exported here and still serve process-hash
  correlation. The per-match workflows still run in parallel with the alert
  layer above.
- **Case management**: TheHive + Cortex for incident triage.
- **Detection-as-code**: Sigma and Wazuh rules, version-controlled,
  CI-scanned for secrets before merge. The MISP sync script, the hash slot
  writer, the domain matching integration, the Shuffle node code (domain workflow and alert
  reader) and the acceptance harness have unit tests (standard library only).
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
    wazuh/
      local_rules/           — local detection rules (Suricata, Sysmon, Atomic Red Team, MISP IOC)
      sysmon/                — Sysmon config and notes
      misp-ioc-sync/         — MISP to Wazuh CDB list export, with tests and design notes
      custom-integrations/   — domain matching integration (normalization, subdomains), with tests
      validation/            — acceptance harness for the domain IOC rules, with tests
      alerting-monitors/     — Wazuh Alerting monitors that group IOC alarms per indicator (IP, domain, hash)
      misp-hash-slots/       — MISP hash indicators to indexer slot documents for terms lookups, with tests
      ingest/                — ingest pipeline that splits Sysmon hashes into typed fields, and how to hook it in
    shuffle/
      shuffle-workflows/     — exported SOAR workflows (original per-event IOC correlation)
      misp-domain-workflow/  — Shuffle node code and TheHive request body for the domain workflow
      ioc-alert-reader/      — Shuffle node that mirrors the monitors' alerts into TheHive with MISP context, with tests
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

Work in progress. IPv4 and domain matching are live. The Alerting-based alert
layer is a pilot: the monitor for firewall destination matches and the TheHive
reader with MISP context have been verified on live traffic; the monitors for
inbound firewall, Sysmon IP and domain matches have not yet been seen on real
alarms (details in
[tools/blue-team/shuffle/ioc-alert-reader/](tools/blue-team/shuffle/ioc-alert-reader/)).
Hash matching is a pilot too: the chain from a Sysmon hash to a TheHive alert
was verified end to end with a control value placed in a slot, but no hash
listed in MISP has appeared in the lab's events yet. IPv6/CIDR indicators and
enforcement (firewall alias, DNS blocklist) are not done yet. The MISP page under `docs/` still describes
the original per-event design; the local-matching redesign is described in
[tools/blue-team/wazuh/misp-ioc-sync/](tools/blue-team/wazuh/misp-ioc-sync/)
until that page is updated.

See the [live documentation](https://k0zzi.github.io/soc-lab-portfolio/) or the `docs/` folder for completed build steps.
