# Wazuh Alerting monitors for IOC alerts

Seven bucket-level monitors over `wazuh-alerts-*` (four for IP addresses and domains, three for file hashes)
and one query-level health monitor. Each bucket-level monitor groups the alarms of the last
5 days by **indicator** and keeps the count, first/last seen and value lists in the Alerting
plugin's own alert (state `ACTIVE`, `ACKNOWLEDGED`, `COMPLETED`). They send no notifications
(`actions` is empty); the alerts are read through the Alerting API by the
[IOC alert reader](../../shuffle/ioc-alert-reader/), which mirrors them into TheHive.

| File | Rules (local_rules.xml) | Bucket key | Value lists kept in the alert | Verification |
|---|---|---|---|---|
| `ioc-fw-dst-t1.json` | 100330 (firewall, destination matched) | `data.dstip` | action, protocol, port, source IP, reporting host, rules, alarm ids | Live: alert content and lifecycle observed on real alarms |
| `ioc-fw-src-t1.json` | 100331 (firewall, source matched) | `data.srcip` | action, protocol, port, destination IP, reporting host, rules, alarm ids | Dry run clean; no real alert content seen yet |
| `ioc-sysmon-ip-t1.json` | 100301, 100304 (Sysmon IP) | `data.win.eventdata.destinationIp` | port, process image, reporting host, rules, alarm ids | Dry run clean; no real alert content seen yet |
| `ioc-domain-t1.json` | 100320, 100322 (DNS) | scripted (see below) | queried name, match kind, reporting host, rules, alarm ids | Dry run over 30 days of real alarms (18 alarms, 10 buckets) clean; the persisted monitor is empty until a new alarm arrives |
| `ioc-hash-sha256-t1.json` | alerts whose `ioc_hash.sha256` is in the slot documents `sha256-1` to `sha256-4` | `ioc_hash.sha256` | process image, parent process, event id, reporting host, rules, alarm ids | Dry run with a positive-control slot (one real hash, 59 alarms, every list filled); no real MISP match seen yet |
| `ioc-hash-md5-t1.json` | alerts whose `ioc_hash.md5` is in `md5-1` to `md5-4` | `ioc_hash.md5` | same as SHA256 | Created and running on schedule; same query shape as SHA256, no positive control run |
| `ioc-hash-sha1-t1.json` | alerts whose `ioc_hash.sha1` is in `sha1-1` | `ioc_hash.sha1` | same as SHA256 | Created and running on schedule; no positive control run |
| `ioc-hash-health.json` | query-level health monitor, see below | n/a | n/a | Dry run: 0 hits over 30 minutes, 5 hits over 8 hours (documents from before the pipeline hook) |

## Behaviour

- Window `now-5d` on `timestamp`, interval 1 minute. The 5 days follow QRadar's offense lifecycle
  (a dormant offense becomes inactive after 5 days and new events then open a new offense). The
  mechanism here is different: a sliding query window, not a state machine. When the newest alarm of
  a bucket is older than 5 days the bucket disappears, the alert completes, and a later alarm opens a
  new alert. Counts and `first` are therefore **windowed**: they drop when old alarms leave the window.
- Trigger `doc_count > 0` per bucket, severity 3. One alert per bucket key; the alert content
  (`agg_alert_content`) is rewritten on every run, also while the alert is acknowledged.
- `terms` buckets are capped (100 indicators; 50 values for IPs, ports, queried names and alarm ids;
  20 hosts and processes; 10 for actions, protocols, rules and match kinds).
- The domain monitor keys the bucket on `data.misp_domain.matched` (the normalised list entry, rule
  100322) and falls back to `data.win.eventdata.queryName` (rule 100320, exact match), so both rules
  land in one alert per indicator. The `containsKey` guards are there because `doc[...]` access on a
  field that is not mapped in an in-range index throws in Painless (OpenSearch behaviour, not checked
  against its documentation here).
- The firewall monitors see the firewall as the reporting host (`agent.name`); the internal client
  appears only as a raw address in the source/destination list.

## Hash monitors

The hash monitors do not select alarms by rule. Sysmon reports all hashes of an event in one string
(`SHA1=...,MD5=...,SHA256=...`, plus `IMPHASH=...` when configured) and Windows event-channel events do not pass through XML
decoders, so an ingest processor in the Wazuh Filebeat module pipeline splits the string into the lowercase
fields `ioc_hash.sha1`, `ioc_hash.md5` and `ioc_hash.sha256`. Each monitor compares one of
those fields with a terms lookup against the slot documents of the `ioc-hash-slots` index (written daily from MISP by
`misp_hash_slots.py`; at most 65,000 values per document because of OpenSearch's terms limit). Only the last
30 days of published MISP hash indicators are loaded.

Limits to know about:

* Only events that Wazuh stores as alerts are visible to these monitors. Events that raise no alert are not
  searched, so coverage is partial unless those events are stored as well.
* The ingest processor lives in a file of the Wazuh Filebeat module. The upgrade guides of the Wazuh versions
  checked (4.3 to 4.9) extract that module again, which replaces the file; the health monitor below shows when the
  processor is gone.
* IMPHASH (import hash) is deliberately not matched. It identifies a shared import table, not a file, and unrelated
  software can share a value; in our MISP data one value occurred in thousands of unrelated events. The vendor
  indicator documentation read for this design (a Microsoft Sentinel template, Palo Alto Cortex, CrowdStrike) lists
  MD5, SHA1 and SHA256 at most. It remains useful as a manual hunting pivot, not as a detection indicator.

`ioc-hash-health` is a query-level monitor (severity 2, no actions). It triggers when an alert of the last 30
minutes has a `data.win.eventdata.hashes` field but no `ioc_hash.sha256`, i.e. when the normalisation is not running.
It shows the current state only; it does not report gaps from the past.

## Create

Wazuh dashboard, Indexer management, Dev Tools (one request per file; the body is the file content). The hash monitors
need the `ioc-hash-slots` index and its documents first:

```
POST _plugins/_alerting/monitors
{ ...content of the JSON file... }
```

Test a monitor without keeping it: `POST _plugins/_alerting/monitors/_execute?dryrun=true` with the
same body. Reading the alerts requires the reserved `alerting_read_access` role (alerts get, monitor
get/search, findings get); map it to the read-only user the reader uses.

## Limits

Monitor and alert ids are assigned by your indexer and are not part of these files. Wazuh 4.14 ships
no default notification channels (Notifications, Channels: 0 on the lab), and in a limited test (two
template paths) a monitor action template resolved the bucket key but not the bucket's counts or value
lists, which is why the alerts are read through the API instead of being pushed. Other template paths
were not explored.
