# Wazuh Alerting monitors for IOC alerts

Four bucket-level monitors over `wazuh-alerts-*`. Each one groups the IOC rule alarms of the last
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

## Create

Wazuh dashboard, Indexer management, Dev Tools (one request per file; the body is the file content):

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
