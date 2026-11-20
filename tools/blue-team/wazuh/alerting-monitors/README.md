# Wazuh Alerting monitors for IOC alerts

Nine bucket-level monitors over `wazuh-alerts-*` (six for IP addresses and domains, three for file hashes)
and five query-level monitors (a hash health check, the reader heartbeat and three pipeline health monitors). Each bucket-level monitor groups the alarms of the last
5 days by **indicator** and keeps the count, first/last seen and value lists in the Alerting
plugin's own alert (state `ACTIVE`, `ACKNOWLEDGED`, `COMPLETED`). The bucket-level monitors send no notifications
(`actions` is empty); the alerts are read through the Alerting API by the
[IOC alert reader](../../shuffle/ioc-alert-reader/), which mirrors them into TheHive.

| File | Rules (local_rules.xml) | Bucket key | Value lists kept in the alert | Verification |
|---|---|---|---|---|
| `ioc-fw-dst-t1.json` | 100330, 100334 (firewall, destination matched; allowed and blocked) | `data.dstip` | action, protocol, port, source IP, reporting host, rules, alarm ids | Live: alert content and lifecycle observed on real alarms |
| `ioc-fw-src-t1.json` | 100331, 100335 (firewall, source matched; allowed and blocked) | `data.srcip` | action, protocol, port, destination IP, reporting host, rules, alarm ids | Dry run clean; no real alert content seen yet |
| `ioc-fw-feed-block-dst.json` | 100360 (firewall block by a threat-feed alias, destination listed) | `data.dstip` | action, protocol, port, source IP, reporting host, rules, alarm ids | Live, real blocked connection (20 Nov 2026): the alert reached TheHive with the feed-block labels |
| `ioc-fw-feed-block-src.json` | 100361 (firewall block by a threat-feed alias, source listed) | `data.srcip` | action, protocol, port, destination IP, reporting host, rules, alarm ids | Dry run clean (no matching alarm yet); no real alert content seen |
| `ioc-sysmon-ip-t1.json` | 100301, 100304 (Sysmon IP) | `data.win.eventdata.destinationIp` | port, process image, reporting host, rules, alarm ids | Dry run clean; no real alert content seen yet |
| `ioc-domain-t1.json` | 100320, 100322 (DNS) | scripted (see below) | queried name, match kind, reporting host, rules, alarm ids | Dry run over 30 days of real alarms (18 alarms, 10 buckets) clean; the persisted monitor is empty until a new alarm arrives |
| `ioc-hash-sha256-t1.json` | alerts whose `ioc_hash.sha256` is in the slot documents `sha256-1` to `sha256-4` | `ioc_hash.sha256` | process image, parent process, event id, reporting host, rules, alarm ids | Dry run with a positive-control slot (one real hash, 59 alarms, every list filled); no real MISP match seen yet |
| `ioc-hash-md5-t1.json` | alerts whose `ioc_hash.md5` is in `md5-1` to `md5-4` | `ioc_hash.md5` | same as SHA256 | Created and running on schedule; same query shape as SHA256, no positive control run |
| `ioc-hash-sha1-t1.json` | alerts whose `ioc_hash.sha1` is in `sha1-1` | `ioc_hash.sha1` | same as SHA256 | Created and running on schedule; no positive control run |
| `ioc-hash-health.json` | query-level health monitor, see below | n/a | n/a | Dry run: 0 hits over 30 minutes, 5 hits over 8 hours (documents from before the pipeline hook) |
| `ioc-reader-heartbeat.json` | query-level monitor over the `ioc-reader-heartbeat` index, see below | n/a | n/a | Live: a real outage of the reader's orchestrator produced the message after 10 minutes and cleared itself |
| `ioc-sync-failure.json` | query-level, rules 100311 (success) and 100312 (failure), see below | n/a | n/a | Saved monitor read back, dry run and notification test; the failure branch has not been seen on a real failure (no 100312 alert is in the indexer) |
| `ioc-hash-slots-failure.json` | query-level, rules 100341 (success) and 100342 (failure), see below | n/a | n/a | Both branches checked against real data; a real failure raised an alert and a Telegram message (2 Nov 2026); closing after a later success has not been observed |
| `filebeat-index-rejects.json` | query-level, rule 100350, see below | n/a | n/a | Live, end to end with a synthetic log line (3 Nov 2026): the alert fired, the repeat was held by the throttle, and the alert closed on its own once the line left the 10-minute window |

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
- The JSON files leave the `terms` ordering, `min_doc_count` and the trigger's `gap_policy` at their defaults. The
  live monitors created or updated on 20 Nov 2026 were posted with those values written out explicitly, so the files
  are equivalent to the live definitions, not byte-identical.

## Firewall block monitors

Two kinds of firewall alarms reach the four firewall monitors. Matches against tier 1 MISP indicators (rules 100330,
100331, 100334 and 100335, `ioc-fw-*-t1`) and blocks by the OPNsense threat-feed aliases (rules 100360 and 100361,
`ioc-fw-feed-block-*`). The tier 2 rules (100332, 100333, 100336, 100337) raise Wazuh alerts only; no monitor mirrors
them to TheHive. A feed block is not a MISP match: the address is on an external feed list that the firewall
enforces, so the TheHive alert carries the tag `feed-block` and the source label `opnsense-feed-block`, not `misp-ioc`
and `tier1`, and the reader makes no MISP lookup for it. If an address is both a MISP indicator and on a feed list,
the MISP rule (100334 or 100335) wins in the rule engine (measured) and the alarm lands in the t1 monitor.

Rule levels (see `local_rules.xml`): an allowed connection to a listed address is level 10, a blocked one level 7,
for both MISP tiers. The tier stays in the rule id and group (`misp_ioc_fw_t1`, `misp_ioc_fw_t2`), not in the level.

Deviations from the vendors, to be read as our choice rather than a standard:

* **Level scale.** The split by firewall action follows Microsoft Sentinel's documentation (allowed rated higher than
  blocked), read in full. Splunk Enterprise Security 8.0 (read in full) does not change severity for a source: a source
  weight (1 to 100, default 60) feeds the risk score. IBM QRadar (read through a Juniper JSA 7.5.0 mirror; IBM's own
  pages could not be read) uses a confidence threshold at match time, and denied sessions can create offenses by
  default. The three disagree on how the source and the action should count, so the scale is ours; keeping the tier
  out of the level is our reading of that disagreement.
* **Tier-weighted risk score** (the Splunk approach) is not implemented; it needs a layer that aggregates scores.
* **Feed list not named.** The six feed aliases share one rule label per direction, so the alert cannot say which
  list blocked the address.
* **TheHive severity** is fixed (medium) and does not follow the action; only the Wazuh level does.
* A `nat` action of the firewall is matched by rule 100330 at level 10.

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

## Reader heartbeat monitor

`ioc-reader-heartbeat.json` is a query-level monitor over the `ioc-reader-heartbeat` index (written by the
[alert reader](../../shuffle/ioc-alert-reader/) as the last step of every live run), severity 1, every minute. Its query asks for the document
`reader` with `ok: true` and a `last_run` newer than 10 minutes; the trigger fires when there is none
(`hits.total.value == 0`). Its action posts to a Notifications channel with a throttle of 60 minutes. The message
template is the body that Telegram's `sendMessage` expects (`chat_id` and `text`). The file carries two placeholders you
must replace before posting it: `<CHAT_ID>` and `<NOTIFICATION_CHANNEL_ID>`.

The channel is a *Custom webhook* channel (method POST) whose URL is `https://api.telegram.org/bot<token>/sendMessage`,
the approach in Wazuh's own [blog post](https://wazuh.com/blog/exploring-security-alerting-options-for-improved-threat-detection-in-wazuh-part-2)
(written for Wazuh 4.8.1). The bot token is part of that URL, so it is stored in the channel configuration and readable by
whoever can read the Notifications configuration; it is not part of this repository.

It catches the reader node, the Shuffle orchestrator under it, or the path to TheHive stopping, so that no healthy run is
recorded. It does not catch the Wazuh VM itself being down (the monitor runs there), a failure of the Telegram path, or a MISP outage
(the reader still writes an ok heartbeat; failures of the list refresh have their own rules and monitors, see below).

Live (lab, 26 Oct 2026): stopping the Shuffle orchestrator at 10:39:20 UTC froze the heartbeat at 10:38:56 UTC; the Telegram
message arrived with the period end 10:49:22 UTC; after the restart the heartbeat came back within about two minutes and the alert closed on its own. The 60-minute throttle
was read back from the live monitor; whether it suppresses a repeat message in a long outage was not observed (the test outage lasted 11 minutes).
The `ok: false` paths of the reader were exercised against fakes only.

## Pipeline health monitors

Three query-level monitors (severity 2, every 5 minutes) watch the list refresh and the indexing path. They read alerts of
`wazuh-alerts-*` and post to the same Notifications channel as the heartbeat monitor; each file carries the same two
placeholders, `<CHAT_ID>` and `<NOTIFICATION_CHANNEL_ID>`.

* `ioc-sync-failure.json`: the MISP IP and domain list refresh writes rule 100311 on success and rule 100312 on failure.
  The monitor looks at the last 7 days and triggers when there is a failure older than 30 minutes and no success after
  the latest of those failures. The 30 minutes give a later run time to succeed before anyone is notified. Throttle 10 minutes.
* `ioc-hash-slots-failure.json`: the same pattern for the hash slot writer, rule 100342 (failure) and rule 100341
  (success). Throttle 10 minutes.
* `filebeat-index-rejects.json`: triggers when rule 100350 fired in the last 10 minutes. The rule matches the line
  `Cannot index event` of the Filebeat log, which Wazuh reads through a `localfile` entry on `/var/log/filebeat/filebeat`
  (`log_format` syslog, `restrict` `Cannot index event`). That entry belongs to the manager's `ossec.conf`, which is not part of
  this repository. Throttle 60 minutes.

These monitors read alerts that travel through the same Filebeat and indexer path they watch: if Filebeat or the indexer
stops completely, they stay silent, like the heartbeat monitor.

## Create

Wazuh dashboard, Indexer management, Dev Tools (one request per file; the body is the file content). The hash monitors
need the `ioc-hash-slots` index and its documents first:

```
POST _plugins/_alerting/monitors
{ ...content of the JSON file... }
```

Test a monitor without keeping it: `POST _plugins/_alerting/monitors/_execute?dryrun=true` with the
same body. The heartbeat monitor also needs its index, role and Notifications channel first (see the reader's README); the three pipeline health monitors need the same channel. Reading the alerts requires the reserved `alerting_read_access` role (alerts get, monitor
get/search, findings get); map it to the read-only user the reader uses.

## Limits

Monitor and alert ids are assigned by your indexer and are not part of these files. Wazuh 4.14 ships
no default notification channels (Notifications, Channels: 0 on the lab), and in a limited test (two
template paths) a monitor action template resolved the bucket key but not the bucket's counts or value
lists, which is why the alerts are read through the API instead of being pushed. Other template paths
were not explored. The lab later created one custom webhook channel (Telegram) for the heartbeat monitor, and the three pipeline health monitors use the same channel; the bucket-level
monitors still send nothing.
