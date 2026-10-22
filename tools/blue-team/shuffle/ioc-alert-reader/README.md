# IOC alert reader (Wazuh Alerting to TheHive)

A Shuffle Python node that mirrors the open alerts of the
[Wazuh Alerting monitors](../../wazuh/alerting-monitors/) into TheHive and adds MISP context to each
alert. It keeps **no state of its own**: grouping, counters and the alert lifecycle live in the
Alerting plugin of the Wazuh indexer; TheHive is the analyst-facing view. Wazuh has no incident or
case object, so promoting an alert to a case stays an analyst action in TheHive.

```
MISP -> CDB lists (misp-ioc-sync) -> Wazuh rules (Sysmon IP, DNS, firewall) -> wazuh-alerts-*
     -> bucket-level monitors, one alert per indicator (engine keeps count, first/last seen, state)
     -> this node, every 60 s: reads the Alerting API, asks MISP about the indicator
     -> one TheHive alert per engine alert
```

The hash monitors work the same way over `ioc_hash.*` fields that an ingest pipeline adds to the alerts; see the
[alerting monitors](../../wazuh/alerting-monitors/), the [ingest hook](../../wazuh/ingest/) and the
[slot writer](../../wazuh/misp-hash-slots/).

## What a TheHive alert contains

| Field | Value |
|---|---|
| Title | `Threat Activity Detected (<indicator>, <source list>, <reporting hosts>)`, at most 256 bytes |
| `sourceRef` | the engine alert id; `<id>\|<last seen ms>` for an alert opened after an analyst closed the previous one |
| `date` | first seen in the monitor window at creation |
| Tags | `misp-ioc`, `tier1`, `wazuh`, `ioc:<indicator>`, `engine-alert:<id>`, `monitor:<name>`, and `hash-type:<type>` for hash monitors |
| Observable | the indicator (`ip`, `domain` or `hash`; a hash observable also carries `hash-type:<type>`) |
| Description | header, monitor, engine alert id and state, when the engine alert opened, alarms in the window, first/last seen, match side, **Details** value lists, then the **MISP context** section |
| Summary | `count=N first=<UTC> last=<UTC>` |
| Comments | never written; they stay for analysts. TheHive's History tab records every update |

**Details** lists show `value (count)` for action, protocol, port, source IP, destination IP, process, parent process,
event id, DNS query, match kind, reporting host and rules, plus the latest alarm ids, capped at 2 KB combined
(least frequent values go first, oldest alarm ids first). Protocol and port are separate lists because a
bucket aggregation cannot pair them.

**MISP context** comes from a live `attributes/restSearch` for the indicator (published events, IDS flag,
the same decay overrides the list sync uses) and lists the events (id, info, creating organisation,
date, analysis state), attribute types and categories, tags, comments, first/last seen when MISP has
them, the decay score under the lists' own policy (only when MISP returns one for the attribute), and links to the events. Example:

```
**MISP context** (live MISP query: published events, IDS flag)
- Events: #1234 Example feed event (example.org, 2026-08-06, analysis ongoing); #99 Test (soc.dev, 2026-06-22, analysis completed)
- Attributes: ip-dst (2), ip-src (1) | Category: Network activity
- Tags: tlp:clear, osint:source-type="manual-collection"
- Decay (NIDS Simple Decaying Model, lifetime 365, threshold 10): best score 44.22; not decayed in 3 of 3 attributes
- MISP: https://misp.example/events/view/1234 https://misp.example/events/view/99
```

MISP text is treated as untrusted: control characters, HTML, backticks and Markdown link syntax are
removed and `http(s)://`, `ftp://` and `www.` are defanged (`hxxp://`, `www[.]`). The section is capped at
2 KB. MISP has no confidence field, so none is shown; the threat level is not shown because
`threat_level_id` and `ThreatLevel` disagreed in the lab's MISP 2.5.40 response.

The engine owns title, description and summary and rewrites them on the next run if an analyst edits
them. Analysts own status, assignee, comments and tags; the reader never changes them.

## Lifecycle

| Situation | Reader |
|---|---|
| Engine alert `ACTIVE` or `ACKNOWLEDGED` | mirrored (an analyst working on an alert does not stop updates) |
| Engine alert `COMPLETED`, `DELETED`, `ERROR` | ignored; the TheHive alert keeps its last content |
| TheHive alert open (New, InProgress, or imported into an open case) | updated in place, only the fields that changed |
| TheHive alert closed | never reopened or edited. New activity (last seen later than the closed alert's) opens a **new** alert |
| No alarm for an indicator for 5 days, then a new alarm | the engine opens a new alert, so a new TheHive alert follows |
| MISP cannot be queried | the alert is still written; a new alert simply has no MISP section yet, and an existing section is kept as it is. The failure is listed in `errors` with MISP's own message and the shape (not the value) of the key |
| MISP finds no record | the section says so (the lists refresh once a day, so a removed indicator can still alert) |

## How this compares with the vendors

| Topic | Vendors (documentation read in Oct 2026) | This design |
|---|---|---|
| Where grouping and state live | In the SIEM engine: QRadar offense, Sentinel alert and incident, Splunk ES finding group | In the Wazuh Alerting monitor alert. Same place; Wazuh has no case object |
| Alert granularity | One row or alert per indicator (Sentinel threat-intelligence templates, QRadar offense indexed by indicator) | One alert per indicator and monitor |
| Closed, then new activity | QRadar: new offense. Sentinel: new incident, or the old one reopened if the rule setting is on (not available in the Defender portal). Splunk ES: the same finding group is reopened with an automatic note when new findings arrive within its maximum append time (8.2 and later can keep it closed) | New TheHive alert. **Deviation:** its content is the monitor window, so it can repeat alarms already shown in the closed alert. This resembles a Sentinel alert (evidence over a lookback window) and differs from QRadar (fresh count) and Splunk (same group) |
| Analyst working on it | Not a stop condition on any page read; closing (or the grouping time frame) ends updates | Same: acknowledged and in-progress alerts keep updating |
| Inactivity | QRadar: dormant 5 days, then inactive | 5 days, as a sliding query window |
| Alert detail fields | Sentinel custom details surface chosen event fields as value lists (50 values, 2 KB combined); Splunk shows additional fields | Value lists as above, with a count per value (the count is engine data, not in Sentinel's custom details) |
| Indicator context in the alert | Sentinel's threat-intelligence templates join the indicator table and carry indicator fields into the alert (templates read in full); Splunk ES threat matching adds fields of the matched intelligence record to the notable (excerpts only); QRadar not checked for this point | **Deviation:** a live MISP query when the alert is written, not a join against a local indicator store. It shows MISP's current state, not the state at the last list refresh |
| Title | Splunk ES default notable title `Threat Activity Detected ($threat_match_value$, $threat_source_id$, ...)` | Same pattern with the reporting host added |

### Documented deviations

- **Polling, not push.** Notifications are not wired: Wazuh 4.14 ships no default channel (a custom webhook
  channel can be created), and in a limited test (two template paths) a monitor action template resolved the
  bucket key but not the bucket's counts or lists. Other template paths were not explored.
- **One-way.** Closing a TheHive alert does not touch the engine alert; acknowledging in Wazuh does not
  change the TheHive status.
- **Windowed counts** (see the monitors README) and `first` moving forward as old alarms leave the window.
- **No cross-family merge.** The same indicator seen by two monitors gives two alerts; merging is a case-level action.
- **Firewall alerts show raw addresses.** The internal client is a plain IP; the reporting host is the firewall.
- **MISP context is a live query**, with no confidence value and no threat level (see above).
- Hash alerts exist for SHA256, MD5 and SHA1 only. IMPHASH is not matched (see the monitors README).
- Tier 1 indicators only; the tier 2 list is not mirrored.

## Verification

Live (lab, 19 Oct 2026): reading ACTIVE and ACKNOWLEDGED alerts with the read-only account, creating
alerts, no duplicates on re-run, updating description, summary and title (an analyst edit of the title
was restored on the next run), History entries, updating an InProgress alert, closed alert followed by
new activity opening a new alert, an acknowledged engine alert keeps updating the TheHive alert, the
MISP context section written into the alerts (3 and 2 attributes found; the rendered section was checked in
TheHive on one of them), a MISP 403 (wrong credential node) reported per alert in a dry run.

Live (lab, 22 Oct 2026, reader 1.5): a hash alert for a SHA256 value that was placed into a slot as a control.
TheHive accepted the observable type `hash`; the tags including `hash-type:sha256`, the Details lists with
process, parent process and event id, and the MISP section for a value that MISP does not know were checked
in TheHive. The engine alert completed when the control value was removed from the slot.

Only against fakes: the lifecycle of imported alerts with open or closed cases, the 256-byte title, 2 KB
details and 2 KB context bounds with hundreds of values, a failing Alerting query for one state,
the behaviour when MISP is down or unreachable (alert still written, existing section kept), the
sanitising and defanging of MISP text, missing MISP credentials, the alert content of the MD5 and SHA1
monitors, and MISP context for a hash that MISP does know.

Not verified: monitor content for `ioc-fw-src-t1`, `ioc-sysmon-ip-t1` and `ioc-domain-t1` on real
alarms, the Shuffle run-quota impact of a 60 s schedule (about 43,200 runs per 30 days if the unit is
workflow runs), `alertState=ACKNOWLEDGED` outside the lab's Wazuh 4.14.5, MISP context for domain
indicators (only IP indicators were seen live).

## Setup

1. Map the reserved `alerting_read_access` role to the read-only indexer user:
   `PUT _plugins/_security/api/rolesmapping/alerting_read_access` with `{"users": ["<user>"]}`
   (check first that the mapping does not exist; the request replaces it).
2. Create the monitors from [`../../wazuh/alerting-monitors/`](../../wazuh/alerting-monitors/): four for IP
   addresses and domains, three for hashes (the hash monitors need the slot index and its documents first).
3. In a Shuffle workflow add three HTTP nodes that only carry credentials, plus the Python node:
   - `http_1`: `username` and `password` parameters of the indexer account,
   - `http_2`: `headers` parameter `Authorization: Bearer <TheHive service account key>`,
   - `misp_key` (rename the node to exactly this label): `headers` parameter `Authorization: <MISP auth key>`,
     without quotes or a `Bearer` prefix. Use a key of a read-only MISP user, restricted to the Shuffle
     host's address; check it from that host first with `curl` (a wrong or address-restricted key
     answers 403),
   - a *Shuffle Tools, Execute Python* node with `ioc_alert_reader.py`, on a schedule (60 s in the lab).
   Credentials are read from the parameters at run time and never printed.
4. Keep `DRY_RUN = True` for the first run and check the plan (each alert lists its `misp` status); set it
   to `False` to write. The dry run reads MISP but writes nothing.

Constants at the top of the script: `SOURCE`, `ALERT_TYPE`, `INDEXER_URL`, `THEHIVE_URL`, `MISP_URL`,
`MISP_NODE`, `MISP_DECAY` and `MISP_DECAY_MODEL` (keep them equal to the list sync's decay settings),
`MONITORS` (monitor name to indicator type, source list, match side and, for hashes, label and hash type), `READ_STATES`, `MAX_ALERTS`
(500 per state), `MAX_TITLE_BYTES`, `MAX_DETAILS_BYTES`, `MAX_CONTEXT_BYTES`, `MAX_RUN_SECONDS`.

## Tests

```
python3 tests/test_ioc_alert_reader.py
```

Standard library only; it starts a fake Alerting API, a fake TheHive and a fake MISP on 127.0.0.1 and
runs 129 checks. During development deliberate faults were injected into the node (31 for the original
version, 14 more for the hash monitors) and each one was caught (the harness is not part of this repository).

## Sources

| Source | Read |
|---|---|
| Wazuh indexer Alerting module (5.0-rc documentation; behaviour measured on Wazuh 4.14.5) | in full |
| Microsoft Learn, [Scheduled analytics rules in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) | in full |
| Splunk ES 8.5, [Create finding groups](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/findings/create-finding-groups-in-splunk-enterprise-security) and [Change the status of a finding](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/findings/change-the-status-of-a-finding-or-an-investigation-in-splunk-enterprise-security) | in full |
| QRadar offense retention, as reproduced in the [Juniper JSA 7.5.0 documentation](https://www.juniper.net/documentation/us/en/software/jsa7.5.0/jsa/topics/concept/concept-jsa-user-offense-retention.html) | in full |
| Sentinel threat-intelligence analytic rule templates (YAML), IBM QRadar offense indexing and its MD5 example (earlier sessions) | in full |
| Sentinel custom details limits, Splunk additional fields, default notable title and threat-match fields | search excerpts only |
