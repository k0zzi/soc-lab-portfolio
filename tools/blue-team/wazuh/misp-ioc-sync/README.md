# MISP IOC matching on Wazuh (IPv4 and domains)

Indicators are matched **locally on the Wazuh manager** instead of querying MISP for every event.
Only matches leave the manager. Tested on Wazuh 4.14.x (the manager runs 4.14.5 at the time of writing), MISP 2.5.40, TheHive 5.5.3.

```
MISP --(restSearch, daily + on start)--> misp_ioc_sync.py  (Wazuh command module)
        |  writes CDB lists:  misp-ip-t1 / misp-ip-t2 / misp-domain-t1 / misp-domain-t2
        v
Wazuh rules   100301-100305  IPv4 match (Sysmon Event 3)
              100320/100321  exact domain match (Sysmon Event 22, CDB lookup)
              100330-100337  IPv4 match on OPNsense firewall logs (both ends; blocks rank lower)
              100360/100361  firewall blocks by the threat-feed aliases (not a MISP match)
        |
        +-- rule 100160 alerts (every non-excluded DNS query)
              --> custom-misp-domain (integration script)  normalized + suffix match
              --> rules 100322 / 100323 (match), 100324 (script failure)
        v
Wazuh Alerting monitors (tier 1, one alert per indicator)  -->  Shuffle alert reader  -->  TheHive
```

## Components

| Path | What it is |
|---|---|
| `misp_ioc_sync.py` | Pulls indicators from MISP and writes the CDB lists. One JSON status line per run (alert rules 100310-100312) |
| `../custom-integrations/custom-misp-domain` | Wazuh integration: matches the DNS name after normalization, and its parent names for `domain` entries |
| `../custom-integrations/install_domain_integration.py` | Installs the integration, its rules and the `<integration>` block with pre-checks and rollback |
| `../validation/domain_ioc_marker_test.py` | Acceptance harness: harmless `.example` markers, real DNS queries from an endpoint, PASS/FAIL per query |
| `../alerting-monitors/` | Wazuh Alerting monitors that group the tier 1 matches per indicator |
| `../../shuffle/ioc-alert-reader/` | Shuffle node that mirrors the monitors' alerts into TheHive with MISP context |
| `../../shuffle/misp-domain-workflow/` | Node code and TheHive request body of the earlier per-match domain workflow (switched off on 26 Oct 2026; kept for reference) |

## Firewall matching (rules 100330-100337, 100360-100361)

OPNsense filterlog events (decoded by the stock `pf` decoder, children of rule 87700) are matched against the IP
CDB lists on both ends of the connection: `dstip` (100330 tier 1, 100332 tier 2) and `srcip` (100331 tier 1,
100333 tier 2). Passed and translated (`nat`) traffic stays at level 10 for both tiers. Blocked traffic is caught
by child rules at level 7: 100334 and 100335 (tier 1, `dstip` and `srcip`), 100336 and 100337 (tier 2). The level
follows the firewall action; the tier stays in the rule id and in the group (`misp_ioc_fw_t1` / `misp_ioc_fw_t2`,
plus `misp_ioc_fw_block` for blocks). The level scale and keeping the tier out of the level are a local choice:
Sentinel, Splunk ES and QRadar do not agree on how source confidence and action affect severity.

Rules 100360 (`dstip`) and 100361 (`srcip`) are different: they are children of the stock rule 87701 (a firewall
block) and fire when an OPNsense threat-feed alias rule blocked the traffic. They do not use the CDB lists, are
not MISP matches, and cannot name the feed list because the aliases share one rule label per direction. Level 7.

No `<integration>` block forwards these alerts. Tier 1 matches (100330, 100331, 100334, 100335) and the feed
blocks reach TheHive through Wazuh Alerting monitors and the Shuffle reader
([`../alerting-monitors/`](../alerting-monitors/), [`../../shuffle/ioc-alert-reader/`](../../shuffle/ioc-alert-reader/));
tier 2 stays in Wazuh. The rules live in `../local_rules/local_rules.xml`.

## Design decisions

- **Filters:** `to_ids=1`, decaying model overrides (lifetime 365, threshold 10), `enforceWarninglist`.
- **Retrieval (`[filters] retrieval` for the IP lists, `[filters] domain_retrieval` for the domain lists, v0.7):** `text-bulk` (default, v0.5 behaviour) asks MISP for one large text
  export per type and tier and lets MISP apply the decay filter and the warninglists. `json-paged` fetches paged
  JSON, following the pattern of the Microsoft Sentinel MISP connector (paged JSON, warninglists enforced by MISP,
  decay from the scores MISP returns): MISP enforces the warninglists, and the decay decision is taken
  here from the decay scores MISP returns (`includeDecayScore` with the same `modelOverrides`; a value is kept when
  MISP marks it not decayed under `decay_model_id`). The run stops without writing when the decaying model is
  missing or disabled (rows without a score), when paging does not finish, or when a list shrinks too much.
- **Tiers:** tier 1 = indicators from published MISP events, tier 2 = unpublished. In MISP, *published* is a
  publication state, not a quality signal; using it as a curation proxy is a local heuristic.
- **Domain semantics (MISP data model):** a `domain` entry matches the name and everything below it, a
  `hostname` entry matches that exact host only. The list value carries the type: `name:domain` / `name:hostname`.
- **Normalization (RFC 4343):** only ASCII `A-Z` is case-folded, one trailing dot is ignored, non-ASCII names go
  through IDNA. No locale-dependent call is used anywhere (checked by a static test).
- **Safe writes:** nothing is written unless every query succeeded and every list passes a shrink guard;
  writes are atomic; the ruleset is hot-reloaded through analysisd; a failed run is an alert (rule 100312).
- **TheHive:** tier 1 matches reach TheHive through the Alerting monitors and the alert reader, one alert per
  indicator (see [`../../shuffle/ioc-alert-reader/`](../../shuffle/ioc-alert-reader/)). The earlier per-match
  domain workflow (`sourceRef` = Wazuh alert id, one TheHive alert per match) and the per-match IPv4 workflow were
  switched off on 26 Oct 2026; their `<integration>` blocks are disabled.
- **Failed runs** raise rule 100312; the monitor `ioc-sync-failure` sends a notification when no successful run
  (rule 100311) follows a failure (see [`../alerting-monitors/`](../alerting-monitors/)).

## Observed behaviour (lab, Wazuh 4.14.x)

- Exact name: rule 100320 (tier 1) / 100321 (tier 2). Subdomain, trailing dot, upper case: 100322 / 100323.
- A name with a letter glued in front (`xevil.com` vs `evil.com`) and a `hostname` entry's subdomains do not match.
- Turkish dotted capital I (U+0130) is a different name from ASCII `I`, as in DNS.
- CDB lookups are exact and case-sensitive. Sysmon Event 22 keeps the case and logs non-ASCII names as Unicode.
- integratord runs integrations sequentially: about 0.5 s per alert was observed.
- **MISP 2.5.40, bulk text export, warninglists:** for the tier 2 `ip-dst` set `enforceWarninglist` removed 34,980 of
  119,228 IPs, while MISP's own `warninglists/checkValue` flagged almost none of them (1 of 300 sampled) and a
  single-value query returned them. Paged JSON removed 24 and `checkValue` confirmed all 24; tier 1 removed 9, all 9
  confirmed.
- **MISP 2.5.40, bulk text export, decay:** for tier 1 `ip-dst|port` the text export kept 7,232 IPs, the paged JSON
  with client-side decay 26,588. Single-value queries with the same decay filter returned 20 of 20 sampled IPs of the
  19,358 that only the JSON path kept (by IP and by attribute UUID), so the text export drops live indicators. For
  plain `ip-dst` both paths agree.
- A paged JSON query with `excludeDecayed` leaves leading pages empty (MISP filters after paging), so the JSON path
  asks for decay scores and decides client-side. The scores honour `modelOverrides` when the query carries them; the
  two client rules (`decayed` flag, score above threshold) agreed on every indicator.
- A single-value query by the full composite string (`ip|port`) returns nothing; query by IP or by attribute UUID.

## Known limits

- The MISP lists are used for detection only; they are not published to the firewall or the DNS resolver. The lab's
  OPNsense blocks addresses and names from external feed lists configured on the firewall itself (not from MISP and
  not part of this repository). Rules 100360 and 100361 report the address blocks; blocked DNS names are not
  reported to Wazuh yet.
- `json-paged` pulls every attribute of a type and decides decay locally, so a run is slower than `text-bulk`
  (composite types return many rows). Measured in the lab: a live run (IP lists with `json-paged`, domain lists
  with `text-bulk`) took 199 s; a dry run with `json-paged` for both took 397 s (6 min 37 s). The Wazuh command
  timeout is 900 s.
- The domain lists are fetched with `text-bulk` in the live setup; only the IP lists use `json-paged`. The
  `json-paged` result for domains is not verified: the tier 1 list has 76,620 entries (domain and hostname)
  with `text-bulk` and 319,177 in a `json-paged` dry run, and no single-value check has been made yet to
  decide which is right.
- IPv6 and CIDR entries are skipped in the CDB lists (CDB keys cannot hold them).
- Rule 100160 excludes some noisy suffixes, so IOCs under those suffixes are not seen by the integration.
- Suffix matching can raise false positives for shared platforms; no popularity filter is enabled yet.
- Tier 2 is not forwarded to TheHive. Hashes are not covered by this component (see
  [`../misp-hash-slots/`](../misp-hash-slots/)).

## Deployment notes (placeholders only)

```xml
<wodle name="command">
  <disabled>no</disabled><tag>misp-ioc-sync</tag>
  <command>/usr/bin/python3 /usr/local/sbin/misp_ioc_sync.py --wazuh</command>
  <interval>1d</interval><time>10:00</time><run_on_start>yes</run_on_start>
  <ignore_output>no</ignore_output><timeout>900</timeout>
</wodle>

<integration>
  <name>custom-misp-domain</name>
  <rule_id>100160</rule_id>
  <alert_format>json</alert_format>
</integration>
```

The lab's hosts are switched off at night, so a fixed night-time `<time>` never ran there; the time was moved to
10:00 and `run_on_start` covers the start of the day. The run at start fails if MISP is not ready yet (in the lab MISP
answered HTTP 500 for about 12 minutes after boot, one measurement); the failure is an alert (rule 100312) and the
previous lists stay in place.

The `shuffle` integration block of the earlier per-match domain workflow (group `misp_ioc_domain_t1`) is disabled in
the live configuration and is not shown here.

The MISP key lives in a root-only file (`/etc/misp-ioc-sync/misp.key`, mode 600). The Wazuh Shuffle integration
sends no authentication header (its `api_key` option is not used), so the webhook must not require one. Checked on
the lab's Wazuh 4.14.5 on 20 Nov 2026: the installed `shuffle.py` sends only `content-type` and `Accept-Charset`,
no `shuffle` block sets `<api_key>`, and the webhooks it calls run on those requests.
The upstream Wazuh shuffle script (current master) writes its arguments, including any `<api_key>` value and the
hook URL, to `integrations.log`; check whether the installed version does the same before putting a secret there.

## Tests

Each component has a `tests/` folder. They need only the Python standard library and a Linux host
(`/proc`, Unix sockets): `python3 tests/<file>.py`. They use a fake MISP server and a fake Wazuh tree.
