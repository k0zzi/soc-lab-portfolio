# MISP IOC matching on Wazuh (IPv4 and domains)

Indicators are matched **locally on the Wazuh manager** instead of querying MISP for every event.
Only matches leave the manager. Tested on Wazuh 4.14.3, MISP 2.5.40, TheHive 5.5.3.

```
MISP --(restSearch, daily + on start)--> misp_ioc_sync.py  (Wazuh command module)
        |  writes CDB lists:  misp-ip-t1 / misp-ip-t2 / misp-domain-t1 / misp-domain-t2
        v
Wazuh rules   100301-100305  IPv4 match (Sysmon Event 3)
              100320/100321  exact domain match (Sysmon Event 22, CDB lookup)
        |
        +-- rule 100160 alerts (every non-excluded DNS query)
              --> custom-misp-domain (integration script)  normalized + suffix match
              --> rules 100322 / 100323 (match), 100324 (script failure)
        v
Shuffle  (group misp_ioc_domain_t1, tier 1 only)  -->  TheHive: one alert per Wazuh alert
```

## Components

| Path | What it is |
|---|---|
| `misp_ioc_sync.py` | Pulls indicators from MISP and writes the CDB lists. One JSON status line per run (alert rules 100310-100312) |
| `../custom-integrations/custom-misp-domain` | Wazuh integration: matches the DNS name after normalization, and its parent names for `domain` entries |
| `../custom-integrations/install_domain_integration.py` | Installs the integration, its rules and the `<integration>` block with pre-checks and rollback |
| `../validation/domain_ioc_marker_test.py` | Acceptance harness: harmless `.example` markers, real DNS queries from an endpoint, PASS/FAIL per query |
| `../../shuffle/misp-domain-workflow/` | Shuffle node code and TheHive request body for the domain workflow |

## Design decisions

- **Filters:** `to_ids=1`, decaying model overrides (lifetime 365, threshold 10), `enforceWarninglist`.
- **Tiers:** tier 1 = indicators from published MISP events, tier 2 = unpublished. In MISP, *published* is a
  publication state, not a quality signal; using it as a curation proxy is a local heuristic.
- **Domain semantics (MISP data model):** a `domain` entry matches the name and everything below it, a
  `hostname` entry matches that exact host only. The list value carries the type: `name:domain` / `name:hostname`.
- **Normalization (RFC 4343):** only ASCII `A-Z` is case-folded, one trailing dot is ignored, non-ASCII names go
  through IDNA. No locale-dependent call is used anywhere (checked by a static test).
- **Safe writes:** nothing is written unless every query succeeded and every list passes a shrink guard;
  writes are atomic; the ruleset is hot-reloaded through analysisd; a failed run is an alert (rule 100312).
- **TheHive (domain workflow):** `sourceRef` is the Wazuh alert id (a re-delivered alert is refused, a new match is a new alert),
  `date` is the Wazuh alert time, the observable is the *matched indicator* so TheHive's similarity groups all
  occurrences of one indicator.

## Observed behaviour (lab, Wazuh 4.14.3)

- Exact name: rule 100320 (tier 1) / 100321 (tier 2). Subdomain, trailing dot, upper case: 100322 / 100323.
- A name with a letter glued in front (`xevil.com` vs `evil.com`) and a `hostname` entry's subdomains do not match.
- Turkish dotted capital I (U+0130) is a different name from ASCII `I`, as in DNS.
- CDB lookups are exact and case-sensitive. Sysmon Event 22 keeps the case and logs non-ASCII names as Unicode.
- integratord runs integrations sequentially: about 0.5 s per alert was observed.

## Known limits

- Enforcement (firewall alias, DNS blocklist) is not wired; this is detection only.
- IPv6 and CIDR entries are skipped in the CDB lists (CDB keys cannot hold them).
- Rule 100160 excludes some noisy suffixes, so IOCs under those suffixes are not seen by the integration.
- Suffix matching can raise false positives for shared platforms; no popularity filter is enabled yet.
- Tier 2 is not forwarded to Shuffle. Hashes are not covered by this component.
- Only the **domain** workflow is in this repository and creates one TheHive alert per match. The IPv4 matches
  reach TheHive through a separate Shuffle workflow that is not included here and still deduplicates per
  indicator, host and day.

## Deployment notes (placeholders only)

```xml
<wodle name="command">
  <disabled>no</disabled><tag>misp-ioc-sync</tag>
  <command>/usr/bin/python3 /usr/local/sbin/misp_ioc_sync.py --wazuh</command>
  <interval>1d</interval><time>03:30</time><run_on_start>yes</run_on_start>
  <ignore_output>no</ignore_output><timeout>900</timeout>
</wodle>

<integration>
  <name>custom-misp-domain</name>
  <rule_id>100160</rule_id>
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>shuffle</name>
  <hook_url>http://<shuffle-host>:3001/api/v1/hooks/<REDACTED_WEBHOOK_ID></hook_url>
  <group>misp_ioc_domain_t1</group>
  <alert_format>json</alert_format>
</integration>
```

The MISP key lives in a root-only file (`/etc/misp-ioc-sync/misp.key`, mode 600). The Wazuh Shuffle integration
sends no authentication header (its `api_key` option is not used), so the webhook must not require one.
The upstream Wazuh shuffle script (current master) writes its arguments, including any `<api_key>` value and the
hook URL, to `integrations.log`; check whether the installed version does the same before putting a secret there.

## Tests

Each component has a `tests/` folder. They need only the Python standard library and a Linux host
(`/proc`, Unix sockets): `python3 tests/<file>.py`. They use a fake MISP server and a fake Wazuh tree.
