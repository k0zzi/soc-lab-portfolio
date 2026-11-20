# misp_hash_slots.py

Builds IOC hash "slot" documents for OpenSearch terms lookups from file-hash
indicators in MISP. It is the hash counterpart of the CDB-list synchronization
used for IP addresses and domains, for the case where the matching has to happen
in the indexer.

## Why slots

Sysmon reports all file hashes of an event in one string
(`SHA1=...,MD5=...,SHA256=...`, plus `IMPHASH=...` when configured). Wazuh's CDB lookup needs a single
decoded value, and Windows event-channel events do not pass through XML
decoders, so the string is split by an ingest pipeline instead (field
`ioc_hash.<type>`). An Alerting monitor then compares those fields with a terms
lookup against a slot document. OpenSearch limits a terms query to
`index.max_terms_count` (default 65,536) terms, so each hash type is stored in a
fixed number of slot documents with at most 65,000 values each.

IMPHASH, which Sysmon can also report, is deliberately not handled: it identifies a shared
import table rather than a file and is shared by unrelated software, so it suits hunting
more than detection.

## What it does

1. Reads `md5`, `sha1`, `sha256` (and their `filename|<hash>` variants) with
   `to_ids=1`, `published=1`, `enforceWarninglist=1` and a publish window
   (default 30 days) through paged `attributes/restSearch` JSON calls.
2. Lowercases and validates every value (length and hex), drops the file name of
   composite attributes, removes duplicates and counts everything it skips.
3. Writes one document per slot: `sha256-1..4`, `md5-1..4`, `sha1-1`. Unused
   slots are written with an empty `values` array so the documents a monitor
   refers to always exist.

## Safety rules

* Dry run by default. Nothing is written without `--write`.
* Nothing is written if any hash type exceeds its slot capacity (no silent
  truncation) or shrinks below the shrink-guard limit compared with the
  previous run.
* After the writes, every slot document is read back with a real-time GET
  (independent of the index refresh interval) and its `type`, `slot` and `count`
  are compared with what was sent. A document count query is not used: with a
  refresh interval it would not show documents written moments earlier.
* Any MISP or indexer error leaves the existing slot documents untouched.
  A failure while writing can leave a mix of new and old slot documents; each
  document is still valid on its own, and the exit code reports the failure.
* Secrets are read from files and are never printed or logged.
* The indexer connection always verifies TLS. MISP verification follows
  `[misp] verify_tls` (default `false` for a lab PKI; use `ca_file` to verify).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK (dry run or write) |
| 1 | Configuration error |
| 2 | MISP error |
| 3 | Refused: capacity exceeded or shrink guard |
| 4 | Indexer error |

## Configuration

Defaults are built in. An optional INI file (`--config`) may override any of
them. Unknown sections or options are rejected.

| Section | Option | Default |
|---|---|---|
| misp | url | https://10.1.30.15 |
| misp | key_file | /etc/misp-ioc-sync/misp.key |
| misp | verify_tls / ca_file / timeout | false / (empty) / 120 |
| indexer | url | https://127.0.0.1:9200 |
| indexer | user / password_file | ioc_hash_writer / /etc/misp-ioc-sync/indexer-writer.pass |
| indexer | ca_file / index / timeout | /etc/wazuh-indexer/certs/root-ca.pem / ioc-hash-slots / 60 |
| hash_slots | window_days | 30 |
| hash_slots | page_size / max_pages | 5000 / 600 |
| hash_slots | slot_capacity | 65000 (maximum 65536) |
| hash_slots | slots_sha256 / slots_md5 / slots_sha1 | 4 / 4 / 1 |
| hash_slots | shrink_guard_percent / shrink_guard_min_previous | 50 / 1000 |
| hash_slots | log_file | /var/log/misp-hash-slots.log |

## Index and role

The index uses a strict mapping (`type`, `slot`, `count`, `generated_at`,
`window_days`, `values`); `values` is not indexed, a terms lookup reads it from
`_source`. The writer account needs only the `crud` action group on that index.
The script writes single documents, so no cluster-level bulk permission is
required.

## Deployment on a Wazuh manager

1. **Script and secrets.** Install the script as `/usr/local/sbin/misp_hash_slots.py` (owner root, mode 0755).
   The MISP key and the indexer account's password are read from files under `/etc/misp-ioc-sync/`
   (owner root, mode 0600), the directory the list synchronisation already uses.
2. **Index, role and account.** In Dev Tools of the Wazuh dashboard (the account itself is created in the
   dashboard under Indexer management, Security, Internal users, so that its password never appears in a request):

```
PUT ioc-hash-slots
{
  "settings": {
    "index": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "30s"
    }
  },
  "mappings": {
    "dynamic": "strict",
    "properties": {
      "type": {
        "type": "keyword"
      },
      "slot": {
        "type": "integer"
      },
      "count": {
        "type": "integer"
      },
      "generated_at": {
        "type": "date"
      },
      "window_days": {
        "type": "integer"
      },
      "values": {
        "type": "keyword",
        "index": false,
        "doc_values": false
      }
    }
  }
}

PUT _plugins/_security/api/roles/ioc_hash_writer
{
  "description": "Writes IOC hash slot documents; no access to any other index",
  "cluster_permissions": [],
  "index_permissions": [
    {
      "index_patterns": [
        "ioc-hash-slots"
      ],
      "allowed_actions": [
        "crud"
      ]
    }
  ],
  "tenant_permissions": []
}

PUT _plugins/_security/api/rolesmapping/ioc_hash_writer
{"users":["ioc_hash_writer"]}
```

   The index has one shard and no replica (single node). The script verifies each write by reading the document
   back, not by counting documents, because the 30 s refresh interval hides new documents from a count.
   The indexer certificate of the lab's install lists only the loopback address, so the script connects to
   `https://127.0.0.1:9200` and verifies it with the indexer's own root CA.
3. **Scheduling through the Wazuh command module** (`ossec.conf`, restart the manager once):

```
<wodle name="command">
  <disabled>no</disabled>
  <tag>misp-hash-slots</tag>
  <command>/usr/bin/python3 /usr/local/sbin/misp_hash_slots.py --write</command>
  <interval>1d</interval>
  <time>10:15</time>
  <run_on_start>yes</run_on_start>
  <ignore_output>no</ignore_output>
  <timeout>900</timeout>
</wodle>
```

4. **Rules `100340` to `100342`** in the repository's [`local_rules.xml`](../local_rules/local_rules.xml): the base rule
   matches the location `command_misp-hash-slots`, `100341` (level 3) the success line and `100342` (level 12) the
   failure line. They match the script's JSON output with a space after the colon (`"result": "ok"`); changing
   the output format breaks them. The monitor `ioc-hash-slots-failure` in
   [`../alerting-monitors/`](../alerting-monitors/) sends a notification when no success follows a failure.
5. **Ingest hook.** The monitors compare `ioc_hash.*` fields that an ingest pipeline creates; see
   [`../ingest/`](../ingest/).

### Start order

The run at manager start (`run_on_start`) fails if MISP is not ready yet, and rule `100342` raises a level 12
alert; the slot documents then keep their previous content. A fixed `<time>` does not help on a host that is
powered off at that time. In the lab the hosts are switched off at night, so the night-time schedule never ran and
the time was moved to 10:15. In one measurement the MISP and Wazuh machines started in the same minute and MISP
answered HTTP 500 for about 12 minutes; the run at start failed and the 10:15 run is the one that refreshes the
slots. Starting MISP first (in Proxmox: the Start/Shutdown order and the `up` delay) would let the run at start
succeed; this has not been applied in the lab.

### Shrink guard after a feed outage

The publish window counts from each event's publish time. When MISP stops receiving feed updates, the window
empties and the shrink guard refuses the next write (the previous slots stay in place); a later bulk publication
fills the window again, and when it ages out the guard can refuse again. In the lab the feed fetch was off from
30 Sep to 2 Nov 2026; after it was turned back on the MD5 count stayed below half of the previous run, so the guard
keeps refusing and rule `100342` fires every day. This was accepted as it is. A one-off run with a lower
`shrink_guard_percent` in a `--config` file would reset the baseline; it was not done.

## Tests

```
python3 -B tests/test_misp_hash_slots.py
```

The tests run the script as a real process against fake MISP and fake
OpenSearch servers. They do not talk to a real MISP or a real OpenSearch
cluster. Every behaviour listed above is covered by a test that fails when a
deliberate fault is injected into the script.
