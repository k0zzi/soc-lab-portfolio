# Ingest hook for hash normalisation

Sysmon reports all file hashes of an event in one string (`SHA1=...,MD5=...,SHA256=...`, plus `IMPHASH=...` when
configured). Windows event-channel events do not pass through XML decoders, so the string is split at index time:
the pipeline in [`ioc-hash-normalize.json`](ioc-hash-normalize.json) writes the lowercase keyword fields
`ioc_hash.sha1`, `ioc_hash.md5` and `ioc_hash.sha256`. The
[hash monitors](../alerting-monitors/) compare those fields with the slot documents of the
[slot writer](../misp-hash-slots/). IMPHASH is not extracted.

## How it is called

The Wazuh Filebeat module's alert pipeline gets one extra processor right after `date_index_name`:

```
{"pipeline": {"name": "ioc-hash-normalize", "ignore_failure": true}}
```

`ignore_failure` is essential: the module pipeline's `on_failure` drops the document, so without it a missing
`ioc-hash-normalize` pipeline would drop every alert.

`index.final_pipeline` was tried first and did not work. The module pipeline rewrites `_index` into a date-math
expression (`<wazuh-alerts-4.x-{...}>`), and a `final_pipeline` set on the daily index, or on a template matching
the original target, never ran in the lab (the pipeline's ingest counter stayed at the number of simulated
documents). The cause was not established (observed on OpenSearch 2.19.5).

## Install

1. Create the pipeline in Dev Tools: `PUT _ingest/pipeline/ioc-hash-normalize` with the file's content. Test it first
   with `POST _ingest/pipeline/_simulate` and a few documents (with and without `IMPHASH`, and without `hashes`).
2. On the manager, back up and edit the module file (the script does nothing if the processor is already there,
   and stops without writing if `date_index_name` is not found exactly once):

```
sudo cp -a /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json /root/alerts-pipeline.json.bak
sudo python3 - <<'PY'
import json
p = '/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json'
d = json.load(open(p))
procs = d['processors']
if any('pipeline' in x and x['pipeline'].get('name') == 'ioc-hash-normalize' for x in procs):
    print('already present'); raise SystemExit
i = [k for k, x in enumerate(procs) if 'date_index_name' in x]
assert len(i) == 1, i
procs.insert(i[0] + 1, {"pipeline": {"name": "ioc-hash-normalize", "ignore_failure": True}})
json.dump(d, open(p, 'w'), indent=2)
print('added at', i[0] + 1, 'of', len(procs))
PY
sudo filebeat setup --pipelines
sudo systemctl restart filebeat
```

3. Check: a new alert that has `data.win.eventdata.hashes` also has `ioc_hash.sha256`, and the
   `ioc-hash-health` monitor stays quiet.

## After a Wazuh upgrade

The upgrade guides of the Wazuh versions checked (4.3 to 4.9) extract the Filebeat module again, which replaces
`pipeline.json`; the guide of the running version was not read. Repeat step 2 after every upgrade. The
`ioc-hash-health` monitor triggers when alerts carry `hashes` but no `ioc_hash.sha256`, i.e. when the hook is gone.

## Known limits

* Only alerts are normalised. Archive indices are not processed by this hook.
* The `drop` processor at the end of the pipeline never matches on the alert path: its `_index` condition expects a
  name starting with `wazuh-archives`, but at that point `_index` is the date-math value. It is a leftover of an
  archive design that was not completed, and is kept so that this file equals the live pipeline. Remove or
  replace it when archives are added.
* Documents indexed before the hook existed have no `ioc_hash` fields.
