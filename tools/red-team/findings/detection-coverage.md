# Detection Coverage Summary — ADIM B (Atomic Red Team Capstone)

Six MITRE ATT&CK techniques (seven counting the two sub-techniques scored separately in the AD-recon step) were tested against this lab's live Wazuh/Sysmon/Suricata/Shuffle stack. Scores below use [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT)'s own official detection scoring scale — DeTT&CT (Detect Tactics, Techniques & Combat Threats), developed and maintained by Rabobank's CDC team, is the industry-standard open-source framework for scoring and visualizing ATT&CK-based detection coverage, and is the tool this project has designated for pre/post capstone coverage comparison.

## Scoring scale used (verbatim from DeTT&CT's official wiki)

| Score | Name | Description |
|---|---|---|
| -1 | None | No detection. |
| 0 | Forensics / context | No detection, but the technique is being logged for forensic purposes and can be used to provide context. |
| 1 | Basic | A basic signature detects a specific part of the technique's procedures. Minimal aspects covered; false negatives high. |
| 2 | Fair | A (correlation) rule covers more aspects of the technique's procedures than a basic signature; false negatives lower but may still be significant. |
| 3 | Good | Effective, real-time detection using more complex analytics; many known aspects covered. |
| 4 | Very good | Very effective, real-time detection covering almost all known aspects; harder to bypass. |
| 5 | Excellent | Same as "Very good" but all known aspects of the technique's procedures are covered. |

Scores here are assigned conservatively — none of this lab's rules involve genuine cross-event correlation or advanced analytics, so no technique is scored above "2 / Fair," even where a rule performs its narrow job well.

## Coverage table

| Technique | Tactic | Result | Score | Why |
|---|---|---|---|---|
| [T1059.001](./T1059.001.md) | Execution | ✅ Caught | **1 / Basic** | Rule 92057 is a single signature matching `-e`/`-encodedcommand` variants — one specific part of T1059.001's procedure space, not a correlation rule. |
| [T1218](./T1218.md) | Defense Evasion | ❌ Missed | **-1 / None** | Zero Sysmon telemetry generated at all (UWP/AppX activation not in the ProcessCreate allowlist) — no detection, and not even forensic logging exists for this specific activation pattern. |
| [T1055](./T1055.md) | Defense Evasion / Priv Esc | ❌ Missed | **0 / Forensics / context** | Sysmon *did* generate the `CreateRemoteThread` event (Event 8) — unlike T1218, raw data exists and could support a forensic investigation — but no Wazuh rule inspects it, so no detection occurred. |
| [T1003.001](./T1003.001.md) | Credential Access | 🛡️ Prevented | **N/A** | Doesn't fit this scale — the technique never reached LSASS at all (RunAsPPL + Defender), so there is no detection *question* to score; DeTT&CT's scale assumes the technique's activity occurred and asks whether it was seen. |
| [T1018](./T1018-T1087.002.md) | Discovery | ✅ Caught | **2 / Fair** | Custom rule 100190 combines multiple field conditions (image name + commandline pattern + UNC-path exclusion), covering more of the procedure space than a bare signature — plus two independent default-ruleset rules (92034/92035) also fired. |
| [T1087.002](./T1018-T1087.002.md) | Discovery | ✅ Caught | **2 / Fair** | Custom rule 100200 matches an 18-entry list of known AdFind recon flags — broader procedure coverage than a single-signature match, still single-event rather than true correlation. |
| [T1046](./T1046.md) | Discovery | Split — see below | **-1 / None** (endpoint) — **not independently scored** (network) | See the split-layer note below; this technique doesn't reduce to one score. |

## T1046 — a legitimate case for DeTT&CT's per-data-source scoring, not a single number

DeTT&CT explicitly supports scoring visibility and detection **per data source**, not just per technique — this is exactly the right tool for T1046's actual result. Scored as one number, T1046 would misleadingly read as either "fully missed" (ignoring that the network perimeter genuinely reacted) or "caught" (ignoring that the SIEM has no record of it). The honest breakdown:

- **Endpoint / Sysmon data source: -1 / None.** No Sysmon Event 3 was generated for the scan at all (same root cause as T1218), so no rule — however sophisticated — could have detected it from this data source.
- **Network / Suricata data source: functionally effective, but unscored here.** Suricata's ET SCAN ruleset detected the activity and a real, automated response chain (Wazuh rule 100100 → Shuffle → OPNsense block → TheHive case #1024, confirmed live) executed correctly and in real time. This isn't scored on the 5-point scale above because the missing piece isn't detection quality or even documentation — a human-visible case record does exist — it's *correlation*: Wazuh itself cannot show "this alert led to this containment outcome" as one linked record, since the outcome lives only in TheHive (see the [T1046 finding](./T1046.md) for the specific gaps). A technique can be effectively detected and its response genuinely documented, and still have a cross-tool correlation gap; DeTT&CT's scale measures detection quality, not tool integration.

## Reproducing this in the actual DeTT&CT tool

This table is the manual equivalent of what DeTT&CT's `detection` mode produces from a YAML administration file. A full DeTT&CT technique-administration YAML (scored per technique, exportable to an ATT&CK Navigator layer via `dettect.py detection -eg`) is a natural next artifact once the deferred remediation pass (see each finding's "why this isn't fixed here" section) closes some of these gaps — the pre/post comparison DeTT&CT is designed for would then show a real, evidenced improvement rather than a static snapshot.
