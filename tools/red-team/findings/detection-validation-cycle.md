# Detection Validation Cycle — Atomic Red Team Capstone

This capstone is a **purple-team detection-validation exercise**, not an incident response — no host was ever actually compromised. The structure below follows the purple-team / detection-engineering lifecycle used across the industry for exactly this kind of exercise, rather than an incident-handling framework like SANS's PICERL, which assumes a real breach and forces awkward "not applicable" phases onto planned, authorized testing.

Three independent, current sources describe the same six-part cycle: **Praetorian**'s purple team service ("Finalize Objectives" → "Create & Tune TTPs" → "TTP Execution" → "Documentation"), **JumpCloud**'s purple team definition (*"The Red Team re-runs the exact same attack to validate that the new detection rule is effective. This iterative process repeats until the defense is proven effective against that specific TTP"*), and **Exabeam**'s 7-step detection engineering lifecycle (map to threat frameworks → confirm data availability → build detection logic → test against realistic scenarios → deploy → monitor and tune). This capstone is structured as: **Planning → TTP Execution → Detection Gap Identification → Tuning/Rule Creation → Re-Test and Validation → Lessons Learned.**

---

## 1. Planning

Four prerequisites were completed before any technique was run, in this order:

1. **Proxmox snapshots** ("pre-atomic-baseline") on SRV201, SRV202, and CLT601 — taken after NTP was fixed, so the baseline itself wouldn't need correcting mid-run.
2. **NTP synchronization** — all lab hosts verified against a single internal authoritative source (OPNsense), a precondition for timeline correlation across techniques.
3. **PowerShell Script Block (4104) and Module (4103) Logging**, via a GPO scoped to a new "Clients" OU.
4. **A narrow Windows Defender exclusion** (`C:\AtomicRedTeam\` only) — real-time protection was deliberately left **on**, per Atomic Red Team's own official guidance, so genuine prevention (as later happened with T1003.001) would still occur and be observed.

**Objectives and TTP selection** were grounded in official guidance, matching Praetorian's own "Finalize Objectives" and "TTP Creation" stages. MITRE Engenuity's Center for Threat-Informed Defense (CTID) explicitly names attempting full ATT&CK matrix coverage **"ATT&CK bingo"** and calls it counterproductive; its own prioritization criteria are prevalence, choke point, and actionability. Applying those criteria, the six techniques were cross-validated across independent source categories: commercial malware-sample analysis (Picus Security's Red Report, 2023 and 2026), confirmed SOC detections (Red Canary's Threat Detection Report, "Forever Techniques"), and real government red-team assessment outcomes (CISA's Risk and Vulnerability Assessment infographics, FY21 and FY23), in which all six chosen (sub-)techniques appear as named, top-tier entries rather than CISA's own long-tail "Other" category.

The run order followed MITRE ATT&CK's own tactic sequence (Execution → Defense Evasion/Privilege Escalation → Credential Access → Discovery), matching how MITRE's own ATT&CK Evaluations program structures adversary emulation as a chronological scenario.

## 2. TTP Execution

| Technique | Tactic | Detected during execution? | Evidence |
|---|---|---|---|
| [T1059.001](./T1059.001.md) | Execution | ✅ Yes | Wazuh rule 92057, real-time, correctly tagged |
| [T1218](./T1218.md) | Defense Evasion | ❌ No | Zero Sysmon telemetry generated |
| [T1055](./T1055.md) | Defense Evasion / Priv Esc | ❌ No | Telemetry existed; no rule inspected it |
| [T1003.001](./T1003.001.md) | Credential Access | Prevented before reaching an identifiable state | Defender + RunAsPPL |
| [T1018](./T1018-T1087.002.md) | Discovery | ✅ Yes | Wazuh's default ruleset (92034/92035), before any custom rule existed |
| [T1087.002](./T1018-T1087.002.md) | Discovery | ✅ Yes (after tuning — see Section 4) | Only visible by name after rule 100200 was deployed |
| [T1046](./T1046.md) | Discovery | Split — ❌ endpoint, ✅ network perimeter | Suricata/Shuffle auto-block fired; SIEM itself saw nothing |

## 3. Detection Gap Identification

Every miss and partial result above was traced to a specific, sourced root cause rather than left as an unexplained negative:

- **A single telemetry-layer root cause explains two independent misses.** T1218 (UWP/AppX process activation) and T1046 (raw `.NET TcpClient` connections) were both missed because Olaf Hartong's sysmon-modular "balanced" configuration uses an `onmatch: include` **allowlist** for both ProcessCreate and NetworkConnect events — neither activation pattern matches it, so Sysmon never generates the underlying event. The upstream project's own documentation acknowledges this trade-off (*"there will be potential blind spots"*) and names the fix (the `excludes-only` tier).
- **A genuine rule-coverage gap, separate from the telemetry gap above:** T1055's `CreateRemoteThread` event reached Sysmon without issue, but no Wazuh rule inspects Event 8/10 content at all.
- **Two mistagging defects were found in Wazuh's *default*, bundled ruleset** (92032, 61618) — both statically applied specific ATT&CK sub-technique tags through logic that provided no actual supporting evidence. Both are named, documented problem classes at the industry level: Elastic independently deprecated a directly comparable rule in 2021, and Wazuh's own support staff have, on their own public mailing list (May 2023), directly recommended overriding this exact rule family.
- **A working control whose record lives in the wrong tool to be useful from the SIEM.** T1046's network-perimeter containment (Suricata → Wazuh rule 100100 → Shuffle → OPNsense block) executed correctly and automatically, and produced a genuine, human-visible record — TheHive case #1024, confirmed live — not an undocumented action. NIST SP 800-61 names the two more precise underlying gaps: Section 2.3 lists firewall logs as a standard detection data source (OPNsense's own filterlog never reaches Wazuh at all), and Section 2.5 calls for recording "actions taken" as part of incident documentation (the containment outcome is recorded, but only in TheHive, with no link back to the Wazuh alert or rule ID that triggered it).

## 4. Tuning / Detection Rule Creation

Two categories of change were made, matching Praetorian's "Create & Tune TTPs" stage and JumpCloud's "tune the Blue Team's tools... create a new detection rule":

**Corrections to existing rules** — both applying the same standard, CISA and MITRE ATT&CK's joint "Best Practices for MITRE ATT&CK® Mapping" (v2.0, January 2023): remove an ATT&CK tag entirely when the evidence supporting it is insufficient, rather than downgrade to a vaguer guess.
- Rule **92032**: unearned T1087/T1059.003 tags removed.
- Rule **61618**: unearned T1055 tag removed.

**New rules deployed** — both ported from SigmaHQ's own currently-maintained, canonical rules, which happen to reference the exact same Atomic Red Team commits used for testing:
- Rule **100190** (T1018, level 6) — from `proc_creation_win_net_view_share_and_sessions_enum.yml`.
- Rule **100200** (T1087.002, level 12, `mail: true`) — from `proc_creation_win_pua_adfind_susp_usage.yml`.

## 5. Re-Test and Validation

Matching JumpCloud's own description of this stage — *"The Red Team re-runs the exact same attack to validate that the new detection rule is effective"* — every fix in this capstone was verified with a genuine before/after comparison, not declared fixed on faith:

- **92032**: re-run after the fix — rule 92057 unchanged, rule 92032 fired with the `mitre` block entirely absent.
- **61618**: the first re-test attempt was misleading (a non-boot-time restart let an unrelated suppression rule silence the alert correctly, which could be mistaken for the fix doing nothing). CLT601 was rebooted to reproduce the actual target condition (`ParentImage: "-"`), producing a clean before/after: `mitre: T1055` present pre-fix, absent post-fix, across 7 separate firings at the same condition.
- **100190 / 100200**: both re-run after deployment — 100190 fired on both `net view` variants; 100200 fired on the AdFind commandline that, before deployment, had only produced indirect/mistagged alerts. This is the cleanest before/after in the capstone: identical input, only the new rule as the variable.

## 6. Lessons Learned

### 6.1 — Two Sysmon telemetry gaps trace to one root cause
T1218 and T1046 share an identical underlying mechanism (Sysmon's allowlist model). **One config-tier change addresses two independent findings** — this is the kind of connection that only becomes visible by tracing each miss to its actual root cause rather than treating each technique's result in isolation.

### 6.2 — A rule's alert label is not proof of what the rule evaluated
Both mistagging defects (92032, 61618) were found in Wazuh's *default*, bundled ruleset — not this project's own rules. Reading the underlying field logic, not trusting the resulting tag, is what surfaced both.

### 6.3 — Defense-in-depth can work correctly and still be invisible from the one tool an analyst would actually check first
T1046's network-perimeter containment is the most important finding in this capstone precisely because it complicates a simple caught/missed scorecard: a real control worked correctly and automatically, and produced a genuine record — TheHive case #1024, confirmed live, correctly attributing the source host. The record is not missing; it is simply in a different tool than the one that raised the original alert, with no link between them. An analyst working from Wazuh alone would never learn that containment happened at all. A detection engineering program can have real, working controls, genuinely documented, and still have a real cross-tool correlation gap — those are not the same question.

### 6.4 — Methodology discipline caught real, if minor, problems along the way
Trusting a general GitHub reference over the live system's own installed files led to a version mismatch, caught only by checking the local copy directly. A benign Wazuh warning (`overwrite="yes"` cannot change `if_group`) could easily have been misread as a failed fix, had it not been checked against Wazuh's own documentation and support staff.

### 6.5 — The next iteration of this same cycle is already scoped
Following Exabeam's own lifecycle framing — *"monitor and tune: continuously refine detections"* as an ongoing, not one-time, step — every fix identified but not applied mid-capstone (Sysmon config-tier change, a properly-sourced T1055 detection per MITRE's DET0508, a `comsvcs.dll` ImageLoad rule, a frequency-based T1046 rule per MITRE's DET0376, an AdFind user-scoped exception, closed-loop SOAR-action logging, and `filterlog` forwarding) is queued as the next Planning→Tuning→Re-Test pass through this same cycle — not scattered into the current one. This follows NIST SP 800-115's structure, which separates testing from remediation specifically to preserve comparability of results within a single test pass; applying fixes mid-run would have made each subsequent technique's result incomparable to the ones before it.

### 6.6 — The headline number isn't the point
Of seven technique-slots: three detected cleanly, two missed with fully root-caused explanations, one prevented by defense-in-depth, and one split between an endpoint miss and a genuine (if invisible) network-layer success. The actual deliverable of this capstone isn't that ratio — it's that every result, in both directions, was measured rather than assumed, traced to a specific root cause, checked against official and vendor sourcing rather than left as opinion, and verified with a real before/after wherever a fix was made. That discipline, applied consistently across six techniques and one unplanned network-layer discovery, is the actual finding of this capstone.
