# Atomic Red Team Capstone — Findings

Per-technique detection findings from testing six MITRE ATT&CK techniques against this lab's live Wazuh/Sysmon/Suricata/Shuffle stack. For full DeTT&CT scoring, methodology, and the split-layer T1046 discussion, see [`detection-coverage.md`](detection-coverage.md) — this page is a quick index into the individual write-ups below.

| Technique | Tactic | Result | Finding |
|---|---|---|---|
| T1059.001 — PowerShell | Execution | ✅ Caught | [T1059.001.md](T1059.001.md) |
| T1218 — System Binary Proxy Execution | Defense Evasion | ❌ Missed | [T1218.md](T1218.md) |
| T1055 — Process Injection | Defense Evasion / Privilege Escalation | ✅ Caught (gap closed) | [T1055.md](T1055.md) |
| T1003.001 — OS Credential Dumping: LSASS Memory | Credential Access | 🛡️ Prevented | [T1003.001.md](T1003.001.md) |
| T1018 — Remote System Discovery | Discovery | ✅ Caught | [T1018-T1087.002.md](T1018-T1087.002.md) |
| T1087.002 — Domain Account Discovery | Discovery | ✅ Caught | [T1018-T1087.002.md](T1018-T1087.002.md) |
| T1046 — Network Service Discovery | Discovery | Split — endpoint missed, network perimeter caught | [T1046.md](T1046.md) |

See also [`detection-validation-cycle.md`](detection-validation-cycle.md) for the purple-team methodology (Planning → TTP Execution → Detection Gap ID → Tuning → Re-Test → Lessons Learned) used across every technique above.
