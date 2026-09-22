# Red Team

`findings/` holds Atomic Red Team detection-validation results — six MITRE ATT&CK techniques run against live telemetry in this lab, each result (caught, missed, or prevented) traced to a specific root cause and cross-checked against MITRE ATT&CK, CISA, and major-vendor detection guidance, with fixes verified through genuine before/after comparisons. See `findings/detection-validation-cycle.md` for the full methodology write-up and `findings/detection-coverage.md` for the DeTT&CT-scored coverage summary.

Caldera-based adversary emulation is planned for a later phase — partly to test the deferred remediation items already identified in the current findings (see `findings/detection-validation-cycle.md`'s Lessons Learned section), and partly to exercise scenarios closer to a real intrusion chain than single, isolated techniques. Its own artifacts will land here as a sibling to `findings/` when that work starts.
