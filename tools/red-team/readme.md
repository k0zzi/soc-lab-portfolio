# Red Team

`findings/` holds Atomic Red Team detection-validation results — six MITRE ATT&CK techniques (seven counting the two AD-recon techniques separately) run against live telemetry in this lab, each result (caught, missed, or prevented) traced to a specific root cause and cross-checked against MITRE ATT&CK, CISA, and major-vendor detection guidance, with fixes verified through genuine before/after comparisons. See `findings/detection-validation-cycle.md` for the full methodology write-up and `findings/detection-coverage.md` for the DeTT&CT-scored coverage summary, including the gaps that remain open.

Caldera-based adversary emulation is planned as a recurring exercise rather than a one-off phase, to run scenarios closer to a real intrusion chain than single, isolated techniques. Its own artifacts will land here as a sibling to `findings/` when that work starts.
