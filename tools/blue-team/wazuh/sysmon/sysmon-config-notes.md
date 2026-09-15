# Sysmon configuration — source and Wazuh-side customizations

## Base config

This lab uses [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular)
community configuration for Windows endpoint telemetry (Sysmon). See
`THIRD-PARTY-LICENSE.md` in this folder for the MIT license and
attribution.

`sysmonconfig.xml` in this folder is the live configuration, pulled
directly off the endpoint via `Sysmon64.exe -c`, rather than a static
copy of the upstream download — it reflects whatever customizations
are actually in effect on the deployed agents.

For how Sysmon itself gets rolled out (GPO-based, shared install
script, agent-side `agent.conf` wiring to read the Sysmon Operational
channel), see `docs/03-wazuh-sysmon-fim.html` in this repo — that
chapter covers the deployment mechanics end to end.

A design property of the upstream config worth calling out separately:
**NetworkConnect (Event 3) is include-only (allowlist)**. Only
connections matching a MITRE-technique-tagged process/port combination
are logged. Ordinary browser or curl HTTPS traffic — even a fully
successful TCP handshake — produces no Event 3 at all. This was
verified experimentally and confirmed against the upstream project's
documented intent. It's a deliberate, industry-standard noise-reduction
choice, not a gap in this lab's Wazuh rules.

## Wazuh-side customizations

See `local_rules.xml` in the neighboring folder. Three custom child
rules sit on top of the base Sysmon event-mapping rules (which stay at
their default level, usually 0):

| Rule ID | Base (`if_sid`) | Sysmon Event | Purpose |
|---------|------------------|--------------|---------|
| 100160  | 61650            | 22 (DNS query) | Filters internal/infra DNS noise before triggering MISP correlation. |
| 100170  | 61603            | 1 (Process creation) | Forwards every process hash to the SOAR hash-correlation workflow. |
| 100180  | 61605            | 3 (Network connection) | Filters out RFC1918/loopback/link-local destinations, forwarding only external connections. |

(The MISP threat-intel correlation these rules feed into isn't part of
the `docs/` build series yet — it's a later phase of the project,
documented here at the rule level in the meantime.)

## A bug found the hard way: an unfiltered rule flooding the SOAR

Rule 100180 didn't exist from the start. Wazuh's base rule for network
connections, `61605`, normally sits at level 0 and produces no alert.
At some point it had instead been overridden directly
(`overwrite="yes"`, level 0 → 3) with no destination-IP filter at all —
meaning every single Sysmon Event 3, including ordinary internal
traffic, was being forwarded downstream.

**How it surfaced**: the downstream SOAR platform's execution count
spiked hard — far more runs per second than a correctly filtered
workflow should ever produce. That volume was the tell.

**How it was confirmed**: rather than guessing from the symptom, alert
volume was measured directly and compared side by side, live — SSH'd
into the Wazuh manager to count matching entries in `alerts.json` in
real time, while watching the downstream execution count in the
browser at the same time, in the same window. To generate real signal
instead of relying on synthetic test traffic, ordinary web browsing was
run on a domain-joined client to produce genuine outbound connections.
The two counts moved together and confirmed the rule was firing on
effectively everything, not just external connections.

**The fix**: the unfiltered override on `61605` was removed entirely,
and replaced with the properly filtered child rule `100180` shown
above — consistent with how the DNS and hash rules were already built.
Leaving the old override in place alongside the new child rule would
have caused both to fire in parallel, so the old block had to be
removed as its own explicit step, not just supplemented.

**Verification**: after the fix, real traffic (background Defender
cloud-lookup connections, plus ordinary client browsing) was used
again to confirm end to end — Wazuh alert timestamps were matched
second-for-second against the corresponding downstream webhook calls,
confirming the filtered rule fires only on genuine external
connections.
