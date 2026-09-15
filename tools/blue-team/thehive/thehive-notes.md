# TheHive — MISP integration notes

> **Note on scope**: this is a *different* connector issue from the
> TheHive↔Cortex connection problem covered in
> `docs/06-thehive-cortex.html` (a startup-ordering race condition with
> a systemd-level fix). This note is about the separate TheHive↔MISP
> integration, which isn't part of the `docs/` build series yet. The
> two connectors failed for genuinely different reasons — the
> similarity in symptoms (an integration that looks broken) is
> coincidental, not the same bug twice.

## Root cause: license, not SSL

TheHive supports two separate paths for connecting to MISP: a
UI-configured connector, or a block in `application.conf`. Having both
active at the same time breaks the integration — and the symptom looks
exactly like a TLS/certificate problem. That was the first suspect
here, since this lab runs its own internal PKI (self-signed by an
offline root, chained through an enterprise subordinate CA), so a
trust-chain issue seemed like the obvious explanation.

It wasn't. The actual root cause was **licensing**: TheHive's
`application.conf`-based MISP connector depends on features that are
gated behind a paid license tier, and running it alongside a
UI-configured connector produces the same silent-failure symptom
regardless of whether the certificate is trusted or not. Once the
`application.conf` MISP block was removed entirely and the UI
connector was left as the single source of truth, the integration
worked — confirmed with a real case created from a MISP-correlated
alert.

**Takeaway for anyone debugging a similar TheHive+MISP setup on a
self-signed or internal-CA certificate**: don't assume TLS trust is
the cause before checking whether both connector paths are configured
at once. A Community-license limitation can look identical to a
certificate trust failure.

## Current state

- Single connector: TheHive UI-configured MISP integration.
- License: Community (StrangeBee).
- Verified live: cases created from MISP-correlated Wazuh alerts
  (network, DNS, and hash indicator correlation — see the exported
  workflows in `tools/blue-team/shuffle/`).
