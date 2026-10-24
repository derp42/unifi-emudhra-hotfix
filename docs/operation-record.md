# Cloud Gateway Fiber mitigation record

- Status: Accepted as an operator-authorized temporary mitigation
- Date: 2026-10-24
- Scope: UniFi gateway system trust

## Context

A Cloud Gateway Fiber running UniFi OS 5.1.33 trusted both certificate paths
affected by the October 2026 eMudhra intermediate-CA compromise. Its stable
firmware feed still offered 5.1.33 and its configured package repositories were
pinned to a September snapshot. Refreshing package metadata did not make a
fixed certificate package available. Network 10.6.109 supplied an application
fix, which did not remove the OS trust anchors.

## Decision

With explicit operator approval, disable the exact emSign ECC Root CA - G3 and
AAA Certificate Services roots in the system CA configuration and rebuild the
store using its existing updater. Match certificate SHA-256 fingerprints,
preserve unrelated trust anchors, retain a protected backup, and provide
guarded rollback. This is an independent workaround, not a Ubiquiti release.

The [standalone script](../unifi-emudhra-mitigation.py) and
[shareable instructions](../USAGE.txt) are operator tools run with explicit
root access.
Firmware, package sources, firewall rules, and SSH policy remain unchanged.

## Evidence and Consequences

On 2026-10-24, application removed two trust anchors and preserved all other
previously observed anchors. Both research test endpoints subsequently failed
with curl exit 60 and OpenSSL verification code 20; HTTPS to ui.com continued
to validate. The system updater emitted its normal warning about skipping the
multi-certificate bundle during single-certificate rehashing.

AAA Certificate Services also anchors legitimate chains, so this change may
affect unrelated services. Bundled application trust, cached trust, and existing
TLS sessions require separate vendor updates or operator-managed restarts.
Firmware/provisioning may replace the change; reverify afterward. Rollback
restores the previous risk and must not overwrite a newer vendor trust update.

Repeat application completed without changing the already-mitigated store.
UniFi Core, Network, and nginx were active afterward. Rollback logic and failure
recovery were tested with isolated fixtures, not by re-enabling affected trust
on the live gateway. Other device models remain untested.

## References

- [Debian certificate trust correction](https://bugs.debian.org/1151446)
- [Incident details and verification endpoints](https://emudhra.we-have-a-problem.com/)
- [UniFi Network 10.6.109 and vendor OS clarification](https://community.ui.com/releases/UniFi-Network-Application-10-6-109/772020d5-1426-4015-bbd6-631d28803933)
