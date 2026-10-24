# UniFi eMudhra temporary hotfix

A reversible system-certificate mitigation written for a **UniFi Cloud Gateway
Fiber running UniFi OS 5.1.33**. It stops the OS trust store from trusting the two
root paths associated with the October 2026 eMudhra intermediate-CA compromise.

**Independent community tool, not an official Ubiquiti patch.** This addresses
certificate trust, not PHP2Shell. Use a supported vendor fix when available.

## Vendor update or temporary hotfix?

Status checked **2026-10-24**; release channels and availability can change.

| Option | When to choose it | What to do |
| --- | --- | --- |
| Install a vendor OS fix | A suitable fixed release is available for your exact console, and you accept its release channel | Ubiquiti staff identified **UniFi OS 6.0.15** as containing an OS fix. Check the current release notes and availability for your model, then verify the installed trust store. |
| Keep Official firmware and use this temporary hotfix | Your Official OS release still trusts the affected chains and you want to avoid a prerelease firmware upgrade | Run the dry run, review the tradeoffs, then apply this script. Recheck after every firmware update and move to a verified vendor fix when available. |

On the test Cloud Gateway Fiber, Ubiquiti's public Official firmware feed still
offered **5.1.33** on the date above. The vendor discussion identified 6.0.15 as
the separate OS fix while users reported it on Early Access. **Do not assume
6.0.15 is available, Official, or appropriate for every model.** A newer version
number alone is not verification: stale certificate stores have also been
reported after updates. [Vendor release discussion][network-release]

To look for the vendor OS update, open **Settings > Control Plane > Updates**,
select the **UniFi Console**, and inspect its release channel. If a fixed build
is offered only on Early Access or Release Candidate for your model, choosing
that channel is a prerelease firmware decision, with the corresponding upgrade
and downtime considerations. Check the linked release notes and back up your
console configuration first. [Ubiquiti update instructions][updates]

Here, “switch repositories” means changing the **UniFi OS release channel in
the UI**. Do not replace the appliance's Debian/APT repositories to force a
different distribution or certificate package. The test gateway's package
sources were pinned to a September snapshot, so refreshing package metadata
did not supply the October fix. This script leaves package sources unchanged.

**UniFi Network 10.6.109 is an application fix, not proof the OS trust store is
fixed.** Update applications as appropriate too. [Network release][network-release]

## Compatibility

| Device/platform | Status |
| --- | --- |
| Cloud Gateway Fiber, UniFi OS **5.1.33** | **Tested live:** apply, repeat apply, root removal, unrelated-root preservation, both TLS test paths rejected, normal HTTPS and UniFi services healthy. |
| Cloud Gateway Ultra/Max; Dream Machine Pro/SE/Pro Max; Dream Router; Dream Wall on modern UniFi OS | **Plausible but untested candidates.** This is an inference from their UniFi OS platform, conditional on every prerequisite below. No device-level support claim. |
| CloudKey Gen2/Gen2 Plus, UNVR and other UniFi OS consoles | **Unverified.** They may share the needed layout, but model name and OS version are insufficient; inspect first and report results. |
| Legacy USG/EdgeOS, switches, APs, standalone Network Server, UniFi OS Server on a general-purpose host, non-Debian appliances | **Outside this script's scope.** Do not bypass the platform checks. |

Prerequisites:

- Run on the console host, not inside an application container.
- Debian identified in `/etc/os-release` and a firmware marker in `/usr/lib/version`.
- Python **3.9 or newer**, root access for changes, and `update-ca-certificates`.
- The standard `/etc/ca-certificates.conf`, `/etc/ssl/certs`, and
  `/usr/share/ca-certificates` layout, with expected ownership and fingerprints.
- `curl` and direct internet access only if using `--verify-online`.

The script fails closed on missing prerequisites, changed fingerprints, or
ambiguous managed entries. Passing those checks establishes that it understands
the local layout; it does not certify an untested console. There are no
third-party Python runtime dependencies. For compatibility reports, include
model, OS version, Python version, and sanitized output; omit credentials,
addresses, device identifiers, and support bundles.

## Usage

Download or clone this repository, review the script, then transfer
`unifi-emudhra-mitigation.py` to your console with your normal secure transfer
method. Run it over SSH. No Git installation is needed on the console. Do not
pipe an unreviewed remote download directly into a root shell.

```sh
# Inspect only: default behavior, no changes
python3 unifi-emudhra-mitigation.py

# Run as root to apply and perform live verification
python3 unifi-emudhra-mitigation.py --apply --verify-online

# Inspect and verify again after an update
python3 unifi-emudhra-mitigation.py --verify-online
```

The online check contacts the incident researcher's two test sites and
`https://ui.com/`, with no credentials. It ignores curl configuration and proxy
settings to test this machine's default trust directly. The affected paths
must fail with certificate-chain verification errors and normal HTTPS must
still work. A DNS error, timeout, expired certificate, or hostname mismatch
does not count as a pass. The check is optional; local store verification is
always performed when applying. [Incident and test endpoints][incident]

| Exit | Meaning |
| --- | --- |
| `0` | Requested local operation completed. A dry run can still report `TRUSTED`; read its output. |
| `1` | Local error or refused operation. |
| `2` | Online verification failed or was inconclusive; a successfully applied local mitigation remains in place. |

## What changes and why

The script disables these exact entries in `/etc/ca-certificates.conf`, then
runs the existing system updater:

| Trust anchor | SHA-256 certificate fingerprint |
| --- | --- |
| emSign ECC Root CA - G3 | `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b` |
| AAA Certificate Services (`Comodo_AAA_Services_root.crt`) | `d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4` |

The second root covers an alternate cross-signed path. These roots anchor the
compromised intermediates; this does not claim the roots' own private keys were
compromised. **Distrusting AAA Certificate Services can also break legitimate,
unrelated TLS chains.** This follows the root exclusions in Debian's incident
response. [Debian record][debian]

A protected backup stores the original configuration, public CA bundle, and
configuration checksums. The script checks both the bundle and certificate
directory, verifies unrelated anchors remain, and treats repeat application as
a no-op. A failed apply or local verification triggers a configuration restore
and rebuild; if that also fails, operator recovery is needed. The system updater
may invoke existing certificate-update hooks. The script does not directly
restart services, reboot, upgrade packages/firmware, or change firewall/SSH rules.

## Rollback

Each modifying run prints `BACKUP=/var/backups/unifi-emudhra/backup-...`.
Use the directory from **your own run**:

```sh
python3 unifi-emudhra-mitigation.py \
  --rollback /var/backups/unifi-emudhra/backup-REPLACE_ME \
  --accept-restored-risk
```

Rollback restores the prior certificate risk. It checks the backup and refuses
to overwrite configuration that changed afterward or to restore roots removed
by a later update. Do not copy an old bundle over a new vendor trust store.
Keep the backup path and use the [detailed operating notes](USAGE.txt) for recovery.

## Limits and retirement

This covers the **system CA store**. Java, Node.js, containers, and other
applications may use separate or cached trust. Existing TLS sessions are not
revalidated. Vendor application updates and any necessary restarts remain
separate work. This is not proof that the whole appliance is free of exposure.

Firmware updates/provisioning may replace the configuration. Re-run inspection
and verification after changes. Once a vendor fix is installed and verified,
retain its updated trust store; **do not roll back this workaround just to
“uninstall” it**, because rollback can re-enable affected trust. Do not schedule
this script to overwrite future vendor policy automatically.

## Development and evidence

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
ruff check .
ruff format --check .
```

Tests cover exact matching, fingerprint refusal, ambiguous entries, preservation
of unrelated roots, repeat application, failure recovery, rollback guards, and
distinguishing network failures from certificate distrust. Unit tests use
fixtures and mocks; they do not touch the host trust store or contact test sites.
CI tests Python 3.9 and 3.13 on Linux. Device evidence is in the
[operation record](docs/operation-record.md).

Licensed under [Apache-2.0](LICENSE). Not affiliated with or endorsed by Ubiquiti.

[network-release]: https://community.ui.com/releases/UniFi-Network-Application-10-6-109/772020d5-1426-4015-bbd6-631d28803933
[updates]: https://help.ui.com/hc/en-us/articles/7605005245975-UniFi-Updates
[incident]: https://emudhra.we-have-a-problem.com/
[debian]: https://bugs.debian.org/1151446
