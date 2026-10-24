#!/usr/bin/env python3
"""Temporary system CA mitigation; not a Ubiquiti firmware patch.

Tested on Cloud Gateway Fiber, UniFi OS 5.1.33, 2026-10-24.
Requires Debian-style ca-certificates, Python 3.9+, and root for changes.
Default: inspect only. Use --apply to change trust, --verify-online to probe TLS.
Removing AAA Certificate Services can break unrelated legitimate TLS chains.
Bundled application trust stores and existing TLS sessions are outside scope.
Sources:
https://bugs.debian.org/1151446
https://emudhra.we-have-a-problem.com/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CONFIG = Path("/etc/ca-certificates.conf")
BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
CERTDIR = Path("/etc/ssl/certs")
SOURCES = Path("/usr/share/ca-certificates")
BACKUPS = Path("/var/backups/unifi-emudhra")
UPDATER = "/usr/sbin/update-ca-certificates"
TARGETS = {
    "mozilla/emSign_ECC_Root_CA_-_G3.crt": "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "mozilla/Comodo_AAA_Services_root.crt": "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
}
BLOCKED = set(TARGETS.values())
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprints(data: str) -> set[str]:
    blocks = PEM.findall(data)
    if not blocks or len(blocks) != data.count("-----BEGIN CERTIFICATE-----"):
        raise RuntimeError("Missing or malformed PEM certificate data")
    return {digest(ssl.PEM_cert_to_DER_cert(cert)) for cert in blocks}


def trusted_fingerprints() -> set[str]:
    # Inspect both the bundle and individual files, including hashed symlinks.
    result = fingerprints(BUNDLE.read_text())
    visited = {BUNDLE.resolve()}
    for entry in CERTDIR.iterdir():
        if not entry.is_file() or entry.resolve() in visited:
            continue
        visited.add(entry.resolve())
        text = entry.read_text(errors="replace")
        if "-----BEGIN CERTIFICATE-----" in text:
            result.update(fingerprints(text))
    return result


def change_plan(original: str) -> str:
    lines = original.splitlines(keepends=True)
    return "".join("!" + line if line.strip() in TARGETS else line for line in lines)


def validate_sources(original: str, trusted: set[str]) -> None:
    entries = [line.strip().lstrip("!") for line in original.splitlines()]
    for relative, expected in TARGETS.items():
        source = SOURCES / relative
        if source.exists() and fingerprints(source.read_text()) != {expected}:
            raise RuntimeError("Fingerprint mismatch: " + relative)
        if expected in trusted and (
            not source.is_file() or entries.count(relative) != 1
        ):
            raise RuntimeError("Unmanaged or ambiguous trust anchor: " + relative)


def trusted_path(path: Path, directory: bool = False) -> None:
    if path.is_symlink():
        raise RuntimeError("Refusing symlink: " + str(path))
    info = path.stat()
    correct_type = (
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    )
    if not correct_type or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("Expected root-owned, non-writable path: " + str(path))


def preflight() -> None:
    if sys.platform != "linux":
        raise RuntimeError("Only Linux with Debian-style ca-certificates is supported")
    for path in (CONFIG, BUNDLE, Path(UPDATER)):
        if not path.is_file():
            raise RuntimeError("Unsupported system; missing " + str(path))
    os_release = Path("/etc/os-release").read_text()
    if not re.search(r"^ID=\"?debian\"?$", os_release, re.MULTILINE):
        raise RuntimeError("This script is limited to Debian-based UniFi OS")
    firmware = Path("/usr/lib/version")
    if not firmware.is_file() or not re.search(r"\.v\d+\.\d+\.", firmware.read_text()):
        raise RuntimeError("UniFi firmware marker not found; refusing this platform")


def atomic_config(data: bytes) -> None:
    trusted_path(CONFIG)
    fd, name = tempfile.mkstemp(prefix=".ca-remediation-", dir=str(CONFIG.parent))
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(CONFIG.stat().st_mode))
        os.replace(temporary, CONFIG)
    finally:
        temporary.unlink(missing_ok=True)


def rebuild() -> None:
    trusted_path(Path(UPDATER))
    subprocess.run([UPDATER], check=True, timeout=90)


def verify_store(before: set[str]) -> None:
    after = trusted_fingerprints()
    if after & BLOCKED:
        raise RuntimeError("Affected roots remain trusted (possibly custom copies)")
    if not (before - BLOCKED).issubset(after):
        raise RuntimeError("An unrelated trust anchor was removed")


def apply() -> None:
    original = CONFIG.read_bytes()
    before = trusted_fingerprints()
    validate_sources(original.decode(), before)
    planned = change_plan(original.decode()).encode()
    if planned == original and not before & BLOCKED:
        print("Already mitigated; no change.")
        return
    if planned == original:
        raise RuntimeError(
            "Trust store needs repair; no managed enabled entry to change"
        )
    trusted_path(BACKUPS.parent, directory=True)
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    trusted_path(BACKUPS, directory=True)
    backup = Path(tempfile.mkdtemp(prefix="backup-", dir=str(BACKUPS)))
    (backup / "ca-certificates.conf").write_bytes(original)
    shutil.copyfile(BUNDLE, backup / "ca-certificates.crt")
    manifest = {
        "schema": 1,
        "before_sha256": digest(original),
        "after_sha256": digest(planned),
        "blocked_sha256": sorted(BLOCKED),
    }
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("BACKUP=" + str(backup), flush=True)
    if CONFIG.read_bytes() != original:
        raise RuntimeError("Configuration changed during preflight")
    try:
        atomic_config(planned)
        rebuild()
        verify_store(before)
    except (Exception, KeyboardInterrupt):
        print(
            "Apply failed; restoring previous configuration (previous risk returns).",
            file=sys.stderr,
        )
        atomic_config(original)
        rebuild()
        raise
    print("System trust mitigation applied; unrelated anchors preserved.")
    print(
        "Rollback: python3 unifi-emudhra-mitigation.py --rollback "
        + str(backup)
        + " --accept-restored-risk"
    )


def rollback(backup: Path) -> None:
    backup = backup.absolute()
    if backup.parent != BACKUPS or not backup.name.startswith("backup-"):
        raise RuntimeError(
            "Backup must be an immediate backup-* directory in " + str(BACKUPS)
        )
    for path in (BACKUPS, backup):
        trusted_path(path, directory=True)
    for name in ("manifest.json", "ca-certificates.conf"):
        trusted_path(backup / name)
    manifest = json.loads((backup / "manifest.json").read_text())
    original = (backup / "ca-certificates.conf").read_bytes()
    if manifest.get("schema") != 1 or digest(original) != manifest.get("before_sha256"):
        raise RuntimeError("Invalid backup manifest or checksum")
    if digest(CONFIG.read_bytes()) != manifest.get("after_sha256"):
        raise RuntimeError("Configuration has since changed; refusing to overwrite it")
    validate_sources(original.decode(), BLOCKED)
    atomic_config(original)
    rebuild()
    print("Original configuration restored. The previous certificate risk returns.")


def online_checks() -> bool:
    curl = shutil.which("curl")
    if curl is None:
        raise RuntimeError("curl is required for --verify-online")
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper()
        not in {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "CURL_CA_BUNDLE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }
    }
    good = True
    for url, expected in (
        ("https://dv-g3b-emudhra.we-have-a-problem.com/", 60),
        ("https://dv-g3b-aaa-emudhra.we-have-a-problem.com/", 60),
        ("https://ui.com/", 0),
    ):
        result = subprocess.run(
            [
                curl,
                "-q",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "--output",
                "/dev/null",
                "--write-out",
                "%{ssl_verify_result}",
                url,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )
        # A network failure, expiry or hostname mismatch is not distrust evidence.
        passed = result.returncode == expected and result.stdout.strip() in (
            {"20", "21"} if expected == 60 else {"0"}
        )
        print(
            ("PASS " if passed else "FAIL/INCONCLUSIVE ")
            + url
            + " curl_exit="
            + str(result.returncode)
            + " verify="
            + result.stdout.strip()
        )
        good = good and passed
    return good


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--rollback", type=Path)
    parser.add_argument("--accept-restored-risk", action="store_true")
    parser.add_argument("--verify-online", action="store_true")
    args = parser.parse_args()
    preflight()
    modifying = args.apply or args.rollback is not None
    if modifying:
        if os.geteuid() != 0:
            raise RuntimeError("Run as root to change system trust")
        import fcntl

        # Lock the existing protected configuration inode's directory-independent
        # lock file; configuration itself is replaced atomically.
        lock_path = Path("/run/unifi-emudhra.lock")
        trusted_path(lock_path.parent, directory=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            trusted_path(lock_path)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            trusted_path(CONFIG)
            if args.apply:
                apply()
            else:
                if not args.accept_restored_risk:
                    raise RuntimeError("Rollback requires --accept-restored-risk")
                rollback(args.rollback)
    else:
        before = trusted_fingerprints()
        validate_sources(CONFIG.read_text(), before)
        for name, fp in TARGETS.items():
            print(
                name
                + ": "
                + ("TRUSTED" if fp in before else "not found in trust store")
            )
        print("DRY RUN: no files changed. Use --apply for the temporary mitigation.")
    print(
        "Scope: system CA store only; cached/application trust needs separate updates."
    )
    print(
        "Recheck after firmware changes. No services restarted or firewall rules changed."
    )
    if args.verify_online and not online_checks():
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
