"""Regression checks for the standalone operational trust-store tool."""

import importlib.util
import ssl
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "unifi-emudhra-mitigation.py"


@pytest.fixture
def tool():
    spec = importlib.util.spec_from_file_location("ca_mitigation", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_plan_changes_only_exact_enabled_entries_and_is_idempotent(tool):
    target = next(iter(tool.TARGETS))
    original = f"# {target}\n{target}\n!{target}\ncustom/{target}\nmozilla/other.crt\n"
    planned = tool.change_plan(original)
    assert planned == original.replace(f"\n{target}\n", f"\n!{target}\n")
    assert tool.change_plan(planned) == planned


def test_fingerprint_rejects_missing_or_truncated_pem(tool):
    for data in ("", "not a certificate", "-----BEGIN CERTIFICATE-----\nAAAA"):
        with pytest.raises(RuntimeError):
            tool.fingerprints(data)


def test_source_fingerprint_mismatch_is_rejected(tool, tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "SOURCES", tmp_path)
    name = next(iter(tool.TARGETS))
    source = tmp_path / name
    source.parent.mkdir()
    source.write_text(ssl.DER_cert_to_PEM_cert(b"different certificate"))
    with pytest.raises(RuntimeError, match="Fingerprint mismatch"):
        tool.validate_sources(name + "\n", tool.BLOCKED)


def test_duplicate_config_entries_are_rejected(tool, tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "SOURCES", tmp_path)
    name, fp = next(iter(tool.TARGETS.items()))
    source = tmp_path / name
    source.parent.mkdir()
    source.write_text("fixture")
    monkeypatch.setattr(tool, "fingerprints", lambda _: {fp})
    with pytest.raises(RuntimeError, match="ambiguous"):
        tool.validate_sources(name + "\n" + name + "\n", {fp})


def test_verification_preserves_unrelated_roots(tool, monkeypatch):
    monkeypatch.setattr(tool, "trusted_fingerprints", lambda: {"root-a"})
    with pytest.raises(RuntimeError, match="unrelated"):
        tool.verify_store({"root-a", "root-b"} | tool.BLOCKED)
    tool.verify_store({"root-a"} | tool.BLOCKED)


def test_custom_copy_of_blocked_root_fails_verification(tool, monkeypatch):
    monkeypatch.setattr(tool, "trusted_fingerprints", lambda: tool.BLOCKED)
    with pytest.raises(RuntimeError, match="remain trusted"):
        tool.verify_store(tool.BLOCKED)


def test_failed_rebuild_restores_original_configuration(tool, tmp_path, monkeypatch):
    config = tmp_path / "ca-certificates.conf"
    original = next(iter(tool.TARGETS)) + "\nmozilla/other.crt\n"
    config.write_text(original)
    bundle = tmp_path / "bundle"
    bundle.write_text("original public bundle")
    monkeypatch.setattr(tool, "CONFIG", config)
    monkeypatch.setattr(tool, "BUNDLE", bundle)
    monkeypatch.setattr(tool, "BACKUPS", tmp_path / "backups")
    monkeypatch.setattr(tool, "trusted_path", lambda *a, **kw: None)
    monkeypatch.setattr(tool, "trusted_fingerprints", lambda: tool.BLOCKED)
    monkeypatch.setattr(tool, "validate_sources", lambda *a: None)
    calls = []

    def rebuild():
        calls.append(config.read_text())
        if len(calls) == 1:
            raise RuntimeError("simulated updater failure")

    monkeypatch.setattr(tool, "rebuild", rebuild)
    with pytest.raises(RuntimeError, match="simulated"):
        tool.apply()
    assert config.read_text() == original
    assert calls == [tool.change_plan(original), original]
    backups = list(tool.BACKUPS.glob("backup-*"))
    assert len(backups) == 1
    assert (backups[0] / "ca-certificates.conf").read_text() == original


def test_rollback_refuses_path_outside_backup_directory(tool, tmp_path):
    with pytest.raises(RuntimeError, match="immediate"):
        tool.rollback(tmp_path / "unexpected")


def test_online_network_failure_is_not_a_security_pass(tool, monkeypatch):
    from subprocess import CompletedProcess

    monkeypatch.setattr(tool.shutil, "which", lambda _: "/usr/bin/curl")
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda *a, **kw: CompletedProcess([], 6, stdout="0", stderr="DNS failure"),
    )
    assert tool.online_checks() is False


def test_apply_idempotence_and_rollback_guards(tool, tmp_path, monkeypatch):
    config = tmp_path / "ca-certificates.conf"
    original = "\n".join(tool.TARGETS) + "\nmozilla/other.crt\n"
    config.write_text(original)
    bundle = tmp_path / "bundle"
    bundle.write_text("public test bundle")
    monkeypatch.setattr(tool, "CONFIG", config)
    monkeypatch.setattr(tool, "BUNDLE", bundle)
    monkeypatch.setattr(tool, "BACKUPS", tmp_path / "backups")
    monkeypatch.setattr(tool, "trusted_path", lambda *a, **kw: None)
    monkeypatch.setattr(tool, "validate_sources", lambda *a: None)
    state = {"trusted": tool.BLOCKED | {"unrelated-root"}}
    monkeypatch.setattr(tool, "trusted_fingerprints", lambda: state["trusted"])

    def rebuild():
        enabled = set(config.read_text().splitlines())
        state["trusted"] = {"unrelated-root"} | {
            fp for name, fp in tool.TARGETS.items() if name in enabled
        }

    monkeypatch.setattr(tool, "rebuild", rebuild)
    tool.apply()
    tool.apply()
    backups = list(tool.BACKUPS.glob("backup-*"))
    assert len(backups) == 1
    assert state["trusted"] == {"unrelated-root"}
    applied = config.read_text()
    config.write_text(applied + "# subsequent operator change\n")
    with pytest.raises(RuntimeError, match="since changed"):
        tool.rollback(backups[0])
    assert "subsequent operator change" in config.read_text()
    config.write_text(applied)
    tool.rollback(backups[0])
    assert config.read_text() == original
    assert state["trusted"] == tool.BLOCKED | {"unrelated-root"}
