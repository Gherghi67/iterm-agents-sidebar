"""Shared Claude subscription switches with real scratch configs and mocked credentials."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import accounts


ALICE = {"accountUuid": "alice", "emailAddress": "alice@example.com"}
BOB = {"accountUuid": "bob", "emailAddress": "bob@example.com"}


def write_config(path, login=ALICE, **extra):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"oauthAccount": login, **extra}))
    return str(path)


@pytest.mark.parametrize("env, service", [
    ({}, accounts.LIVE_SERVICE),
    ({"CLAUDE_CONFIG_DIR": "/profile"}, accounts.LIVE_SERVICE + "-"
     + hashlib.sha256(b"/profile").hexdigest()[:8]),
    ({"CLAUDE_CONFIG_DIR": "/profile", "CLAUDE_SECURESTORAGE_CONFIG_DIR": ""}, accounts.LIVE_SERVICE),
    ({"CLAUDE_CONFIG_DIR": "/profile", "CLAUDE_SECURESTORAGE_CONFIG_DIR": "/shared"},
     accounts.LIVE_SERVICE + "-" + hashlib.sha256(b"/shared").hexdigest()[:8]),
])
def test_live_item_uses_the_runtime_credential_namespace(env, service):
    assert accounts.live_item({"USER": "tester", **env}) == (service, "tester")


def test_credential_names_and_locks_match_claudes_unicode_normalization():
    env = {"USER": "tester", "CLAUDE_CONFIG_DIR": "/prof\u0069\u0301le"}
    normalized = "/prof\u00edle"
    assert accounts.live_item(env)[0] == accounts.LIVE_SERVICE + "-" + hashlib.sha256(
        normalized.encode()).hexdigest()[:8]
    assert accounts.claude_credential_dir(env, "/home") == normalized


def test_shared_default_credentials_take_default_refresh_locks():
    env = {"CLAUDE_CONFIG_DIR": "/code-sessions/profile", "CLAUDE_SECURESTORAGE_CONFIG_DIR": ""}
    assert accounts.claude_credential_dir(env, "/home") == "/home/.claude"
    assert accounts.claude_credential_dir({"CLAUDE_CONFIG_DIR": "/profile"}, "/home") == "/profile"
    assert accounts.claude_credential_dir({"CLAUDE_SECURESTORAGE_CONFIG_DIR": "/shared"}, "/home") == "/shared"


def test_discovery_finds_initialized_profile_and_encrypted_configs_only(tmp_path):
    profile = tmp_path / ".local/share/code-sessions/home"
    shared = write_config(tmp_path / ".claude.json")
    profile_config = write_config(profile / ".claude/.claude.json")
    encrypted = write_config(profile / "sessions/vaulted/.cs/claude-config/.claude.json")
    write_config(profile / "sessions/plain/.cs/unrelated/.claude.json")
    (profile / "sessions/uninitialized/.cs/claude-config").mkdir(parents=True)
    (profile / "sessions/alias").symlink_to(profile / "sessions/vaulted", target_is_directory=True)
    found = accounts.code_sessions_claude_configs(str(tmp_path), (accounts.LIVE_SERVICE, "tester"), shared)
    assert {str(Path(path).resolve()) for path in found} == {profile_config, encrypted}
    assert len(found) == 2
    assert not (profile / "sessions/uninitialized/.cs/claude-config/.claude.json").exists()
    assert accounts.code_sessions_claude_configs(str(tmp_path), ("another-profile", "tester"), shared) == []


def test_discovery_does_not_create_a_profile(tmp_path):
    assert accounts.code_sessions_claude_configs(str(tmp_path), (accounts.LIVE_SERVICE, "tester"),
                                                 str(tmp_path / ".claude.json")) == []
    assert list(tmp_path.iterdir()) == []


@pytest.fixture
def world(tmp_path, monkeypatch):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    primary = write_config(tmp_path / ".claude.json", numStartups=7)
    profile = write_config(tmp_path / "profile/.claude.json", {"accountUuid": "previous-profile"},
                           projects={"private": {"lastPrompt": "keep local"}})
    encrypted = write_config(tmp_path / "vault/.claude.json", None, theme="dark")
    stored = [{"id": "a", "accountUuid": "alice"}, {"id": "b", "accountUuid": "bob"}]
    store = str(tmp_path / "store/accounts.json")
    accounts.save_store(store, stored)
    live = (accounts.LIVE_SERVICE, "tester")
    secret = lambda tag: json.dumps({"claudeAiOauth": {"refreshToken": tag},
                                     "mcpOAuth": {"machine": tag}})
    secrets = {live: secret("live"), ("panel", "a"): secret("stored-a"),
               ("panel", "b"): secret("stored-b"),
               ("panel", accounts.login_item("b")): json.dumps(BOB)}
    writes = []
    monkeypatch.setattr(accounts, "read_secret", lambda *item: secrets.get(tuple(item)))

    def save(service, item, value):
        writes.append((service, item))
        secrets[service, item] = value

    monkeypatch.setattr(accounts, "write_secret", save)
    monkeypatch.setattr(accounts, "refresh_account", lambda *args, **kwargs: "ok")
    return {"root": tmp_path, "dir": str(claude_dir), "primary": primary, "profile": profile,
            "encrypted": encrypted, "stored": stored, "store": store, "live": live,
            "secrets": secrets, "writes": writes, "original_secret": secrets[live]}


def run(w, linked=None):
    plan = accounts.plan_switch(w["stored"], "b", ALICE, w["dir"], w["primary"])
    accounts.run_switch(plan, w["store"], "panel", w["live"], w["primary"], now=1000,
                        lock_timeout=0.03,
                        linked_claude_jsons=linked if linked is not None else [w["profile"], w["encrypted"]])


def no_locks(w):
    assert not list(w["root"].rglob("*.lock"))


def test_switch_changes_shared_login_and_all_local_metadata_without_copying_credentials(world):
    run(world, [world["primary"], world["profile"], world["encrypted"], world["profile"]])
    assert json.loads(Path(world["primary"]).read_text()) == {"oauthAccount": BOB, "numStartups": 7}
    assert json.loads(Path(world["profile"]).read_text()) == {
        "oauthAccount": BOB, "projects": {"private": {"lastPrompt": "keep local"}}}
    assert json.loads(Path(world["encrypted"]).read_text()) == {"oauthAccount": BOB, "theme": "dark"}
    credential = json.loads(world["secrets"][world["live"]])
    assert credential == {"claudeAiOauth": {"refreshToken": "stored-b"}, "mcpOAuth": {"machine": "live"}}
    assert all(service in ("panel", accounts.LIVE_SERVICE) for service, _ in world["writes"])
    no_locks(world)


def test_linked_config_failure_restores_each_original_account_and_shared_credential(world, monkeypatch):
    original = {path: json.loads(Path(path).read_text())
                for path in [world["primary"], world["profile"], world["encrypted"]]}
    replace = accounts._replace_login

    def fail_once(path, login):
        replace(path, login)
        if path == world["encrypted"] and login == BOB:
            raise OSError("injected config failure after write")

    monkeypatch.setattr(accounts, "_replace_login", fail_once)
    with pytest.raises(accounts.SwitchRefused, match="switch undone"):
        run(world)
    assert world["secrets"][world["live"]] == world["original_secret"]
    assert {path: json.loads(Path(path).read_text()) for path in original} == original
    no_locks(world)


def test_rollback_restores_missing_account_field(world, monkeypatch):
    Path(world["profile"]).write_text('{"theme": "local"}')
    replace = accounts._replace_login

    def fail_last(path, login):
        if path == world["encrypted"] and login == BOB:
            raise OSError("last config unavailable")
        replace(path, login)

    monkeypatch.setattr(accounts, "_replace_login", fail_last)
    with pytest.raises(accounts.SwitchRefused, match="switch undone"):
        run(world)
    assert json.loads(Path(world["profile"]).read_text()) == {"theme": "local"}
    no_locks(world)


def test_held_linked_config_lock_refuses_before_the_shared_login_changes(world):
    held = Path(world["profile"] + ".lock")
    held.mkdir()
    with pytest.raises(accounts.SwitchRefused, match="Claude Code is refreshing"):
        run(world)
    assert world["secrets"][world["live"]] == world["original_secret"]
    assert world["writes"] == []
    assert json.loads(Path(world["primary"]).read_text())["oauthAccount"] == ALICE
    held.rmdir()
    no_locks(world)


@pytest.mark.parametrize("content", ["{torn", "[]"])
def test_unreadable_linked_config_refuses_before_any_write(world, content):
    Path(world["profile"]).write_text(content)
    with pytest.raises(accounts.SwitchRefused):
        run(world)
    assert world["writes"] == []
    assert world["secrets"][world["live"]] == world["original_secret"]
    no_locks(world)


def test_linked_locks_stay_held_during_every_login_write(world, monkeypatch):
    replace = accounts._replace_login
    observed = []

    def inspect(path, login):
        assert Path(world["profile"] + ".lock").is_dir()
        assert Path(world["encrypted"] + ".lock").is_dir()
        observed.append(path)
        replace(path, login)

    monkeypatch.setattr(accounts, "_replace_login", inspect)
    run(world)
    assert set(observed) == {world["primary"], world["profile"], world["encrypted"]}
    no_locks(world)


def test_meter_manual_switch_discovers_current_linked_configs(world):
    calls = []

    def linked():
        calls.append("discover")
        return [world["profile"]]

    meters = accounts.AccountMeters(world["store"], "panel", world["live"], world["primary"],
                                    claude_dir=world["dir"], linked_configs=linked)
    result = meters.switch("b", now=1000)
    assert result["id"] == "b" and calls == ["discover"]
    assert json.loads(Path(world["profile"]).read_text())["oauthAccount"] == BOB
    assert meters.last_switch["auto"] is False


def test_linked_config_file_symlink_keeps_alias_and_updates_target(world):
    alias = world["root"] / "linked/.claude.json"
    alias.parent.mkdir()
    alias.symlink_to(world["profile"])
    run(world, [str(alias), world["profile"]])
    assert alias.is_symlink()
    assert json.loads(Path(world["profile"]).read_text())["oauthAccount"] == BOB
    assert json.loads(alias.read_text())["oauthAccount"] == BOB
    no_locks(world)


def test_symlinked_config_rollback_restores_target_and_preserves_alias(world, monkeypatch):
    alias = world["root"] / "linked/.claude.json"
    alias.parent.mkdir()
    alias.symlink_to(world["profile"])
    original = json.loads(Path(world["profile"]).read_text())
    replace = accounts._replace_login

    def fail_after_target_write(path, login):
        replace(path, login)
        if path == world["profile"] and login == BOB:
            raise OSError("injected target failure")

    monkeypatch.setattr(accounts, "_replace_login", fail_after_target_write)
    with pytest.raises(accounts.SwitchRefused, match="switch undone"):
        run(world, [str(alias)])
    assert alias.is_symlink()
    assert json.loads(Path(world["profile"]).read_text()) == original
    assert world["secrets"][world["live"]] == world["original_secret"]
    no_locks(world)


def test_symlinked_config_respects_target_native_lock(world):
    alias = world["root"] / "linked/.claude.json"
    alias.parent.mkdir()
    alias.symlink_to(world["profile"])
    held = Path(world["profile"] + ".lock")
    held.mkdir()
    with pytest.raises(accounts.SwitchRefused, match="Claude Code is refreshing"):
        run(world, [str(alias)])
    assert alias.is_symlink()
    assert world["writes"] == []
    assert world["secrets"][world["live"]] == world["original_secret"]
    held.rmdir()
    no_locks(world)
