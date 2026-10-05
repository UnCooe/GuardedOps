from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .audit import default_run_id, new_operation_id
from .fleet import load_fleet

SHELL_COMPOSITION_TOKENS = {";", "&&", "||", "|", "|&", "&", "<", ">", ">>", "2>", "2>>", "<<<"}
SHELL_COMPOSITION_CHARS = set(";&|<>`")
# Raw protected-host exceptions are limited to diagnostics that do not read
# arbitrary files. File and log inspection must go through a guarded entrypoint.
READ_ONLY_TOOLS = {"pwd", "whoami", "hostname", "date", "uptime"}
READ_ONLY_SUPERVISOR_OPS = {"status"}
GIT_READ_OPTION_FLAGS = {
    "status": {"--short", "-s", "--branch", "-b", "--porcelain", "--porcelain=v1", "--untracked-files=no"},
    "rev-parse": {"--verify", "--short", "--abbrev-ref", "--show-toplevel", "--show-prefix", "--show-cdup", "--is-inside-work-tree"},
    "log": {"-1", "-2", "-3", "-4", "-5", "--oneline", "--stat", "--decorate", "--no-decorate"},
    "show": {"--stat", "--name-only", "--name-status", "--oneline", "--no-patch", "-s"},
    "diff": {"--stat", "--name-only", "--name-status", "--check", "--cached"},
    "branch": {"--show-current", "--list", "-a", "-r", "-v", "-vv"},
}
GIT_READ_OPTIONS_WITH_VALUE = {
    "log": {"-n", "--max-count", "--since", "--until", "--format", "--pretty"},
}
GIT_REF_RE = r"^[A-Za-z0-9][A-Za-z0-9._/~^:-]*$"


@dataclass(frozen=True)
class HookDecision:
    allowed: bool
    reason: str
    suggestion: str | None = None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hook_block_evidence(
    command: str,
    decision: HookDecision,
    *,
    user_turn_id: str | None = None,
    operation_id: str | None = None,
    run_id: str | None = None,
    host: str | None = None,
    action: str | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "command_hash": _sha256(command),
        "decision_reason_hash": _sha256(decision.reason),
    }
    if user_turn_id:
        details["user_turn_sha256"] = _sha256(user_turn_id)
    if decision.suggestion:
        details["suggestion_hash"] = _sha256(decision.suggestion)
    payload: dict[str, Any] = {
        "schema_version": "guardedops.evidence/v1",
        "operation_id": operation_id or new_operation_id("hook-block"),
        "run_id": run_id or default_run_id(),
        "host": host or "unknown",
        "source": "ops-guard-hook",
        "reason_code": "hook_denied",
        "status": "blocked",
        "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "details": details,
    }
    if action is not None:
        payload["action"] = action
    return payload


def append_hook_evidence(path: str | Path, evidence: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(dict(evidence), sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def protected_aliases(fleet_path: str | Path) -> set[str]:
    fleet = load_fleet(fleet_path)
    aliases: set[str] = set()
    for name, host in (fleet.get("hosts") or {}).items():
        aliases.add(str(name))
        aliases.add(f"aiserver-{name}")
        aliases.add(f"aiserver-{name}-codex")
        alias = host.get("ssh_alias")
        if alias:
            aliases.add(str(alias))
        for extra in host.get("aliases") or host.get("protected_aliases") or ():
            aliases.add(str(extra))
    return aliases


def route_hosts(fleet_path: str | Path) -> set[str]:
    route_path = Path(fleet_path).resolve().parent / "route.example.json"
    if not route_path.exists():
        return set()
    data = json.loads(route_path.read_text(encoding="utf-8"))
    hosts: set[str] = set()
    for target in (data.get("targets") or {}).values():
        host = target.get("host")
        if host:
            hosts.add(str(host))
    return hosts


def normalize_destination(destination: str) -> str:
    if "@" in destination:
        destination = destination.rsplit("@", 1)[1]
    if ":" in destination and not destination.startswith("["):
        destination = destination.split(":", 1)[0]
    return destination.strip("[]")


def find_ssh_destination(words: list[str]) -> str | None:
    index = 1
    options_with_value = {"-b", "-c", "-D", "-E", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"}
    while index < len(words):
        word = words[index]
        if word == "--":
            index += 1
            break
        if word.startswith("-"):
            option = word[:2]
            if option in options_with_value and word == option:
                index += 2
            else:
                index += 1
            continue
        break
    if index < len(words):
        return normalize_destination(words[index])
    return None


def ssh_command_words(words: list[str]) -> list[str]:
    index = 1
    options_with_value = {"-b", "-c", "-D", "-E", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"}
    while index < len(words):
        word = words[index]
        if word == "--":
            index += 1
            break
        if word.startswith("-"):
            option = word[:2]
            if option in options_with_value and word == option:
                index += 2
            else:
                index += 1
            continue
        index += 1
        break
    if index < len(words):
        if words[index] == "--":
            index += 1
        return words[index:]
    return []


def raw_ssh_write_detected(remote_words: list[str]) -> bool:
    if not remote_words:
        return True
    rendered = " ".join(remote_words)
    try:
        words = shlex.split(rendered)
    except ValueError:
        words = remote_words
    if not words:
        return True
    if shell_composition_detected(rendered, words):
        return True
    tool = Path(words[0]).name
    if tool in {"bash", "sh", "zsh", "python", "python3", "perl", "ruby", "node"}:
        nested = unwrap_shell_command(words)
        if nested:
            try:
                return raw_ssh_write_detected(shlex.split(nested))
            except ValueError:
                return True
        return True
    if tool in {"sudo", "env", "command"} and len(words) > 1:
        nested = unwrap_env(words) if tool == "env" else words[1:]
        if nested:
            return raw_ssh_write_detected(nested)
    if tool == "git":
        return not git_read_command_allowed(words)
    if tool == "supervisorctl":
        op = next((word for word in words[1:] if not word.startswith("-")), "")
        return op not in READ_ONLY_SUPERVISOR_OPS
    if tool in {
        "systemctl",
        "service",
        "docker",
        "kubectl",
        "pm2",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "rmdir",
        "ln",
        "chmod",
        "chown",
        "touch",
        "tee",
        "rsync",
        "scp",
        "tar",
        "unzip",
    }:
        return True
    if tool == "sed" and "-i" in words[1:]:
        return True
    if tool in READ_ONLY_TOOLS:
        return False
    return True


def git_subcommand(words: list[str]) -> str:
    index = 1
    options_with_value = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
    while index < len(words):
        word = words[index]
        if word == "--":
            index += 1
            break
        if word in options_with_value:
            index += 2
            continue
        if word.startswith("--git-dir=") or word.startswith("--work-tree=") or word.startswith("--namespace=") or word.startswith("--exec-path="):
            index += 1
            continue
        if word.startswith("-"):
            index += 1
            continue
        return word
    if index < len(words):
        return words[index]
    return ""


def _looks_like_git_ref(word: str) -> bool:
    if word.startswith("-") or ".." in word:
        return False
    return re_fullmatch(GIT_REF_RE, word)


def re_fullmatch(pattern: str, value: str) -> bool:
    return re.fullmatch(pattern, value) is not None


def git_read_command_allowed(words: list[str]) -> bool:
    index = 1
    while index < len(words):
        word = words[index]
        if word == "-C" and index + 1 < len(words):
            index += 2
            continue
        if word in {"-c", "--config-env", "--exec-path", "--git-dir", "--work-tree", "--namespace"}:
            return False
        if word.startswith(("-c", "--config-env=", "--exec-path=", "--git-dir=", "--work-tree=", "--namespace=", "-C")):
            return False
        if word.startswith("-"):
            return False
        break
    if index >= len(words):
        return False
    op = words[index]
    if op not in GIT_READ_OPTION_FLAGS:
        return False
    index += 1
    flags = GIT_READ_OPTION_FLAGS[op]
    options_with_value = GIT_READ_OPTIONS_WITH_VALUE.get(op, set())
    while index < len(words):
        word = words[index]
        if word in flags:
            index += 1
            continue
        if word in options_with_value:
            if index + 1 >= len(words):
                return False
            index += 2
            continue
        if any(word.startswith(option + "=") for option in options_with_value):
            index += 1
            continue
        if word.startswith("-"):
            return False
        if _looks_like_git_ref(word):
            index += 1
            continue
        return False
    return True


def shell_composition_detected(rendered: str, words: list[str]) -> bool:
    if "$(" in rendered:
        return True
    for word in words:
        if word in SHELL_COMPOSITION_TOKENS:
            return True
        if any(char in word for char in SHELL_COMPOSITION_CHARS):
            return True
    return False


def protected_command_destination(command: str, fleet_path: str | Path = "examples/fleet.example.json") -> str | None:
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if not words:
        return None
    aliases = protected_aliases(fleet_path)
    aliases.update(route_hosts(fleet_path))
    for index, word in enumerate(words):
        tool = Path(word).name
        candidate_words = words[index:]
        if tool in {"ssh", "sftp"}:
            destination = find_ssh_destination(candidate_words)
            if destination in aliases:
                return destination
        elif tool in {"scp", "rsync"}:
            destination = find_file_transfer_destination(candidate_words)
            if destination in aliases:
                return destination
        elif tool in {"bash", "sh", "zsh"}:
            nested = unwrap_shell_command(candidate_words)
            if nested:
                destination = protected_command_destination(nested, fleet_path)
                if destination:
                    return destination
    return None


def protected_target_mentioned(command: str, words: list[str], aliases: set[str]) -> bool:
    for index, word in enumerate(words):
        tool = Path(word).name
        if tool in {"ssh", "sftp"}:
            destination = find_ssh_destination(words[index:])
            if destination in aliases:
                return True
        if tool in {"scp", "rsync"}:
            destination = find_file_transfer_destination(words[index:])
            if destination in aliases:
                return True
    if not re.search(r"(?<![A-Za-z0-9_-])(ssh|sftp|scp|rsync)(?![A-Za-z0-9_-])", command):
        return False
    return any(re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(alias)}(?![A-Za-z0-9_.-])", command) for alias in aliases)


def composed_protected_command_detected(command: str, words: list[str], aliases: set[str]) -> bool:
    return shell_composition_detected(command, words) and protected_target_mentioned(command, words, aliases)


def find_file_transfer_destination(words: list[str]) -> str | None:
    for word in words[1:]:
        if word.startswith("-"):
            continue
        if ":" in word:
            return normalize_destination(word)
    return None


def unwrap_env(words: list[str]) -> list[str] | None:
    index = 1
    options_with_value = {"-u", "--unset"}
    while index < len(words):
        word = words[index]
        if word == "--":
            index += 1
            break
        if "=" in word and not word.startswith("-"):
            index += 1
            continue
        if word in {"-i", "--ignore-environment", "-0", "--null"}:
            index += 1
            continue
        if word in options_with_value:
            index += 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        break
    if index < len(words):
        return words[index:]
    return None


def unwrap_shell_command(words: list[str]) -> str | None:
    for index, word in enumerate(words[1:], start=1):
        if word == "-c" or (word.startswith("-") and "c" in word[1:]):
            if index + 1 < len(words):
                return words[index + 1]
    return None


def decide_command(command: str, fleet_path: str | Path = "examples/fleet.example.json") -> HookDecision:
    try:
        words = shlex.split(command)
    except ValueError as exc:
        return HookDecision(False, f"cannot parse command: {exc}")
    if not words:
        return HookDecision(True, "empty command")
    aliases = protected_aliases(fleet_path)
    aliases.update(route_hosts(fleet_path))
    if composed_protected_command_detected(command, words, aliases):
        return HookDecision(
            False,
            "composed command containing a protected target is blocked",
            "Use a single guarded entrypoint or one standalone allowed raw read.",
        )
    tool = Path(words[0]).name
    if tool == "env":
        nested_words = unwrap_env(words)
        if nested_words:
            return decide_command(" ".join(shlex.quote(part) for part in nested_words), fleet_path)
        return HookDecision(True, "env command without executable")
    if tool == "command" and len(words) > 1:
        return decide_command(" ".join(shlex.quote(part) for part in words[1:]), fleet_path)
    if tool in {"bash", "sh", "zsh"} and "-c" in words:
        nested_command = unwrap_shell_command(words)
        if nested_command:
            nested = decide_command(nested_command, fleet_path)
            if not nested.allowed:
                return nested
    elif tool in {"bash", "sh", "zsh"}:
        nested_command = unwrap_shell_command(words)
        if nested_command:
            nested = decide_command(nested_command, fleet_path)
            if not nested.allowed:
                return nested
    if Path(words[0]).name in {"opsctl", "ops-wrapper", "routectl"}:
        return HookDecision(True, "guarded entrypoint")
    destination = None
    if tool in {"ssh", "sftp"}:
        destination = find_ssh_destination(words)
    elif tool in {"scp", "rsync"}:
        destination = find_file_transfer_destination(words)
    if destination in aliases:
        if tool == "ssh":
            remote_words = ssh_command_words(words)
            if not raw_ssh_write_detected(remote_words):
                return HookDecision(True, f"raw ssh read to protected target is allowed: {destination}")
        return HookDecision(
            False,
            f"raw {tool} write to protected target is blocked: {destination}",
            "Use opsctl observe/logs/plan-config or an allowed ops-wrapper action.",
        )
    return HookDecision(True, "no protected pattern detected")
