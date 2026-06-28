from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path

from .fleet import load_fleet


@dataclass(frozen=True)
class HookDecision:
    allowed: bool
    reason: str
    suggestion: str | None = None


def protected_aliases(fleet_path: str | Path) -> set[str]:
    fleet = load_fleet(fleet_path)
    aliases: set[str] = set()
    for host in (fleet.get("hosts") or {}).values():
        alias = host.get("ssh_alias")
        if alias:
            aliases.add(str(alias))
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
    aliases = protected_aliases(fleet_path)
    aliases.update(route_hosts(fleet_path))
    destination = None
    if tool in {"ssh", "sftp"}:
        destination = find_ssh_destination(words)
    elif tool in {"scp", "rsync"}:
        destination = find_file_transfer_destination(words)
    if destination in aliases:
        return HookDecision(
            False,
            f"raw {tool} to protected target is blocked: {destination}",
            "Use opsctl observe/logs/plan-config or an allowed ops-wrapper action.",
        )
    return HookDecision(True, "no protected pattern detected")
