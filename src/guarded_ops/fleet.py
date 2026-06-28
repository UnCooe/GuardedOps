from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import FleetError


def default_fleet_path() -> Path:
    return Path.cwd() / "examples" / "fleet.example.json"


def load_fleet(path: str | Path | None = None) -> dict[str, Any]:
    fleet_path = Path(path) if path else default_fleet_path()
    try:
        data = json.loads(fleet_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FleetError(f"{fleet_path} must be JSON in GuardedOps v0.1: {exc}") from exc
    if not isinstance(data, dict):
        raise FleetError("fleet must be a JSON object")
    hosts = data.get("hosts")
    if not isinstance(hosts, dict) or not hosts:
        raise FleetError("fleet must contain a non-empty hosts object")
    return data


def host_config(fleet: dict[str, Any], host: str) -> dict[str, Any]:
    hosts = fleet.get("hosts") or {}
    if host not in hosts:
        known = ", ".join(sorted(hosts)) or "<none>"
        raise FleetError(f"unknown host {host}; known hosts: {known}")
    config = hosts[host]
    if not isinstance(config, dict):
        raise FleetError(f"host {host} must be an object")
    required = ["ssh_alias", "app_path", "service", "server_wrapper", "policy_path"]
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise FleetError(f"host {host} missing required keys: {', '.join(missing)}")
    return config


def resolve_app_path(fleet_path: str | Path | None, host: dict[str, Any]) -> Path:
    app_path = Path(str(host["app_path"]))
    if app_path.is_absolute():
        return app_path
    base = Path(fleet_path).resolve().parent if fleet_path else default_fleet_path().resolve().parent
    return (base / app_path).resolve()


def allowed_config_key(host: dict[str, Any], file_name: str, key_path: str) -> bool:
    config_files = host.get("config_files") or {}
    file_policy = config_files.get(file_name)
    if not isinstance(file_policy, dict):
        return False
    allowed = file_policy.get("allowed_keys") or []
    return any(key_path == item or key_path.startswith(item + ".") for item in allowed)


def disallowed_config_keys(host: dict[str, Any], file_name: str, key_paths: list[str]) -> list[str]:
    return [key_path for key_path in key_paths if not allowed_config_key(host, file_name, key_path)]

