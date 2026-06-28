from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .approval import approval_hint, validate_approval
from .config_patch import parse_set_expr, read_env, set_env_value, write_env
from .errors import GuardedOpsError
from .fleet import allowed_config_key, host_config, load_fleet, resolve_app_path
from .redaction import redact_value

SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


def state_root() -> Path:
    root = Path.cwd() / ".guarded_ops"
    root.mkdir(exist_ok=True)
    return root


def changes_dir() -> Path:
    path = state_root() / "changes"
    path.mkdir(parents=True, exist_ok=True)
    return path


def records_dir() -> Path:
    path = state_root() / "records"
    path.mkdir(parents=True, exist_ok=True)
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_id(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def emit(payload: dict[str, Any]) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def common_host(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    fleet = load_fleet(args.fleet)
    return fleet, host_config(fleet, args.host)


def cmd_status(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    app_path = resolve_app_path(args.fleet, host)
    config_files = sorted((host.get("config_files") or {}).keys())
    return emit(
        {
            "status": "ok",
            "host": args.host,
            "ssh_alias": host["ssh_alias"],
            "service": host["service"],
            "app_path": str(app_path),
            "app_exists": app_path.exists(),
            "config_files": config_files,
        }
    )


def cmd_observe(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    app_path = resolve_app_path(args.fleet, host)
    logs_dir = app_path / "logs"
    return emit(
        {
            "host": args.host,
            "service": host["service"],
            "app_exists": app_path.exists(),
            "logs_exists": logs_dir.exists(),
            "log_files": sorted(item.name for item in logs_dir.glob("*") if item.is_file())[:20],
        }
    )


def cmd_logs(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    app_path = resolve_app_path(args.fleet, host)
    log_path = app_path / "logs" / args.name
    if not log_path.exists():
        raise GuardedOpsError(f"log file not found: {log_path}")
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-args.lines :]
    return emit({"host": args.host, "name": args.name, "lines": lines})


def cmd_plan_config(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    try:
        key, value = parse_set_expr(args.set_expr)
    except ValueError as exc:
        raise GuardedOpsError(str(exc)) from exc
    if not allowed_config_key(host, args.file, key):
        raise GuardedOpsError(f"config key is not allowed for {args.file}: {key}")
    payload = {
        "kind": "config-change",
        "host": args.host,
        "file": args.file,
        "key": key,
        "value": value,
        "created_at": utc_now(),
    }
    change_id = stable_id(payload)
    payload["change_id"] = change_id
    display = {**payload, "value": redact_value(key, value)}
    display["approval"] = approval_hint({"host": args.host, "action": "apply-config", "change_id": change_id})
    if args.dry_run:
        display["dry_run"] = True
        display["path"] = None
        return emit(display)
    path = changes_dir() / f"{change_id}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    display["path"] = str(path)
    return emit(display)


def cmd_apply_config(args: argparse.Namespace) -> int:
    change_path = changes_dir() / f"{args.change_id}.json"
    if not change_path.exists():
        raise GuardedOpsError(f"unknown change_id: {args.change_id}")
    payload = json.loads(change_path.read_text(encoding="utf-8"))
    validate_approval(
        args.approval_token,
        {"host": payload["host"], "action": "apply-config", "change_id": payload["change_id"]},
    )
    fleet = load_fleet(args.fleet)
    host = host_config(fleet, payload["host"])
    if not allowed_config_key(host, payload["file"], payload["key"]):
        raise GuardedOpsError(f"config key is no longer allowed: {payload['key']}")
    if "\n" in payload["value"] or "\r" in payload["value"]:
        raise GuardedOpsError("config value must be a single line")
    app_path = resolve_app_path(args.fleet, host)
    target = app_path / payload["file"]
    if args.dry_run:
        return emit(
            {
                "kind": "config-apply-plan",
                "host": payload["host"],
                "change_id": payload["change_id"],
                "file": payload["file"],
                "key": payload["key"],
                "target": str(target),
                "dry_run": True,
            }
        )
    before = read_env(target)
    after = set_env_value(before, payload["key"], payload["value"])
    write_env(target, after)
    record = {
        "kind": "config-applied",
        "host": payload["host"],
        "change_id": payload["change_id"],
        "file": payload["file"],
        "key": payload["key"],
        "applied_at": utc_now(),
    }
    (records_dir() / f"config-{payload['change_id']}.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return emit(record)


def cmd_plan_deploy(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    if not SHA_RE.match(args.ref):
        raise GuardedOpsError("deploy ref must be an exact hex commit SHA, 7 to 64 characters")
    payload = {
        "kind": "deploy-plan",
        "host": args.host,
        "service": host["service"],
        "ref": args.ref,
        "approval": approval_hint({"host": args.host, "action": "deploy", "ref": args.ref}),
    }
    return emit(payload)


def cmd_deploy(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    if not SHA_RE.match(args.ref):
        raise GuardedOpsError("deploy ref must be an exact hex commit SHA, 7 to 64 characters")
    validate_approval(args.approval_token, {"host": args.host, "action": "deploy", "ref": args.ref})
    if args.dry_run:
        return emit({"kind": "deploy-apply-plan", "host": args.host, "service": host["service"], "ref": args.ref, "dry_run": True})
    record = {"kind": "deploy-record", "host": args.host, "service": host["service"], "ref": args.ref, "deployed_at": utc_now()}
    record_id = stable_id(record)
    (records_dir() / f"deploy-{record_id}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return emit({**record, "record_id": record_id})


def cmd_rollback(args: argparse.Namespace) -> int:
    validate_approval(args.approval_token, {"host": args.host, "action": "rollback", "rollback_id": args.rollback_id})
    if args.dry_run:
        return emit({"kind": "rollback-apply-plan", "host": args.host, "rollback_id": args.rollback_id, "dry_run": True})
    record = {"kind": "rollback-record", "host": args.host, "rollback_id": args.rollback_id, "rolled_back_at": utc_now()}
    (records_dir() / f"rollback-{args.rollback_id}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return emit(record)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opsctl")
    parser.add_argument("--fleet", default=str(Path("examples") / "fleet.example.json"))
    parser.add_argument("--dry-run", action="store_true", help="validate and render the action without applying side effects")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, func in {
        "status": cmd_status,
        "observe": cmd_observe,
        "logs": cmd_logs,
        "plan-config": cmd_plan_config,
        "apply-config": cmd_apply_config,
        "plan-deploy": cmd_plan_deploy,
        "deploy": cmd_deploy,
        "rollback": cmd_rollback,
    }.items():
        cmd = sub.add_parser(name)
        cmd.set_defaults(func=func)
        if name not in {"apply-config", "rollback"}:
            cmd.add_argument("--host", required=True)

    sub.choices["logs"].add_argument("--name", default="current.log")
    sub.choices["logs"].add_argument("--lines", type=int, default=80)
    sub.choices["plan-config"].add_argument("--file", required=True)
    sub.choices["plan-config"].add_argument("--set", dest="set_expr", required=True)
    sub.choices["apply-config"].add_argument("--change-id", required=True)
    sub.choices["apply-config"].add_argument("--approval-token", required=True)
    sub.choices["plan-deploy"].add_argument("--ref", required=True)
    sub.choices["deploy"].add_argument("--ref", required=True)
    sub.choices["deploy"].add_argument("--approval-token", required=True)
    sub.choices["rollback"].add_argument("--host", required=True)
    sub.choices["rollback"].add_argument("--rollback-id", required=True)
    sub.choices["rollback"].add_argument("--approval-token", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GuardedOpsError as exc:
        print(f"opsctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
