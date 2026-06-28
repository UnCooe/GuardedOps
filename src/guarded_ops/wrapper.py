from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config_patch import parse_set_expr, read_env, set_env_value, write_env
from .errors import GuardedOpsError, PolicyError
from .policy import action_policy, load_policy
from .redaction import redact_text

TRUSTED_POLICY_PATHS = {Path("server/policy.example.json"), Path("/etc/ops-wrapper/policy.json")}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def emit(payload: dict) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def audit(policy: dict, action: str, payload: dict) -> None:
    audit_path = policy.get("audit_log")
    if not audit_path:
        return
    path = Path(audit_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {"time": utc_now(), "action": action, **payload}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def cmd_version(policy: dict, _args: argparse.Namespace) -> int:
    sidecar = Path(str(policy.get("version_file", "server/ops-wrapper.version.json")))
    sidecar_payload = {}
    if sidecar.exists():
        sidecar_payload = json.loads(sidecar.read_text(encoding="utf-8"))
    return emit(
        {
            "wrapper": "ops-wrapper",
            "version": sidecar_payload.get("wrapper_version", __version__),
            "source_revision": sidecar_payload.get("source_revision", "example"),
            "policy_version": policy.get("policy_version", sidecar_payload.get("policy_version", "unknown")),
        }
    )


def cmd_host_observe(policy: dict, _args: argparse.Namespace) -> int:
    action_policy(policy, "host-observe")
    app_path = Path(policy["app_path"])
    payload = {
        "hostname": os.uname().nodename,
        "service": policy.get("service"),
        "app_path": str(app_path),
        "app_exists": app_path.exists(),
    }
    audit(policy, "host-observe", {"result": "ok"})
    return emit(payload)


def cmd_log_query(policy: dict, args: argparse.Namespace) -> int:
    settings = action_policy(policy, "log-query")
    max_lines = int(settings.get("max_lines", 200))
    lines = min(args.lines, max_lines)
    roots = [Path(item).resolve() for item in settings.get("roots", [])]
    target = Path(args.path).resolve()
    if not any(target == root or root in target.parents for root in roots):
        raise PolicyError("log path is outside allowed roots")
    if not target.exists():
        raise PolicyError(f"log path not found: {target}")
    output = "\n".join(target.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    audit(policy, "log-query", {"path": str(target), "lines": lines})
    return emit({"path": str(target), "output": redact_text(output)})


def cmd_runtime_baseline(policy: dict, _args: argparse.Namespace) -> int:
    action_policy(policy, "runtime-baseline")
    app_path = Path(policy["app_path"])
    files = sorted(str(path.relative_to(app_path)) for path in app_path.rglob("*") if path.is_file()) if app_path.exists() else []
    audit(policy, "runtime-baseline", {"file_count": len(files)})
    return emit({"app_path": str(app_path), "file_count": len(files), "files": files[:50]})


def cmd_config_patch(policy: dict, args: argparse.Namespace) -> int:
    settings = action_policy(policy, "config-patch")
    try:
        key, value = parse_set_expr(args.set_expr)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    allowed = settings.get("allowed_files", {})
    file_policy = allowed.get(args.file)
    if not isinstance(file_policy, dict):
        raise PolicyError(f"config file is not allowed: {args.file}")
    allowed_keys = file_policy.get("allowed_keys", [])
    if key not in allowed_keys:
        raise PolicyError(f"config key is not allowed: {key}")
    target = Path(policy["app_path"]) / args.file
    if args.dry_run:
        audit(policy, "config-patch", {"file": args.file, "key": key, "dry_run": True})
        return emit({"action": "config-patch", "file": args.file, "key": key, "target": str(target), "dry_run": True})
    lines = read_env(target)
    write_env(target, set_env_value(lines, key, value))
    audit(policy, "config-patch", {"file": args.file, "key": key, "dry_run": False})
    return emit({"action": "config-patch", "file": args.file, "key": key, "target": str(target), "applied": True})


def cmd_safe_git(policy: dict, args: argparse.Namespace) -> int:
    settings = action_policy(policy, "safe-git")
    allowed_ops = set(settings.get("allowed_ops", []))
    if args.op not in allowed_ops:
        raise PolicyError(f"git op is not allowed: {args.op}")
    repo = Path(policy["app_path"])
    command = ["git", "-C", str(repo), args.op]
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    audit(policy, "safe-git", {"op": args.op, "returncode": completed.returncode})
    return emit({"op": args.op, "returncode": completed.returncode, "stdout": redact_text(completed.stdout), "stderr": redact_text(completed.stderr)})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ops-wrapper")
    parser.add_argument("--policy", default="server/policy.example.json")
    parser.add_argument(
        "--allow-untrusted-policy",
        action="store_true",
        help="allow non-default policy paths for local tests; do not use with sudo/root",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("version").set_defaults(func=cmd_version)
    sub.add_parser("host-observe").set_defaults(func=cmd_host_observe)
    log = sub.add_parser("log-query")
    log.add_argument("--path", required=True)
    log.add_argument("--lines", type=int, default=80)
    log.set_defaults(func=cmd_log_query)
    sub.add_parser("runtime-baseline").set_defaults(func=cmd_runtime_baseline)
    config = sub.add_parser("config-patch")
    config.add_argument("--file", required=True)
    config.add_argument("--set", dest="set_expr", required=True)
    config.add_argument("--dry-run", action="store_true")
    config.set_defaults(func=cmd_config_patch)
    git = sub.add_parser("safe-git")
    git.add_argument("--op", required=True, choices=["status", "rev-parse"])
    git.set_defaults(func=cmd_safe_git)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        policy_path = Path(args.policy)
        if policy_path not in TRUSTED_POLICY_PATHS and not args.allow_untrusted_policy:
            raise PolicyError(
                "refusing untrusted policy path "
                f"{policy_path}; use one of {', '.join(str(item) for item in sorted(TRUSTED_POLICY_PATHS, key=str))} "
                "or pass --allow-untrusted-policy for local tests"
            )
        policy = load_policy(args.policy)
        return args.func(policy, args)
    except (GuardedOpsError, OSError) as exc:
        print(f"ops-wrapper: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
