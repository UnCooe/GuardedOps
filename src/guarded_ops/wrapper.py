from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .approval import validate_approval
from .config_patch import parse_batch_set_expr, parse_set_expr, patch_config_text, read_env, set_env_value, write_env
from .errors import GuardedOpsError, PolicyError
from .policy import action_policy, load_policy
from .redaction import redact_text

TRUSTED_POLICY_PATHS = {Path("server/policy.example.json"), Path("/etc/ops-wrapper/policy.json"), Path("/etc/guardedops-demo/policy.json")}
HEX_RE = r"^[0-9a-fA-F]{7,64}$"
SAFE_REF_RE = r"^[A-Za-z0-9._/-]+$"


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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def completed_summary(command: list[str], cwd: Path | None = None) -> dict:
    completed = subprocess.run(command, cwd=cwd, check=False, text=True, capture_output=True)
    return {
        "returncode": completed.returncode,
        "stdout": redact_text(completed.stdout.strip()),
        "stderr": redact_text(completed.stderr.strip()),
    }


def resolve_exact_commit(repo: Path, ref: str) -> str:
    if not re_match(HEX_RE, ref):
        raise PolicyError("ref must be an exact hex commit SHA")
    completed = subprocess.run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise PolicyError("ref is not a commit object")
    commit = completed.stdout.strip()
    if not commit.startswith(ref.lower()):
        raise PolicyError("ref must resolve to the matching commit object id")
    return commit


def app_path(policy: dict) -> Path:
    return Path(policy["app_path"]).resolve(strict=False)


def allowed_key(settings: dict, file_name: str, key_path: str) -> bool:
    file_policy = (settings.get("allowed_files") or {}).get(file_name)
    if not isinstance(file_policy, dict):
        return False
    allowed = file_policy.get("allowed_keys") or []
    return any(key_path == item or key_path.startswith(item + ".") for item in allowed)


def require_allowed_batch(settings: dict, file_name: str, sets: list[dict], deletes: list[str]) -> None:
    keys = [item["path"] for item in sets] + deletes
    missing = [key for key in keys if not allowed_key(settings, file_name, key)]
    if missing:
        raise PolicyError("config key is not allowed: " + ", ".join(missing))


def resolve_app_relative(policy: dict, file_name: str) -> Path:
    root = app_path(policy)
    target = (root / file_name).resolve(strict=False)
    if target != root and root not in target.parents:
        raise PolicyError("path is outside app root")
    return target


def service_status(policy: dict) -> dict:
    service = policy.get("service")
    if not service:
        return {"returncode": 0, "stdout": "no service configured", "stderr": ""}
    if policy.get("service_adapter") == "mock":
        status_file = app_path(policy) / "service" / "status.txt"
        if status_file.exists():
            return {"returncode": 0, "stdout": status_file.read_text(encoding="utf-8").strip(), "stderr": ""}
        return {"returncode": 0, "stdout": "mock-service: unknown", "stderr": ""}
    supervisor = shutil.which("supervisorctl")
    if supervisor:
        return completed_summary([supervisor, "status", service])
    status_file = app_path(policy) / "service" / "status.txt"
    if status_file.exists():
        return {"returncode": 0, "stdout": status_file.read_text(encoding="utf-8").strip(), "stderr": ""}
    return {"returncode": 0, "stdout": "mock-service: unknown", "stderr": ""}


def restart_service(policy: dict, service_name: str) -> dict:
    expected = policy.get("service")
    if service_name != expected:
        raise PolicyError(f"service is not allowed: {service_name}")
    supervisor = shutil.which("supervisorctl")
    if supervisor and policy.get("service_adapter") != "mock":
        return completed_summary([supervisor, "restart", service_name])
    service_dir = app_path(policy) / "service"
    service_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now()
    (service_dir / "status.txt").write_text(f"{service_name} restarted at {stamp}\n", encoding="utf-8")
    log_dir = app_path(policy) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with (log_dir / "current.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp} {service_name} restarted\n")
    return {"returncode": 0, "stdout": f"{service_name} restarted", "stderr": ""}


def host_id(policy: dict) -> str:
    return str(policy.get("host") or policy.get("host_id") or "demo-local")


def require_approval(policy: dict, token: str | None, expected: dict) -> None:
    if not token:
        raise PolicyError("missing approval token")
    expected = {"host": host_id(policy), **expected}
    try:
        validate_approval(token, expected)
    except Exception as exc:
        raise PolicyError(str(exc)) from exc


def require_safe_ref(ref: str) -> None:
    if not re_match(SAFE_REF_RE, ref) or ".." in ref or ref.startswith("-"):
        raise PolicyError(f"unsafe git ref: {ref}")


def cmd_version(policy: dict, _args: argparse.Namespace) -> int:
    return emit(version_payload(policy))


def version_payload(policy: dict) -> dict:
    sidecar = Path(str(policy.get("version_file", "server/ops-wrapper.version.json")))
    sidecar_payload = {}
    if sidecar.exists():
        sidecar_payload = json.loads(sidecar.read_text(encoding="utf-8"))
    return {
        "wrapper": "ops-wrapper",
        "version": sidecar_payload.get("wrapper_version", __version__),
        "source_revision": sidecar_payload.get("source_revision", "example"),
        "policy_version": policy.get("policy_version", sidecar_payload.get("policy_version", "unknown")),
        "wrapper_sha256": sha256_file(Path(__file__).resolve()),
    }


def cmd_host_observe(policy: dict, _args: argparse.Namespace) -> int:
    action_policy(policy, "host-observe")
    root = app_path(policy)
    payload = {
        "hostname": os.uname().nodename,
        "service": policy.get("service"),
        "app_path": str(root),
        "app_exists": root.exists(),
        "service_status": service_status(policy),
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
    root = app_path(policy)
    files = sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()) if root.exists() else []
    git_head = completed_summary(["git", "rev-parse", "HEAD"], cwd=root) if root.exists() else {"returncode": 1}
    git_status = completed_summary(["git", "status", "--short", "--branch", "--untracked-files=no"], cwd=root) if root.exists() else {"returncode": 1}
    audit(policy, "runtime-baseline", {"file_count": len(files)})
    return emit(
        {
            "app_path": str(root),
            "audit_log": policy.get("audit_log"),
            "file_count": len(files),
            "files": files[:50],
            "git": {"head": git_head, "status": git_status},
            "service_status": service_status(policy),
            "version": version_payload(policy),
        }
    )


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
    raise PolicyError("config-patch write is disabled; use apply-config-batch with approval")


def cmd_plan_config_batch(policy: dict, args: argparse.Namespace) -> int:
    settings = action_policy(policy, "config-patch")
    sets = [parse_batch_set_expr(expr) for expr in args.set_exprs]
    deletes = args.deletes
    if not sets and not deletes:
        raise PolicyError("empty config batch")
    require_allowed_batch(settings, args.file, sets, deletes)
    target = resolve_app_relative(policy, args.file)
    old_text = target.read_text(encoding="utf-8") if target.exists() else "{}\n"
    try:
        new_text, changed = patch_config_text(args.file, old_text, sets, deletes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise PolicyError(str(exc)) from exc
    diff = [redact_text(line) for line in difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), fromfile=args.file + ":current", tofile=args.file + ":planned", lineterm="")]
    change_id = hashlib.sha256(json.dumps({"file": args.file, "sets": sets, "deletes": deletes}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    audit(policy, "plan-config-batch", {"file": args.file, "changed": sorted(changed), "change_id": change_id})
    return emit({"action": "plan-config-batch", "file": args.file, "change_id": change_id, "changed": sorted(changed), "diff": diff[:200]})


def cmd_apply_config_batch(policy: dict, args: argparse.Namespace) -> int:
    settings = action_policy(policy, "config-patch")
    sets = [parse_batch_set_expr(expr) for expr in args.set_exprs]
    deletes = args.deletes
    expected = hashlib.sha256(json.dumps({"file": args.file, "sets": sets, "deletes": deletes}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    if args.change_id != expected:
        raise PolicyError("change_id does not match config batch")
    require_approval(policy, args.approval_token, {"action": "apply-config-batch", "change_id": args.change_id})
    require_allowed_batch(settings, args.file, sets, deletes)
    target = resolve_app_relative(policy, args.file)
    old_text = target.read_text(encoding="utf-8") if target.exists() else "{}\n"
    try:
        new_text, changed = patch_config_text(args.file, old_text, sets, deletes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise PolicyError(str(exc)) from exc
    backup_dir = Path(policy.get("backup_dir") or ".guarded_ops/backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{target.name}.{utc_now().replace(':', '').replace('+00:00', 'Z')}.{hashlib.sha256(old_text.encode()).hexdigest()[:12]}.bak"
    if target.exists():
        shutil.copy2(target, backup_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(new_text, encoding="utf-8")
    audit(policy, "apply-config-batch", {"file": args.file, "changed": sorted(changed), "change_id": args.change_id, "backup": str(backup_path)})
    return emit({"action": "apply-config-batch", "file": args.file, "change_id": args.change_id, "changed": sorted(changed), "backup": str(backup_path), "applied": True})


def cmd_safe_git(policy: dict, args: argparse.Namespace) -> int:
    settings = action_policy(policy, "safe-git")
    allowed_ops = set(settings.get("allowed_ops", []))
    if args.op not in allowed_ops:
        raise PolicyError(f"git op is not allowed: {args.op}")
    repo = app_path(policy)
    command = ["git", "-C", str(repo)]
    if args.op == "status":
        command.extend(["status", "--short", "--branch", "--untracked-files=no"])
    elif args.op == "rev-parse":
        ref = args.ref or "HEAD"
        require_safe_ref(ref)
        command.extend(["rev-parse", ref])
    elif args.op == "log":
        ref = args.ref or "HEAD"
        require_safe_ref(ref)
        command.extend(["log", "--oneline", "-n", str(args.limit), ref])
    elif args.op == "fetch":
        if args.remote != "origin":
            raise PolicyError("safe-git fetch only allows remote origin")
        require_approval(policy, args.approval_token, {"action": "safe-git-fetch", "remote": args.remote})
        command.extend(["fetch", "origin"])
    elif args.op == "checkout":
        if not args.ref:
            raise PolicyError("safe-git checkout requires --ref")
        commit = resolve_exact_commit(repo, args.ref)
        require_approval(policy, args.approval_token, {"action": "safe-git-checkout", "ref": args.ref})
        command.extend(["checkout", "--detach", commit])
    else:
        raise PolicyError(f"git op is not allowed: {args.op}")
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    audit(policy, "safe-git", {"op": args.op, "returncode": completed.returncode})
    return emit({"op": args.op, "returncode": completed.returncode, "stdout": redact_text(completed.stdout), "stderr": redact_text(completed.stderr)})


def re_match(pattern: str, value: str) -> bool:
    import re

    return bool(re.match(pattern, value))


def cmd_deploy_ref(policy: dict, args: argparse.Namespace) -> int:
    action_policy(policy, "deploy-ref")
    repo = app_path(policy)
    commit = resolve_exact_commit(repo, args.ref)
    require_approval(policy, args.approval_token, {"action": "deploy", "ref": args.ref})
    before = completed_summary(["git", "rev-parse", "HEAD"], cwd=repo)
    checkout = completed_summary(["git", "checkout", "--detach", commit], cwd=repo)
    after = completed_summary(["git", "rev-parse", "HEAD"], cwd=repo)
    audit(policy, "deploy-ref", {"ref": args.ref, "returncode": checkout["returncode"]})
    return emit({"action": "deploy-ref", "ref": args.ref, "before": before, "checkout": checkout, "after": after})


def cmd_restart_service(policy: dict, args: argparse.Namespace) -> int:
    action_policy(policy, "restart-service")
    require_approval(policy, args.approval_token, {"action": "restart-service", "service": args.service_name})
    result = restart_service(policy, args.service_name)
    audit(policy, "restart-service", {"service": args.service_name, "returncode": result["returncode"]})
    return emit({"action": "restart-service", "service": args.service_name, **result})


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
    config_batch = sub.add_parser("plan-config-batch")
    config_batch.add_argument("--file", required=True)
    config_batch.add_argument("--set", dest="set_exprs", action="append", default=[])
    config_batch.add_argument("--delete", dest="deletes", action="append", default=[])
    config_batch.set_defaults(func=cmd_plan_config_batch)
    apply_batch = sub.add_parser("apply-config-batch")
    apply_batch.add_argument("--change-id", required=True)
    apply_batch.add_argument("--approval-token", required=True)
    apply_batch.add_argument("--file", required=True)
    apply_batch.add_argument("--set", dest="set_exprs", action="append", default=[])
    apply_batch.add_argument("--delete", dest="deletes", action="append", default=[])
    apply_batch.set_defaults(func=cmd_apply_config_batch)
    git = sub.add_parser("safe-git")
    git.add_argument("--op", required=True, choices=["status", "rev-parse", "log", "fetch", "checkout"])
    git.add_argument("--ref")
    git.add_argument("--remote", default="origin")
    git.add_argument("--limit", type=int, default=5)
    git.add_argument("--approval-token")
    git.set_defaults(func=cmd_safe_git)
    deploy = sub.add_parser("deploy-ref")
    deploy.add_argument("--ref", required=True)
    deploy.add_argument("--approval-token", required=True)
    deploy.set_defaults(func=cmd_deploy_ref)
    restart = sub.add_parser("restart-service")
    restart.add_argument("--service-name", required=True)
    restart.add_argument("--approval-token", required=True)
    restart.set_defaults(func=cmd_restart_service)
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
