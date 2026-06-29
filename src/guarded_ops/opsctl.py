from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .approval import approval_hint, validate_approval
from .config_patch import parse_batch_set_expr, parse_set_expr, read_env, set_env_value, write_env
from .errors import GuardedOpsError
from .fleet import allowed_config_key, host_config, load_fleet, resolve_app_path
from .redaction import redact_value

SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
SAFE_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


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


def demo_root() -> Path:
    path = state_root() / "demo-local"
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


def run_json(command: list[str], dry_run: bool = False) -> int:
    if dry_run:
        return emit({"kind": "remote-command", "command": command, "dry_run": True})
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    return completed.returncode


def wrapper_command(host: dict[str, Any], action: str, args: list[str] | None = None) -> list[str]:
    action_args = args or []
    base = [
        host["server_wrapper"],
        "--policy",
        host["policy_path"],
    ]
    if host.get("allow_untrusted_policy"):
        base.append("--allow-untrusted-policy")
    transport = host.get("transport", "local")
    if transport == "local":
        return [sys.executable, *base, action, *action_args]
    if transport == "ssh":
        remote = [*base, action, *action_args]
        prefix = []
        if host.get("become") == "sudo":
            prefix.append("sudo")
        remote_text = " ".join(shlex.quote(str(part)) for part in [*prefix, *remote])
        return ["ssh", host["ssh_alias"], "--", remote_text]
    raise GuardedOpsError(f"unsupported transport: {transport}")


def run_wrapper(args: argparse.Namespace, host: dict[str, Any], action: str, action_args: list[str] | None = None) -> int:
    return run_json(wrapper_command(host, action, action_args), dry_run=args.dry_run)


def run_checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=cwd, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise GuardedOpsError(f"{' '.join(command)} failed: {completed.stderr.strip() or completed.stdout.strip()}")
    return completed


def ensure_demo_local_workspace(force: bool = False) -> dict[str, str]:
    root = demo_root()
    app = root / "app"
    origin = root / "origin.git"
    fixture = Path("examples/demo-remote/app")
    if not fixture.exists():
        raise GuardedOpsError("demo fixture not found: examples/demo-remote/app")
    if force:
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True, exist_ok=True)
    if app.exists() and origin.exists():
        head = run_checked(["git", "rev-parse", "HEAD"], app).stdout.strip()
        return {"app_path": str(app), "origin_path": str(origin), "head": head, "created": "false"}
    if app.exists() or origin.exists():
        raise GuardedOpsError("partial demo-local workspace exists; rerun init-demo --force to rebuild it")
    shutil.copytree(fixture, app, ignore=shutil.ignore_patterns(".git", "service"))
    run_checked(["git", "init"], app)
    run_checked(["git", "config", "user.email", "guardedops-demo@example.com"], app)
    run_checked(["git", "config", "user.name", "GuardedOps Demo"], app)
    run_checked(["git", "add", "."], app)
    run_checked(["git", "commit", "-m", "initial demo app"], app)
    run_checked(["git", "init", "--bare", str(origin)], root)
    run_checked(["git", "remote", "add", "origin", str(origin)], app)
    run_checked(["git", "push", "origin", "HEAD:main"], app)
    head = run_checked(["git", "rev-parse", "HEAD"], app).stdout.strip()
    return {"app_path": str(app), "origin_path": str(origin), "head": head, "created": "true"}


def materialize_demo_local_policy(host: dict[str, Any], workspace: dict[str, str]) -> str:
    source = Path(host["policy_path"])
    policy = json.loads(source.read_text(encoding="utf-8"))
    app = Path(workspace["app_path"])
    policy["app_path"] = str(app)
    policy["audit_log"] = str(demo_root() / "audit.jsonl")
    policy["backup_dir"] = str(demo_root() / "backups")
    log_action = (policy.get("actions") or {}).get("log-query")
    if isinstance(log_action, dict):
        log_action["roots"] = [str(app / "logs")]
    generated = demo_root() / "policy.json"
    generated.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(generated)


def batch_change_payload(host_key: str, file_name: str, sets: list[dict[str, Any]], deletes: list[str]) -> dict[str, Any]:
    material = {"file": file_name, "sets": sets, "deletes": deletes}
    change_id = stable_id(material)
    return {
        "kind": "config-batch-change",
        "host": host_key,
        "file": file_name,
        "sets": sets,
        "deletes": deletes,
        "change_id": change_id,
        "created_at": utc_now(),
    }


def batch_args(payload: dict[str, Any]) -> list[str]:
    rendered = ["--file", payload["file"]]
    for item in payload["sets"]:
        rendered.extend(["--set", f"{item['path']}={json.dumps(item['value'], separators=(',', ':'))}"])
    for item in payload["deletes"]:
        rendered.extend(["--delete", item])
    return rendered


def redacted_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        **payload,
        "sets": [{"path": item["path"], "value": redact_value(item["path"], item["value"])} for item in payload["sets"]],
    }


def common_host(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    fleet = load_fleet(args.fleet)
    host = host_config(fleet, args.host)
    return fleet, prepare_local_demo_host(host)


def prepare_local_demo_host(host: dict[str, Any]) -> dict[str, Any]:
    if host.get("transport") == "local" and host.get("demo_fixture"):
        workspace = ensure_demo_local_workspace()
        host = {**host, "app_path": workspace["app_path"], "policy_path": materialize_demo_local_policy(host, workspace)}
    return host


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


def cmd_init_demo(args: argparse.Namespace) -> int:
    workspace = ensure_demo_local_workspace(force=args.force)
    return emit({"kind": "demo-local-workspace", **workspace})


def cmd_observe(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    if host.get("transport"):
        return run_wrapper(args, host, "host-observe")
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
    if host.get("transport"):
        log_path = str(Path(host["app_path"]) / "logs" / args.name)
        return run_wrapper(args, host, "log-query", ["--path", log_path, "--lines", str(args.lines)])
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
    if host.get("transport"):
        return run_wrapper(args, host, "deploy-ref", ["--ref", args.ref, "--approval-token", args.approval_token])
    if args.dry_run:
        return emit({"kind": "deploy-apply-plan", "host": args.host, "service": host["service"], "ref": args.ref, "dry_run": True})
    record = {"kind": "deploy-record", "host": args.host, "service": host["service"], "ref": args.ref, "deployed_at": utc_now()}
    record_id = stable_id(record)
    (records_dir() / f"deploy-{record_id}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return emit({**record, "record_id": record_id})


def cmd_version(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    return run_wrapper(args, host, "version")


def cmd_baseline(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    return run_wrapper(args, host, "runtime-baseline")


def cmd_git(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    op = args.op
    rendered = ["--op", op]
    if op == "fetch":
        validate_approval(args.approval_token or "", {"host": args.host, "action": "safe-git-fetch", "remote": args.remote})
        rendered.extend(["--remote", args.remote, "--approval-token", args.approval_token or ""])
    elif op == "checkout":
        if not args.ref or not SHA_RE.match(args.ref):
            raise GuardedOpsError("safe-git checkout requires an exact hex ref")
        validate_approval(args.approval_token or "", {"host": args.host, "action": "safe-git-checkout", "ref": args.ref})
        rendered.extend(["--ref", args.ref, "--approval-token", args.approval_token or ""])
    else:
        if args.ref:
            if not SAFE_REF_RE.match(args.ref) or ".." in args.ref or args.ref.startswith("-"):
                raise GuardedOpsError(f"unsafe git ref: {args.ref}")
            rendered.extend(["--ref", args.ref])
    if args.limit is not None:
        rendered.extend(["--limit", str(args.limit)])
    return run_wrapper(args, host, "safe-git", rendered)


def cmd_restart_service(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    service = args.service or host["service"]
    if service != host["service"]:
        raise GuardedOpsError(f"service is not allowed for host {args.host}: {service}")
    validate_approval(args.approval_token, {"host": args.host, "action": "restart-service", "service": service})
    return run_wrapper(args, host, "restart-service", ["--service-name", service, "--approval-token", args.approval_token])


def cmd_plan_config_batch(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    try:
        sets = [parse_batch_set_expr(expr) for expr in args.set_exprs]
    except ValueError as exc:
        raise GuardedOpsError(str(exc)) from exc
    deletes = args.deletes
    if not sets and not deletes:
        raise GuardedOpsError("empty config batch")
    for key in [item["path"] for item in sets] + deletes:
        if not allowed_config_key(host, args.file, key):
            raise GuardedOpsError(f"config key is not allowed for {args.file}: {key}")
    payload = batch_change_payload(args.host, args.file, sets, deletes)
    if not args.dry_run:
        (changes_dir() / f"{payload['change_id']}.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    display = redacted_batch_payload(payload)
    preview_cmd = wrapper_command(host, "plan-config-batch", batch_args(display))
    return emit({**display, "approval": approval_hint({"host": args.host, "action": "apply-config-batch", "change_id": payload["change_id"]}), "remote_command": preview_cmd, "path": None if args.dry_run else str(changes_dir() / f"{payload['change_id']}.json")})


def cmd_apply_config_batch(args: argparse.Namespace) -> int:
    change_path = changes_dir() / f"{args.change_id}.json"
    if not change_path.exists():
        raise GuardedOpsError(f"unknown change_id: {args.change_id}")
    payload = json.loads(change_path.read_text(encoding="utf-8"))
    validate_approval(args.approval_token, {"host": payload["host"], "action": "apply-config-batch", "change_id": payload["change_id"]})
    fleet = load_fleet(args.fleet)
    host = prepare_local_demo_host(host_config(fleet, payload["host"]))
    for key in [item["path"] for item in payload["sets"]] + payload["deletes"]:
        if not allowed_config_key(host, payload["file"], key):
            raise GuardedOpsError(f"config key is no longer allowed: {key}")
    return run_wrapper(args, host, "apply-config-batch", ["--change-id", payload["change_id"], "--approval-token", args.approval_token, *batch_args(payload)])


def cmd_install_wrapper(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    runtime_source = Path(args.runtime_source)
    if not runtime_source.exists():
        candidate = Path(args.wrapper_source).resolve().parents[1] / "src" / "guarded_ops"
        runtime_source = candidate if candidate.exists() else Path(__file__).resolve().parent
    policy_source = Path(host.get("policy_source") or args.policy_source)
    policy_data = json.loads(policy_source.read_text(encoding="utf-8"))
    policy_data["host"] = args.host
    policy_data["app_path"] = host["app_path"]
    policy_data["service"] = host["service"]
    if "audit_log" not in policy_data:
        policy_data["audit_log"] = str(Path(host["policy_path"]).parent / "audit.jsonl")
    if "backup_dir" not in policy_data:
        policy_data["backup_dir"] = str(Path(host["policy_path"]).parent / "backups")
    log_action = (policy_data.get("actions") or {}).get("log-query")
    if isinstance(log_action, dict) and host.get("transport") == "ssh":
        log_action["roots"] = [str(Path(host["app_path"]) / "logs")]
    generated_policy = state_root() / "install" / f"{args.host}-policy.json"
    generated_policy.parent.mkdir(parents=True, exist_ok=True)
    generated_policy.write_text(json.dumps(policy_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if host.get("transport") == "ssh":
        wrapper_path = host["server_wrapper"]
        policy_path = host["policy_path"]
        runtime_dir = str(Path(policy_path).parent / "src")
        commands = [
            ["ssh", host["ssh_alias"], "--", "mkdir", "-p", str(Path(policy_path).parent), runtime_dir],
            ["scp", args.wrapper_source, f"{host['ssh_alias']}:{wrapper_path}"],
            ["scp", str(generated_policy), f"{host['ssh_alias']}:{policy_path}"],
            ["scp", "-r", str(runtime_source), f"{host['ssh_alias']}:{runtime_dir}/"],
        ]
        if args.dry_run:
            return emit({"kind": "install-wrapper-plan", "host": args.host, "commands": commands, "wrapper": wrapper_path, "policy": policy_path, "runtime_dir": runtime_dir, "generated_policy": str(generated_policy), "dry_run": True})
        for command in commands:
            rc = run_json(command)
            if rc != 0:
                return rc
        return emit({"kind": "install-wrapper", "host": args.host, "wrapper": wrapper_path, "policy": policy_path, "runtime_dir": runtime_dir, "generated_policy": str(generated_policy), "installed": True})
    wrapper_target = Path(host["server_wrapper"])
    policy_target = Path(host["policy_path"])
    runtime_target = policy_target.parent / "src" / "guarded_ops"
    if args.dry_run:
        return emit({"kind": "install-wrapper-plan", "host": args.host, "wrapper": str(wrapper_target), "policy": str(policy_target), "dry_run": True})
    wrapper_target.parent.mkdir(parents=True, exist_ok=True)
    policy_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.wrapper_source, wrapper_target)
    shutil.copy2(generated_policy, policy_target)
    if runtime_target.exists():
        shutil.rmtree(runtime_target)
    shutil.copytree(runtime_source, runtime_target)
    return emit({"kind": "install-wrapper", "host": args.host, "wrapper": str(wrapper_target), "policy": str(policy_target), "runtime_dir": str(runtime_target.parent), "generated_policy": str(generated_policy), "installed": True})


def cmd_init_ssh_demo(args: argparse.Namespace) -> int:
    _, host = common_host(args)
    if not args.reset:
        raise GuardedOpsError("init-ssh-demo requires --reset")
    if host.get("transport") != "ssh":
        raise GuardedOpsError("init-ssh-demo requires an ssh transport host")
    app_path = Path(str(host["app_path"]))
    sandbox_root = Path("/opt/guardedops-demo")
    if app_path != sandbox_root / "app":
        raise GuardedOpsError("init-ssh-demo only supports app_path /opt/guardedops-demo/app")
    backup_dir = Path("/var/backups/guardedops-demo")
    audit_dir = Path("/var/log/guardedops-demo")
    fixture = Path(host.get("demo_fixture") or "examples/demo-remote/app")
    if not fixture.exists():
        raise GuardedOpsError(f"demo fixture not found: {fixture}")
    tar_path = state_root() / "install" / "demo-app.tar.gz"
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "w:gz") as archive:
        for item in sorted(fixture.rglob("*")):
            if ".git" in item.parts:
                continue
            archive.add(item, arcname=str(item.relative_to(fixture)))
    init_script = (
        "set -eu; "
        f"cd {shlex.quote(str(app_path))}; "
        "git init -b main >/dev/null; "
        "git config user.email guardedops-demo@example.com; "
        "git config user.name 'GuardedOps Demo'; "
        "git add .; "
        "git commit -m 'initial demo app' >/dev/null; "
        f"git init --bare {shlex.quote(str(sandbox_root / 'origin.git'))} >/dev/null; "
        f"git remote add origin {shlex.quote(str(sandbox_root / 'origin.git'))}; "
        "GIT_TERMINAL_PROMPT=0 git push origin HEAD:main >/dev/null"
    )
    commands = [
        ["ssh", host["ssh_alias"], "--", "rm", "-rf", str(app_path), str(sandbox_root / "origin.git")],
        ["ssh", host["ssh_alias"], "--", "mkdir", "-p", str(app_path), str(audit_dir), str(backup_dir)],
        ["sh", "-lc", f"cat {shlex.quote(str(tar_path))} | ssh {shlex.quote(host['ssh_alias'])} -- tar -xzf - -C {shlex.quote(str(app_path))}"],
        ["ssh", host["ssh_alias"], "--", "sh", "-lc", init_script],
    ]
    if args.dry_run:
        return emit({"kind": "init-ssh-demo-plan", "host": args.host, "commands": commands, "tar": str(tar_path), "app": str(app_path), "origin": str(sandbox_root / "origin.git"), "audit_dir": str(audit_dir), "backup_dir": str(backup_dir), "dry_run": True})
    for command in commands:
        rc = run_json(command)
        if rc != 0:
            return rc
    head = subprocess.run(["ssh", host["ssh_alias"], "--", "git", "-C", str(app_path), "rev-parse", "HEAD"], check=False, text=True, capture_output=True)
    return emit({"kind": "init-ssh-demo", "host": args.host, "app": str(app_path), "origin": str(sandbox_root / "origin.git"), "audit_dir": str(audit_dir), "backup_dir": str(backup_dir), "head": head.stdout.strip(), "initialized": True})


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

    hostless_commands = {"apply-config", "apply-config-batch", "rollback", "init-demo"}
    for name, func in {
        "status": cmd_status,
        "init-demo": cmd_init_demo,
        "observe": cmd_observe,
        "logs": cmd_logs,
        "version": cmd_version,
        "baseline": cmd_baseline,
        "git": cmd_git,
        "plan-config": cmd_plan_config,
        "apply-config": cmd_apply_config,
        "plan-config-batch": cmd_plan_config_batch,
        "apply-config-batch": cmd_apply_config_batch,
        "plan-deploy": cmd_plan_deploy,
        "deploy": cmd_deploy,
        "restart-service": cmd_restart_service,
        "install-wrapper": cmd_install_wrapper,
        "init-ssh-demo": cmd_init_ssh_demo,
        "rollback": cmd_rollback,
    }.items():
        cmd = sub.add_parser(name)
        cmd.set_defaults(func=func)
        if name not in hostless_commands:
            cmd.add_argument("--host", required=True)

    sub.choices["init-demo"].add_argument("--host", default="demo-local")
    sub.choices["init-demo"].add_argument("--force", action="store_true")
    sub.choices["logs"].add_argument("--name", default="current.log")
    sub.choices["logs"].add_argument("--lines", type=int, default=80)
    sub.choices["plan-config"].add_argument("--file", required=True)
    sub.choices["plan-config"].add_argument("--set", dest="set_expr", required=True)
    sub.choices["apply-config"].add_argument("--change-id", required=True)
    sub.choices["apply-config"].add_argument("--approval-token", required=True)
    sub.choices["git"].add_argument("--op", required=True, choices=["status", "rev-parse", "log", "fetch", "checkout"])
    sub.choices["git"].add_argument("--ref")
    sub.choices["git"].add_argument("--remote", default="origin")
    sub.choices["git"].add_argument("--limit", type=int, default=5)
    sub.choices["git"].add_argument("--approval-token")
    sub.choices["plan-config-batch"].add_argument("--file", required=True)
    sub.choices["plan-config-batch"].add_argument("--set", dest="set_exprs", action="append", default=[])
    sub.choices["plan-config-batch"].add_argument("--delete", dest="deletes", action="append", default=[])
    sub.choices["apply-config-batch"].add_argument("--change-id", required=True)
    sub.choices["apply-config-batch"].add_argument("--approval-token", required=True)
    sub.choices["plan-deploy"].add_argument("--ref", required=True)
    sub.choices["deploy"].add_argument("--ref", required=True)
    sub.choices["deploy"].add_argument("--approval-token", required=True)
    sub.choices["restart-service"].add_argument("--service")
    sub.choices["restart-service"].add_argument("--approval-token", required=True)
    sub.choices["install-wrapper"].add_argument("--wrapper-source", default="server/ops-wrapper")
    sub.choices["install-wrapper"].add_argument("--policy-source", default="server/policy.example.json")
    sub.choices["install-wrapper"].add_argument("--runtime-source", default="src/guarded_ops")
    sub.choices["install-wrapper"].add_argument("--target-dir")
    sub.choices["init-ssh-demo"].add_argument("--reset", action="store_true")
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
