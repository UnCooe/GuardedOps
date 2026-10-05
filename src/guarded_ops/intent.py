from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .audit import IDENTIFIER_RE, parse_rfc3339, utc_now
from .errors import AuditWriteError, GuardedOpsError
from .redaction import key_is_secret, redact_text, redact_value

INTENT_SCHEMA_VERSION = "guardedops.intent/v1"
INTENT_FIELDS = {
    "schema_version",
    "operation_id",
    "run_id",
    "ts",
    "host",
    "action",
    "operation_kind",
    "status",
    "transport",
    "command",
    "details",
}

DETAIL_ALLOWLIST = {
    "apply-config-batch": {"change_id", "file"},
    "deploy-ref": {"ref"},
    "install-wrapper": {"backup_id", "policy", "runtime_dir", "wrapper"},
    "restart-service": {"service"},
    "safe-git": {"op", "remote", "ref"},
}


def default_intent_log() -> Path:
    return Path.cwd() / ".guarded_ops" / "intent.jsonl"


def sanitize_command(command: list[str]) -> list[str]:
    safe: list[str] = []
    redact_next = False
    value_flags = {
        "--approval-token",
        "--token",
        "--secret",
        "--password",
        "--api-key",
        "--authorization",
        "--cookie",
        "--set",
    }
    for part in command:
        rendered = str(part)
        if redact_next:
            safe.append("<redacted>")
            redact_next = False
            continue
        lower_part = rendered.lower()
        equals_flag = next((flag for flag in value_flags if lower_part.startswith(flag + "=")), None)
        if equals_flag:
            safe.append(f"{rendered.split('=', 1)[0]}=<redacted>")
            continue
        safe.append(redact_text(rendered))
        if lower_part in value_flags:
            redact_next = True
    return safe


def sanitize_details(action: str, details: dict[str, Any]) -> dict[str, Any]:
    allowed = DETAIL_ALLOWLIST.get(action, set())
    safe: dict[str, Any] = {}
    for key, value in details.items():
        if key not in allowed or key_is_secret(str(key)):
            continue
        if isinstance(value, str):
            safe[key] = redact_text(value)
        elif isinstance(value, bool) or isinstance(value, int) or value is None:
            safe[key] = value
        else:
            safe[key] = redact_value(str(key), value)
    return safe


def intent_payload(
    *,
    operation_id: str,
    run_id: str,
    host: str,
    action: str,
    operation_kind: str,
    transport: str,
    command: list[str],
    details: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "schema_version": INTENT_SCHEMA_VERSION,
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": utc_now(),
        "host": host,
        "action": action,
        "operation_kind": operation_kind,
        "status": "planned",
        "transport": transport,
        "command": sanitize_command(command),
        "details": sanitize_details(action, details),
    }
    validate_intent(payload)
    return payload


def validate_intent(payload: dict[str, Any]) -> None:
    fields = set(payload)
    missing = sorted(INTENT_FIELDS - fields)
    if missing:
        raise GuardedOpsError("intent missing required fields: " + ", ".join(missing))
    extra = sorted(fields - INTENT_FIELDS)
    if extra:
        raise GuardedOpsError("intent has unsupported fields: " + ", ".join(extra))
    if payload["schema_version"] != INTENT_SCHEMA_VERSION:
        raise GuardedOpsError("unsupported intent schema version")
    for key in ("operation_id", "run_id", "ts", "host", "action", "operation_kind", "status", "transport"):
        if not isinstance(payload[key], str) or not payload[key]:
            raise GuardedOpsError(f"intent {key} must be a non-empty string")
    if not IDENTIFIER_RE.fullmatch(payload["operation_id"]):
        raise GuardedOpsError("intent operation_id has an invalid format")
    if not IDENTIFIER_RE.fullmatch(payload["run_id"]):
        raise GuardedOpsError("intent run_id has an invalid format")
    try:
        parse_rfc3339(payload["ts"], "ts")
    except AuditWriteError as exc:
        raise GuardedOpsError(str(exc)) from exc
    if payload["operation_kind"] != "write":
        raise GuardedOpsError("intent operation_kind must be write")
    if payload["status"] != "planned":
        raise GuardedOpsError("intent status must be planned")
    if payload["transport"] not in {"local", "ssh"}:
        raise GuardedOpsError("intent transport must be local or ssh")
    if not isinstance(payload["command"], list) or not all(isinstance(item, str) for item in payload["command"]):
        raise GuardedOpsError("intent command must be a list of strings")
    if not isinstance(payload["details"], dict):
        raise GuardedOpsError("intent details must be an object")
    json.dumps(payload, sort_keys=True)


def append_intent(path: str | Path | None, payload: dict[str, Any]) -> None:
    target = Path(path) if path else default_intent_log()
    validate_intent(payload)
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
        try:
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise OSError(f"short intent write: wrote {written} of {len(encoded)} bytes")
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise GuardedOpsError(f"intent append failed for {target}: {exc}; side effects blocked") from exc
