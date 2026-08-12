from __future__ import annotations

import json
import os
import re
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import AuditWriteError, GuardedOpsError
from .redaction import redact_text, redact_value

AUDIT_SCHEMA_VERSION = "guardedops.audit/v1"
AUDIT_SUMMARY_SCHEMA_VERSION = "guardedops.audit-summary/v1"

V1_FIELDS = {
    "schema_version",
    "operation_id",
    "run_id",
    "ts",
    "host",
    "action",
    "operation_kind",
    "phase",
    "status",
    "reason_code",
    "details",
    "wrapper_version",
    "policy_version",
}

RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ACTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

V1_ACTIONS = {
    "apply-config-batch",
    "config-patch",
    "deploy-ref",
    "host-observe",
    "log-query",
    "plan-config-batch",
    "restart-service",
    "runtime-baseline",
    "safe-git",
}

ACTION_DETAIL_ALLOWLIST = {
    "apply-config-batch": {"backup", "change_id", "changed", "decision", "file"},
    "config-patch": {"decision", "dry_run", "file", "key"},
    "deploy-ref": {"decision", "ref", "returncode"},
    "host-observe": {"decision"},
    "log-query": {"decision", "lines", "path"},
    "plan-config-batch": {"change_id", "changed", "decision", "file"},
    "restart-service": {"decision", "returncode", "service"},
    "runtime-baseline": {"decision"},
    "safe-git": {"decision", "op", "ref", "returncode"},
}

DETAIL_DENYLIST = {
    "approval",
    "approval_token",
    "config",
    "deletes",
    "diff",
    "new_text",
    "old_text",
    "output",
    "sets",
    "stderr",
    "stdout",
    "token",
    "value",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_run_id() -> str:
    return "run-" + utc_now().replace("-", "").replace(":", "").replace("Z", "Z")


def new_operation_id(action: str) -> str:
    return f"{action}:{uuid.uuid4().hex[:16]}"


def parse_rfc3339(value: Any, field: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        raise AuditWriteError(f"audit {field} must be an RFC3339 timestamp with timezone")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuditWriteError(f"audit {field} must be a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditWriteError(f"audit {field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def render_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_details(action: str, details: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    allowed = ACTION_DETAIL_ALLOWLIST.get(action, set())
    safe: dict[str, Any] = {}
    for key, value in details.items():
        if key in DETAIL_DENYLIST or key not in allowed:
            continue
        if isinstance(value, str):
            safe[key] = redact_text(value)
        elif isinstance(value, bool) or isinstance(value, int) or value is None:
            safe[key] = value
        elif isinstance(value, list):
            safe[key] = [redact_text(item) for item in value[:20] if isinstance(item, str)]
        else:
            safe[key] = redact_value(str(key), value)
    return safe


def validate_event(event: dict[str, Any]) -> None:
    fields = set(event)
    missing = sorted(V1_FIELDS - fields)
    if missing:
        raise AuditWriteError("audit event missing required fields: " + ", ".join(missing))
    extra = sorted(fields - V1_FIELDS)
    if extra:
        raise AuditWriteError("audit event has unsupported fields: " + ", ".join(extra))
    if event["schema_version"] != AUDIT_SCHEMA_VERSION:
        raise AuditWriteError("unsupported audit schema version")
    for key in ("operation_id", "run_id", "ts", "host", "action", "wrapper_version", "policy_version"):
        if not isinstance(event[key], str) or not event[key]:
            raise AuditWriteError(f"audit {key} must be a non-empty string")
    if not IDENTIFIER_RE.fullmatch(event["operation_id"]):
        raise AuditWriteError("audit operation_id has an invalid format")
    if not IDENTIFIER_RE.fullmatch(event["run_id"]):
        raise AuditWriteError("audit run_id has an invalid format")
    if event["action"] not in V1_ACTIONS:
        raise AuditWriteError("audit action is not registered")
    parse_rfc3339(event["ts"], "ts")
    if event["operation_kind"] not in {"read", "write"}:
        raise AuditWriteError("invalid audit operation_kind")
    if event["phase"] not in {"start", "result"}:
        raise AuditWriteError("invalid audit phase")
    if event["status"] not in {"started", "success", "failed"}:
        raise AuditWriteError("invalid audit status")
    if event["phase"] == "start" and event["status"] != "started":
        raise AuditWriteError("audit start phase must use started status")
    if event["phase"] == "result" and event["status"] == "started":
        raise AuditWriteError("audit result phase must be terminal")
    if event["operation_kind"] == "read" and event["phase"] != "result":
        raise AuditWriteError("audit read operations must use a single result event")
    if event["reason_code"] is not None and not isinstance(event["reason_code"], str):
        raise AuditWriteError("audit reason_code must be a string or null")
    if event["status"] == "failed" and not event["reason_code"]:
        raise AuditWriteError("audit failed results require a reason_code")
    if event["status"] != "failed" and event["reason_code"] is not None:
        raise AuditWriteError("audit non-failed events cannot include a reason_code")
    if not isinstance(event["details"], dict):
        raise AuditWriteError("audit details must be an object")
    allowed_details = ACTION_DETAIL_ALLOWLIST[event["action"]]
    unsupported_details = sorted(set(event["details"]) - allowed_details)
    if unsupported_details:
        raise AuditWriteError("audit details has unsupported fields for action: " + ", ".join(unsupported_details))
    for key, value in event["details"].items():
        if isinstance(value, str):
            if redact_text(value) != value:
                raise AuditWriteError(f"audit detail {key} contains unredacted secret material")
        elif isinstance(value, bool) or isinstance(value, int) or value is None:
            continue
        elif isinstance(value, list) and len(value) <= 20 and all(isinstance(item, str) and redact_text(item) == item for item in value):
            continue
        else:
            raise AuditWriteError(f"audit detail {key} has an invalid value")
    json.dumps(event, sort_keys=True)


def event_payload(
    *,
    operation_id: str,
    run_id: str,
    host: str,
    action: str,
    operation_kind: str,
    phase: str,
    status: str,
    wrapper_version: str,
    policy_version: str,
    reason_code: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": utc_now(),
        "host": host,
        "action": action,
        "operation_kind": operation_kind,
        "phase": phase,
        "status": status,
        "reason_code": reason_code,
        "details": sanitize_details(action, details),
        "wrapper_version": wrapper_version,
        "policy_version": policy_version,
    }
    validate_event(event)
    return event


def append_event(path: str | Path | None, event: dict[str, Any]) -> None:
    if not path:
        raise AuditWriteError("policy audit_log is required")
    validate_event(event)
    encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
        try:
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise OSError(f"short audit write: wrote {written} of {len(encoded)} bytes")
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AuditWriteError(f"audit append failed for {target}: {exc}") from exc


@dataclass(frozen=True)
class AuditFilters:
    host: str | None = None
    run_id: str | None = None
    since: str | None = None


def _source_format(data: dict[str, Any]) -> str:
    schema = data.get("schema_version")
    if schema == AUDIT_SCHEMA_VERSION:
        try:
            validate_event(data)
        except AuditWriteError:
            return "unknown"
        return AUDIT_SCHEMA_VERSION
    if isinstance(schema, str):
        return "unknown"
    if "time" in data and "action" in data:
        return "legacy_guardedops"
    if all(key in data for key in ("ts", "action", "status", "details")):
        return "legacy_aiserver_prod_ops"
    return "unknown"


def _record_timestamp(data: dict[str, Any]) -> datetime | None:
    value = data.get("ts") or data.get("time")
    if not value:
        return None
    try:
        return parse_rfc3339(value)
    except AuditWriteError:
        return None


def _matches_filters(data: dict[str, Any], filters: AuditFilters, since: datetime | None) -> bool:
    record_host = data.get("host")
    if filters.host and record_host is not None and record_host != filters.host:
        return False
    if filters.run_id and data.get("run_id") != filters.run_id:
        return False
    if since:
        record_time = _record_timestamp(data)
        if record_time is not None and record_time < since:
            return False
    return True


def _valid_v1_record(data: dict[str, Any]) -> bool:
    if data.get("schema_version") != AUDIT_SCHEMA_VERSION:
        return False
    try:
        validate_event(data)
    except AuditWriteError:
        return False
    return True


def _empty_summary(path: Path, filters: AuditFilters, verdict: str, reasons: list[str]) -> dict[str, Any]:
    return {
        "schema_version": AUDIT_SUMMARY_SCHEMA_VERSION,
        "source": str(path),
        "filters": {"host": filters.host, "run_id": filters.run_id, "since": filters.since},
        "verdict": verdict,
        "reasons": reasons,
        "records": {"total": 0, "malformed": 0, "unknown": 0},
        "source_formats": {},
        "operations": {
            "total": 0,
            "read": 0,
            "write": 0,
            "success": 0,
            "failed": 0,
            "rejected": 0,
            "incomplete": 0,
            "orphan_results": 0,
            "invalid_sequences": 0,
        },
        "counts_by_reason_code": {},
        "counts_by_action": {},
        "counts_by_status": {},
        "window": {"first_ts": None, "last_ts": None},
        "hosts": [],
        "run_ids": [],
    }


def summarize_audit_log(path: str | Path, filters: AuditFilters | None = None) -> tuple[dict[str, Any], int]:
    target = Path(path)
    filters = filters or AuditFilters()
    if filters.run_id and not IDENTIFIER_RE.fullmatch(filters.run_id):
        return _empty_summary(target, filters, "insufficient", ["invalid_run_id"]), 2
    try:
        since = parse_rfc3339(filters.since, "since") if filters.since else None
    except AuditWriteError:
        return _empty_summary(target, filters, "insufficient", ["invalid_since"]), 2
    if not target.exists():
        return _empty_summary(target, filters, "insufficient", ["missing"]), 2
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return _empty_summary(target, filters, "insufficient", ["unreadable", str(exc)]), 2

    malformed = 0
    unknown = 0
    source_formats: Counter[str] = Counter()
    selected_records: list[tuple[int, dict[str, Any], str, datetime | None]] = []
    valid_v1: list[tuple[int, dict[str, Any]]] = []
    selected_parseable = 0
    invalid_v1 = 0
    nonblank_lines = 0

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        nonblank_lines += 1
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(data, dict):
            malformed += 1
            continue
        source = _source_format(data)
        valid_v1_record = source == AUDIT_SCHEMA_VERSION
        invalid_v1_record = data.get("schema_version") == AUDIT_SCHEMA_VERSION and not valid_v1_record
        if filters.host or filters.run_id or filters.since:
            if not _matches_filters(data, filters, since):
                continue
        selected_parseable += 1
        source_formats[source] += 1
        timestamp = _record_timestamp(data)
        selected_records.append((line_number, data, source, timestamp))
        if source == "unknown":
            unknown += 1
        if invalid_v1_record:
            invalid_v1 += 1
        if valid_v1_record:
            valid_v1.append((line_number, data))

    grouped: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for line_number, data in valid_v1:
        grouped[str(data["operation_id"])].append((line_number, data))

    operations = {
        "total": len(grouped),
        "read": 0,
        "write": 0,
        "success": 0,
        "failed": 0,
        "rejected": 0,
        "incomplete": 0,
        "orphan_results": 0,
        "invalid_sequences": 0,
    }
    reason_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    reasons: set[str] = set()
    timestamps: list[datetime] = []
    hosts: set[str] = set()
    run_ids: set[str] = set()

    for _line_number, data, source, timestamp in selected_records:
        if timestamp is not None:
            timestamps.append(timestamp)
        elif data.get("ts") or data.get("time"):
            reasons.add("invalid_timestamp")
        record_host = data.get("host") or filters.host
        if record_host:
            hosts.add(str(record_host))
        if data.get("run_id"):
            run_ids.add(str(data["run_id"]))
        if source in {"legacy_guardedops", "legacy_aiserver_prod_ops"}:
            action = data.get("action")
            if isinstance(action, str) and ACTION_RE.fullmatch(action):
                action_counts[action] += 1
            status = data.get("status")
            status_counts[status if isinstance(status, str) and status in {"success", "failed"} else "unknown"] += 1

    for indexed_records in grouped.values():
        indexed_records.sort(key=lambda item: item[0])
        records = [item[1] for item in indexed_records]
        first = records[0]
        kind = str(first.get("operation_kind"))
        if kind in {"read", "write"}:
            operations[kind] += 1
        action = str(first.get("action"))
        action_counts[action] += 1
        consistent = all(
            all(record.get(key) == first.get(key) for key in ("host", "run_id", "action", "operation_kind", "wrapper_version", "policy_version"))
            for record in records
        )
        starts = [item for item in records if item.get("phase") == "start"]
        results = [item for item in records if item.get("phase") == "result"]
        phases = [str(item.get("phase")) for item in records]
        policy_denied = (
            len(records) == 1
            and phases == ["result"]
            and records[0].get("status") == "failed"
            and records[0].get("reason_code") == "policy_denied"
        )
        rejected = kind == "write" and policy_denied
        incomplete = kind == "write" and len(records) == 1 and phases == ["start"]
        complete_write = kind == "write" and len(records) == 2 and phases == ["start", "result"]
        complete_read = kind == "read" and len(records) == 1 and phases == ["result"]
        if not consistent or not (rejected or incomplete or complete_write or complete_read):
            if kind == "write" and results and not starts and not rejected:
                operations["orphan_results"] += 1
                reasons.add("orphan_results")
            operations["invalid_sequences"] += 1
            status_counts["invalid"] += 1
            reasons.add("invalid_operation_sequence")
            continue
        if incomplete:
            operations["incomplete"] += 1
            status_counts["incomplete"] += 1
            reasons.add("incomplete")
            continue
        terminal = results[-1]
        if terminal:
            if terminal.get("status") == "success":
                operations["success"] += 1
                status_counts["success"] += 1
            elif terminal.get("status") == "failed":
                operations["failed"] += 1
                status_counts["failed"] += 1
            reason_code = terminal.get("reason_code")
            if reason_code:
                reason_counts[str(reason_code)] += 1
                if reason_code == "policy_denied":
                    operations["rejected"] += 1

    if malformed:
        reasons.add("malformed")
    if unknown:
        reasons.add("unknown_schema")
    if invalid_v1:
        reasons.add("invalid_v1_record")
    if source_formats.get("legacy_guardedops") or source_formats.get("legacy_aiserver_prod_ops"):
        reasons.add("legacy_records")
    if selected_parseable == 0 and malformed == 0 and nonblank_lines == 0:
        reasons.add("empty")
    elif selected_parseable == 0:
        reasons.add("no_matching_records" if (filters.host or filters.run_id or filters.since) else "no_parseable_records")
    if operations["orphan_results"]:
        reasons.add("orphan_results")

    verdict = "complete" if not reasons else "partial"
    exit_code = 0 if verdict == "complete" else 3
    summary = {
        "schema_version": AUDIT_SUMMARY_SCHEMA_VERSION,
        "source": str(target),
        "filters": {"host": filters.host, "run_id": filters.run_id, "since": filters.since},
        "verdict": verdict,
        "reasons": sorted(reasons),
        "records": {"total": selected_parseable, "malformed": malformed, "unknown": unknown},
        "source_formats": dict(sorted(source_formats.items())),
        "operations": operations,
        "counts_by_reason_code": dict(sorted(reason_counts.items())),
        "counts_by_action": dict(sorted(action_counts.items())),
        "counts_by_status": dict(sorted(status_counts.items())),
        "window": {
            "first_ts": render_rfc3339(min(timestamps)) if timestamps else None,
            "last_ts": render_rfc3339(max(timestamps)) if timestamps else None,
        },
        "hosts": sorted(hosts),
        "run_ids": sorted(run_ids),
    }
    return summary, exit_code


def emit_summary(path: str | Path, filters: AuditFilters | None = None, output: str | Path | None = None) -> int:
    summary, exit_code = summarize_audit_log(path, filters)
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if output:
        try:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            raise GuardedOpsError(f"cannot write audit summary to {output}: {exc}") from exc
    print(rendered, end="")
    return exit_code
