from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .audit import (
    AUDIT_SCHEMA_VERSION,
    IDENTIFIER_RE,
    AuditFilters,
    parse_rfc3339,
    validate_event,
)
from .errors import AuditWriteError, GuardedOpsError
from .intent import DETAIL_ALLOWLIST, INTENT_FIELDS, validate_intent
from .redaction import redact_text

RECONCILE_SCHEMA_VERSION = "guardedops.audit-reconcile/v1"
DAILY_EVIDENCE_SCHEMA_VERSION = "guardedops.daily-evidence/v1"
INTENT_SCHEMA_VERSION = "guardedops.intent/v1"
EVIDENCE_SCHEMA_VERSION = "guardedops.evidence/v1"

SECRET_FLAG_RE = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|cookie)")
VALUE_BEARING_SECRET_FLAGS = {
    "--set",
    "--approval-token",
    "--token",
    "--secret",
    "--password",
    "--api-key",
    "--authorization",
    "--cookie",
}
DAILY_REASON_RE = re.compile(r"^[a-z][a-z0-9_:-]{0,127}$")
DAILY_VERDICTS = {"complete", "partial", "insufficient"}
DAILY_FILTER_KEYS = {"host", "run_id", "since"}
DAILY_COUNT_KEYS = {
    "known_writes",
    "intent_records",
    "known_reads_excluded",
    "wrapper_success",
    "wrapper_failed",
    "policy_denied",
    "hook_blocked",
    "external_writes",
    "missing_wrapper_audit",
    "missing_intent",
    "unmatched_wrapper_writes",
    "incomplete",
    "duplicate_intent",
    "duplicate_operation_id",
    "metadata_conflict",
    "invalid_audit_sequence",
    "duplicate_evidence",
    "unexplained_evidence",
}
DAILY_COVERAGE_KEYS = {"known_write_coverage_ratio", "explained_writes", "known_writes"}


@dataclass(frozen=True)
class SourceRecord:
    line: int
    data: dict[str, Any]


@dataclass(frozen=True)
class AuditOperation:
    operation_id: str
    host: str | None
    run_id: str | None
    action: str | None
    operation_kind: str
    status: str
    reason_code: str | None
    sequence_status: str


@dataclass(frozen=True)
class EvidenceOperation:
    operation_id: str
    host: str | None
    run_id: str | None
    source: str
    action: str | None
    status: str
    reason_code: str | None


def _load_jsonl(path: str | Path, source: str) -> tuple[list[SourceRecord], Counter[str], str | None]:
    target = Path(path)
    counts: Counter[str] = Counter()
    if not target.exists():
        return [], counts, f"missing_{source}_input"
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], counts, f"unreadable_{source}_input"
    records: list[SourceRecord] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            counts[f"{source}_malformed"] += 1
            continue
        if not isinstance(data, dict):
            counts[f"{source}_malformed"] += 1
            continue
        records.append(SourceRecord(line_number, data))
    return records, counts, None


def _record_timestamp(data: dict[str, Any]) -> datetime | None:
    value = data.get("ts") or data.get("time")
    if value is None:
        return None
    try:
        return parse_rfc3339(value)
    except AuditWriteError:
        return None


def _compile_since(since: str | None) -> tuple[datetime | None, str | None]:
    if not since:
        return None, None
    try:
        return parse_rfc3339(since, "since"), None
    except AuditWriteError:
        return None, "invalid_since"


def _matches_filters(data: dict[str, Any], filters: AuditFilters, since: datetime | None) -> bool:
    if filters.host and data.get("host") is not None and data.get("host") != filters.host:
        return False
    if filters.run_id and data.get("run_id") != filters.run_id:
        return False
    if since:
        record_time = _record_timestamp(data)
        if record_time is not None and record_time < since:
            return False
    return True


def _matches_anomaly_filters(data: dict[str, Any], filters: AuditFilters, since: datetime | None) -> bool:
    """Select quality anomalies without hiding records lacking scope metadata.

    A malformed or legacy record can still be scoped out when it carries an
    explicit, different host/run/timestamp.  If it omits one of those fields,
    keep it in the selected evidence set so a missing identifier cannot make a
    report appear complete.
    """
    host = data.get("host")
    run_id = data.get("run_id")
    if filters.host and isinstance(host, str) and host and host != filters.host:
        return False
    if filters.run_id and isinstance(run_id, str) and run_id and run_id != filters.run_id:
        return False
    if since:
        record_time = _record_timestamp(data)
        if record_time is not None and record_time < since:
            return False
    return True


def _render_command_template(command: Any) -> str | None:
    if command is None:
        return None
    if isinstance(command, str):
        parts = command.split()
    elif isinstance(command, list) and all(isinstance(item, str) for item in command):
        parts = list(command)
    else:
        return None
    rendered: list[str] = []
    redact_next = False
    for part in parts:
        lower_part = part.lower()
        if redact_next:
            rendered.append("<redacted>")
            redact_next = False
            continue
        if any(lower_part == flag or lower_part.startswith(flag + "=") for flag in VALUE_BEARING_SECRET_FLAGS):
            if "=" in part:
                flag, _value = part.split("=", 1)
                rendered.append(f"{flag}=<redacted>")
            else:
                rendered.append(part)
                redact_next = True
            continue
        if SECRET_FLAG_RE.search(part):
            rendered.append(redact_text(part))
            if part.startswith("-") and "=" not in part:
                redact_next = True
            continue
        redacted = redact_text(part)
        if redacted != part and "=" in part:
            rendered.append("<redacted>")
        else:
            rendered.append(redacted)
    return " ".join(rendered)


def _safe_details_object(details: Any) -> bool:
    if not isinstance(details, dict):
        return False
    for key, value in details.items():
        if not isinstance(key, str) or SECRET_FLAG_RE.search(key):
            return False
        if not isinstance(value, (str, int, bool)) and value is not None:
            return False
        if isinstance(value, str) and redact_text(value) != value:
            return False
    return True


def _sanitize_details(action: Any, details: Any) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    allowlist = DETAIL_ALLOWLIST.get(str(action), set())
    safe: dict[str, Any] = {}
    for key in sorted(details):
        if key not in allowlist or SECRET_FLAG_RE.search(str(key)):
            continue
        value = details[key]
        if isinstance(value, str):
            safe[str(key)] = redact_text(value)
        elif isinstance(value, (int, bool)) or value is None:
            safe[str(key)] = value
    return safe


def _valid_intent(data: dict[str, Any]) -> bool:
    if set(data) != INTENT_FIELDS:
        return False
    if data.get("operation_kind") == "write":
        try:
            validate_intent(data)
        except GuardedOpsError:
            return False
        return True
    if data.get("schema_version") != INTENT_SCHEMA_VERSION:
        return False
    for key in ("operation_id", "run_id", "ts", "host", "action", "operation_kind", "status", "transport"):
        if not isinstance(data.get(key), str) or not data.get(key):
            return False
    if not isinstance(data.get("command"), list) or not all(isinstance(item, str) and item for item in data["command"]):
        return False
    if not IDENTIFIER_RE.fullmatch(data["operation_id"]) or not IDENTIFIER_RE.fullmatch(data["run_id"]):
        return False
    if data["operation_kind"] != "read":
        return False
    if data["status"] != "planned":
        return False
    if data["transport"] not in {"local", "ssh"}:
        return False
    if not _safe_details_object(data.get("details")):
        return False
    try:
        parse_rfc3339(data["ts"], "ts")
    except AuditWriteError:
        return False
    return True


def _valid_evidence(data: dict[str, Any]) -> bool:
    if data.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        return False
    required = ("operation_id", "run_id", "ts", "host", "source", "status", "details")
    if any(not isinstance(data.get(key), str) or not data.get(key) for key in required[:-1]):
        return False
    if not IDENTIFIER_RE.fullmatch(data["operation_id"]) or not IDENTIFIER_RE.fullmatch(data["run_id"]):
        return False
    if data.get("operation_kind", "write") not in {"read", "write"}:
        return False
    if not isinstance(data.get("details"), dict):
        return False
    reason_code = data.get("reason_code")
    if reason_code is not None and not isinstance(reason_code, str):
        return False
    try:
        parse_rfc3339(data["ts"], "ts")
    except AuditWriteError:
        return False
    return True


def _metadata_tuple(data: dict[str, Any]) -> tuple[Any, Any, Any]:
    return data.get("host"), data.get("run_id"), data.get("action")


def _evidence_matches_intent(evidence: EvidenceOperation, intent: dict[str, Any]) -> bool:
    if evidence.host != intent.get("host") or evidence.run_id != intent.get("run_id"):
        return False
    return evidence.action is None or evidence.action == intent.get("action")


def _parse_intents(
    records: list[SourceRecord],
    filters: AuditFilters,
    since: datetime | None,
    record_counts: Counter[str],
    reasons: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    intents: dict[str, list[dict[str, Any]]] = defaultdict(list)
    known_reads_excluded = 0
    for record in records:
        data = record.data
        if not _matches_anomaly_filters(data, filters, since):
            continue
        if data.get("schema_version") != INTENT_SCHEMA_VERSION:
            record_counts["intent_unknown"] += 1
            reasons.add("unknown_intent_schema")
            continue
        if not _valid_intent(data):
            record_counts["intent_malformed"] += 1
            reasons.add("malformed")
            continue
        record_counts["intent_records"] += 1
        if not _matches_filters(data, filters, since):
            continue
        if data["operation_kind"] == "read":
            known_reads_excluded += 1
            continue
        intents[data["operation_id"]].append(data)
    return intents, known_reads_excluded


def _parse_evidence(
    records: list[SourceRecord],
    filters: AuditFilters,
    since: datetime | None,
    record_counts: Counter[str],
    reasons: set[str],
) -> dict[str, list[EvidenceOperation]]:
    evidence: dict[str, list[EvidenceOperation]] = defaultdict(list)
    for record in records:
        data = record.data
        if not _matches_anomaly_filters(data, filters, since):
            continue
        if data.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
            record_counts["evidence_unknown"] += 1
            reasons.add("unknown_evidence_schema")
            continue
        if not _valid_evidence(data):
            record_counts["evidence_malformed"] += 1
            reasons.add("malformed")
            continue
        record_counts["evidence_records"] += 1
        if not _matches_filters(data, filters, since):
            continue
        if data.get("operation_kind", "write") == "read":
            continue
        evidence[data["operation_id"]].append(
            EvidenceOperation(
                operation_id=data["operation_id"],
                host=data.get("host"),
                run_id=data.get("run_id"),
                source=data.get("source", ""),
                action=data.get("action"),
                status=data.get("status", ""),
                reason_code=data.get("reason_code"),
            )
        )
    return evidence


def _parse_audit(
    records: list[SourceRecord],
    filters: AuditFilters,
    since: datetime | None,
    record_counts: Counter[str],
    reasons: set[str],
) -> dict[str, AuditOperation]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        data = record.data
        if not _matches_anomaly_filters(data, filters, since):
            continue
        if data.get("schema_version") == AUDIT_SCHEMA_VERSION and data.get("operation_kind") == "read":
            if _matches_filters(data, filters, since):
                record_counts["audit_records"] += 1
            continue
        source_format = _audit_source_format(data)
        if source_format in {"legacy_guardedops", "legacy_aiserver_prod_ops"}:
            record_counts["legacy_audit"] += 1
            reasons.add("legacy_records")
            continue
        if source_format == "unknown":
            if data.get("schema_version") == AUDIT_SCHEMA_VERSION:
                record_counts["audit_malformed"] += 1
                reasons.add("malformed")
            else:
                record_counts["audit_unknown"] += 1
                reasons.add("unknown_schema")
            continue
        if data.get("operation_kind") == "read":
            record_counts["audit_records"] += 1
            continue
        try:
            validate_event(data)
        except AuditWriteError:
            record_counts["audit_malformed"] += 1
            reasons.add("malformed")
            continue
        record_counts["audit_records"] += 1
        if not _matches_filters(data, filters, since):
            continue
        if data["operation_kind"] == "read":
            continue
        grouped[data["operation_id"]].append(data)

    operations: dict[str, AuditOperation] = {}
    for operation_id, items in grouped.items():
        first = items[0]
        consistent = all(_metadata_tuple(item) == _metadata_tuple(first) and item.get("operation_kind") == first.get("operation_kind") for item in items)
        phases = [item.get("phase") for item in items]
        starts = [item for item in items if item.get("phase") == "start"]
        results = [item for item in items if item.get("phase") == "result"]
        policy_denied = (
            len(items) == 1
            and phases == ["result"]
            and items[0].get("status") == "failed"
            and items[0].get("reason_code") == "policy_denied"
        )
        complete = len(items) == 2 and phases == ["start", "result"] and len(starts) == 1 and len(results) == 1
        incomplete = len(items) == 1 and phases == ["start"]
        if not consistent or not (policy_denied or complete or incomplete):
            sequence_status = "invalid"
            status = "invalid"
            reason_code = "invalid_operation_sequence"
            reasons.add("invalid_operation_sequence")
        elif incomplete:
            sequence_status = "incomplete"
            status = "incomplete"
            reason_code = "incomplete"
            reasons.add("incomplete")
        else:
            terminal = items[0] if policy_denied else results[0]
            sequence_status = "terminal"
            status = str(terminal.get("status"))
            reason_code = terminal.get("reason_code")
        operations[operation_id] = AuditOperation(
            operation_id=operation_id,
            host=first.get("host"),
            run_id=first.get("run_id"),
            action=first.get("action"),
            operation_kind="write",
            status=status,
            reason_code=reason_code,
            sequence_status=sequence_status,
        )
    return operations


def _audit_source_format(data: dict[str, Any]) -> str:
    if data.get("schema_version") == AUDIT_SCHEMA_VERSION and data.get("operation_kind") == "read":
        required = {"operation_id", "run_id", "ts", "host", "action", "operation_kind", "phase", "status"}
        if required.issubset(data) and data.get("phase") == "result" and data.get("status") in {"success", "failed"}:
            return AUDIT_SCHEMA_VERSION
    if data.get("schema_version") == AUDIT_SCHEMA_VERSION:
        try:
            validate_event(data)
        except AuditWriteError:
            return "unknown"
        return AUDIT_SCHEMA_VERSION
    if isinstance(data.get("schema_version"), str):
        return "unknown"
    if "time" in data and "action" in data:
        return "legacy_guardedops"
    if all(key in data for key in ("ts", "action", "status", "details")):
        return "legacy_aiserver_prod_ops"
    return "unknown"


def _operation_summary(operation_id: str, intent: dict[str, Any] | None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "operation_id": operation_id,
        "intent_match": "exact" if intent else "missing",
        "audit_match": "missing",
        "status": "unknown",
    }
    if intent:
        item.update(
            {
                "host": intent.get("host"),
                "run_id": intent.get("run_id"),
                "action": intent.get("action"),
                "command_template": _render_command_template(intent.get("command")),
                "details": _sanitize_details(intent.get("action"), intent.get("details")),
            }
        )
    return {key: value for key, value in item.items() if value is not None}


def reconcile_audit(
    *,
    intent_path: str | Path,
    audit_path: str | Path,
    evidence_path: str | Path | None = None,
    filters: AuditFilters | None = None,
) -> tuple[dict[str, Any], int]:
    filters = filters or AuditFilters()
    if filters.run_id and not IDENTIFIER_RE.fullmatch(filters.run_id):
        return _insufficient_report(filters, ["invalid_run_id"]), 2
    since, filter_error = _compile_since(filters.since)
    if filter_error:
        return _insufficient_report(filters, [filter_error]), 2

    reasons: set[str] = set()
    record_counts: Counter[str] = Counter()
    intent_records, intent_counts, intent_error = _load_jsonl(intent_path, "intent")
    audit_records, audit_counts, audit_error = _load_jsonl(audit_path, "audit")
    record_counts.update(intent_counts)
    record_counts.update(audit_counts)
    load_errors = [reason for reason in (intent_error, audit_error) if reason]
    evidence_records: list[SourceRecord] = []
    if evidence_path is not None:
        evidence_records, evidence_counts, evidence_error = _load_jsonl(evidence_path, "evidence")
        record_counts.update(evidence_counts)
        if evidence_error:
            load_errors.append(evidence_error)
    if load_errors:
        existing_intents, existing_reads = _parse_intents(intent_records, filters, since, record_counts, reasons) if intent_error is None else ({}, 0)
        report = _insufficient_report(filters, sorted(load_errors), record_counts)
        report["counts"]["known_writes"] = len(existing_intents)
        report["counts"]["intent_records"] = record_counts["intent_records"]
        report["counts"]["known_reads_excluded"] = existing_reads
        report["coverage"]["known_writes"] = len(existing_intents)
        return report, 2

    for key in ("intent_malformed", "audit_malformed", "evidence_malformed"):
        if record_counts[key]:
            reasons.add("malformed")

    intents, reads_excluded = _parse_intents(intent_records, filters, since, record_counts, reasons)
    audits = _parse_audit(audit_records, filters, since, record_counts, reasons)
    evidence = _parse_evidence(evidence_records, filters, since, record_counts, reasons)

    counts: Counter[str] = Counter()
    counts["intent_records"] = record_counts["intent_records"]
    counts["known_reads_excluded"] = reads_excluded
    operations: list[dict[str, Any]] = []
    explained = 0
    known_ids = sorted(set(intents) | set(audits) | set(evidence))

    for operation_id in known_ids:
        intent_list = intents.get(operation_id, [])
        selected_intent = intent_list[0] if intent_list else None
        item = _operation_summary(operation_id, selected_intent)
        intent_mapping_valid = len(intent_list) == 1
        if len(intent_list) > 1:
            tuples = {_metadata_tuple(intent) for intent in intent_list}
            if len(tuples) > 1:
                counts["metadata_conflict"] += 1
                reasons.add("metadata_conflict")
            else:
                counts["duplicate_intent"] += 1
                reasons.add("duplicate_intent")

        audit = audits.get(operation_id)
        evidence_items = evidence.get(operation_id, [])
        operation_explained = False
        audit_metadata_matches = False
        if audit:
            item["audit_match"] = "exact"
            item["audit_status"] = audit.status
            item["status"] = audit.status
            if selected_intent is None:
                counts["missing_intent"] += 1
                reasons.add("missing_intent")
                item["intent_match"] = "missing"
            elif _metadata_tuple(selected_intent) != (audit.host, audit.run_id, audit.action):
                counts["metadata_conflict"] += 1
                reasons.add("metadata_conflict")
            else:
                audit_metadata_matches = True
            if audit.sequence_status == "terminal":
                if audit.status == "success":
                    counts["wrapper_success"] += 1
                elif audit.status == "failed":
                    counts["wrapper_failed"] += 1
                    if audit.reason_code == "policy_denied":
                        counts["policy_denied"] += 1
                if selected_intent is not None and intent_mapping_valid and audit_metadata_matches:
                    operation_explained = True
            elif audit.sequence_status == "incomplete":
                counts["incomplete"] += 1
                reasons.add("incomplete")
                item["audit_match"] = "incomplete"
            else:
                counts["invalid_audit_sequence"] += 1
                reasons.add("invalid_operation_sequence")
                item["audit_match"] = "invalid"
        elif selected_intent is not None:
            counts["missing_wrapper_audit"] += 1
            reasons.add("missing_wrapper_audit")

        hook_explained = False
        external_explained = False
        evidence_classified = False
        evidence_mapping_valid = len(evidence_items) == 1
        if len(evidence_items) > 1:
            tuples = {(item.host, item.run_id, item.action, item.source) for item in evidence_items}
            if len(tuples) > 1:
                counts["metadata_conflict"] += 1
                reasons.add("metadata_conflict")
            else:
                counts["duplicate_evidence"] += 1
                reasons.add("duplicate_evidence")
        for evidence_item in evidence_items:
            if selected_intent is not None and not _evidence_matches_intent(evidence_item, selected_intent):
                evidence_mapping_valid = False
                counts["metadata_conflict"] += 1
                reasons.add("metadata_conflict")
                item["evidence_match"] = "metadata_conflict"
                continue
            if evidence_item.source == "ops-guard-hook" or evidence_item.reason_code in {"hook_denied", "hook_blocked"}:
                counts["hook_blocked"] += 1
                reasons.add("hook_blocked")
                evidence_classified = True
                hook_explained = True
                item["evidence_match"] = "hook_blocked"
                item["status"] = "blocked"
            elif evidence_item.status == "observed" or evidence_item.reason_code == "external_write_detected" or evidence_item.source.startswith("external"):
                counts["external_writes"] += 1
                reasons.add("external_write_detected")
                evidence_classified = True
                external_explained = True
                item["evidence_match"] = "external_observed"
                item["status"] = "external_observed"
        if evidence_items and not evidence_classified:
            counts["unexplained_evidence"] += 1
            reasons.add("unexplained_evidence")
            item["evidence_match"] = "unexplained"
        if hook_explained and not audit and evidence_mapping_valid and (selected_intent is None or intent_mapping_valid):
            operation_explained = True
            if selected_intent is not None:
                counts["missing_wrapper_audit"] = max(0, counts["missing_wrapper_audit"] - 1)
        elif external_explained and not audit and evidence_mapping_valid and (selected_intent is None or intent_mapping_valid):
            operation_explained = True
        if operation_explained:
            explained += 1
        operations.append(item)

    counts["known_writes"] = len(known_ids)
    counts["unmatched_wrapper_writes"] = counts["missing_intent"]
    if record_counts["legacy_audit"]:
        reasons.add("legacy_records")
    for key in ("intent_malformed", "audit_malformed", "evidence_malformed"):
        if record_counts[key]:
            reasons.add("malformed")

    coverage_ratio = (explained / len(known_ids)) if known_ids else None
    if not known_ids:
        reasons.add("insufficient_exposure")
        verdict = "insufficient"
        exit_code = 2
    elif reasons or explained != len(known_ids) or coverage_ratio != 1.0:
        verdict = "partial"
        exit_code = 3
    else:
        verdict = "complete"
        exit_code = 0

    report = {
        "schema_version": RECONCILE_SCHEMA_VERSION,
        "verdict": verdict,
        "reasons": sorted(reasons),
        "filters": {"host": filters.host, "run_id": filters.run_id, "since": filters.since},
        "records": {
            "intent_total": record_counts["intent_records"],
            "audit_total": record_counts["audit_records"],
            "evidence_total": record_counts["evidence_records"],
            "intent_malformed": record_counts["intent_malformed"],
            "audit_malformed": record_counts["audit_malformed"],
            "evidence_malformed": record_counts["evidence_malformed"],
            "legacy_audit": record_counts["legacy_audit"],
            "unknown": record_counts["intent_unknown"] + record_counts["audit_unknown"] + record_counts["evidence_unknown"],
        },
        "counts": {
            "known_writes": counts["known_writes"],
            "intent_records": counts["intent_records"],
            "known_reads_excluded": counts["known_reads_excluded"],
            "wrapper_success": counts["wrapper_success"],
            "wrapper_failed": counts["wrapper_failed"],
            "policy_denied": counts["policy_denied"],
            "hook_blocked": counts["hook_blocked"],
            "external_writes": counts["external_writes"],
            "missing_wrapper_audit": counts["missing_wrapper_audit"],
            "missing_intent": counts["missing_intent"],
            "unmatched_wrapper_writes": counts["unmatched_wrapper_writes"],
            "incomplete": counts["incomplete"],
            "duplicate_intent": counts["duplicate_intent"],
            "duplicate_operation_id": counts["duplicate_intent"],
            "metadata_conflict": counts["metadata_conflict"],
            "invalid_audit_sequence": counts["invalid_audit_sequence"],
            "duplicate_evidence": counts["duplicate_evidence"],
            "unexplained_evidence": counts["unexplained_evidence"],
        },
        "coverage": {
            "known_write_coverage_ratio": coverage_ratio,
            "explained_writes": explained,
            "known_writes": len(known_ids),
        },
        "operations": operations,
    }
    return report, exit_code


def _insufficient_report(filters: AuditFilters, reasons: list[str], records: Counter[str] | None = None) -> dict[str, Any]:
    records = records or Counter()
    return {
        "schema_version": RECONCILE_SCHEMA_VERSION,
        "verdict": "insufficient",
        "reasons": reasons,
        "filters": {"host": filters.host, "run_id": filters.run_id, "since": filters.since},
        "records": {
            "intent_total": records["intent_records"],
            "audit_total": records["audit_records"],
            "evidence_total": records["evidence_records"],
            "intent_malformed": records["intent_malformed"],
            "audit_malformed": records["audit_malformed"],
            "evidence_malformed": records["evidence_malformed"],
            "legacy_audit": records["legacy_audit"],
            "unknown": records["intent_unknown"] + records["audit_unknown"] + records["evidence_unknown"],
        },
        "counts": {
            "known_writes": 0,
            "intent_records": records["intent_records"],
            "known_reads_excluded": 0,
            "wrapper_success": 0,
            "wrapper_failed": 0,
            "policy_denied": 0,
            "hook_blocked": 0,
            "external_writes": 0,
            "missing_wrapper_audit": 0,
            "missing_intent": 0,
            "unmatched_wrapper_writes": 0,
            "incomplete": 0,
            "duplicate_intent": 0,
            "duplicate_operation_id": 0,
            "metadata_conflict": 0,
            "invalid_audit_sequence": 0,
            "duplicate_evidence": 0,
            "unexplained_evidence": 0,
        },
        "coverage": {"known_write_coverage_ratio": None, "explained_writes": 0, "known_writes": 0},
        "operations": [],
    }


def emit_reconcile(
    *,
    intent_path: str | Path,
    audit_path: str | Path,
    evidence_path: str | Path | None = None,
    filters: AuditFilters | None = None,
    output: str | Path | None = None,
) -> int:
    report, exit_code = reconcile_audit(intent_path=intent_path, audit_path=audit_path, evidence_path=evidence_path, filters=filters)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output:
        try:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            raise GuardedOpsError(f"cannot write reconciliation report to {output}: {exc}") from exc
    print(rendered, end="")
    return exit_code


def _percent(value: Any) -> str:
    if isinstance(value, (int, float)):
        return f"{value * 100:.2f}%"
    return "n/a"


def _validated_daily_payload(report: dict[str, Any]) -> dict[str, Any]:
    verdict = report.get("verdict")
    reasons = report.get("reasons")
    filters = report.get("filters")
    counts = report.get("counts")
    coverage = report.get("coverage")
    if verdict not in DAILY_VERDICTS:
        raise GuardedOpsError("daily evidence input has an invalid verdict")
    if not isinstance(reasons, list) or not all(isinstance(reason, str) and DAILY_REASON_RE.fullmatch(reason) for reason in reasons):
        raise GuardedOpsError("daily evidence input has invalid reasons")
    if not isinstance(filters, dict) or set(filters) != DAILY_FILTER_KEYS:
        raise GuardedOpsError("daily evidence input has invalid filters")
    for key, value in filters.items():
        if value is not None and (
            not isinstance(value, str)
            or not value
            or len(value) > 256
            or "\n" in value
            or "\r" in value
            or redact_text(value) != value
        ):
            raise GuardedOpsError(f"daily evidence input has an invalid {key} filter")
    if filters["run_id"] is not None and not IDENTIFIER_RE.fullmatch(filters["run_id"]):
        raise GuardedOpsError("daily evidence input has an invalid run_id filter")
    if filters["since"] is not None:
        try:
            parse_rfc3339(filters["since"], "since")
        except AuditWriteError as exc:
            raise GuardedOpsError(str(exc)) from exc
    if not isinstance(counts, dict) or not set(counts).issubset(DAILY_COUNT_KEYS):
        raise GuardedOpsError("daily evidence input has invalid counters")
    if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in counts.values()):
        raise GuardedOpsError("daily evidence input counters must be non-negative integers")
    if not isinstance(coverage, dict) or not set(coverage).issubset(DAILY_COVERAGE_KEYS):
        raise GuardedOpsError("daily evidence input has invalid coverage")
    ratio = coverage.get("known_write_coverage_ratio")
    if ratio is not None and (not isinstance(ratio, (int, float)) or isinstance(ratio, bool) or not 0 <= ratio <= 1):
        raise GuardedOpsError("daily evidence input has an invalid coverage ratio")
    for key in ("explained_writes", "known_writes"):
        value = coverage.get(key)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise GuardedOpsError(f"daily evidence input has an invalid {key} value")
    return {
        "schema_version": DAILY_EVIDENCE_SCHEMA_VERSION,
        "source_schema_version": RECONCILE_SCHEMA_VERSION,
        "verdict": verdict,
        "reasons": list(reasons),
        "filters": dict(filters),
        "counts": {key: counts[key] for key in sorted(counts)},
        "coverage": {key: coverage[key] for key in sorted(coverage)},
    }


def emit_daily_evidence(input_path: str | Path, output_dir: str | Path) -> int:
    source = Path(input_path)
    try:
        report = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardedOpsError(f"cannot read daily evidence input {source}: {exc}") from exc
    if not isinstance(report, dict) or report.get("schema_version") != RECONCILE_SCHEMA_VERSION:
        raise GuardedOpsError("daily evidence input must be a guardedops.audit-reconcile/v1 report")
    payload = _validated_daily_payload(report)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rendered_json = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    (output / "daily-evidence.json").write_text(rendered_json, encoding="utf-8")
    counts = payload["counts"]
    coverage = payload["coverage"]
    markdown = "\n".join(
        [
            "# GuardedOps Daily Evidence",
            "",
            f"Verdict: {payload['verdict']}",
            f"Reasons: {', '.join(payload['reasons']) if payload['reasons'] else 'none'}",
            f"Known writes: {counts.get('known_writes', 0)}",
            f"Wrapper success: {counts.get('wrapper_success', 0)}",
            f"Wrapper failed: {counts.get('wrapper_failed', 0)}",
            f"Hook blocked: {counts.get('hook_blocked', 0)}",
            f"External writes: {counts.get('external_writes', 0)}",
            f"Missing wrapper audit: {counts.get('missing_wrapper_audit', 0)}",
            f"Missing intent: {counts.get('missing_intent', 0)}",
            f"Coverage: {_percent(coverage.get('known_write_coverage_ratio'))}",
            "",
        ]
    )
    (output / "daily-evidence.md").write_text(markdown, encoding="utf-8")
    print(rendered_json, end="")
    return 0
