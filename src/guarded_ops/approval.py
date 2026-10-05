from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

import fcntl

from .errors import ApprovalError

APPROVAL_SCHEMA_VERSION = "guardedops.approval/v1"
APPROVAL_RECEIPT_SCHEMA_VERSION = "guardedops.approval-receipt/v1"
USER_TURN_RECEIPT_SCHEMA_VERSION = "guardedops.user-turn/v1"
APPROVAL_TTL_MINUTES = 15
APPROVAL_ID_RE = re.compile(r"^ap-[0-9a-f]{12}-[0-9a-f]{12}$")

BLANKET_APPROVAL_RE = re.compile(
    r"(后面|以后|未来).*(所有|全部|一切|任何)|"
    r"(所有|全部|一切|任何).*(操作|写入|部署|发布)|"
    r"(你自己看着办|随便|都行|无限授权|永久授权|blanket|all future|everything)",
    re.IGNORECASE,
)
APPROVAL_RE = re.compile(
    r"(可以|确认|同意|授权|批准|执行|继续|上吧|部署|发布|重启|恢复|按.*计划|"
    r"approve|approved|confirm|confirmed|go ahead|proceed|continue|deploy|restart)",
    re.IGNORECASE,
)
PLAN_REFERENCE_RE = re.compile(r"(计划|刚才|上面|这个|该|展示|plan)", re.IGNORECASE)
NEGATION_RE = re.compile(r"(不要|别|不可以|不能|不行|取消|停止|no\b|cancel|stop|do not|don't|not approve)", re.IGNORECASE)
QUESTION_RE = re.compile(r"(\?|？|吗\b|是否|能不能|可以吗|should\s+i|should\s+we)", re.IGNORECASE)
ACTION_TERMS = {
    "deploy": {"deploy", "deployment", "部署", "发布", "上线", "上"},
    "restart-service": {"restart", "重启"},
    "apply-config": {"config", "configuration", "配置"},
    "apply-config-batch": {"config", "configuration", "配置"},
    "safe-git-fetch": {"fetch"},
    "safe-git-checkout": {"checkout", "切换"},
    "rollback": {"rollback", "回滚"},
}
KNOWN_HOST_TERMS = {"pre", "test", "staging", "prod-us", "us", "jp", "sg"}


@dataclass(frozen=True)
class Approval:
    values: dict[str, str]

    @classmethod
    def parse(cls, token: str | None) -> "Approval":
        if not token or not token.strip():
            raise ApprovalError("missing approval token")
        values: dict[str, str] = {}
        for item in shlex.split(token):
            if "=" not in item:
                raise ApprovalError(f"approval token item is not key=value: {item}")
            key, value = item.split("=", 1)
            if not key:
                raise ApprovalError(f"approval token item has empty key: {item}")
            if key in values:
                raise ApprovalError(f"approval token duplicate key: {key}")
            values[key] = value
        return cls(values)

    def require(self, expected: Mapping[str, str]) -> None:
        mismatches: list[str] = []
        expected_keys = set(expected)
        actual_keys = set(self.values)
        if actual_keys != expected_keys:
            missing = sorted(expected_keys - actual_keys)
            extra = sorted(actual_keys - expected_keys)
            details = []
            if missing:
                details.append("missing keys: " + ", ".join(missing))
            if extra:
                details.append("unexpected keys: " + ", ".join(extra))
            raise ApprovalError("approval token scope mismatch: " + "; ".join(details))
        for key, value in expected.items():
            actual = self.values.get(key)
            if actual != value:
                mismatches.append(f"{key}: expected {value!r}, got {actual!r}")
        if mismatches:
            raise ApprovalError("approval token mismatch: " + "; ".join(mismatches))


def validate_approval(token: str | None, expected: Mapping[str, str]) -> None:
    Approval.parse(token).require(expected)


def approval_hint(expected: Mapping[str, str]) -> str:
    return " ".join(f"{key}={value}" for key, value in expected.items())


def approval_state_dir(root: str | Path | None = None) -> Path:
    base = Path(root) if root else Path.cwd() / ".guarded_ops"
    path = base / "approvals"
    path.mkdir(parents=True, exist_ok=True)
    try:
        base.chmod(0o700)
        path.chmod(0o700)
    except OSError:
        pass
    return path


def plan_sha256(expected: Mapping[str, str]) -> str:
    encoded = json.dumps(dict(sorted(expected.items())), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def stable_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def approval_id_for(expected: Mapping[str, str]) -> str:
    return "ap-" + plan_sha256(expected)[:12] + "-" + secrets.token_hex(6)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ApprovalError(f"approval record {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError(f"approval record {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ApprovalError(f"approval record {field} must include timezone")
    return parsed.astimezone(timezone.utc)


def _check_approval_id(approval_id: str | None) -> str:
    if not approval_id:
        raise ApprovalError("missing approval id")
    if not APPROVAL_ID_RE.match(approval_id):
        raise ApprovalError("invalid approval id")
    return approval_id


def _approval_path(approval_id: str, state_root: str | Path | None) -> Path:
    return approval_state_dir(state_root) / f"{_check_approval_id(approval_id)}.json"


def _receipt_dir(state_root: str | Path | None) -> Path:
    path = approval_state_dir(state_root) / "turn-receipts"
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def _receipt_path(receipt_id: str, state_root: str | Path | None) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_id):
        raise ApprovalError("invalid user turn receipt id")
    return _receipt_dir(state_root) / f"{receipt_id}.json"


def _message_hmac_key(state_root: str | Path | None) -> bytes:
    path = approval_state_dir(state_root) / ".message-hmac-key"
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def _message_hmac(message: str, state_root: str | Path | None) -> str:
    return hmac.new(_message_hmac_key(state_root), message.encode("utf-8"), hashlib.sha256).hexdigest()


@contextmanager
def _approval_lock(state_root: str | Path | None) -> Iterator[None]:
    directory = approval_state_dir(state_root)
    lock_path = directory / ".lock"
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _load_record(path: Path, approval_id: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ApprovalError(f"unknown approval id: {approval_id}") from exc
    except json.JSONDecodeError as exc:
        raise ApprovalError(f"invalid approval record: {approval_id}") from exc
    if not isinstance(payload, dict):
        raise ApprovalError("approval record is invalid")
    if payload.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        raise ApprovalError("unsupported approval record schema")
    if payload.get("approval_id") != approval_id:
        raise ApprovalError("approval id mismatch")
    return payload


def _scope(payload: Mapping[str, Any]) -> dict[str, str]:
    scope = payload.get("scope")
    if not isinstance(scope, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in scope.items()):
        raise ApprovalError("approval record scope is invalid")
    return dict(scope)


def _ensure_plan_hash(payload: Mapping[str, Any], scope: Mapping[str, str]) -> None:
    if payload.get("plan_sha256") != plan_sha256(scope):
        raise ApprovalError("approval plan hash mismatch")


def _ensure_not_expired(payload: Mapping[str, Any]) -> None:
    expires = _parse_time(payload.get("expires_at"), "expiry")
    if datetime.now(timezone.utc) > expires:
        raise ApprovalError("approval id has expired")


def _ensure_metadata(payload: Mapping[str, Any], operation_id: str | None, run_id: str | None) -> None:
    if payload.get("operation_id") and operation_id is None:
        raise ApprovalError("approval operation_id is required")
    if payload.get("run_id") and run_id is None:
        raise ApprovalError("approval run_id is required")
    if payload.get("operation_id") and payload.get("operation_id") != operation_id:
        raise ApprovalError("approval operation_id mismatch")
    if payload.get("run_id") and payload.get("run_id") != run_id:
        raise ApprovalError("approval run_id mismatch")


def _message_approves_scope(message: str, scope: Mapping[str, str]) -> None:
    rendered = " ".join(message.split()).strip()
    if not rendered:
        raise ApprovalError("missing user approval message")
    if NEGATION_RE.search(rendered):
        raise ApprovalError("user approval message is negative")
    if QUESTION_RE.search(rendered):
        raise ApprovalError("user approval message is a question, not an approval")
    if BLANKET_APPROVAL_RE.search(rendered):
        raise ApprovalError("ambiguous future approval does not bind to a specific plan scope")
    if not APPROVAL_RE.search(rendered):
        raise ApprovalError("plan scope is not explicitly approved")
    lowered = rendered.lower()
    mentions_plan = bool(PLAN_REFERENCE_RE.search(rendered))
    mentions_scope = any(str(value).lower() in lowered for key, value in scope.items() if key in {"host", "action", "service", "ref", "change_id", "rollback_id"})
    if not (mentions_plan or mentions_scope):
        raise ApprovalError("user approval message does not reference the plan scope")
    expected_ref = scope.get("ref")
    if expected_ref:
        mentioned_refs = re.findall(r"\b[0-9a-f]{7,64}\b", lowered)
        if mentioned_refs and expected_ref.lower() not in mentioned_refs:
            raise ApprovalError("user approval message ref mismatch")
    expected_host = scope.get("host")
    if expected_host:
        host_terms = set(KNOWN_HOST_TERMS)
        host_terms.add(expected_host.lower())
        mentioned_hosts = {host for host in host_terms if re.search(rf"(?<![a-z0-9_-]){re.escape(host)}(?![a-z0-9_-])", lowered)}
        if mentioned_hosts and expected_host.lower() not in mentioned_hosts:
            raise ApprovalError("user approval message host mismatch")
    expected_action = scope.get("action")
    if expected_action:
        expected_terms = ACTION_TERMS.get(expected_action, {expected_action})
        other_terms = set().union(*(terms for action, terms in ACTION_TERMS.items() if action != expected_action))
        if any(term in lowered for term in other_terms) and not any(term in lowered for term in expected_terms):
            raise ApprovalError("user approval message action mismatch")


def create_approval_record(
    expected: Mapping[str, str],
    *,
    state_root: str | Path | None = None,
    operation_id: str | None = None,
    run_id: str | None = None,
) -> dict[str, str]:
    scope = {str(key): str(value) for key, value in expected.items()}
    digest = plan_sha256(scope)
    now = _utc_now()
    payload = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "approval_id": approval_id_for(scope),
        "plan_sha256": digest,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=APPROVAL_TTL_MINUTES)).isoformat(),
        "status": "pending",
        "scope": scope,
    }
    if operation_id:
        payload["operation_id"] = str(operation_id)
    if run_id:
        payload["run_id"] = str(run_id)
    with _approval_lock(state_root):
        path = approval_state_dir(state_root) / f"{payload['approval_id']}.json"
        _write_json_atomic(path, payload)
    return {
        "approval_id": payload["approval_id"],
        "plan_sha256": payload["plan_sha256"],
        "expires_at": payload["expires_at"],
    }


def record_user_turn_receipt(
    message: str,
    *,
    user_turn_id: str,
    state_root: str | Path | None = None,
    source: str = "ops-approval-prompt",
    approval_id: str | None = None,
    plan_sha256: str | None = None,
) -> dict[str, Any]:
    if not user_turn_id or not str(user_turn_id).strip():
        raise ApprovalError("missing user turn id")
    if not message or not message.strip():
        raise ApprovalError("missing user approval message")
    if (approval_id is None) != (plan_sha256 is None):
        raise ApprovalError("approval receipt binding requires approval id and plan hash")
    if approval_id is not None:
        approval_id = _check_approval_id(approval_id)
        if not isinstance(plan_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", plan_sha256):
            raise ApprovalError("invalid approval plan hash")
    receipt_id = stable_sha256(str(user_turn_id).strip())
    payload = {
        "schema_version": USER_TURN_RECEIPT_SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "user_turn_sha256": receipt_id,
        "message_hmac_sha256": _message_hmac(message, state_root),
        "recorded_at": _iso_now(),
        "status": "recorded",
        "source": source,
    }
    if approval_id is not None and plan_sha256 is not None:
        payload["approval_id"] = approval_id
        payload["plan_sha256"] = plan_sha256
    path = _receipt_path(receipt_id, state_root)
    with _approval_lock(state_root):
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                if approval_id is not None and (
                    existing.get("approval_id") not in {None, approval_id}
                    or existing.get("plan_sha256") not in {None, plan_sha256}
                ):
                    raise ApprovalError("user turn receipt is bound to a different approval plan")
                if approval_id is not None and existing.get("approval_id") is None:
                    if existing.get("message_hmac_sha256") != payload["message_hmac_sha256"]:
                        raise ApprovalError("user turn receipt message does not match")
                    existing["approval_id"] = approval_id
                    existing["plan_sha256"] = plan_sha256
                    _write_json_atomic(path, existing)
                return {
                    key: existing[key]
                    for key in ("schema_version", "receipt_id", "user_turn_sha256", "recorded_at", "status", "source", "approval_id", "plan_sha256")
                    if key in existing
                }
        _write_json_atomic(path, payload)
    return {
        key: payload[key]
        for key in ("schema_version", "receipt_id", "user_turn_sha256", "recorded_at", "status", "source", "approval_id", "plan_sha256")
        if key in payload
    }


def record_user_prompt_turn(
    message: str,
    *,
    user_turn_id: str,
    state_root: str | Path | None = None,
    source: str = "ops-approval-prompt",
    approval_id: str | None = None,
    plan_sha256: str | None = None,
) -> dict[str, Any]:
    return record_user_turn_receipt(
        message,
        user_turn_id=user_turn_id,
        state_root=state_root,
        source=source,
        approval_id=approval_id,
        plan_sha256=plan_sha256,
    )


def approve_plan_with_receipt(
    approval_id: str | None,
    *,
    receipt_id: str | None = None,
    user_turn_id: str | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    approval_id = _check_approval_id(approval_id)
    if not receipt_id:
        if not user_turn_id:
            raise ApprovalError("missing user turn receipt id")
        receipt_id = stable_sha256(str(user_turn_id).strip())
    approval_path = _approval_path(approval_id, state_root)
    receipt_path = _receipt_path(receipt_id, state_root)
    with _approval_lock(state_root):
        payload = _load_record(approval_path, approval_id)
        status = payload.get("status")
        if status == "consumed":
            raise ApprovalError("approval id has already been consumed")
        if status != "pending":
            raise ApprovalError(f"approval id is not pending: {status}")
        scope = _scope(payload)
        _ensure_plan_hash(payload, scope)
        _ensure_not_expired(payload)
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ApprovalError("unknown user turn receipt id") from exc
        except json.JSONDecodeError as exc:
            raise ApprovalError("invalid user turn receipt") from exc
        if not isinstance(receipt, dict) or receipt.get("schema_version") != USER_TURN_RECEIPT_SCHEMA_VERSION:
            raise ApprovalError("unsupported user turn receipt schema")
        if receipt.get("approval_id") != approval_id or receipt.get("plan_sha256") != payload.get("plan_sha256"):
            raise ApprovalError("user turn receipt is not bound to this approval plan")
        if receipt.get("status") != "recorded":
            raise ApprovalError("user turn receipt has already been consumed")
        created_at = _parse_time(payload.get("created_at"), "created_at")
        recorded_at = _parse_time(receipt.get("recorded_at"), "recorded_at")
        if recorded_at < created_at:
            raise ApprovalError("user turn receipt predates approval plan")

        approved_at = _iso_now()
        payload["status"] = "approved"
        payload["approved_at"] = approved_at
        payload["approved_by_turn_sha256"] = receipt["user_turn_sha256"]
        payload["user_turn_receipt_id"] = receipt["receipt_id"]
        receipt["status"] = "consumed"
        receipt["approval_id"] = approval_id
        receipt["plan_sha256"] = payload["plan_sha256"]
        receipt["consumed_at"] = approved_at
        approval_receipt = {
            "schema_version": APPROVAL_RECEIPT_SCHEMA_VERSION,
            "approval_id": approval_id,
            "plan_sha256": payload["plan_sha256"],
            "scope": scope,
            "status": "approved",
            "approved_at": approved_at,
            "user_turn_sha256": receipt["user_turn_sha256"],
            "user_turn_receipt_id": receipt["receipt_id"],
        }
        if payload.get("operation_id"):
            approval_receipt["operation_id"] = payload["operation_id"]
        if payload.get("run_id"):
            approval_receipt["run_id"] = payload["run_id"]
        _write_json_atomic(approval_path, payload)
        _write_json_atomic(receipt_path, receipt)
        _append_jsonl(approval_state_dir(state_root) / "receipts.jsonl", approval_receipt)
        return approval_receipt


def approve_plan_from_user_turn(
    approval_id: str | None,
    message: str | None = None,
    *,
    user_turn_id: str | None = None,
    user_turn_receipt_id: str | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    approval_id = _check_approval_id(approval_id)
    if user_turn_receipt_id:
        return approve_plan_with_receipt(approval_id, receipt_id=user_turn_receipt_id, state_root=state_root)
    if message is None:
        raise ApprovalError("missing user approval message")
    if user_turn_id is None:
        raise ApprovalError("missing user turn id")
    with _approval_lock(state_root):
        payload = _load_record(_approval_path(approval_id, state_root), approval_id)
        scope = _scope(payload)
        _message_approves_scope(message, scope)
        digest = str(payload.get("plan_sha256"))
    receipt = record_user_turn_receipt(
        message,
        user_turn_id=user_turn_id,
        state_root=state_root,
        source="opsctl-direct",
        approval_id=approval_id,
        plan_sha256=digest,
    )
    return approve_plan_with_receipt(approval_id, receipt_id=str(receipt["receipt_id"]), state_root=state_root)


def verify_approval_record(
    approval_id: str | None,
    expected: Mapping[str, str],
    *,
    state_root: str | Path | None = None,
    operation_id: str | None = None,
    run_id: str | None = None,
) -> None:
    approval_id = _check_approval_id(approval_id)
    path = _approval_path(approval_id, state_root)
    with _approval_lock(state_root):
        payload = _load_record(path, approval_id)
        scope = _scope(payload)
        Approval(scope).require({str(key): str(value) for key, value in expected.items()})
        _ensure_plan_hash(payload, scope)
        _ensure_not_expired(payload)
        _ensure_metadata(payload, operation_id, run_id)
        status = payload.get("status")
        if status == "pending":
            raise ApprovalError("approval id has not been approved")
        if status == "consumed":
            raise ApprovalError("approval id has already been consumed")
        if status != "approved":
            raise ApprovalError(f"approval id has invalid status: {status}")


def consume_approval_record(
    approval_id: str | None,
    expected: Mapping[str, str],
    *,
    state_root: str | Path | None = None,
    operation_id: str | None = None,
    run_id: str | None = None,
) -> None:
    approval_id = _check_approval_id(approval_id)
    path = _approval_path(approval_id, state_root)
    with _approval_lock(state_root):
        payload = _load_record(path, approval_id)
        scope = _scope(payload)
        Approval(scope).require({str(key): str(value) for key, value in expected.items()})
        _ensure_plan_hash(payload, scope)
        _ensure_not_expired(payload)
        _ensure_metadata(payload, operation_id, run_id)
        status = payload.get("status")
        if status == "pending":
            raise ApprovalError("approval id has not been approved")
        if status == "consumed":
            raise ApprovalError("approval id has already been consumed")
        if status != "approved":
            raise ApprovalError(f"approval id has invalid status: {status}")
        payload["status"] = "consumed"
        payload["consumed_at"] = _iso_now()
        _write_json_atomic(path, payload)


def list_approval_records(
    *,
    state_root: str | Path | None = None,
    statuses: set[str] | None = None,
) -> list[dict[str, Any]]:
    directory = approval_state_dir(state_root)
    rows: list[dict[str, Any]] = []
    with _approval_lock(state_root):
        for path in sorted(directory.glob("ap-*.json")):
            try:
                payload = _load_record(path, path.stem)
                status = str(payload.get("status") or "")
                if statuses is not None and status not in statuses:
                    continue
                scope = _scope(payload)
                rows.append(
                    {
                        "schema_version": payload.get("schema_version"),
                        "approval_id": payload.get("approval_id"),
                        "plan_sha256": payload.get("plan_sha256"),
                        "created_at": payload.get("created_at"),
                        "expires_at": payload.get("expires_at"),
                        "approved_at": payload.get("approved_at"),
                        "consumed_at": payload.get("consumed_at"),
                        "status": status,
                        "scope": scope,
                        "operation_id": payload.get("operation_id"),
                        "run_id": payload.get("run_id"),
                    }
                )
            except ApprovalError:
                continue
    return rows


def approval_record_metadata(approval_id: str | None, *, state_root: str | Path | None = None) -> dict[str, Any]:
    approval_id = _check_approval_id(approval_id)
    with _approval_lock(state_root):
        payload = _load_record(_approval_path(approval_id, state_root), approval_id)
        scope = _scope(payload)
        return {
            "approval_id": approval_id,
            "plan_sha256": payload.get("plan_sha256"),
            "status": payload.get("status"),
            "scope": scope,
            "operation_id": payload.get("operation_id"),
            "run_id": payload.get("run_id"),
        }


def approve_matching_pending_from_user_turn(
    message: str,
    *,
    user_turn_id: str,
    state_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    pending = list_approval_records(state_root=state_root, statuses={"pending"})
    explicit_ids = [item for item in pending if str(item.get("approval_id")) in message]
    candidates = explicit_ids or pending
    matching: list[str] = []
    errors: list[str] = []
    for item in candidates:
        approval_id = str(item["approval_id"])
        try:
            _message_approves_scope(message, item["scope"])
        except ApprovalError as exc:
            errors.append(str(exc))
            continue
        matching.append(approval_id)
    if not matching:
        raise ApprovalError(errors[0] if errors else "no pending approval matches user message")
    if len(matching) > 1:
        raise ApprovalError("ambiguous approval matches multiple pending plans")
    return [approve_plan_from_user_turn(matching[0], message, user_turn_id=user_turn_id, state_root=state_root)]
