#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guarded_ops.approval import ApprovalError, _message_approves_scope, list_approval_records, record_user_turn_receipt


def _extract_prompt(payload: dict[str, object]) -> str:
    for key in ("user_prompt", "prompt", "input", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _state_root(payload: dict[str, object]) -> Path:
    configured = os.environ.get("GUARDEDOPS_STATE_ROOT")
    if configured:
        return Path(configured).expanduser()
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        return Path(cwd).expanduser() / ".guarded_ops"
    return Path.cwd() / ".guarded_ops"


def _turn_ref(payload: dict[str, object], prompt: str) -> str | None:
    for key in ("user_turn_id", "turn_id", "prompt_id", "message_id"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return f"{key}:{value.strip()}"

    transcript = payload.get("transcript_path")
    session = payload.get("session_id") or payload.get("conversation_id") or payload.get("thread_id")
    material: list[str] = []
    if isinstance(transcript, str) and transcript.strip():
        material.append(f"transcript:{Path(transcript).expanduser()}")
    if isinstance(session, str) and session.strip():
        material.append(f"session:{session.strip()}")
    if not material:
        return None
    material.append("prompt-sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest())
    return "|".join(material)


def _emit_context(message: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": message,
                }
            },
            ensure_ascii=False,
        )
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    if not isinstance(payload, dict):
        return 0

    prompt = _extract_prompt(payload)
    if not prompt:
        return 0

    state_root = _state_root(payload)
    approvals_dir = state_root / "approvals"
    if not approvals_dir.exists():
        return 0

    turn_ref = _turn_ref(payload, prompt)
    if not turn_ref:
        _emit_context("GuardedOps approval was not recorded: hook payload has no stable user-turn reference.")
        return 0

    pending = list_approval_records(state_root=state_root, statuses={"pending"})
    if not pending:
        return 0
    matching = []
    for item in pending:
        try:
            _message_approves_scope(prompt, item["scope"])
        except ApprovalError:
            continue
        matching.append(item)
    candidate = matching[0] if len(matching) == 1 else None
    try:
        receipt = record_user_turn_receipt(
            prompt,
            user_turn_id=turn_ref,
            state_root=state_root,
            approval_id=candidate["approval_id"] if candidate else None,
            plan_sha256=candidate["plan_sha256"] if candidate else None,
        )
    except ApprovalError:
        return 0
    snippets = []
    for item in pending[:3]:
        scope = item.get("scope") if isinstance(item.get("scope"), dict) else {}
        rendered_scope = " ".join(f"{key}={value}" for key, value in sorted(scope.items()))
        snippets.append(
            f"approval_id={item['approval_id']} plan_sha256={item['plan_sha256']} {rendered_scope}".strip()
        )
    more = "" if len(pending) <= 3 else f" and {len(pending) - 3} more"
    _emit_context(
        "GuardedOps user-turn receipt recorded: "
        f"receipt_id={receipt['receipt_id']}. "
        "If the user's message clearly approves exactly one pending plan, run "
        f"opsctl approve-plan --approval-id <id> --receipt-id {receipt['receipt_id']}. "
        "Pending: "
        + "; ".join(snippets)
        + more
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
