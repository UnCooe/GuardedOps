from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import PolicyError


def load_policy(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    if "actions" not in data or not isinstance(data["actions"], dict):
        raise PolicyError("policy must contain an actions object")
    return data


def action_policy(policy: dict[str, Any], action: str) -> dict[str, Any]:
    actions = policy.get("actions") or {}
    item = actions.get(action)
    if not isinstance(item, dict) or not item.get("enabled", False):
        raise PolicyError(f"action is not allowed: {action}")
    return item

