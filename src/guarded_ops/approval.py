from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Mapping

from .errors import ApprovalError


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
