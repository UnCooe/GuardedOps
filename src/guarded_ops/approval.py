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
            values[key] = value
        return cls(values)

    def require(self, expected: Mapping[str, str]) -> None:
        mismatches: list[str] = []
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

