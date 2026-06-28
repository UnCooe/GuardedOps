from __future__ import annotations

from pathlib import Path


def parse_set_expr(expr: str) -> tuple[str, str]:
    if "=" not in expr:
        raise ValueError("--set must be KEY=VALUE")
    key, value = expr.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError("--set key must not be empty")
    if "\n" in key or "\r" in key:
        raise ValueError("--set key must be a single line")
    if "\n" in value or "\r" in value:
        raise ValueError("--set value must be a single line")
    return key, value


def read_env(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def set_env_value(lines: list[str], key: str, value: str) -> list[str]:
    rendered = f"{key}={value}"
    output: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(f"{key}="):
            output.append(rendered)
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(rendered)
    return output


def write_env(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
