from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any


DOTENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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


def parse_json_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def parse_batch_set_expr(expr: str) -> dict[str, Any]:
    key, raw = parse_set_expr(expr)
    return {"path": key, "value": parse_json_value(raw)}


def parse_dotenv(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if DOTENV_KEY_RE.match(key):
            data[key] = value.strip().strip("\"'")
    return data


def render_dotenv_value(value: Any) -> str:
    if not isinstance(value, (str, int, float, bool)) and value is not None:
        raise ValueError("dotenv values must be scalar")
    text = "" if value is None else str(value)
    if "\n" in text or "\r" in text:
        raise ValueError("dotenv values must be single-line")
    return text


def patch_dotenv(text: str, sets: list[dict[str, Any]], deletes: list[str]) -> tuple[str, set[str]]:
    for item in sets:
        if "." in item["path"] or not DOTENV_KEY_RE.match(item["path"]):
            raise ValueError(f"dotenv key must be a top-level env name: {item['path']}")
    for key in deletes:
        if "." in key or not DOTENV_KEY_RE.match(key):
            raise ValueError(f"dotenv key must be a top-level env name: {key}")

    before = parse_dotenv(text)
    after = dict(before)
    set_by_key = {item["path"]: render_dotenv_value(item["value"]) for item in sets}
    for key, value in set_by_key.items():
        after[key] = value
    for key in deletes:
        after.pop(key, None)
    changed = {key for key in set(set_by_key) | set(deletes) if before.get(key) != after.get(key)}

    seen: set[str] = set()
    output: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            output.append(line)
            continue
        raw_key, _ = line.split("=", 1)
        key = raw_key.strip()
        if key in deletes:
            seen.add(key)
            continue
        if key in set_by_key:
            output.append(f"{key}={set_by_key[key]}")
            seen.add(key)
            continue
        output.append(line)
    for key, value in set_by_key.items():
        if key not in seen:
            output.append(f"{key}={value}")
    return "\n".join(output) + "\n", changed


def set_dotted(data: Any, key_path: str, value: Any) -> None:
    parts = key_path.split(".")
    cursor = data
    for part in parts[:-1]:
        if isinstance(cursor, dict):
            cursor = cursor.setdefault(part, {})
        elif isinstance(cursor, list) and part.isdigit():
            cursor = cursor[int(part)]
        else:
            raise ValueError(f"cannot traverse key path at {part}")
    last = parts[-1]
    if isinstance(cursor, dict):
        cursor[last] = value
    elif isinstance(cursor, list) and last.isdigit():
        cursor[int(last)] = value
    else:
        raise ValueError(f"cannot set key path at {last}")


def delete_dotted(data: Any, key_path: str) -> None:
    parts = key_path.split(".")
    cursor = data
    for part in parts[:-1]:
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        elif isinstance(cursor, list) and part.isdigit():
            cursor = cursor[int(part)]
        else:
            raise ValueError(f"cannot traverse key path at {part}")
    last = parts[-1]
    if isinstance(cursor, dict) and last in cursor:
        del cursor[last]
    elif isinstance(cursor, list) and last.isdigit():
        del cursor[int(last)]
    else:
        raise ValueError(f"cannot delete missing key path {key_path}")


def changed_json_paths(old: Any, new: Any, prefix: str = "") -> set[str]:
    if type(old) is not type(new):
        return {prefix or "<root>"}
    if isinstance(old, dict):
        paths: set[str] = set()
        for key in sorted(set(old) | set(new)):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in old or key not in new:
                paths.add(child)
            else:
                paths.update(changed_json_paths(old[key], new[key], child))
        return paths
    if isinstance(old, list):
        paths: set[str] = set()
        for index in range(max(len(old), len(new))):
            child = f"{prefix}.{index}" if prefix else str(index)
            if index >= len(old) or index >= len(new):
                paths.add(child)
            else:
                paths.update(changed_json_paths(old[index], new[index], child))
        return paths
    return set() if old == new else {prefix or "<root>"}


def path_allowed(changed: str, intended: set[str]) -> bool:
    return any(changed == item or changed.startswith(item + ".") or item.startswith(changed + ".") for item in intended)


def patch_json(text: str, sets: list[dict[str, Any]], deletes: list[str]) -> tuple[str, set[str]]:
    old = json.loads(text)
    new = deepcopy(old)
    intended = {item["path"] for item in sets} | set(deletes)
    for item in sets:
        set_dotted(new, item["path"], item["value"])
    for key in deletes:
        delete_dotted(new, key)
    changed = changed_json_paths(old, new)
    unexpected = sorted(path for path in changed if not path_allowed(path, intended))
    if unexpected:
        raise ValueError("semantic diff includes unexpected paths: " + ", ".join(unexpected[:20]))
    return json.dumps(new, indent=2, sort_keys=False) + "\n", changed


def patch_config_text(file_name: str, text: str, sets: list[dict[str, Any]], deletes: list[str]) -> tuple[str, set[str]]:
    if Path(file_name).suffix == ".env" or Path(file_name).name == ".env":
        return patch_dotenv(text, sets, deletes)
    return patch_json(text, sets, deletes)
