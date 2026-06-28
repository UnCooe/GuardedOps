#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
ROOT="${2:-.}"

if [[ "${MODE}" != "--public" ]]; then
  echo "usage: scripts/leak_scan.sh --public <path>" >&2
  exit 2
fi

python - "$ROOT" <<'PY'
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
allowed_ip_networks = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
sentinels = [
    "INTERNAL_" + "PROJECT_SENTINEL",
    "REAL_" + "HOST_SENTINEL",
    "PRIVATE_" + "PROXY_SENTINEL",
]
home_path_re = re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+")
private_key_re = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
env_file_re = re.compile(r"(^|/)\.env($|[./])")
ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

skip_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist", ".guarded_ops"}
violations: list[str] = []

def should_skip(path: Path) -> bool:
    return any(part in skip_dirs for part in path.parts)

if root.resolve().name != "dist":
    for generated in (".guarded_ops", "build", "dist"):
        generated_path = root / generated
        if generated_path.exists():
            violations.append(f"{generated}: generated directory must be removed before public release")

for path in sorted(root.rglob("*")):
    rel = path.relative_to(root)
    if should_skip(rel) or not path.is_file():
        continue
    if env_file_re.search(str(rel)):
        violations.append(f"{rel}: env files are not allowed in the public repo")
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for sentinel in sentinels:
        if sentinel in text:
            violations.append(f"{rel}: synthetic private sentinel found")
    if private_key_re.search(text):
        violations.append(f"{rel}: private key material marker found")
    for match in home_path_re.finditer(text):
        violations.append(f"{rel}: absolute home path found: {match.group(0)}")
    for match in ipv4_re.finditer(text):
        value = match.group(0)
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not any(ip in network for network in allowed_ip_networks):
            violations.append(f"{rel}: non-documentation IPv4 address found: {value}")

if violations:
    for item in violations:
        print(item)
    raise SystemExit(1)
print("public leak scan passed")
PY
