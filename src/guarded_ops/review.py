from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from .errors import GuardedOpsError
from .redaction import redact_text

SECRET_RE = re.compile(r"(token|secret|password|api[_-]?key|authorization|cookie)", re.I)


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def classify_command(command: str) -> tuple[str, str]:
    lower = command.lower()
    if SECRET_RE.search(command):
        return "sensitive_read", "sensitive_read"
    if " opsctl " in f" {lower} " or lower.startswith("opsctl "):
        return "guarded_entry", "safe_read"
    if lower.startswith("ssh ") or " ssh " in lower:
        return "direct_ssh", "unknown"
    if "rm -rf" in lower or " sudo " in f" {lower} ":
        return "dangerous_write", "dangerous_write"
    return "unknown", "unknown"


def normalize_template(data: dict[str, Any], command: str) -> str:
    template = str(data.get("template") or "").strip()
    if not template:
        template = command.split(" ", 1)[0] if command else "unknown"
    template = redact_text(template)
    if SECRET_RE.search(template):
        return "<redacted-template>"
    return template


def iter_session_events(input_dir: Path) -> list[dict[str, Any]]:
    if not input_dir.exists():
        raise GuardedOpsError(f"input directory does not exist: {input_dir}")
    events: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*.jsonl")):
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            data = json.loads(line)
            command = str(data.get("command", ""))
            intent, safety = classify_command(command)
            events.append(
                {
                    "source": path.name,
                    "line": index,
                    "command_hash": stable_hash(command),
                    "normalized_template": normalize_template(data, command),
                    "intent": intent,
                    "safety": safety,
                }
            )
    return events


def write_outputs(events: list[dict[str, Any]], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "event_count": len(events),
        "direct_ssh": sum(1 for item in events if item["intent"] == "direct_ssh"),
        "guarded_entry": sum(1 for item in events if item["intent"] == "guarded_entry"),
        "dangerous_write": sum(1 for item in events if item["intent"] == "dangerous_write"),
        "sensitive_read": sum(1 for item in events if item["intent"] == "sensitive_read"),
    }
    candidates = []
    if summary["direct_ssh"]:
        candidates.append(
            {
                "target_type": "docs",
                "problem_pattern": "direct SSH appeared in synthetic sessions",
                "recommended_change": "Document the guarded opsctl or wrapper path for this operation.",
                "decision": "manual_review",
            }
        )
    (output_dir / "operation-events.json").write_text(json.dumps({"events": events}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "operation-candidates.json").write_text(json.dumps({"candidates": candidates}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "operation-summary.md").write_text(
        "\n".join(
            [
                "# Operation Review Summary",
                "",
                f"- Events: {summary['event_count']}",
                f"- Guarded entry: {summary['guarded_entry']}",
                f"- Direct SSH: {summary['direct_ssh']}",
                f"- Sensitive read: {summary['sensitive_read']}",
                f"- Dangerous write: {summary['dangerous_write']}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return summary


def cmd_collect(args: argparse.Namespace) -> int:
    events = iter_session_events(Path(args.input))
    summary = write_outputs(events, Path(args.output))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    output = Path(args.output)
    summary = output / "operation-summary.md"
    if not summary.exists():
        raise GuardedOpsError(f"summary not found: {summary}")
    print(summary.read_text(encoding="utf-8"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ops-review")
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect")
    collect.add_argument("--input", required=True)
    collect.add_argument("--output", default=str(Path(".guarded_ops") / "review"))
    collect.set_defaults(func=cmd_collect)
    mine = sub.add_parser("mine-operations")
    mine.add_argument("--input", required=True)
    mine.add_argument("--output", default=str(Path(".guarded_ops") / "review"))
    mine.set_defaults(func=cmd_collect)
    report = sub.add_parser("report")
    report.add_argument("--output", default=str(Path(".guarded_ops") / "review"))
    report.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GuardedOpsError as exc:
        print(f"ops-review: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
