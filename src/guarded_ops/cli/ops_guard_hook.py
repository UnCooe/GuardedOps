from __future__ import annotations

import argparse
import sys
from pathlib import Path

from guarded_ops.hook_policy import append_hook_evidence, decide_command, hook_block_evidence, protected_command_destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ops-guard-hook")
    parser.add_argument("--fleet", default="examples/fleet.example.json")
    parser.add_argument("--command", required=True)
    parser.add_argument("--evidence-output", default=str(Path(".guarded_ops") / "evidence.jsonl"))
    parser.add_argument("--operation-id")
    parser.add_argument("--run-id")
    parser.add_argument("--user-turn-id")
    args = parser.parse_args(argv)
    decision = decide_command(args.command, args.fleet)
    if decision.allowed:
        print(decision.reason)
        return 0
    host = protected_command_destination(args.command, args.fleet)
    evidence = hook_block_evidence(
        args.command,
        decision,
        user_turn_id=args.user_turn_id,
        operation_id=args.operation_id,
        run_id=args.run_id,
        host=host,
    )
    try:
        append_hook_evidence(args.evidence_output, evidence)
    except OSError as exc:
        print(f"failed to append hook evidence: {exc}", file=sys.stderr)
    print(decision.reason, file=sys.stderr)
    if decision.suggestion:
        print(decision.suggestion, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
