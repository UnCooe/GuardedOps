from __future__ import annotations

import argparse
import sys

from guarded_ops.hook_policy import decide_command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ops-guard-hook")
    parser.add_argument("--fleet", default="examples/fleet.example.json")
    parser.add_argument("--command", required=True)
    args = parser.parse_args(argv)
    decision = decide_command(args.command, args.fleet)
    if decision.allowed:
        print(decision.reason)
        return 0
    print(decision.reason, file=sys.stderr)
    if decision.suggestion:
        print(decision.suggestion, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

