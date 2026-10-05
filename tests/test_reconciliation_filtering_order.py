from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
SELECTED_HOST = "selected-host"
SELECTED_RUN = "selected-run"
SINCE = "2026-08-12T00:00:00Z"


def run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)


def write_jsonl(path: Path, records: list[dict[str, Any] | str]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            if isinstance(record, str):
                handle.write(record + "\n")
            else:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


def intent_event(
    operation_id: str,
    *,
    host: str = SELECTED_HOST,
    run_id: str = SELECTED_RUN,
    ts: str = "2026-08-12T00:00:02Z",
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.intent/v1",
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": ts,
        "host": host,
        "action": "apply-config-batch",
        "operation_kind": "write",
        "status": "planned",
        "transport": "local",
        "command": ["opsctl", "apply-config-batch", "--change-id", operation_id],
        "details": {"change_id": operation_id},
    }


def audit_event(
    operation_id: str,
    *,
    phase: str,
    status: str,
    host: str = SELECTED_HOST,
    run_id: str = SELECTED_RUN,
    ts: str = "2026-08-12T00:00:03Z",
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.audit/v1",
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": ts,
        "host": host,
        "action": "apply-config-batch",
        "operation_kind": "write",
        "phase": phase,
        "status": status,
        "reason_code": None,
        "details": {"change_id": operation_id},
        "wrapper_version": "0.2.0-test",
        "policy_version": "demo-v2",
    }


def evidence_event(
    operation_id: str,
    *,
    host: str = SELECTED_HOST,
    run_id: str = SELECTED_RUN,
    ts: str = "2026-08-12T00:00:04Z",
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.evidence/v1",
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": ts,
        "host": host,
        "source": "ops-guard-hook",
        "status": "blocked",
        "reason_code": "hook_denied",
        "details": {"command_template": "opsctl apply-config-batch"},
    }


class ReconciliationFilteringOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guardedops-reconcile-filtering-"))
        self.intent = self.tmp / "intent.jsonl"
        self.audit = self.tmp / "audit.jsonl"
        self.evidence = self.tmp / "evidence.jsonl"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def reconcile(self) -> subprocess.CompletedProcess[str]:
        return run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.review",
                "audit-reconcile",
                "--intent",
                str(self.intent),
                "--audit",
                str(self.audit),
                "--evidence",
                str(self.evidence),
                "--host",
                SELECTED_HOST,
                "--run-id",
                SELECTED_RUN,
                "--since",
                SINCE,
            ],
            cwd=self.tmp,
        )

    def payload(self, result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        self.assertTrue(result.stdout.strip(), result.stderr)
        return json.loads(result.stdout)

    def test_out_of_scope_malformed_unknown_and_legacy_records_do_not_taint_selected_report(self) -> None:
        selected = intent_event("op-selected-001")
        out_of_scope_malformed_intent = intent_event(
            "op-other-intent-malformed",
            host="other-host",
            run_id="other-run",
        )
        del out_of_scope_malformed_intent["command"]

        write_jsonl(self.intent, [selected, out_of_scope_malformed_intent])
        write_jsonl(
            self.audit,
            [
                audit_event("op-selected-001", phase="start", status="started"),
                audit_event("op-selected-001", phase="result", status="success"),
                {
                    "schema_version": "guardedops.audit/v999",
                    "operation_id": "op-other-audit-unknown",
                    "run_id": "other-run",
                    "ts": "2026-08-12T00:00:03Z",
                    "host": "other-host",
                },
                {
                    "run_id": "other-run",
                    "ts": "2026-08-12T00:00:03Z",
                    "host": "other-host",
                    "action": "deploy-ref",
                    "status": "success",
                },
                {
                    "schema_version": "guardedops.audit/v1",
                    "operation_id": "op-other-audit-malformed",
                    "run_id": "other-run",
                    "ts": "2026-08-12T00:00:03Z",
                    "host": "other-host",
                    "action": "deploy-ref",
                    "operation_kind": "write",
                    "status": "success",
                },
            ],
        )
        write_jsonl(
            self.evidence,
            [
                {
                    "schema_version": "guardedops.evidence/v999",
                    "operation_id": "op-other-evidence-unknown",
                    "run_id": "other-run",
                    "ts": "2026-08-12T00:00:04Z",
                    "host": "other-host",
                },
                {
                    "run_id": "other-run",
                    "ts": "2026-08-12T00:00:04Z",
                    "host": "other-host",
                    "source": "external-ssh",
                    "status": "observed",
                },
                {
                    "schema_version": "guardedops.evidence/v1",
                    "operation_id": "op-other-evidence-malformed",
                    "run_id": "other-run",
                    "ts": "2026-08-12T00:00:04Z",
                    "host": "other-host",
                    "status": "observed",
                },
            ],
        )

        result = self.reconcile()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = self.payload(result)
        self.assertEqual(report["verdict"], "complete")
        self.assertEqual(report["filters"], {"host": SELECTED_HOST, "run_id": SELECTED_RUN, "since": SINCE})
        self.assertEqual(report["counts"]["known_writes"], 1)
        self.assertEqual(report["coverage"]["explained_writes"], 1)
        self.assertEqual(report["operations"][0]["operation_id"], "op-selected-001")
        self.assertEqual(report["reasons"], [])
        self.assertEqual(report["records"].get("intent_malformed", 0), 0)
        self.assertEqual(report["records"].get("audit_malformed", 0), 0)
        self.assertEqual(report["records"].get("evidence_malformed", 0), 0)
        self.assertEqual(report["records"].get("legacy_audit", 0), 0)
        self.assertEqual(report["records"].get("legacy_evidence", 0), 0)

    def test_in_scope_malformed_legacy_and_unknown_records_force_partial(self) -> None:
        write_jsonl(self.intent, [intent_event("op-selected-002")])
        write_jsonl(
            self.audit,
            [
                audit_event("op-selected-002", phase="start", status="started"),
                audit_event("op-selected-002", phase="result", status="success"),
                {
                    "time": "2026-08-12T00:00:03Z",
                    "action": "deploy-ref",
                    "status": "success",
                },
                {
                    "schema_version": "guardedops.audit/v999",
                    "operation_id": "op-selected-unknown-audit",
                    "run_id": SELECTED_RUN,
                    "ts": "2026-08-12T00:00:03Z",
                    "host": SELECTED_HOST,
                },
                {
                    "schema_version": "guardedops.audit/v999",
                    "operation_id": "op-selected-invalid-host-type",
                    "run_id": SELECTED_RUN,
                    "ts": "2026-08-12T00:00:03Z",
                    "host": [SELECTED_HOST],
                },
                {
                    "schema_version": "guardedops.audit/v999",
                    "operation_id": "op-selected-invalid-run-type",
                    "run_id": 42,
                    "ts": "2026-08-12T00:00:03Z",
                    "host": SELECTED_HOST,
                },
                {
                    "schema_version": "guardedops.audit/v1",
                    "operation_id": "op-selected-malformed",
                    "run_id": SELECTED_RUN,
                    "ts": "2026-08-12T00:00:03Z",
                    "host": SELECTED_HOST,
                    "action": "deploy-ref",
                    "operation_kind": "write",
                    "status": "success",
                },
                {
                    "schema_version": "guardedops.audit/v1",
                    "operation_id": "op-selected-empty-host",
                    "run_id": SELECTED_RUN,
                    "ts": "2026-08-12T00:00:03Z",
                    "host": "",
                    "action": "deploy-ref",
                    "operation_kind": "write",
                    "status": "success",
                },
                {
                    "schema_version": "guardedops.audit/v1",
                    "operation_id": "op-selected-empty-run",
                    "run_id": "",
                    "ts": "2026-08-12T00:00:03Z",
                    "host": SELECTED_HOST,
                    "action": "deploy-ref",
                    "operation_kind": "write",
                    "status": "success",
                },
            ],
        )
        write_jsonl(
            self.evidence,
            [
                {
                    "schema_version": "guardedops.evidence/v999",
                    "operation_id": "op-selected-unknown",
                    "run_id": SELECTED_RUN,
                    "ts": "2026-08-12T00:00:04Z",
                    "host": SELECTED_HOST,
                    "source": "external-ssh",
                    "status": "observed",
                }
            ],
        )

        result = self.reconcile()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        report = self.payload(result)
        self.assertEqual(report["verdict"], "partial")
        self.assertIn("malformed", report["reasons"])
        self.assertIn("legacy_records", report["reasons"])
        self.assertIn("unknown_schema", report["reasons"])
        self.assertEqual(report["operations"][0]["operation_id"], "op-selected-002")

    def test_filtered_reconciliation_keeps_operation_id_matching_exact(self) -> None:
        write_jsonl(self.intent, [intent_event("op-selected-exact")])
        write_jsonl(
            self.audit,
            [
                audit_event("op-different-exact", phase="start", status="started"),
                audit_event("op-different-exact", phase="result", status="success"),
                audit_event(
                    "op-out-of-scope-exact",
                    phase="start",
                    status="started",
                    host="other-host",
                    run_id="other-run",
                ),
                audit_event(
                    "op-out-of-scope-exact",
                    phase="result",
                    status="success",
                    host="other-host",
                    run_id="other-run",
                ),
            ],
        )
        write_jsonl(self.evidence, [])

        result = self.reconcile()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        report = self.payload(result)
        self.assertEqual(report["verdict"], "partial")
        self.assertIn("missing_wrapper_audit", report["reasons"])
        self.assertEqual(report["counts"]["known_writes"], 2)
        self.assertEqual(report["counts"]["missing_wrapper_audit"], 1)
        self.assertEqual(report["counts"]["unmatched_wrapper_writes"], 1)
        operations = {item["operation_id"]: item for item in report["operations"]}
        self.assertEqual(operations["op-selected-exact"]["audit_match"], "missing")
        self.assertEqual(operations["op-different-exact"]["intent_match"], "missing")


if __name__ == "__main__":
    unittest.main()
