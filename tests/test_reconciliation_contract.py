from __future__ import annotations

import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run_cli(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    env = {"PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)


def write_jsonl(path: Path, records: list[dict[str, Any] | str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            if isinstance(record, str):
                handle.write(record + "\n")
            else:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_reconcile(
    intent: Path,
    audit: Path,
    *extra: str,
    evidence: Path | None = None,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    args = [
        PYTHON,
        "-m",
        "guarded_ops.review",
        "audit-reconcile",
        "--intent",
        str(intent),
        "--audit",
        str(audit),
    ]
    if evidence is not None:
        args.extend(["--evidence", str(evidence)])
    args.extend(extra)
    return run_cli(args, cwd=cwd)


def intent_event(
    operation_id: str,
    *,
    action: str = "apply-config-batch",
    operation_kind: str = "write",
    host: str = "demo-local",
    run_id: str = "run-contract",
    ts: str = "2026-08-12T00:00:00Z",
    status: str = "planned",
    transport: str = "local",
    command: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.intent/v1",
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": ts,
        "host": host,
        "action": action,
        "operation_kind": operation_kind,
        "status": status,
        "transport": transport,
        "command": command or ["opsctl", "apply-config-batch", "--change-id", operation_id],
        "details": details or {"change_id": operation_id},
    }


def audit_event(
    operation_id: str,
    *,
    phase: str,
    status: str,
    action: str = "apply-config-batch",
    operation_kind: str = "write",
    host: str = "demo-local",
    run_id: str = "run-contract",
    ts: str = "2026-08-12T00:00:01Z",
    reason_code: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.audit/v1",
        "operation_id": operation_id,
        "run_id": run_id,
        "ts": ts,
        "host": host,
        "action": action,
        "operation_kind": operation_kind,
        "phase": phase,
        "status": status,
        "reason_code": reason_code,
        "details": details or {"change_id": operation_id, "file": "config/app.json"},
        "wrapper_version": "0.2.0-test",
        "policy_version": "demo-v2",
    }


def hook_evidence(
    operation_id: str,
    *,
    status: str = "blocked",
    reason_code: str = "hook_denied",
    ts: str = "2026-08-12T00:00:02Z",
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.evidence/v1",
        "operation_id": operation_id,
        "run_id": "run-contract",
        "ts": ts,
        "host": "demo-local",
        "source": "ops-guard-hook",
        "status": status,
        "reason_code": reason_code,
        "details": {"command_template": "opsctl apply-config-batch"},
    }


class ReconciliationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guardedops-reconcile-test-"))
        self.intent = self.tmp / "intent.jsonl"
        self.audit = self.tmp / "audit.jsonl"
        self.evidence = self.tmp / "evidence.jsonl"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def assert_json_stdout(self, result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        self.assertTrue(result.stdout.strip(), result.stderr)
        return json.loads(result.stdout)

    def test_reconcile_complete_pairs_write_intent_with_exact_operation_id_audit(self) -> None:
        write_jsonl(self.intent, [intent_event("op-exact-001")])
        write_jsonl(
            self.audit,
            [
                audit_event("op-exact-001", phase="start", status="started"),
                audit_event("op-exact-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["schema_version"], "guardedops.audit-reconcile/v1")
        self.assertEqual(payload["verdict"], "complete")
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["wrapper_success"], 1)
        self.assertEqual(payload["counts"]["missing_wrapper_audit"], 0)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 1.0)
        self.assertEqual(payload["operations"][0]["operation_id"], "op-exact-001")
        self.assertEqual(payload["operations"][0]["audit_match"], "exact")

    def test_reconcile_requires_exact_operation_id_not_host_action_run_correlation(self) -> None:
        write_jsonl(self.intent, [intent_event("op-intent-expected")])
        write_jsonl(
            self.audit,
            [
                audit_event("op-wrapper-different", phase="start", status="started"),
                audit_event("op-wrapper-different", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertIn("missing_wrapper_audit", payload["reasons"])
        self.assertEqual(payload["counts"]["missing_wrapper_audit"], 1)
        self.assertEqual(payload["counts"]["unmatched_wrapper_writes"], 1)
        self.assertEqual(payload["operations"][0]["operation_id"], "op-intent-expected")
        self.assertEqual(payload["operations"][0]["audit_match"], "missing")

    def test_reconcile_excludes_reads_from_intent_denominator(self) -> None:
        write_jsonl(
            self.intent,
            [
                intent_event("op-read-001", action="runtime-baseline", operation_kind="read", command=["opsctl", "baseline"]),
                intent_event("op-write-001"),
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-read-001", action="runtime-baseline", operation_kind="read", phase="result", status="success", details={}),
                audit_event("op-write-001", phase="start", status="started"),
                audit_event("op-write-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["counts"]["intent_records"], 2)
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["known_reads_excluded"], 1)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 1.0)

    def test_reconcile_counts_hook_blocked_and_external_write_evidence(self) -> None:
        write_jsonl(self.intent, [intent_event("op-hook-001"), intent_event("op-wrapper-001")])
        write_jsonl(
            self.audit,
            [
                audit_event("op-wrapper-001", phase="start", status="started"),
                audit_event("op-wrapper-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )
        write_jsonl(
            self.evidence,
            [
                hook_evidence("op-hook-001"),
                {
                    "schema_version": "guardedops.evidence/v1",
                    "operation_id": "external-ssh-001",
                    "run_id": "run-contract",
                    "ts": "2026-08-12T00:00:04Z",
                    "host": "demo-local",
                    "source": "external-ssh",
                    "status": "observed",
                    "reason_code": "external_write_detected",
                    "details": {"command_template": "ssh <host> -- <redacted>"},
                },
            ],
        )

        result = run_reconcile(self.intent, self.audit, evidence=self.evidence)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["counts"]["known_writes"], 3)
        self.assertEqual(payload["counts"]["wrapper_success"], 1)
        self.assertEqual(payload["counts"]["hook_blocked"], 1)
        self.assertEqual(payload["counts"]["external_writes"], 1)
        self.assertIn("external_write_detected", payload["reasons"])
        self.assertIn("hook_blocked", payload["reasons"])

    def test_reconcile_hook_only_evidence_counts_as_explained_but_not_green(self) -> None:
        write_jsonl(self.intent, [])
        write_jsonl(self.audit, [])
        write_jsonl(self.evidence, [hook_evidence("op-hook-only-001")])

        result = run_reconcile(self.intent, self.audit, evidence=self.evidence)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["hook_blocked"], 1)
        self.assertEqual(payload["coverage"]["explained_writes"], 1)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 1.0)
        self.assertIn("hook_blocked", payload["reasons"])

    def test_reconcile_evidence_metadata_conflict_is_not_counted_as_explained(self) -> None:
        write_jsonl(self.intent, [intent_event("op-hook-conflict-001", host="demo-local")])
        write_jsonl(self.audit, [])
        conflicting = hook_evidence("op-hook-conflict-001")
        conflicting["host"] = "other-host"
        write_jsonl(self.evidence, [conflicting])

        result = run_reconcile(self.intent, self.audit, evidence=self.evidence)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertEqual(payload["counts"]["metadata_conflict"], 1)
        self.assertEqual(payload["counts"]["missing_wrapper_audit"], 1)
        self.assertEqual(payload["coverage"]["explained_writes"], 0)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 0.0)
        self.assertIn("metadata_conflict", payload["reasons"])

    def test_reconcile_audit_write_without_intent_enters_denominator_and_is_partial(self) -> None:
        write_jsonl(self.intent, [])
        write_jsonl(
            self.audit,
            [
                audit_event("op-audit-only-001", phase="start", status="started"),
                audit_event("op-audit-only-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertIn("missing_intent", payload["reasons"])
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["missing_intent"], 1)
        self.assertEqual(payload["operations"][0]["operation_id"], "op-audit-only-001")
        self.assertEqual(payload["operations"][0]["intent_match"], "missing")

    def test_reconcile_duplicate_operation_id_with_metadata_conflict_is_partial(self) -> None:
        write_jsonl(
            self.intent,
            [
                intent_event("op-conflict-001", host="demo-local", action="deploy-ref", details={"ref": "abcdef0"}),
                intent_event("op-conflict-001", host="other-host", action="restart-service", details={"service": "guardedops-demo"}),
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-conflict-001", phase="start", status="started", action="deploy-ref", details={"ref": "abcdef0"}),
                audit_event("op-conflict-001", phase="result", status="success", action="deploy-ref", ts="2026-08-12T00:00:03Z", details={"ref": "abcdef0"}),
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertTrue(
            {"duplicate_operation_id", "metadata_conflict"}.intersection(payload["reasons"]),
            payload["reasons"],
        )
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertTrue(
            payload["counts"].get("duplicate_operation_id", 0) == 1
            or payload["counts"].get("metadata_conflict", 0) == 1,
            payload["counts"],
        )

    def test_reconcile_reports_incomplete_malformed_legacy_and_duplicates(self) -> None:
        write_jsonl(
            self.intent,
            [
                intent_event("op-incomplete-001"),
                intent_event("op-duplicate-001"),
                intent_event("op-duplicate-001"),
                "{not-json",
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-incomplete-001", phase="start", status="started"),
                audit_event("op-duplicate-001", phase="start", status="started"),
                audit_event("op-duplicate-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
                {"time": "2026-08-12T00:00:04Z", "action": "deploy-ref", "status": "success"},
                "not-json",
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "partial")
        for reason in ("incomplete", "duplicate_intent", "malformed", "legacy_records"):
            self.assertIn(reason, payload["reasons"])
        self.assertEqual(payload["counts"]["incomplete"], 1)
        self.assertEqual(payload["counts"]["duplicate_intent"], 1)
        self.assertEqual(payload["records"]["intent_malformed"], 1)
        self.assertEqual(payload["records"]["audit_malformed"], 1)
        self.assertEqual(payload["records"]["legacy_audit"], 1)

    def test_reconcile_filters_by_host_run_id_since_and_writes_output_file(self) -> None:
        output = self.tmp / "filtered" / "report.json"
        write_jsonl(
            self.intent,
            [
                intent_event("op-old", ts="2026-08-11T23:59:59Z"),
                intent_event("op-other-host", host="other-host", ts="2026-08-12T00:00:02Z"),
                intent_event("op-other-run", run_id="other-run", ts="2026-08-12T00:00:02Z"),
                intent_event("op-selected", ts="2026-08-12T00:00:02Z"),
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-selected", phase="start", status="started", ts="2026-08-12T00:00:03Z"),
                audit_event("op-selected", phase="result", status="success", ts="2026-08-12T00:00:04Z"),
            ],
        )

        result = run_reconcile(
            self.intent,
            self.audit,
            "--host",
            "demo-local",
            "--run-id",
            "run-contract",
            "--since",
            "2026-08-12T00:00:00Z",
            "--output",
            str(output),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = load_json(output)
        self.assertEqual(payload["filters"], {"host": "demo-local", "run_id": "run-contract", "since": "2026-08-12T00:00:00Z"})
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual([item["operation_id"] for item in payload["operations"]], ["op-selected"])

    def test_reconcile_zero_known_writes_is_insufficient_exposure_exit_2(self) -> None:
        write_jsonl(self.intent, [])
        write_jsonl(self.audit, [])

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["verdict"], "insufficient")
        self.assertIn("insufficient_exposure", payload["reasons"])
        self.assertEqual(payload["counts"]["known_writes"], 0)

    def test_reconcile_redacts_sensitive_command_and_detail_values(self) -> None:
        write_jsonl(
            self.intent,
            [
                intent_event(
                    "op-secret-001",
                    command=["opsctl", "deploy", "--approval-token", "token=super-secret-value"],
                    details={"token": "super-secret-value", "authorization": "Bearer should-not-leak", "change_id": "op-secret-001"},
                )
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-secret-001", phase="start", status="started"),
                audit_event("op-secret-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit)

        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout + result.stderr
        self.assertNotIn("super-secret-value", rendered)
        self.assertNotIn("should-not-leak", rendered)
        payload = self.assert_json_stdout(result)
        self.assertEqual(payload["operations"][0]["command_template"], "opsctl deploy --approval-token <redacted>")

    def test_daily_evidence_writes_json_and_markdown_from_reconcile_report(self) -> None:
        report = {
            "schema_version": "guardedops.audit-reconcile/v1",
            "verdict": "partial",
            "reasons": ["external_write_detected"],
            "counts": {
                "known_writes": 2,
                "wrapper_success": 1,
                "wrapper_failed": 0,
                "hook_blocked": 0,
                "missing_wrapper_audit": 0,
                "external_writes": 1,
            },
            "coverage": {"known_write_coverage_ratio": 0.5},
            "filters": {"host": None, "run_id": "run-contract", "since": None},
            "operations": [],
        }
        input_report = self.tmp / "report.json"
        output_dir = self.tmp / "daily"
        input_report.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.review",
                "daily-evidence",
                "--input",
                str(input_report),
                "--output",
                str(output_dir),
            ]
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        daily_json = output_dir / "daily-evidence.json"
        daily_md = output_dir / "daily-evidence.md"
        self.assertTrue(daily_json.exists())
        self.assertTrue(daily_md.exists())
        daily_payload = load_json(daily_json)
        self.assertEqual(daily_payload["schema_version"], "guardedops.daily-evidence/v1")
        self.assertEqual(daily_payload["verdict"], "partial")
        markdown = daily_md.read_text(encoding="utf-8")
        self.assertIn("Known writes: 2", markdown)
        self.assertIn("Wrapper success: 1", markdown)
        self.assertIn("External writes: 1", markdown)
        self.assertIn("Coverage: 50.00%", markdown)

    def test_reconcile_missing_intent_or_audit_input_file_is_structured_insufficient(self) -> None:
        missing_intent = self.tmp / "missing-intent.jsonl"
        write_jsonl(self.audit, [])

        missing_intent_result = run_reconcile(missing_intent, self.audit)

        self.assertEqual(missing_intent_result.returncode, 2, missing_intent_result.stdout + missing_intent_result.stderr)
        missing_intent_payload = self.assert_json_stdout(missing_intent_result)
        self.assertEqual(missing_intent_payload["schema_version"], "guardedops.audit-reconcile/v1")
        self.assertEqual(missing_intent_payload["verdict"], "insufficient")
        self.assertIn("missing_intent_input", missing_intent_payload["reasons"])
        self.assertEqual(missing_intent_payload["counts"]["known_writes"], 0)

        write_jsonl(self.intent, [intent_event("op-missing-audit-001")])
        missing_audit = self.tmp / "missing-audit.jsonl"
        missing_audit_result = run_reconcile(self.intent, missing_audit)

        self.assertEqual(missing_audit_result.returncode, 2, missing_audit_result.stdout + missing_audit_result.stderr)
        missing_audit_payload = self.assert_json_stdout(missing_audit_result)
        self.assertEqual(missing_audit_payload["schema_version"], "guardedops.audit-reconcile/v1")
        self.assertEqual(missing_audit_payload["verdict"], "insufficient")
        self.assertIn("missing_audit_input", missing_audit_payload["reasons"])
        self.assertEqual(missing_audit_payload["counts"]["known_writes"], 1)

    def make_wrapper_workspace(self) -> tuple[Path, Path, Path]:
        app = self.tmp / "app"
        shutil.copytree(ROOT / "examples/demo-remote/app", app)
        audit_log = self.tmp / "audit.jsonl"
        policy = {
            "policy_version": "demo-v2",
            "host": "demo-local",
            "service": "guardedops-demo",
            "service_adapter": "mock",
            "app_path": str(app),
            "version_file": str(ROOT / "server/ops-wrapper.version.json"),
            "audit_log": str(audit_log),
            "backup_dir": str(self.tmp / "backups"),
            "actions": {
                "apply-config-batch": {"enabled": True},
                "config-patch": {
                    "enabled": True,
                    "allowed_files": {"config/app.json": {"allowed_keys": ["feature.enabled"]}},
                },
            },
        }
        policy_path = self.tmp / "policy.json"
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return app, policy_path, audit_log

    def make_local_opsctl_workspace(self, *, audit_log: Path | None = None) -> tuple[Path, Path, Path, Path]:
        fleet_path = self.tmp / "fleet.json"
        policy_path = self.tmp / "policy.json"
        app = self.tmp / "app"
        shutil.copytree(ROOT / "examples/demo-remote/app", app)
        policy_path.write_text(
            json.dumps(
                {
                    "policy_version": "demo-v2",
                    "host": "demo-local",
                    "service": "guardedops-demo",
                    "app_path": str(app),
                    "version_file": str(ROOT / "server/ops-wrapper.version.json"),
                    "audit_log": str(audit_log or (self.tmp / "audit.jsonl")),
                    "backup_dir": str(self.tmp / "backups"),
                    "actions": {
                        "apply-config-batch": {"enabled": True},
                        "config-patch": {
                            "enabled": True,
                            "allowed_files": {"config/app.json": {"allowed_keys": ["feature.enabled"]}},
                        },
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        fleet_path.write_text(
            json.dumps(
                {
                    "rollout_order": ["demo-local"],
                    "hosts": {
                        "demo-local": {
                            "ssh_alias": "local-demo",
                            "transport": "local",
                            "allow_untrusted_policy": True,
                            "server_wrapper": str(ROOT / "server/ops-wrapper"),
                            "policy_path": str(policy_path),
                            "app_path": str(app),
                            "service": "guardedops-demo",
                            "config_files": {"config/app.json": {"allowed_keys": ["feature.enabled"]}},
                        }
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return app, fleet_path, policy_path, Path(json.loads(policy_path.read_text(encoding="utf-8"))["audit_log"])

    def plan_config_batch(self, fleet_path: Path, cwd: Path | None = None) -> dict[str, Any]:
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                str(fleet_path),
                "plan-config-batch",
                "--host",
                "demo-local",
                "--file",
                "config/app.json",
                "--set",
                "feature.enabled=true",
            ],
            cwd=cwd or self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_wrapper_accepts_and_propagates_exact_operation_id(self) -> None:
        _app, policy_path, audit_log = self.make_wrapper_workspace()
        operation_id = "op-explicit-wrapper-001"
        change_payload = {"file": "config/app.json", "sets": [{"path": "feature.enabled", "value": True}], "deletes": []}

        change_id = hashlib.sha256(json.dumps(change_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
        approval = f"host=demo-local action=apply-config-batch change_id={change_id}"

        result = run_cli(
            [
                PYTHON,
                str(ROOT / "server/ops-wrapper"),
                "--policy",
                str(policy_path),
                "--allow-untrusted-policy",
                "apply-config-batch",
                "--operation-id",
                operation_id,
                "--change-id",
                change_id,
                "--approval-token",
                approval,
                "--file",
                "config/app.json",
                "--set",
                "feature.enabled=true",
            ],
            cwd=ROOT,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["operation_id"] for record in records], [operation_id, operation_id])
        self.assertEqual([record["phase"] for record in records], ["start", "result"])

    def test_wrapper_rejects_invalid_operation_id_before_side_effect(self) -> None:
        app, policy_path, audit_log = self.make_wrapper_workspace()
        target = app / "config/app.json"
        before = target.read_text(encoding="utf-8")
        change_payload = {"file": "config/app.json", "sets": [{"path": "feature.enabled", "value": True}], "deletes": []}
        change_id = hashlib.sha256(json.dumps(change_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
        approval = f"host=demo-local action=apply-config-batch change_id={change_id}"

        result = run_cli(
            [
                PYTHON,
                str(ROOT / "server/ops-wrapper"),
                "--policy",
                str(policy_path),
                "--allow-untrusted-policy",
                "apply-config-batch",
                "--operation-id",
                "bad id/with slash",
                "--change-id",
                change_id,
                "--approval-token",
                approval,
                "--file",
                "config/app.json",
                "--set",
                "feature.enabled=true",
            ],
            cwd=ROOT,
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("operation_id", (result.stdout + result.stderr).lower())
        self.assertEqual(target.read_text(encoding="utf-8"), before)
        self.assertFalse(audit_log.exists(), "invalid operation_id must be rejected before audit start/result append")

    def test_opsctl_apply_config_batch_records_intent_audit_and_reconciles_complete(self) -> None:
        app, fleet_path, _policy_path, audit_log = self.make_local_opsctl_workspace()
        intent_log = self.tmp / ".guarded_ops" / "intent.jsonl"
        change = self.plan_config_batch(fleet_path)
        operation_id = "op-local-complete-001"

        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                str(fleet_path),
                "apply-config-batch",
                "--operation-id",
                operation_id,
                "--change-id",
                change["change_id"],
                "--approval-token",
                change["approval"],
            ],
            cwd=self.tmp,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("true", (app / "config/app.json").read_text(encoding="utf-8"))
        intent_records = load_jsonl(intent_log)
        self.assertEqual(len(intent_records), 1)
        intent = intent_records[0]
        self.assertEqual(intent["schema_version"], "guardedops.intent/v1")
        self.assertEqual(intent["operation_id"], operation_id)
        self.assertEqual(intent["operation_kind"], "write")
        self.assertEqual(intent["status"], "planned")
        rendered_intent = json.dumps(intent, sort_keys=True)
        self.assertNotIn(change["approval"], rendered_intent)
        self.assertNotIn("feature.enabled=true", rendered_intent)
        self.assertNotIn("authorization", rendered_intent.lower())
        audit_records = load_jsonl(audit_log)
        self.assertEqual([record["operation_id"] for record in audit_records], [operation_id, operation_id])
        self.assertEqual([record["phase"] for record in audit_records], ["start", "result"])

        reconcile = run_reconcile(intent_log, audit_log)

        self.assertEqual(reconcile.returncode, 0, reconcile.stderr)
        payload = self.assert_json_stdout(reconcile)
        self.assertEqual(payload["verdict"], "complete")
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["wrapper_success"], 1)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 1.0)

    def test_opsctl_dry_run_wrapper_managed_write_does_not_record_intent_audit_or_change_target(self) -> None:
        app, fleet_path, _policy_path, audit_log = self.make_local_opsctl_workspace()
        target = app / "config/app.json"
        before = target.read_text(encoding="utf-8")
        intent_log = self.tmp / ".guarded_ops" / "intent.jsonl"
        change = self.plan_config_batch(fleet_path)

        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                str(fleet_path),
                "--dry-run",
                "apply-config-batch",
                "--operation-id",
                "op-dry-run-001",
                "--change-id",
                change["change_id"],
                "--approval-token",
                change["approval"],
            ],
            cwd=self.tmp,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = self.assert_json_stdout(result)
        self.assertTrue(payload["dry_run"])
        self.assertEqual(target.read_text(encoding="utf-8"), before)
        self.assertFalse(intent_log.exists(), "dry-run wrapper-managed writes must not emit intent records")
        self.assertFalse(audit_log.exists(), "dry-run wrapper-managed writes must not execute wrapper audit")

    def test_opsctl_apply_config_batch_accepts_operation_id_and_persists_intent_before_transport(self) -> None:
        app, fleet_path, _policy_path, _audit_log = self.make_local_opsctl_workspace(audit_log=self.tmp / "blocked" / "audit.jsonl")
        change = self.plan_config_batch(fleet_path)
        operation_id = "op-explicit-opsctl-001"
        intent_log = self.tmp / ".guarded_ops" / "intent.jsonl"
        intent_log.mkdir(parents=True)
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                str(fleet_path),
                "apply-config-batch",
                "--operation-id",
                operation_id,
                "--change-id",
                change["change_id"],
                "--approval-token",
                change["approval"],
            ],
            cwd=self.tmp,
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("intent", result.stderr.lower())
        self.assertFalse((app / "config/app.json").read_text(encoding="utf-8").count("true"), "write transport must not run when intent persistence fails")
        self.assertTrue(intent_log.is_dir(), "intent append target must remain a failing directory fixture")


if __name__ == "__main__":
    unittest.main()
