from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def review_audit_summary(audit_log: Path, cwd: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return run_cli([PYTHON, "-m", "guarded_ops.review", "audit-summary", "--input", str(audit_log), *extra], cwd=cwd)


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def v1_event(
    *,
    operation_id: str,
    action: str,
    operation_kind: str,
    phase: str,
    status: str,
    reason_code: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "guardedops.audit/v1",
        "operation_id": operation_id,
        "run_id": "run-20260811",
        "ts": "2026-08-11T00:00:00Z",
        "host": "demo-local",
        "action": action,
        "operation_kind": operation_kind,
        "phase": phase,
        "status": status,
        "reason_code": reason_code,
        "details": details or {},
        "wrapper_version": "0.2.0-test",
        "policy_version": "demo-v2",
    }


def approval_token(host: str, action: str, **scope: str) -> str:
    fields = {"host": host, "action": action, **scope}
    return " ".join(f"{key}={value}" for key, value in fields.items())


def batch_change_id(file_name: str, sets: list[dict[str, Any]], deletes: list[str] | None = None) -> str:
    payload = {"file": file_name, "sets": sets, "deletes": deletes or []}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


class AuditContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guardedops-audit-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def make_wrapper_workspace(self, audit_log: Path | None = None) -> tuple[Path, Path, Path]:
        app = self.tmp / "app"
        shutil.copytree(ROOT / "examples/demo-remote/app", app)
        policy = {
            "policy_version": "demo-v2",
            "host": "demo-local",
            "service": "guardedops-demo",
            "service_adapter": "mock",
            "app_path": str(app),
            "version_file": str(ROOT / "server/ops-wrapper.version.json"),
            "audit_log": str(audit_log or (self.tmp / "audit.jsonl")),
            "backup_dir": str(self.tmp / "backups"),
            "actions": {
                "host-observe": {"enabled": True},
                "runtime-baseline": {"enabled": True},
                "deploy-ref": {"enabled": True},
                "restart-service": {"enabled": True},
                "config-patch": {
                    "enabled": True,
                    "allowed_files": {
                        "config/app.env": {"allowed_keys": ["APP_LOG_LEVEL", "FEATURE_FLAG_X"]},
                        "config/app.json": {"allowed_keys": ["feature.enabled", "limits.timeout_ms"]},
                    },
                },
                "log-query": {"enabled": True, "roots": [str(app / "logs")], "max_lines": 200},
                "safe-git": {"enabled": True, "allowed_ops": ["status", "rev-parse", "log"]},
            },
        }
        policy_path = self.tmp / "policy.json"
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return app, policy_path, Path(policy["audit_log"])

    def make_local_fleet(self, policy_path: Path) -> Path:
        fleet = {
            "rollout_order": ["demo-local"],
            "hosts": {
                "demo-local": {
                    "ssh_alias": "local-demo",
                    "transport": "local",
                    "allow_untrusted_policy": True,
                    "app_path": str(self.tmp / "app"),
                    "service": "guardedops-demo",
                    "server_wrapper": str(ROOT / "server/ops-wrapper"),
                    "policy_path": str(policy_path),
                    "config_files": {
                        "config/app.env": {"allowed_keys": ["APP_LOG_LEVEL", "FEATURE_FLAG_X"]},
                        "config/app.json": {"allowed_keys": ["feature.enabled", "limits.timeout_ms"]},
                    },
                }
            },
        }
        fleet_path = self.tmp / "fleet.json"
        fleet_path.write_text(json.dumps(fleet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return fleet_path

    def run_wrapper(self, policy_path: Path, action: str, args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        return run_cli(
            [
                str(ROOT / "server/ops-wrapper"),
                "--allow-untrusted-policy",
                "--policy",
                str(policy_path),
                action,
                *(args or []),
            ],
            cwd=self.tmp,
        )

    def wrapper_audit_summary(self, policy_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return self.run_wrapper(policy_path, "audit-summary", list(extra))

    def opsctl_audit_status(self, fleet_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", str(fleet_path), "audit-status", "--host", "demo-local", *extra],
            cwd=self.tmp,
        )

    def init_app_repo(self, app: Path) -> tuple[str, str]:
        subprocess.run(["git", "init"], cwd=app, check=True, text=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "guardedops-test@example.com"], cwd=app, check=True, text=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "GuardedOps Test"], cwd=app, check=True, text=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=app, check=True, text=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=app, check=True, text=True, capture_output=True)
        first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=app, check=True, text=True, capture_output=True).stdout.strip()
        (app / "logs/current.log").write_text("second commit marker\n", encoding="utf-8")
        subprocess.run(["git", "add", "logs/current.log"], cwd=app, check=True, text=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "second"], cwd=app, check=True, text=True, capture_output=True)
        second = subprocess.run(["git", "rev-parse", "HEAD"], cwd=app, check=True, text=True, capture_output=True).stdout.strip()
        return first, second

    def git_head(self, repo: Path) -> str:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, capture_output=True).stdout.strip()

    def git_status(self, repo: Path) -> str:
        return subprocess.run(["git", "status", "--short"], cwd=repo, check=True, text=True, capture_output=True).stdout

    def assert_audit_event_shape(self, event: dict[str, Any], *, phase: str, status: str) -> None:
        for key in (
            "schema_version",
            "operation_id",
            "run_id",
            "ts",
            "host",
            "action",
            "operation_kind",
            "phase",
            "status",
            "reason_code",
            "details",
            "wrapper_version",
            "policy_version",
        ):
            self.assertIn(key, event)
        self.assertEqual(event["schema_version"], "guardedops.audit/v1")
        self.assertRegex(event["operation_id"], r"^[A-Za-z0-9._:-]+$")
        self.assertIn("run_id", event)
        self.assertRegex(event["ts"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(event["host"], "demo-local")
        self.assertIn(event["operation_kind"], {"read", "write"})
        self.assertEqual(event["phase"], phase)
        self.assertEqual(event["status"], status)
        self.assertIn("reason_code", event)
        self.assertIsInstance(event["details"], dict)
        self.assertIsInstance(event["wrapper_version"], str)
        self.assertIsInstance(event["policy_version"], str)

    def test_audit_summary_accepts_rejected_and_executed_failed_writes_as_complete(self) -> None:
        audit_log = self.tmp / "audit.jsonl"
        write_jsonl(
            audit_log,
            [
                v1_event(
                    operation_id="write-denied-1",
                    action="config-patch",
                    operation_kind="write",
                    phase="result",
                    status="failed",
                    reason_code="policy_denied",
                    details={"decision": "blocked"},
                ),
                v1_event(operation_id="write-failed-1", action="restart-service", operation_kind="write", phase="start", status="started"),
                v1_event(
                    operation_id="write-failed-1",
                    action="restart-service",
                    operation_kind="write",
                    phase="result",
                    status="failed",
                    reason_code="command_failed",
                    details={"returncode": 1},
                ),
            ],
        )
        _app, policy_path, _ = self.make_wrapper_workspace(audit_log)
        fleet_path = self.make_local_fleet(policy_path)

        before = audit_log.read_text(encoding="utf-8")
        result = review_audit_summary(audit_log, self.tmp, "--run-id", "run-20260811")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(audit_log.read_text(encoding="utf-8"), before, "audit-summary must not emit an audit event")
        summary = json.loads(result.stdout)
        self.assertEqual(summary["schema_version"], "guardedops.audit-summary/v1")
        self.assertEqual(summary["verdict"], "complete")
        self.assertEqual(summary["records"]["total"], 3)
        self.assertEqual(summary["records"]["malformed"], 0)
        self.assertEqual(summary["records"]["unknown"], 0)
        self.assertEqual(summary["operations"]["total"], 2)
        self.assertEqual(summary["operations"]["write"], 2)
        self.assertEqual(summary["operations"]["failed"], 2)
        self.assertEqual(summary["operations"]["rejected"], 1)
        self.assertEqual(summary["operations"]["orphan_results"], 0)
        self.assertEqual(summary["counts_by_reason_code"]["policy_denied"], 1)

        wrapper = self.wrapper_audit_summary(policy_path, "--run-id", "run-20260811")
        opsctl = self.opsctl_audit_status(fleet_path, "--run-id", "run-20260811")
        self.assertEqual(wrapper.returncode, 0, wrapper.stderr)
        self.assertEqual(opsctl.returncode, 0, opsctl.stderr)
        self.assertEqual(json.loads(wrapper.stdout), summary)
        self.assertEqual(json.loads(opsctl.stdout), summary)
        self.assertEqual(audit_log.read_text(encoding="utf-8"), before, "wrapper and opsctl audit summaries must not emit audit events")

    def test_audit_summary_counts_read_policy_denial_as_rejected(self) -> None:
        audit_log = self.tmp / "read-denial.jsonl"
        write_jsonl(
            audit_log,
            [
                v1_event(
                    operation_id="read-denied-1",
                    action="log-query",
                    operation_kind="read",
                    phase="result",
                    status="failed",
                    reason_code="policy_denied",
                    details={"decision": "blocked"},
                )
            ],
        )

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["operations"]["failed"], 1)
        self.assertEqual(summary["operations"]["rejected"], 1)
        self.assertEqual(summary["counts_by_reason_code"], {"policy_denied": 1})

    def test_audit_summary_marks_legacy_malformed_unknown_empty_and_incomplete_as_partial(self) -> None:
        audit_log = self.tmp / "mixed-audit.jsonl"
        write_jsonl(
            audit_log,
            [
                v1_event(operation_id="read-1", action="runtime-baseline", operation_kind="read", phase="result", status="success"),
                v1_event(operation_id="write-1", action="restart-service", operation_kind="write", phase="start", status="started"),
                {"time": "2026-08-11T00:00:01Z", "action": "host-observe", "result": "ok"},
                {"ts": "2026-08-11T00:00:02Z", "action": "deploy-ref", "status": "success", "details": {"ref": "abcdef0"}},
                {"schema_version": "guardedops.audit/v999", "action": "runtime-baseline"},
                "{malformed-json",
            ],
        )

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 3, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["schema_version"], "guardedops.audit-summary/v1")
        self.assertEqual(summary["verdict"], "partial")
        self.assertEqual(summary["source_formats"]["guardedops.audit/v1"], 2)
        self.assertEqual(summary["source_formats"]["legacy_guardedops"], 1)
        self.assertEqual(summary["source_formats"]["legacy_aiserver_prod_ops"], 1)
        self.assertEqual(summary["source_formats"]["unknown"], 1)
        self.assertEqual(summary["records"]["total"], 5)
        self.assertEqual(summary["records"]["malformed"], 1)
        self.assertEqual(summary["records"]["unknown"], 1)
        self.assertEqual(summary["operations"]["read"], 1)
        self.assertEqual(summary["operations"]["write"], 1)
        self.assertEqual(summary["operations"]["incomplete"], 1)
        self.assertIn("incomplete", summary["reasons"])
        self.assertIn("malformed", summary["reasons"])
        self.assertIn("unknown_schema", summary["reasons"])
        self.assertIn("legacy_records", summary["reasons"])

        empty_log = self.tmp / "empty-audit.jsonl"
        empty_log.write_text("", encoding="utf-8")
        empty = review_audit_summary(empty_log, self.tmp)
        self.assertEqual(empty.returncode, 3, empty.stderr)
        self.assertEqual(json.loads(empty.stdout)["verdict"], "partial")

    def test_audit_summary_missing_or_unreadable_source_is_insufficient_exit_2(self) -> None:
        missing = review_audit_summary(self.tmp / "missing-audit.jsonl", self.tmp)

        self.assertEqual(missing.returncode, 2)
        self.assertTrue(missing.stdout.strip(), missing.stderr)
        payload = json.loads(missing.stdout)
        self.assertEqual(payload["schema_version"], "guardedops.audit-summary/v1")
        self.assertEqual(payload["verdict"], "insufficient")
        self.assertIn("missing", payload["reasons"])

    def test_audit_summary_run_id_filter_no_matches_and_unattributable_malformed_records(self) -> None:
        no_match_log = self.tmp / "no-matching-run.jsonl"
        write_jsonl(
            no_match_log,
            [
                v1_event(operation_id="read-other", action="runtime-baseline", operation_kind="read", phase="result", status="success"),
                {"time": "2026-08-11T00:00:01Z", "action": "host-observe", "file_count": 3},
                {"time": "2026-08-11T00:00:02Z", "action": "plan-config-batch", "change_id": "change-1"},
            ],
        )

        no_match = review_audit_summary(no_match_log, self.tmp, "--run-id", "missing-run")

        self.assertEqual(no_match.returncode, 3, no_match.stderr)
        no_match_summary = json.loads(no_match.stdout)
        self.assertEqual(no_match_summary["verdict"], "partial")
        self.assertEqual(no_match_summary["operations"]["total"], 0)
        self.assertIn("no_matching_records", no_match_summary["reasons"])

        matching_log = self.tmp / "matching-run-with-legacy.jsonl"
        write_jsonl(
            matching_log,
            [
                v1_event(operation_id="read-run", action="runtime-baseline", operation_kind="read", phase="result", status="success"),
                {"time": "2026-08-11T00:00:01Z", "action": "host-observe", "file_count": 3},
                {"time": "2026-08-11T00:00:02Z", "action": "plan-config-batch", "change_id": "change-1"},
            ],
        )

        matching = review_audit_summary(matching_log, self.tmp, "--run-id", "run-20260811")

        self.assertEqual(matching.returncode, 0, matching.stderr)
        matching_summary = json.loads(matching.stdout)
        self.assertEqual(matching_summary["verdict"], "complete")
        self.assertEqual(matching_summary["operations"]["total"], 1)
        self.assertEqual(matching_summary["operations"]["read"], 1)
        self.assertNotIn("legacy_records", matching_summary["reasons"])

        malformed_log = self.tmp / "matching-run-with-malformed.jsonl"
        write_jsonl(
            malformed_log,
            [
                v1_event(operation_id="read-run", action="runtime-baseline", operation_kind="read", phase="result", status="success"),
                "{malformed-json",
            ],
        )
        malformed = review_audit_summary(malformed_log, self.tmp, "--run-id", "run-20260811")
        self.assertEqual(malformed.returncode, 3, malformed.stderr)
        malformed_summary = json.loads(malformed.stdout)
        self.assertEqual(malformed_summary["verdict"], "partial")
        self.assertEqual(malformed_summary["operations"]["total"], 1)
        self.assertIn("malformed", malformed_summary["reasons"])

    def test_audit_summary_strict_v1_parser_rejects_invalid_enums_types_and_extra_fields(self) -> None:
        audit_log = self.tmp / "invalid-v1.jsonl"
        invalid_records = [
            {**v1_event(operation_id="bad-kind", action="runtime-baseline", operation_kind="read", phase="result", status="success"), "operation_kind": "inspect"},
            {**v1_event(operation_id="bad-phase", action="runtime-baseline", operation_kind="read", phase="result", status="success"), "phase": "finish"},
            {**v1_event(operation_id="bad-status", action="runtime-baseline", operation_kind="read", phase="result", status="success"), "status": "ok"},
            {**v1_event(operation_id="bad-details", action="runtime-baseline", operation_kind="read", phase="result", status="success"), "details": "leaky string"},
            {**v1_event(operation_id="bad-extra", action="runtime-baseline", operation_kind="read", phase="result", status="success"), "unexpected": "field"},
        ]
        write_jsonl(audit_log, invalid_records)

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 3, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["verdict"], "partial")
        self.assertEqual(summary["records"]["total"], 5)
        self.assertEqual(summary["records"]["unknown"], 5)
        self.assertEqual(summary["source_formats"]["unknown"], 5)
        self.assertEqual(summary["operations"]["total"], 0)
        self.assertIn("invalid_v1_record", summary["reasons"])

    def test_audit_summary_counts_real_legacy_guardedops_shapes_without_result(self) -> None:
        audit_log = self.tmp / "legacy-guardedops.jsonl"
        write_jsonl(
            audit_log,
            [
                {"time": "2026-08-11T00:00:01Z", "action": "runtime-baseline", "file_count": 3},
                {"time": "2026-08-11T00:00:02Z", "action": "plan-config-batch", "change_id": "change-1"},
            ],
        )

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 3, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["verdict"], "partial")
        self.assertEqual(summary["records"]["total"], 2)
        self.assertIn("legacy_guardedops", summary["source_formats"])
        self.assertEqual(summary["source_formats"]["legacy_guardedops"], 2)
        self.assertEqual(summary["records"]["unknown"], 0)
        self.assertIn("legacy_records", summary["reasons"])

    def test_audit_summary_exposes_action_status_window_host_and_run_id_indexes(self) -> None:
        audit_log = self.tmp / "indexed-summary.jsonl"
        write_jsonl(
            audit_log,
            [
                {
                    **v1_event(operation_id="read-1", action="runtime-baseline", operation_kind="read", phase="result", status="success"),
                    "ts": "2026-08-11T00:00:00Z",
                    "host": "demo-local",
                    "run_id": "run-1",
                },
                {
                    **v1_event(operation_id="write-1", action="restart-service", operation_kind="write", phase="start", status="started"),
                    "ts": "2026-08-11T00:01:00Z",
                    "host": "demo-ssh",
                    "run_id": "run-2",
                },
                {
                    **v1_event(operation_id="write-1", action="restart-service", operation_kind="write", phase="result", status="failed", reason_code="execution_failed"),
                    "ts": "2026-08-11T00:02:00Z",
                    "host": "demo-ssh",
                    "run_id": "run-2",
                },
            ],
        )

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertIn("counts_by_action", summary)
        self.assertIn("counts_by_status", summary)
        self.assertIn("window", summary)
        self.assertIn("hosts", summary)
        self.assertIn("run_ids", summary)
        self.assertEqual(summary["counts_by_action"]["runtime-baseline"], 1)
        self.assertEqual(summary["counts_by_action"]["restart-service"], 1)
        self.assertEqual(summary["counts_by_status"]["success"], 1)
        self.assertEqual(summary["counts_by_status"]["failed"], 1)
        self.assertEqual(summary["window"]["first_ts"], "2026-08-11T00:00:00Z")
        self.assertEqual(summary["window"]["last_ts"], "2026-08-11T00:02:00Z")
        self.assertEqual(summary["hosts"], ["demo-local", "demo-ssh"])
        self.assertEqual(summary["run_ids"], ["run-1", "run-2"])

    def test_ops_wrapper_records_durable_start_then_result_for_successful_write(self) -> None:
        app, policy_path, audit_log = self.make_wrapper_workspace()
        sets = [{"path": "feature.enabled", "value": True}]
        change_id = batch_change_id("config/app.json", sets)
        token = approval_token("demo-local", "apply-config-batch", change_id=change_id)

        result = self.run_wrapper(
            policy_path,
            "apply-config-batch",
            [
                "--run-id",
                "run-20260811",
                "--change-id",
                change_id,
                "--approval-token",
                token,
                "--file",
                "config/app.json",
                "--set",
                "feature.enabled=true",
            ],
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(audit_log.exists(), "successful writes must durably audit before returning success")
        events = load_jsonl(audit_log)
        self.assertEqual(len(events), 2)
        self.assert_audit_event_shape(events[0], phase="start", status="started")
        self.assert_audit_event_shape(events[1], phase="result", status="success")
        self.assertEqual(events[0]["operation_id"], events[1]["operation_id"])
        self.assertEqual(events[0]["run_id"], "run-20260811")
        self.assertEqual(events[1]["run_id"], "run-20260811")
        self.assertEqual(events[0]["operation_kind"], "write")
        self.assertEqual(events[1]["operation_kind"], "write")
        self.assertEqual(json.loads((app / "config/app.json").read_text(encoding="utf-8"))["feature"]["enabled"], True)

    def test_ops_wrapper_generates_same_run_id_on_write_start_and_result_without_explicit_run_id(self) -> None:
        _app, policy_path, audit_log = self.make_wrapper_workspace()
        sets = [{"path": "limits.timeout_ms", "value": 2500}]
        change_id = batch_change_id("config/app.json", sets)
        token = approval_token("demo-local", "apply-config-batch", change_id=change_id)

        result = self.run_wrapper(
            policy_path,
            "apply-config-batch",
            ["--change-id", change_id, "--approval-token", token, "--file", "config/app.json", "--set", "limits.timeout_ms=2500"],
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        events = load_jsonl(audit_log)
        self.assertEqual(len(events), 2)
        self.assert_audit_event_shape(events[0], phase="start", status="started")
        self.assert_audit_event_shape(events[1], phase="result", status="success")
        self.assertTrue(events[0]["run_id"])
        self.assertEqual(events[0]["run_id"], events[1]["run_id"])

    def test_ops_wrapper_precondition_denial_is_single_rejected_write_result(self) -> None:
        _app, policy_path, audit_log = self.make_wrapper_workspace()

        result = self.run_wrapper(
            policy_path,
            "config-patch",
            ["--file", "config/app.env", "--set", "UNLISTED_KEY=value"],
        )

        self.assertEqual(result.returncode, 2)
        self.assertTrue(audit_log.exists(), result.stderr)
        events = load_jsonl(audit_log)
        self.assertEqual(len(events), 1)
        self.assert_audit_event_shape(events[0], phase="result", status="failed")
        self.assertEqual(events[0]["operation_kind"], "write")
        self.assertEqual(events[0]["reason_code"], "policy_denied")
        summary = review_audit_summary(audit_log, self.tmp)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertEqual(json.loads(summary.stdout)["operations"]["orphan_results"], 0)

    def test_ops_wrapper_wrong_restart_service_with_matching_token_is_single_policy_denied_result(self) -> None:
        _app, policy_path, audit_log = self.make_wrapper_workspace()
        token = approval_token("demo-local", "restart-service", service="wrong-service")

        result = self.run_wrapper(policy_path, "restart-service", ["--service-name", "wrong-service", "--approval-token", token])

        self.assertEqual(result.returncode, 2)
        self.assertTrue(audit_log.exists(), result.stderr)
        events = load_jsonl(audit_log)
        self.assertEqual(len(events), 1)
        self.assert_audit_event_shape(events[0], phase="result", status="failed")
        self.assertEqual(events[0]["operation_kind"], "write")
        self.assertEqual(events[0]["reason_code"], "policy_denied")
        summary = review_audit_summary(audit_log, self.tmp)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertEqual(json.loads(summary.stdout)["operations"]["orphan_results"], 0)

    def test_ops_wrapper_missing_policy_audit_log_blocks_config_apply_before_state_or_backup_change(self) -> None:
        app, policy_path, _audit_log = self.make_wrapper_workspace()
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy.pop("audit_log")
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        config_path = app / "config/app.json"
        before_hash = sha256_path(config_path)
        backup_dir = self.tmp / "backups"
        sets = [{"path": "feature.enabled", "value": True}]
        change_id = batch_change_id("config/app.json", sets)
        token = approval_token("demo-local", "apply-config-batch", change_id=change_id)

        result = self.run_wrapper(
            policy_path,
            "apply-config-batch",
            ["--change-id", change_id, "--approval-token", token, "--file", "config/app.json", "--set", "feature.enabled=true"],
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(sha256_path(config_path), before_hash)
        self.assertFalse(any(backup_dir.glob("*")) if backup_dir.exists() else False)

    def test_ops_wrapper_audit_start_failure_blocks_config_apply_state_change(self) -> None:
        blocked_parent = self.tmp / "audit-parent-is-file"
        blocked_parent.write_text("not a directory\n", encoding="utf-8")
        app, policy_path, _audit_log = self.make_wrapper_workspace(blocked_parent / "audit.jsonl")
        config_path = app / "config/app.json"
        before_hash = sha256_path(config_path)
        sets = [{"path": "feature.enabled", "value": True}]
        change_id = batch_change_id("config/app.json", sets)
        token = approval_token("demo-local", "apply-config-batch", change_id=change_id)

        result = self.run_wrapper(
            policy_path,
            "apply-config-batch",
            ["--change-id", change_id, "--approval-token", token, "--file", "config/app.json", "--set", "feature.enabled=true"],
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(sha256_path(config_path), before_hash)

    def test_ops_wrapper_audit_start_failure_blocks_restart_state_change(self) -> None:
        blocked_parent = self.tmp / "restart-audit-parent-is-file"
        blocked_parent.write_text("not a directory\n", encoding="utf-8")
        app, policy_path, _audit_log = self.make_wrapper_workspace(blocked_parent / "audit.jsonl")
        status_path = app / "service/status.txt"
        log_path = app / "logs/current.log"
        before_status_hash = sha256_path(status_path)
        before_log_hash = sha256_path(log_path)
        token = approval_token("demo-local", "restart-service", service="guardedops-demo")

        result = self.run_wrapper(policy_path, "restart-service", ["--service-name", "guardedops-demo", "--approval-token", token])

        self.assertEqual(result.returncode, 2)
        self.assertEqual(sha256_path(status_path), before_status_hash)
        self.assertEqual(sha256_path(log_path), before_log_hash)

    def test_ops_wrapper_audit_start_failure_blocks_deploy_ref_state_change(self) -> None:
        blocked_parent = self.tmp / "deploy-audit-parent-is-file"
        blocked_parent.write_text("not a directory\n", encoding="utf-8")
        app, policy_path, _audit_log = self.make_wrapper_workspace(blocked_parent / "audit.jsonl")
        first, second = self.init_app_repo(app)
        before_log_hash = sha256_path(app / "logs/current.log")
        before_status = self.git_status(app)
        token = approval_token("demo-local", "deploy", ref=first[:12])

        result = self.run_wrapper(policy_path, "deploy-ref", ["--ref", first[:12], "--approval-token", token])

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.git_head(app), second)
        self.assertEqual(self.git_status(app), before_status)
        self.assertEqual(sha256_path(app / "logs/current.log"), before_log_hash)

    def test_ops_wrapper_post_start_execution_exception_closes_failed_terminal_event(self) -> None:
        app, policy_path, audit_log = self.make_wrapper_workspace()
        shutil.rmtree(app / "service")
        (app / "service").write_text("not a directory\n", encoding="utf-8")
        token = approval_token("demo-local", "restart-service", service="guardedops-demo")

        result = self.run_wrapper(policy_path, "restart-service", ["--service-name", "guardedops-demo", "--approval-token", token])

        self.assertEqual(result.returncode, 2)
        self.assertTrue(audit_log.exists(), result.stderr)
        events = load_jsonl(audit_log)
        self.assertEqual(len(events), 2)
        self.assert_audit_event_shape(events[0], phase="start", status="started")
        self.assert_audit_event_shape(events[1], phase="result", status="failed")
        self.assertEqual(events[0]["operation_id"], events[1]["operation_id"])
        self.assertEqual(events[1]["reason_code"], "execution_failed")

    def test_audit_details_and_cli_output_redact_secret_material(self) -> None:
        app, policy_path, audit_log = self.make_wrapper_workspace()
        (app / "logs/current.log").write_text(
            "token=raw-token api_key=raw-api-key Authorization: Bearer raw-auth Cookie: raw-cookie\n",
            encoding="utf-8",
        )

        result = self.run_wrapper(
            policy_path,
            "log-query",
            ["--run-id", "run-20260811", "--path", str(app / "logs/current.log"), "--lines", "10"],
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        combined = result.stdout + result.stderr + audit_log.read_text(encoding="utf-8")
        self.assertNotIn("raw-token", combined)
        self.assertNotIn("raw-api-key", combined)
        self.assertNotIn("raw-auth", combined)
        self.assertNotIn("raw-cookie", combined)
        events = load_jsonl(audit_log)
        self.assertEqual(len(events), 1)
        self.assert_audit_event_shape(events[0], phase="result", status="success")
        self.assertEqual(events[0]["run_id"], "run-20260811")
        self.assertEqual(events[0]["operation_kind"], "read")

    def test_opsctl_dry_run_audit_status_renders_local_and_ssh_wrapper_audit_summary(self) -> None:
        shutil.copytree(ROOT / "examples", self.tmp / "examples")
        shutil.copytree(ROOT / "server", self.tmp / "server")
        local = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "--fleet",
                "examples/fleet.example.json",
                "audit-status",
                "--host",
                "demo-local",
                "--run-id",
                "run-20260811",
            ],
            cwd=self.tmp,
        )
        ssh = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "--fleet",
                "examples/fleet.example.json",
                "audit-status",
                "--host",
                "demo-ssh",
                "--run-id",
                "run-20260811",
            ],
            cwd=self.tmp,
        )

        self.assertEqual(local.returncode, 0, local.stderr)
        self.assertEqual(ssh.returncode, 0, ssh.stderr)
        local_payload = json.loads(local.stdout)
        ssh_payload = json.loads(ssh.stdout)
        self.assertEqual(local_payload["kind"], "remote-command")
        self.assertEqual(ssh_payload["kind"], "remote-command")
        self.assertEqual(local_payload["command"][:3], [PYTHON, "server/ops-wrapper", "--policy"])
        self.assertTrue(local_payload["command"][3].endswith(".guarded_ops/demo-local/policy.json"))
        self.assertIn("audit-summary", local_payload["command"])
        self.assertIn("--run-id", local_payload["command"])
        self.assertIn("run-20260811", local_payload["command"])
        self.assertEqual(ssh_payload["command"][:3], ["ssh", "example-demo-host", "--"])
        self.assertIn("/usr/local/bin/ops-wrapper-demo", ssh_payload["command"][3])
        self.assertIn("--policy /etc/guardedops-demo/policy.json", ssh_payload["command"][3])
        self.assertIn("audit-summary", ssh_payload["command"][3])
        self.assertIn("--run-id run-20260811", ssh_payload["command"][3])

    def test_audit_summary_legacy_indexes_host_context_and_chronological_since(self) -> None:
        legacy_log = self.tmp / "legacy-indexes.jsonl"
        write_jsonl(
            legacy_log,
            [
                {"time": "2026-08-11T00:00:00Z", "action": "runtime-baseline", "file_count": 3},
                {
                    "ts": "2026-08-10T23:30:00-01:00",
                    "action": "deploy-ref",
                    "status": "failed",
                    "details": {"ref": "abcdef0"},
                },
            ],
        )

        legacy = review_audit_summary(legacy_log, self.tmp, "--host", "demo-legacy")

        self.assertEqual(legacy.returncode, 3, legacy.stderr)
        summary = json.loads(legacy.stdout)
        self.assertEqual(summary["counts_by_action"], {"deploy-ref": 1, "runtime-baseline": 1})
        self.assertEqual(summary["counts_by_status"], {"failed": 1, "unknown": 1})
        self.assertEqual(summary["window"], {"first_ts": "2026-08-11T00:00:00Z", "last_ts": "2026-08-11T00:30:00Z"})
        self.assertEqual(summary["hosts"], ["demo-legacy"])

        offset_log = self.tmp / "offset.jsonl"
        offset_event = v1_event(
            operation_id="read-offset-1",
            action="runtime-baseline",
            operation_kind="read",
            phase="result",
            status="success",
        )
        offset_event["ts"] = "2026-08-10T23:30:00-01:00"
        write_jsonl(offset_log, [offset_event])

        offset = review_audit_summary(offset_log, self.tmp, "--since", "2026-08-11T00:00:00Z")

        self.assertEqual(offset.returncode, 0, offset.stderr)
        offset_summary = json.loads(offset.stdout)
        self.assertEqual(offset_summary["operations"]["total"], 1)
        self.assertEqual(offset_summary["window"], {"first_ts": "2026-08-11T00:30:00Z", "last_ts": "2026-08-11T00:30:00Z"})

    def test_audit_summary_rejects_invalid_identity_time_action_and_sequence(self) -> None:
        invalid_log = self.tmp / "invalid-identities.jsonl"
        unknown_action = v1_event(
            operation_id="invalid-action-1",
            action="runtime-baseline",
            operation_kind="read",
            phase="result",
            status="success",
        )
        unknown_action["action"] = "unknown-action"
        invalid_time = v1_event(
            operation_id="invalid-time-1",
            action="runtime-baseline",
            operation_kind="read",
            phase="result",
            status="success",
        )
        invalid_time["ts"] = "not-a-time"
        invalid_run = v1_event(
            operation_id="invalid-run-1",
            action="runtime-baseline",
            operation_kind="read",
            phase="result",
            status="success",
        )
        invalid_run["run_id"] = "bad run id"
        write_jsonl(invalid_log, [unknown_action, invalid_time, invalid_run])

        invalid = review_audit_summary(invalid_log, self.tmp)

        self.assertEqual(invalid.returncode, 3, invalid.stderr)
        invalid_summary = json.loads(invalid.stdout)
        self.assertEqual(invalid_summary["records"]["unknown"], 3)
        self.assertEqual(invalid_summary["operations"]["total"], 0)

        sequence_log = self.tmp / "bad-sequence.jsonl"
        write_jsonl(
            sequence_log,
            [
                v1_event(
                    operation_id="out-of-order-1",
                    action="restart-service",
                    operation_kind="write",
                    phase="result",
                    status="success",
                ),
                v1_event(
                    operation_id="out-of-order-1",
                    action="restart-service",
                    operation_kind="write",
                    phase="start",
                    status="started",
                ),
            ],
        )

        sequence = review_audit_summary(sequence_log, self.tmp)

        self.assertEqual(sequence.returncode, 3, sequence.stderr)
        sequence_summary = json.loads(sequence.stdout)
        self.assertIn("invalid_operation_sequence", sequence_summary["reasons"])
        self.assertEqual(sequence_summary["operations"]["invalid_sequences"], 1)
        self.assertEqual(sequence_summary["operations"]["success"], 0)

    def test_append_event_rejects_short_write(self) -> None:
        if str(ROOT / "src") not in sys.path:
            sys.path.insert(0, str(ROOT / "src"))
        from guarded_ops.audit import append_event, event_payload
        from guarded_ops.errors import AuditWriteError

        event = event_payload(
            operation_id="short-write-1",
            run_id="run-20260811",
            host="demo-local",
            action="runtime-baseline",
            operation_kind="read",
            phase="result",
            status="success",
            wrapper_version="0.2.0-test",
            policy_version="demo-v2",
        )

        with mock.patch("guarded_ops.audit.os.write", side_effect=lambda _fd, data: len(data) - 1):
            with self.assertRaises(AuditWriteError):
                append_event(self.tmp / "short-write.jsonl", event)

    def test_audit_details_are_action_scoped_and_filters_reject_invalid_run_ids(self) -> None:
        audit_log = self.tmp / "action-details.jsonl"
        invalid = v1_event(
            operation_id="invalid-details-1",
            action="runtime-baseline",
            operation_kind="read",
            phase="result",
            status="success",
            details={"backup": "/tmp/not-allowed-for-this-action"},
        )
        write_jsonl(audit_log, [invalid])

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)["records"]["unknown"], 1)

        invalid_filter = review_audit_summary(audit_log, self.tmp, "--run-id", "bad run id")

        self.assertEqual(invalid_filter.returncode, 2, invalid_filter.stderr)
        filter_summary = json.loads(invalid_filter.stdout)
        self.assertEqual(filter_summary["verdict"], "insufficient")
        self.assertEqual(filter_summary["reasons"], ["invalid_run_id"])

    def test_audit_summary_tolerates_invalid_legacy_status_types(self) -> None:
        audit_log = self.tmp / "legacy-invalid-status.jsonl"
        write_jsonl(
            audit_log,
            [
                {
                    "ts": "2026-08-11T00:00:00Z",
                    "action": "deploy-ref",
                    "status": {"unexpected": "object"},
                    "details": {},
                }
            ],
        )

        result = review_audit_summary(audit_log, self.tmp)

        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)["counts_by_status"], {"unknown": 1})

    def test_wrapper_runtime_path_prefers_explicit_then_sibling_sources(self) -> None:
        wrapper = self.tmp / "bundle/bin/ops-wrapper"
        wrapper.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "server/ops-wrapper", wrapper)

        def fake_runtime(root: Path, label: str) -> None:
            package = root / "guarded_ops"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "wrapper.py").write_text(
                f"def main():\n    print({label!r})\n    return 0\n",
                encoding="utf-8",
            )

        sibling_src = self.tmp / "bundle/src"
        explicit_src = self.tmp / "explicit-src"
        fake_runtime(sibling_src, "sibling")
        fake_runtime(explicit_src, "explicit")

        env = os.environ.copy()
        env["GUARDEDOPS_SRC"] = str(explicit_src)
        explicit = subprocess.run([PYTHON, str(wrapper)], env=env, text=True, capture_output=True, check=False)
        env.pop("GUARDEDOPS_SRC")
        sibling = subprocess.run([PYTHON, str(wrapper)], env=env, text=True, capture_output=True, check=False)

        self.assertEqual(explicit.returncode, 0, explicit.stderr)
        self.assertEqual(explicit.stdout.strip(), "explicit")
        self.assertEqual(sibling.returncode, 0, sibling.stderr)
        self.assertEqual(sibling.stdout.strip(), "sibling")


if __name__ == "__main__":
    unittest.main()
