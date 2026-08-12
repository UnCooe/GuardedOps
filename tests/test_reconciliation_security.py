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

from guarded_ops.intent import sanitize_command


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run_cli(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = dict(os.environ)
    merged_env["PYTHONPATH"] = str(ROOT / "src")
    if env:
        merged_env.update(env)
    return subprocess.run(args, cwd=cwd, env=merged_env, text=True, capture_output=True, check=False)


def write_jsonl(path: Path, records: list[dict[str, Any] | str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            if isinstance(record, str):
                handle.write(record + "\n")
            else:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


def run_reconcile(
    intent: Path,
    audit: Path,
    *,
    evidence: Path | None = None,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    command = [
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
        command.extend(["--evidence", str(evidence)])
    return run_cli(command, cwd=cwd)


def load_stdout_json(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return json.loads(result.stdout)


def intent_event(
    operation_id: str,
    *,
    command: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "guardedops.intent/v1",
        "operation_id": operation_id,
        "run_id": "run-security",
        "ts": "2026-08-12T00:00:00Z",
        "host": "demo-local",
        "action": "apply-config-batch",
        "operation_kind": "write",
        "status": "planned",
        "transport": "local",
        "command": command or ["opsctl", "apply-config-batch", "--change-id", operation_id],
        "details": details or {"change_id": operation_id, "file": "config/app.json"},
    }
    return payload


def audit_event(operation_id: str, *, phase: str, status: str, ts: str = "2026-08-12T00:00:01Z") -> dict[str, Any]:
    return {
        "schema_version": "guardedops.audit/v1",
        "operation_id": operation_id,
        "run_id": "run-security",
        "ts": ts,
        "host": "demo-local",
        "action": "apply-config-batch",
        "operation_kind": "write",
        "phase": phase,
        "status": status,
        "reason_code": None,
        "details": {"change_id": operation_id, "file": "config/app.json"},
        "wrapper_version": "0.2.0-test",
        "policy_version": "demo-v2",
    }


class ReconciliationSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guardedops-reconcile-security-"))
        self.intent = self.tmp / "intent.jsonl"
        self.audit = self.tmp / "audit.jsonl"
        self.evidence = self.tmp / "evidence.jsonl"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def assert_output_has_no_secret(self, result: subprocess.CompletedProcess[str], *secrets: str) -> None:
        rendered = result.stdout + result.stderr
        for secret in secrets:
            self.assertNotIn(secret, rendered)

    def test_intent_command_redacts_equals_form_value_flags(self) -> None:
        command = sanitize_command(
            [
                "opsctl",
                "--set=feature.enabled=true",
                "--approval-token=approval-secret",
                "--authorization=Bearer-secret",
            ]
        )

        self.assertEqual(
            command,
            ["opsctl", "--set=<redacted>", "--approval-token=<redacted>", "--authorization=<redacted>"],
        )

    def test_unknown_evidence_only_enters_denominator_and_cannot_complete(self) -> None:
        write_jsonl(self.intent, [])
        write_jsonl(self.audit, [])
        write_jsonl(
            self.evidence,
            [
                {
                    "schema_version": "guardedops.evidence/v1",
                    "operation_id": "op-mystery-001",
                    "run_id": "run-security",
                    "ts": "2026-08-12T00:00:02Z",
                    "host": "demo-local",
                    "source": "mystery",
                    "status": "unknown",
                    "reason_code": "mystery_unknown",
                    "details": {"command_template": "mystery command"},
                }
            ],
        )

        result = run_reconcile(self.intent, self.audit, evidence=self.evidence, cwd=self.tmp)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = load_stdout_json(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertIn("unexplained_evidence", payload["reasons"])
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["coverage"]["explained_writes"], 0)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 0)

    def test_malformed_intent_cannot_be_hidden_by_exact_audit(self) -> None:
        malformed_intent = intent_event("op-malformed-001")
        malformed_intent.pop("command")
        write_jsonl(self.intent, [malformed_intent])
        write_jsonl(
            self.audit,
            [
                audit_event("op-malformed-001", phase="start", status="started"),
                audit_event("op-malformed-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit, cwd=self.tmp)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = load_stdout_json(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertIn("malformed", payload["reasons"])
        self.assertIn("missing_intent", payload["reasons"])
        self.assertEqual(payload["records"]["intent_malformed"], 1)
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["missing_intent"], 1)

    def test_hook_block_evidence_only_is_explained_but_not_complete(self) -> None:
        write_jsonl(self.intent, [])
        write_jsonl(self.audit, [])
        write_jsonl(
            self.evidence,
            [
                {
                    "schema_version": "guardedops.evidence/v1",
                    "operation_id": "op-hook-only-001",
                    "run_id": "run-security",
                    "ts": "2026-08-12T00:00:02Z",
                    "host": "demo-local",
                    "source": "ops-guard-hook",
                    "status": "blocked",
                    "reason_code": "hook_denied",
                    "details": {"command_template": "ssh <host> -- <redacted>"},
                }
            ],
        )

        result = run_reconcile(self.intent, self.audit, evidence=self.evidence, cwd=self.tmp)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = load_stdout_json(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertIn("hook_blocked", payload["reasons"])
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["hook_blocked"], 1)
        self.assertEqual(payload["coverage"]["explained_writes"], 1)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 1.0)

    def test_matching_operation_id_with_metadata_conflict_is_not_explained(self) -> None:
        write_jsonl(self.intent, [intent_event("op-metadata-conflict-001")])
        write_jsonl(
            self.audit,
            [
                audit_event(
                    "op-metadata-conflict-001",
                    phase="start",
                    status="started",
                )
                | {"host": "other-host", "run_id": "other-run", "action": "restart-service", "details": {"service": "guardedops-demo"}},
                audit_event(
                    "op-metadata-conflict-001",
                    phase="result",
                    status="success",
                    ts="2026-08-12T00:00:03Z",
                )
                | {"host": "other-host", "run_id": "other-run", "action": "restart-service", "details": {"service": "guardedops-demo"}},
            ],
        )

        result = run_reconcile(self.intent, self.audit, cwd=self.tmp)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        payload = load_stdout_json(result)
        self.assertEqual(payload["verdict"], "partial")
        self.assertIn("metadata_conflict", payload["reasons"])
        self.assertEqual(payload["counts"]["known_writes"], 1)
        self.assertEqual(payload["counts"]["metadata_conflict"], 1)
        self.assertEqual(payload["coverage"]["explained_writes"], 0)
        self.assertEqual(payload["coverage"]["known_write_coverage_ratio"], 0)

    def test_untrusted_intent_details_are_action_allowlisted_and_redacted(self) -> None:
        write_jsonl(
            self.intent,
            [
                intent_event(
                    "op-detail-secret-001",
                    details={
                        "change_id": "op-detail-secret-001",
                        "file": "config/app.json",
                        "value": "token=detail-secret-value",
                        "config": "feature.enabled=true",
                        "stdout": "authorization: Bearer detail-secret",
                    },
                )
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-detail-secret-001", phase="start", status="started"),
                audit_event("op-detail-secret-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit, cwd=self.tmp)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_output_has_no_secret(
            result,
            "detail-secret-value",
            "feature.enabled=true",
            "Bearer detail-secret",
            '"value"',
            '"config"',
            '"stdout"',
        )
        payload = load_stdout_json(result)
        self.assertEqual(payload["operations"][0]["details"], {"change_id": "op-detail-secret-001", "file": "config/app.json"})

    def test_untrusted_intent_command_template_redacts_set_and_auth_arguments(self) -> None:
        write_jsonl(
            self.intent,
            [
                intent_event(
                    "op-command-secret-001",
                    command=[
                        "opsctl",
                        "apply-config-batch",
                        "--set",
                        "feature.enabled=true",
                        "--approval-token",
                        "token=secret-value",
                        "--authorization",
                        "Bearer-secret",
                    ],
                )
            ],
        )
        write_jsonl(
            self.audit,
            [
                audit_event("op-command-secret-001", phase="start", status="started"),
                audit_event("op-command-secret-001", phase="result", status="success", ts="2026-08-12T00:00:03Z"),
            ],
        )

        result = run_reconcile(self.intent, self.audit, cwd=self.tmp)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_output_has_no_secret(result, "feature.enabled=true", "secret-value", "Bearer-secret")
        payload = load_stdout_json(result)
        self.assertEqual(
            payload["operations"][0]["command_template"],
            "opsctl apply-config-batch --set <redacted> --approval-token <redacted> --authorization <redacted>",
        )

    def test_ssh_transport_opsctl_intent_redacts_remote_shell_string_arguments(self) -> None:
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir()
        fake_ssh = fake_bin / "ssh"
        fake_ssh.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
        fake_ssh.chmod(0o755)

        app = self.tmp / "app"
        shutil.copytree(ROOT / "examples/demo-remote/app", app)
        policy_path = self.tmp / "policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "policy_version": "demo-v2",
                    "host": "demo-ssh-test",
                    "service": "guardedops-demo",
                    "app_path": "/opt/guardedops-demo/validation/run-security/app",
                    "version_file": str(ROOT / "server/ops-wrapper.version.json"),
                    "audit_log": "/var/log/guardedops-demo/validation/run-security/audit.jsonl",
                    "backup_dir": "/var/backups/guardedops-demo/validation/run-security",
                    "actions": {"apply-config-batch": {"enabled": True}},
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        fleet_path = self.tmp / "fleet.json"
        fleet_path.write_text(
            json.dumps(
                {
                    "rollout_order": ["demo-ssh-test"],
                    "hosts": {
                        "demo-ssh-test": {
                            "ssh_alias": "fake-ssh-target",
                            "transport": "ssh",
                            "server_wrapper": "/usr/local/bin/ops-wrapper-demo",
                            "policy_path": str(policy_path),
                            "app_path": "/opt/guardedops-demo/validation/run-security/app",
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

        change_payload = {
            "kind": "config-batch-change",
            "host": "demo-ssh-test",
            "file": "config/app.json",
            "sets": [{"path": "feature.enabled", "value": True}],
            "deletes": [],
            "change_id": "change-security-001",
            "created_at": "2026-08-12T00:00:00Z",
        }
        changes = self.tmp / ".guarded_ops" / "changes"
        changes.mkdir(parents=True)
        (changes / f"{change_payload['change_id']}.json").write_text(
            json.dumps(change_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        approval = "host=demo-ssh-test action=apply-config-batch change_id=change-security-001"
        intent_log = self.tmp / ".guarded_ops" / "intent.jsonl"

        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                str(fleet_path),
                "apply-config-batch",
                "--operation-id",
                "op-ssh-redact-001",
                "--change-id",
                change_payload["change_id"],
                "--approval-token",
                approval,
            ],
            cwd=self.tmp,
            env={"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")},
        )

        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        intent_records = [json.loads(line) for line in intent_log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(intent_records), 1)
        rendered_intent = json.dumps(intent_records[0], sort_keys=True)
        self.assertNotIn(approval, rendered_intent)
        self.assertNotIn("feature.enabled=true", rendered_intent)
        self.assertNotIn("change-security-001 --approval-token", rendered_intent)
        self.assertIn("<redacted>", rendered_intent)

    def test_daily_evidence_rejects_forged_report_without_writing_outputs(self) -> None:
        forged_report = {
            "schema_version": "guardedops.audit-reconcile/v1",
            "verdict": "complete\nFORGED MARKDOWN",
            "reasons": "external_write_detected\nFORGED REASON",
            "filters": {"host": ["not", "a", "host"], "run_id": {"bad": "type"}, "since": 123},
            "counts": {"known_writes": "1\nFORGED COUNT", "wrapper_success": {"bad": "type"}},
            "coverage": {"known_write_coverage_ratio": "100%\nFORGED COVERAGE"},
            "operations": [],
        }
        input_report = self.tmp / "forged-report.json"
        output_dir = self.tmp / "daily-output"
        input_report.write_text(json.dumps(forged_report, sort_keys=True) + "\n", encoding="utf-8")

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
            ],
            cwd=self.tmp,
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((output_dir / "daily-evidence.json").exists())
        self.assertFalse((output_dir / "daily-evidence.md").exists())
        if output_dir.exists():
            self.assertEqual(list(output_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
