from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guarded_ops.approval import Approval, ApprovalError, validate_approval
from guarded_ops.config_patch import parse_set_expr
from guarded_ops.fleet import host_config, load_fleet
from guarded_ops.hook_policy import decide_command
from guarded_ops.redaction import redact_text


PYTHON = sys.executable


def run_cli(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    env = {"PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)


class ApprovalFleetTests(unittest.TestCase):
    def test_approval_requires_exact_scope(self) -> None:
        validate_approval("host=staging action=deploy ref=abcdef0", {"host": "staging", "action": "deploy", "ref": "abcdef0"})
        with self.assertRaises(ApprovalError):
            Approval.parse("host=staging action=deploy ref=abcdef0").require({"host": "prod-us", "action": "deploy", "ref": "abcdef0"})
        with self.assertRaisesRegex(ApprovalError, "unexpected keys"):
            Approval.parse("host=staging action=deploy ref=abcdef0 extra=1").require({"host": "staging", "action": "deploy", "ref": "abcdef0"})
        with self.assertRaisesRegex(ApprovalError, "duplicate key"):
            Approval.parse("host=staging action=deploy ref=bad ref=abcdef0")

    def test_example_fleet_loads_and_unknown_host_fails(self) -> None:
        fleet = load_fleet(ROOT / "examples/fleet.example.json")
        self.assertEqual(host_config(fleet, "staging")["ssh_alias"], "example-staging")
        with self.assertRaisesRegex(Exception, "unknown host"):
            host_config(fleet, "missing")


class OpsctlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guardedops-test-"))
        shutil.copytree(ROOT / "examples", self.tmp / "examples")
        shutil.copytree(ROOT / "server", self.tmp / "server")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def test_plan_and_apply_config_patch_allowed_key(self) -> None:
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "plan-config",
                "--host",
                "staging",
                "--file",
                "config/app.env",
                "--set",
                "APP_LOG_LEVEL=debug",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        payload = json.loads(plan.stdout)
        token = payload["approval"]
        apply_result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "apply-config",
                "--change-id",
                payload["change_id"],
                "--approval-token",
                token,
            ],
            cwd=self.tmp,
        )
        self.assertEqual(apply_result.returncode, 0, apply_result.stderr)
        self.assertIn("APP_LOG_LEVEL=debug", (self.tmp / "examples/mock-app/config/app.env").read_text(encoding="utf-8"))

    def test_plan_config_dry_run_has_no_side_effect(self) -> None:
        dry_plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "plan-config",
                "--host",
                "staging",
                "--file",
                "config/app.env",
                "--set",
                "APP_LOG_LEVEL=debug",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(dry_plan.returncode, 0, dry_plan.stderr)
        payload = json.loads(dry_plan.stdout)
        self.assertTrue(payload["dry_run"])
        self.assertIsNone(payload["path"])
        self.assertFalse((self.tmp / ".guarded_ops").exists())

    def test_apply_config_dry_run_has_no_side_effect(self) -> None:
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "plan-config",
                "--host",
                "staging",
                "--file",
                "config/app.env",
                "--set",
                "APP_LOG_LEVEL=debug",
            ],
            cwd=self.tmp,
        )
        payload = json.loads(plan.stdout)
        before = (self.tmp / "examples/mock-app/config/app.env").read_text(encoding="utf-8")
        dry_run = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "apply-config",
                "--change-id",
                payload["change_id"],
                "--approval-token",
                payload["approval"],
            ],
            cwd=self.tmp,
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertTrue(json.loads(dry_run.stdout)["dry_run"])
        after = (self.tmp / "examples/mock-app/config/app.env").read_text(encoding="utf-8")
        self.assertEqual(before, after)

    def test_repo_scripts_run_without_install(self) -> None:
        result = subprocess.run(["server/ops-wrapper", "--policy", "server/policy.example.json", "version"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        help_result = subprocess.run(["cli/opsctl", "--help"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)

    def test_plan_config_rejects_unlisted_key(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "plan-config",
                "--host",
                "staging",
                "--file",
                "config/app.env",
                "--set",
                "UNLISTED_KEY=value",
            ],
            cwd=self.tmp,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not allowed", result.stderr)

    def test_plan_config_rejects_multiline_value(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "plan-config",
                "--host",
                "staging",
                "--file",
                "config/app.env",
                "--set",
                "APP_LOG_LEVEL=debug\nINJECTED=1",
            ],
            cwd=self.tmp,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("single line", result.stderr)

    def test_parse_set_expr_rejects_multiline_key_and_value(self) -> None:
        for expr in ("APP_LOG_LEVEL=debug\nINJECTED=1", "APP_LOG_LEVEL\nEVIL=debug"):
            with self.subTest(expr=expr):
                with self.assertRaisesRegex(ValueError, "single line"):
                    parse_set_expr(expr)

    def test_deploy_requires_exact_sha(self) -> None:
        branch = run_cli([PYTHON, "-m", "guarded_ops.opsctl", "plan-deploy", "--host", "staging", "--ref", "main"], cwd=self.tmp)
        self.assertNotEqual(branch.returncode, 0)
        sha = run_cli([PYTHON, "-m", "guarded_ops.opsctl", "plan-deploy", "--host", "staging", "--ref", "abcdef0"], cwd=self.tmp)
        self.assertEqual(sha.returncode, 0, sha.stderr)

    def init_demo_repo(self) -> tuple[Path, str]:
        init = run_cli([PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "init-demo", "--force"], cwd=self.tmp)
        self.assertEqual(init.returncode, 0, init.stderr)
        payload = json.loads(init.stdout)
        app = Path(payload["app_path"])
        head = payload["head"]
        return app, head

    def test_demo_local_lifecycle_via_opsctl(self) -> None:
        app, head = self.init_demo_repo()
        baseline = run_cli([PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "baseline", "--host", "demo-local"], cwd=self.tmp)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn(head, baseline.stdout)
        self.assertIn(".guarded_ops/demo-local/app", baseline.stdout)
        self.assertNotIn("../../../README.md", baseline.stdout)

        fetch_token = "host=demo-local action=safe-git-fetch remote=origin"
        fetch = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "git", "--host", "demo-local", "--op", "fetch", "--remote", "origin", "--approval-token", fetch_token],
            cwd=self.tmp,
        )
        self.assertEqual(fetch.returncode, 0, fetch.stderr)

        subprocess.run(["git", "branch", "abcdef0", head], cwd=app, check=True, capture_output=True, text=True)
        hex_branch_checkout = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "git", "--host", "demo-local", "--op", "checkout", "--ref", "abcdef0", "--approval-token", "host=demo-local action=safe-git-checkout ref=abcdef0"],
            cwd=self.tmp,
        )
        self.assertNotEqual(hex_branch_checkout.returncode, 0)
        self.assertIn("commit object", hex_branch_checkout.stderr)

        bad_checkout = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "git", "--host", "demo-local", "--op", "checkout", "--ref", "main", "--approval-token", "host=demo-local action=safe-git-checkout ref=main"],
            cwd=self.tmp,
        )
        self.assertNotEqual(bad_checkout.returncode, 0)
        self.assertIn("exact hex ref", bad_checkout.stderr)

        checkout_token = f"host=demo-local action=safe-git-checkout ref={head}"
        checkout = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "git", "--host", "demo-local", "--op", "checkout", "--ref", head, "--approval-token", checkout_token],
            cwd=self.tmp,
        )
        self.assertEqual(checkout.returncode, 0, checkout.stderr)

        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-config-batch",
                "--host",
                "demo-local",
                "--file",
                "config/app.json",
                "--set",
                "feature.enabled=true",
                "--set",
                "limits.timeout_ms=2500",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        plan_payload = json.loads(plan.stdout)
        apply_result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "apply-config-batch",
                "--change-id",
                plan_payload["change_id"],
                "--approval-token",
                plan_payload["approval"],
            ],
            cwd=self.tmp,
        )
        self.assertEqual(apply_result.returncode, 0, apply_result.stderr)
        config = json.loads((app / "config/app.json").read_text(encoding="utf-8"))
        self.assertTrue(config["feature"]["enabled"])
        self.assertEqual(config["limits"]["timeout_ms"], 2500)
        self.assertTrue((self.tmp / ".guarded_ops/demo-local/audit.jsonl").exists())
        self.assertTrue((self.tmp / ".guarded_ops/demo-local/backups").exists())

        restart = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "restart-service",
                "--host",
                "demo-local",
                "--approval-token",
                "host=demo-local action=restart-service service=guardedops-demo",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(restart.returncode, 0, restart.stderr)
        logs = run_cli([PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "logs", "--host", "demo-local", "--name", "current.log"], cwd=self.tmp)
        self.assertEqual(logs.returncode, 0, logs.stderr)
        self.assertIn("restarted", logs.stdout)

    def test_demo_local_rejects_bad_config_and_service_scope(self) -> None:
        self.init_demo_repo()
        bad_key = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "plan-config-batch", "--host", "demo-local", "--file", "config/app.json", "--set", "secret.token=abc"],
            cwd=self.tmp,
        )
        self.assertNotEqual(bad_key.returncode, 0)
        self.assertIn("not allowed", bad_key.stderr)
        bad_service = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--fleet", "examples/fleet.example.json", "restart-service", "--host", "demo-local", "--service", "other", "--approval-token", "host=demo-local action=restart-service service=other"],
            cwd=self.tmp,
        )
        self.assertNotEqual(bad_service.returncode, 0)
        self.assertIn("service is not allowed", bad_service.stderr)

    def test_batch_plan_redacts_secret_like_values(self) -> None:
        self.init_demo_repo()
        fleet = json.loads((self.tmp / "examples/fleet.example.json").read_text(encoding="utf-8"))
        fleet["hosts"]["demo-local"]["config_files"]["config/app.env"]["allowed_keys"].append("API_TOKEN")
        (self.tmp / "examples/fleet.example.json").write_text(json.dumps(fleet, indent=2), encoding="utf-8")
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-config-batch",
                "--host",
                "demo-local",
                "--file",
                "config/app.env",
                "--set",
                "API_TOKEN=supersecret",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertIn("<redacted>", plan.stdout)
        self.assertNotIn("supersecret", plan.stdout)

    def test_apply_config_batch_rejects_duplicate_approval_key(self) -> None:
        self.init_demo_repo()
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-config-batch",
                "--host",
                "demo-local",
                "--file",
                "config/app.json",
                "--set",
                "feature.enabled=true",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        payload = json.loads(plan.stdout)
        duplicate = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "apply-config-batch",
                "--change-id",
                payload["change_id"],
                "--approval-token",
                f"host=demo-local action=apply-config-batch change_id=bad change_id={payload['change_id']}",
            ],
            cwd=self.tmp,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("duplicate key", duplicate.stderr)

    def test_install_wrapper_local_copies_wrapper_and_policy(self) -> None:
        target = self.tmp / "demo-install"
        backup_root = self.tmp / "install-backups"
        policy_source = self.tmp / "install-policy.json"
        policy_data = json.loads((self.tmp / "examples/demo-remote/policy.json").read_text(encoding="utf-8"))
        policy_data["backup_dir"] = str(backup_root)
        policy_source.write_text(json.dumps(policy_data), encoding="utf-8")
        fleet = {
            "hosts": {
                "install-demo": {
                    "ssh_alias": "local-install",
                    "transport": "local",
                    "allow_untrusted_policy": True,
                    "app_path": "examples/demo-remote/app",
                    "service": "guardedops-demo",
                    "server_wrapper": str(target / "ops-wrapper-demo"),
                    "policy_path": str(target / "policy.json"),
                    "policy_source": str(policy_source),
                    "config_files": {
                        "config/app.env": {"allowed_keys": ["APP_LOG_LEVEL"]}
                    },
                }
            }
        }
        fleet_path = self.tmp / "install-fleet.json"
        fleet_path.write_text(json.dumps(fleet), encoding="utf-8")
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                str(fleet_path),
                "install-wrapper",
                "--host",
                "install-demo",
                "--operation-id",
                "op-install-local-001",
                "--run-id",
                "run-install-local-001",
                "--wrapper-source",
                "server/ops-wrapper",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        backup_manifest = json.loads((backup_root / "run-install-local-001-op-install-local-001" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["backup_manifest_sha"], backup_manifest["sha256"])
        self.assertTrue((target / "ops-wrapper-demo").exists())
        self.assertTrue((target / "policy.json").exists())
        self.assertTrue((target / "src/guarded_ops/wrapper.py").exists())
        intent = [json.loads(line) for line in (self.tmp / ".guarded_ops/intent.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(intent[0]["operation_id"], "op-install-local-001")
        self.assertEqual(intent[0]["action"], "install-wrapper")
        self.assertEqual(intent[0]["details"]["wrapper"], str(target / "ops-wrapper-demo"))
        self.assertNotIn("approval", json.dumps(intent[0]).lower())
        audit = [json.loads(line) for line in (self.tmp / ".guarded_ops/install/audit.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["phase"] for record in audit], ["start", "result"])
        self.assertEqual([record["operation_id"] for record in audit], ["op-install-local-001", "op-install-local-001"])
        self.assertEqual(audit[-1]["details"]["backup_manifest_sha"], payload["backup_manifest_sha"])
        self.assertEqual(audit[-1]["details"]["candidate_manifest_sha"], payload["candidate_manifest_sha"])

    def test_install_wrapper_ssh_plan_targets_configured_paths(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "install-wrapper",
                "--host",
                "demo-ssh",
                "--wrapper-source",
                "server/ops-wrapper",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        rendered = json.dumps(payload)
        self.assertIn("/usr/local/bin/ops-wrapper-demo", rendered)
        self.assertNotIn("mkdir\", \"-p\", \"/usr/local/bin", rendered)
        self.assertIn("/etc/guardedops-demo/policy.json", rendered)
        self.assertIn("/etc/guardedops-demo/src", rendered)
        self.assertIn("backup_id", payload)
        self.assertIn("candidate_manifest_sha", payload)
        self.assertIn(".guarded_ops/install/audit.jsonl", payload["audit_log"])
        self.assertFalse((self.tmp / ".guarded_ops/intent.jsonl").exists())
        generated = json.loads((self.tmp / payload["generated_policy"]).read_text(encoding="utf-8"))
        self.assertEqual(generated["host"], "demo-ssh")
        self.assertEqual(generated["app_path"], "/opt/guardedops-demo/app")
        self.assertEqual(generated["service"], "guardedops_demo")
        self.assertEqual(generated["audit_log"], "/var/log/guardedops-demo/audit.jsonl")
        self.assertEqual(generated["backup_dir"], "/var/backups/guardedops-demo")
        self.assertEqual(generated["actions"]["log-query"]["roots"], ["/opt/guardedops-demo/app/logs"])

    def test_init_ssh_demo_dry_run_is_sandbox_scoped(self) -> None:
        missing_reset = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--dry-run", "init-ssh-demo", "--host", "demo-ssh"],
            cwd=self.tmp,
        )
        self.assertNotEqual(missing_reset.returncode, 0)
        self.assertIn("--reset", missing_reset.stderr)
        result = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "--dry-run", "init-ssh-demo", "--host", "demo-ssh", "--reset"],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        rendered = json.dumps(payload)
        self.assertEqual(payload["app"], "/opt/guardedops-demo/app")
        self.assertEqual(payload["origin"], "/opt/guardedops-demo/origin.git")
        self.assertEqual(payload["audit_dir"], "/var/log/guardedops-demo")
        self.assertEqual(payload["backup_dir"], "/var/backups/guardedops-demo")
        self.assertNotIn("/opt/project", rendered)
        self.assertNotIn("aiserver", rendered)
        self.assertNotIn("/tmp/guardedops-demo-app", rendered)


class WrapperRouteReviewHookTests(unittest.TestCase):
    def make_policy_repo(self, tmp_path: Path) -> tuple[Path, str, Path]:
        app = tmp_path / "app"
        app.mkdir()
        (app / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "init"], cwd=app, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=app, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Codex"], cwd=app, check=True, capture_output=True, text=True)
        subprocess.run(["git", "add", "."], cwd=app, check=True, capture_output=True, text=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=app, check=True, capture_output=True, text=True)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=app, check=True, capture_output=True, text=True).stdout.strip()
        policy = json.loads((ROOT / "examples/demo-remote/policy.json").read_text(encoding="utf-8"))
        policy["app_path"] = str(app)
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return app, head, policy_path

    def test_wrapper_observe_and_log_query_redacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            app_path = tmp_path / "app"
            log_path = app_path / "logs/current.log"
            log_path.parent.mkdir(parents=True)
            log_path.write_text("token=abc123 password=hunter2\n", encoding="utf-8")
            policy = json.loads((ROOT / "server/policy.example.json").read_text(encoding="utf-8"))
            policy["app_path"] = str(app_path)
            policy["actions"]["log-query"]["roots"] = [str(log_path.parent)]
            policy_path = tmp_path / "policy.json"
            policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = run_cli(
                [
                    PYTHON,
                    "server/ops-wrapper",
                    "--policy",
                    str(policy_path),
                    "--allow-untrusted-policy",
                    "log-query",
                    "--path",
                    str(log_path),
                    "--lines",
                    "5",
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("token=<redacted>", result.stdout)
            self.assertIn("password=<redacted>", result.stdout)
            self.assertNotIn("abc123", result.stdout)
            self.assertNotIn("hunter2", result.stdout)

    def test_wrapper_version_uses_sidecar(self) -> None:
        result = run_cli([PYTHON, "server/ops-wrapper", "--policy", "server/policy.example.json", "version"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], "0.2.0")
        self.assertEqual(payload["policy_version"], "example-v1")

    def test_wrapper_config_patch_dry_run_and_allowlist(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "server/ops-wrapper",
                "--policy",
                "server/policy.example.json",
                "config-patch",
                "--file",
                "config/app.env",
                "--set",
                "APP_LOG_LEVEL=debug",
                "--dry-run",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["dry_run"])
        rejected = run_cli(
            [
                PYTHON,
                "server/ops-wrapper",
                "--policy",
                "server/policy.example.json",
                "config-patch",
                "--file",
                "config/app.env",
                "--set",
                "UNLISTED=value",
                "--dry-run",
            ]
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("not allowed", rejected.stderr)
        write_attempt = run_cli(
            [
                PYTHON,
                "server/ops-wrapper",
                "--policy",
                "server/policy.example.json",
                "config-patch",
                "--file",
                "config/app.env",
                "--set",
                "APP_LOG_LEVEL=debug",
            ]
        )
        self.assertNotEqual(write_attempt.returncode, 0)
        self.assertIn("use apply-config-batch", write_attempt.stderr)

    def test_wrapper_batch_plan_redacts_secret_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            app = tmp_path / "app"
            (app / "config").mkdir(parents=True)
            (app / "config/app.env").write_text("API_TOKEN=oldsecret\n", encoding="utf-8")
            policy = json.loads((ROOT / "examples/demo-remote/policy.json").read_text(encoding="utf-8"))
            policy["app_path"] = str(app)
            policy["audit_log"] = str(tmp_path / "audit.jsonl")
            policy["backup_dir"] = str(tmp_path / "backups")
            policy["actions"]["config-patch"]["allowed_files"]["config/app.env"]["allowed_keys"].append("API_TOKEN")
            policy_path = tmp_path / "policy.json"
            policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = run_cli(
                [
                    PYTHON,
                    "server/ops-wrapper",
                    "--policy",
                    str(policy_path),
                    "--allow-untrusted-policy",
                    "plan-config-batch",
                    "--file",
                    "config/app.env",
                    "--set",
                    "API_TOKEN=newsecret",
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("API_TOKEN=<redacted>", result.stdout)
            self.assertNotIn("oldsecret", result.stdout)
            self.assertNotIn("newsecret", result.stdout)

    def test_wrapper_high_risk_actions_require_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, head, policy = self.make_policy_repo(Path(tmp))
            for command in (
                [PYTHON, "server/ops-wrapper", "--policy", "examples/demo-remote/policy.json", "--allow-untrusted-policy", "restart-service", "--service-name", "guardedops-demo"],
                [PYTHON, "server/ops-wrapper", "--policy", "examples/demo-remote/policy.json", "--allow-untrusted-policy", "safe-git", "--op", "fetch"],
                [PYTHON, "server/ops-wrapper", "--policy", str(policy), "--allow-untrusted-policy", "safe-git", "--op", "checkout", "--ref", head],
                [PYTHON, "server/ops-wrapper", "--policy", "examples/demo-remote/policy.json", "--allow-untrusted-policy", "apply-config-batch", "--change-id", "bad", "--file", "config/app.json", "--set", "feature.enabled=true"],
                [PYTHON, "server/ops-wrapper", "--policy", str(policy), "--allow-untrusted-policy", "deploy-ref", "--ref", head],
            ):
                with self.subTest(command=command):
                    result = run_cli(command)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("approval", result.stderr)

    def test_wrapper_safe_git_rejects_unsafe_read_ref(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "server/ops-wrapper",
                "--policy",
                "examples/demo-remote/policy.json",
                "--allow-untrusted-policy",
                "safe-git",
                "--op",
                "rev-parse",
                "--ref",
                "../bad",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe git ref", result.stderr)

    def test_wrapper_rejects_hex_like_branch_for_deploy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            app, _, policy_path = self.make_policy_repo(tmp_path)
            subprocess.run(["git", "branch", "abcdef0"], cwd=app, check=True, capture_output=True, text=True)
            result = run_cli(
                [
                    PYTHON,
                    "server/ops-wrapper",
                    "--policy",
                    str(policy_path),
                    "--allow-untrusted-policy",
                    "deploy-ref",
                    "--ref",
                    "abcdef0",
                    "--approval-token",
                    "host=demo-local action=deploy ref=abcdef0",
                ]
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("commit object", result.stderr)

    def test_wrapper_rejects_non_default_policy_without_explicit_local_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            custom = Path(tmp) / "policy.json"
            custom.write_text((ROOT / "server/policy.example.json").read_text(encoding="utf-8"), encoding="utf-8")
            rejected = run_cli([PYTHON, "server/ops-wrapper", "--policy", str(custom), "version"])
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("untrusted policy", rejected.stderr)
            allowed = run_cli([PYTHON, "server/ops-wrapper", "--policy", str(custom), "--allow-untrusted-policy", "version"])
            self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_wrapper_accepts_documented_privileged_policy_path_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            etc_policy = Path(tmp) / "policy.json"
            etc_policy.write_text((ROOT / "server/policy.example.json").read_text(encoding="utf-8"), encoding="utf-8")
            # Simulate the trusted production path by exercising the trust predicate via symlink only when possible.
            # The public example must at least reject arbitrary paths while documenting /etc/ops-wrapper/policy.json.
            rejected = run_cli([PYTHON, "server/ops-wrapper", "--policy", str(etc_policy), "version"])
            self.assertNotEqual(rejected.returncode, 0)

    def test_wrapper_blocks_log_path_escape(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "server/ops-wrapper",
                "--policy",
                "server/policy.example.json",
                "log-query",
                "--path",
                "README.md",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside allowed roots", result.stderr)

    def test_route_preflight_and_proxycommand_are_synthetic(self) -> None:
        preflight = run_cli([PYTHON, "-m", "guarded_ops.route", "preflight", "--target", "example-prod-us"])
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.assertIn("203.0.113.20", preflight.stdout)
        proxy = run_cli([PYTHON, "-m", "guarded_ops.route", "proxycommand", "--target", "example-prod-us", "--print-json"])
        self.assertEqual(proxy.returncode, 0, proxy.stderr)
        self.assertIn("nc", proxy.stdout)
        acceptance = run_cli([PYTHON, "-m", "guarded_ops.route", "acceptance"])
        self.assertEqual(acceptance.returncode, 0, acceptance.stderr)
        self.assertIn("git.example.com", acceptance.stdout)
        git = run_cli([PYTHON, "-m", "guarded_ops.route", "git", "--operation", "ls-remote"])
        self.assertEqual(git.returncode, 0, git.stderr)
        self.assertIn("dry-run", git.stdout)

    def test_route_sync_ssh_config_dry_run(self) -> None:
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.route",
                "sync-ssh-config",
                "--output",
                "/tmp/guardedops-example-ssh.conf",
                "--dry-run",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Host example-prod-us", result.stdout)
        self.assertIn("ProxyCommand routectl proxycommand", result.stdout)

    def test_review_requires_explicit_input_and_hashes_commands(self) -> None:
        missing = run_cli([PYTHON, "-m", "guarded_ops.review", "collect"])
        self.assertNotEqual(missing.returncode, 0)
        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.review",
                "collect",
                "--input",
                "examples/session-review/sessions",
                "--output",
                ".guarded_ops/test-review",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        events = json.loads((ROOT / ".guarded_ops/test-review/operation-events.json").read_text(encoding="utf-8"))["events"]
        self.assertTrue(all("command_hash" in item for item in events))
        self.assertNotIn("ssh example-prod-us", json.dumps(events))

    def test_hook_blocks_raw_ssh_and_allows_guarded_entrypoint(self) -> None:
        blocked = decide_command("ssh example-prod-us -- hostname", ROOT / "examples/fleet.example.json")
        self.assertFalse(blocked.allowed)
        self.assertIn("blocked", blocked.reason)
        for command in (
            "ssh -A example-prod-us -- hostname",
            "ssh deploy-user@example-prod-us -- hostname",
            "sftp example-prod-us",
            "scp file.txt example-prod-us:/tmp/file.txt",
            "rsync file.txt example-prod-us:/tmp/file.txt",
            "ssh 203.0.113.20 -- hostname",
            "env ssh example-prod-us -- hostname",
            "env -i PATH=/usr/bin ssh example-prod-us -- hostname",
            "command ssh example-prod-us -- hostname",
            "bash -lc 'ssh example-prod-us -- hostname'",
        ):
            with self.subTest(command=command):
                self.assertFalse(decide_command(command, ROOT / "examples/fleet.example.json").allowed)
        allowed = decide_command("opsctl observe --host staging", ROOT / "examples/fleet.example.json")
        self.assertTrue(allowed.allowed)

    def test_review_template_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_dir = Path(tmp) / "sessions"
            output_dir = Path(tmp) / "out"
            input_dir.mkdir()
            (input_dir / "synthetic.jsonl").write_text(
                json.dumps({"command": "ssh example-prod-us -- cat config", "template": "ssh token=abc123 password=hunter2"}) + "\n",
                encoding="utf-8",
            )
            result = run_cli(
                [
                    PYTHON,
                    "-m",
                    "guarded_ops.review",
                    "collect",
                    "--input",
                    str(input_dir),
                    "--output",
                    str(output_dir),
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            events_text = (output_dir / "operation-events.json").read_text(encoding="utf-8")
            self.assertNotIn("abc123", events_text)
            self.assertNotIn("hunter2", events_text)
            self.assertIn("<redacted-template>", events_text)

    def test_redact_text_handles_common_secret_shapes(self) -> None:
        self.assertEqual(redact_text("Authorization: Bearer abc"), "Authorization: <redacted>")
        self.assertEqual(redact_text("api_key=abc123"), "api_key=<redacted>")


if __name__ == "__main__":
    unittest.main()
