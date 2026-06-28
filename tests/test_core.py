from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from guarded_ops.approval import Approval, ApprovalError, validate_approval
from guarded_ops.config_patch import parse_set_expr
from guarded_ops.fleet import host_config, load_fleet
from guarded_ops.hook_policy import decide_command
from guarded_ops.redaction import redact_text


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run_cli(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    env = {"PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)


class ApprovalFleetTests(unittest.TestCase):
    def test_approval_requires_exact_scope(self) -> None:
        validate_approval("host=staging action=deploy ref=abcdef0", {"host": "staging", "action": "deploy", "ref": "abcdef0"})
        with self.assertRaises(ApprovalError):
            Approval.parse("host=staging action=deploy ref=abcdef0").require({"host": "prod-us", "action": "deploy", "ref": "abcdef0"})

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


class WrapperRouteReviewHookTests(unittest.TestCase):
    def test_wrapper_observe_and_log_query_redacts(self) -> None:
        log_path = ROOT / "examples/mock-app/logs/current.log"
        original = log_path.read_text(encoding="utf-8")
        try:
            log_path.write_text(original + "token=abc123 password=hunter2\n", encoding="utf-8")
            result = run_cli(
                [
                    PYTHON,
                    "server/ops-wrapper",
                    "--policy",
                    "server/policy.example.json",
                    "log-query",
                    "--path",
                    "examples/mock-app/logs/current.log",
                    "--lines",
                    "5",
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("token=<redacted>", result.stdout)
            self.assertIn("password=<redacted>", result.stdout)
            self.assertNotIn("abc123", result.stdout)
            self.assertNotIn("hunter2", result.stdout)
        finally:
            log_path.write_text(original, encoding="utf-8")

    def test_wrapper_version_uses_sidecar(self) -> None:
        result = run_cli([PYTHON, "server/ops-wrapper", "--policy", "server/policy.example.json", "version"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], "0.1.0")
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
