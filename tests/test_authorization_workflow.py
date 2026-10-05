from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guarded_ops.approval import (  # noqa: E402
    ApprovalError,
    approve_plan_from_user_turn,
    create_approval_record,
    consume_approval_record,
        record_user_prompt_turn,
)
from guarded_ops.hook_policy import decide_command, hook_block_evidence  # noqa: E402


PYTHON = sys.executable


def run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {"PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)


def read_approval(state_root: Path, approval_id: str) -> dict[str, object]:
    return json.loads((state_root / "approvals" / f"{approval_id}.json").read_text(encoding="utf-8"))


def write_approval(state_root: Path, approval_id: str, payload: dict[str, object]) -> None:
    (state_root / "approvals" / f"{approval_id}.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class AuthorizationWorkflowTests(unittest.TestCase):
    """Black-box contract for flexible current-turn approval.

    Expected public API names:
    - guarded_ops.approval.record_user_prompt_turn(message, user_turn_id, state_root=...)
    - guarded_ops.approval.approve_plan_from_user_turn(approval_id, message, user_turn_id, state_root=...)
    - guarded_ops.approval.approve_plan_from_user_turn(approval_id, user_turn_receipt_id=..., state_root=...)
    - guarded_ops.approval.consume_approval_record(approval_id, expected, state_root=...)
    - guarded_ops.hook_policy.hook_block_evidence(command, decision, user_turn_id=...)

    The user may approve a frozen plan in natural language; machinery must bind
    that approval to the immutable plan hash, the current user turn, a TTL, and a
    single consume event. The raw prompt must never be persisted.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="guardedops-auth-test-"))
        shutil.copytree(ROOT / "examples", self.tmp / "examples")
        self.state_root = self.tmp / ".guarded_ops"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def test_current_turn_semantic_approval_is_bound_to_plan_hash_and_consumed_once(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        plan = create_approval_record(scope, state_root=self.state_root)

        receipt = approve_plan_from_user_turn(
            plan["approval_id"],
            "可以，按刚才展示的计划上 pre",
            user_turn_id="turn-20260819-approval-001",
            state_root=self.state_root,
        )

        self.assertEqual(receipt["schema_version"], "guardedops.approval-receipt/v1")
        self.assertEqual(receipt["approval_id"], plan["approval_id"])
        self.assertEqual(receipt["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(receipt["scope"], scope)
        self.assertIn("user_turn_sha256", receipt)
        self.assertNotIn("message", receipt)
        self.assertNotIn("raw", json.dumps(receipt).lower())
        self.assertNotIn("刚才展示", json.dumps(receipt, ensure_ascii=False))

        stored = read_approval(self.state_root, plan["approval_id"])
        self.assertEqual(stored["status"], "approved")
        self.assertEqual(stored["approved_by_turn_sha256"], hashlib.sha256(b"turn-20260819-approval-001").hexdigest())
        self.assertNotIn("可以", json.dumps(stored, ensure_ascii=False))

        consume_approval_record(plan["approval_id"], scope, state_root=self.state_root)
        consumed = read_approval(self.state_root, plan["approval_id"])
        self.assertEqual(consumed["status"], "consumed")
        with self.assertRaisesRegex(ApprovalError, "already been consumed"):
            consume_approval_record(plan["approval_id"], scope, state_root=self.state_root)

    def test_ambiguous_future_blanket_approval_does_not_approve_the_plan(self) -> None:
        scope = {"host": "pre", "action": "restart-service", "service": "aiserver"}
        plan = create_approval_record(scope, state_root=self.state_root)

        with self.assertRaisesRegex(ApprovalError, "ambiguous|scope|future"):
            approve_plan_from_user_turn(
                plan["approval_id"],
                "我授权后面所有操作，你自己看着办",
                user_turn_id="turn-blanket-001",
                state_root=self.state_root,
            )

        stored = read_approval(self.state_root, plan["approval_id"])
        self.assertEqual(stored["status"], "pending")

    def test_user_prompt_submit_records_context_but_does_not_auto_approve(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        plan = create_approval_record(scope, state_root=self.state_root)

        turn = record_user_prompt_turn(
            "可以，按刚才计划上 pre",
            user_turn_id="turn-user-submit-001",
            state_root=self.state_root,
        )

        self.assertEqual(turn["schema_version"], "guardedops.user-turn/v1")
        self.assertIn("receipt_id", turn)
        self.assertEqual(turn["user_turn_sha256"], hashlib.sha256(b"turn-user-submit-001").hexdigest())
        self.assertNotIn("可以", json.dumps(turn, ensure_ascii=False))
        self.assertNotIn("刚才计划", json.dumps(turn, ensure_ascii=False))
        self.assertEqual(read_approval(self.state_root, plan["approval_id"])["status"], "pending")

        with self.assertRaisesRegex(ApprovalError, "not bound"):
            approve_plan_from_user_turn(
                plan["approval_id"],
                user_turn_receipt_id=turn["receipt_id"],
                state_root=self.state_root,
            )
        receipt = approve_plan_from_user_turn(
            plan["approval_id"],
            "可以，按刚才计划上 pre",
            user_turn_id="turn-user-submit-001",
            state_root=self.state_root,
        )
        self.assertEqual(receipt["approval_id"], plan["approval_id"])
        self.assertEqual(read_approval(self.state_root, plan["approval_id"])["status"], "approved")

    def run_prompt_hook(self, prompt: str, *, turn_id: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["GUARDEDOPS_STATE_ROOT"] = str(self.state_root)
        payload = {"user_prompt": prompt, "user_turn_id": turn_id}
        return subprocess.run(
            [PYTHON, str(ROOT / "hooks" / "ops_approval_prompt.py")],
            input=json.dumps(payload, ensure_ascii=False),
            cwd=self.tmp,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def hook_receipt_path(self, turn_id: str) -> Path:
        turn_ref = f"user_turn_id:{turn_id}"
        return self.state_root / "approvals" / "turn-receipts" / f"{hashlib.sha256(turn_ref.encode()).hexdigest()}.json"

    def test_hook_receipt_only_approves_a_matching_positive_plan(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        plan = create_approval_record(scope, state_root=self.state_root)

        negative = self.run_prompt_hook("不要部署 pre，先等等", turn_id="turn-hook-negative-001")
        self.assertEqual(negative.returncode, 0, negative.stderr)
        negative_path = self.hook_receipt_path("turn-hook-negative-001")
        negative_receipt = json.loads(negative_path.read_text(encoding="utf-8"))
        self.assertNotIn("approval_id", negative_receipt)
        with self.assertRaisesRegex(ApprovalError, "not bound"):
            approve_plan_from_user_turn(plan["approval_id"], user_turn_receipt_id=negative_receipt["receipt_id"], state_root=self.state_root)

        neutral = self.run_prompt_hook("先看一下 pre 状态", turn_id="turn-hook-neutral-001")
        self.assertEqual(neutral.returncode, 0, neutral.stderr)
        neutral_path = self.hook_receipt_path("turn-hook-neutral-001")
        neutral_receipt = json.loads(neutral_path.read_text(encoding="utf-8"))
        self.assertNotIn("approval_id", neutral_receipt)

        positive = self.run_prompt_hook("可以，按刚才计划部署 pre", turn_id="turn-hook-positive-001")
        self.assertEqual(positive.returncode, 0, positive.stderr)
        positive_path = self.hook_receipt_path("turn-hook-positive-001")
        positive_receipt = json.loads(positive_path.read_text(encoding="utf-8"))
        self.assertEqual(positive_receipt["approval_id"], plan["approval_id"])
        self.assertEqual(positive_receipt["plan_sha256"], plan["plan_sha256"])

        approved = run_cli(
            [PYTHON, "-m", "guarded_ops.opsctl", "approve-plan", "--approval-id", plan["approval_id"], "--receipt-id", positive_receipt["receipt_id"]],
            cwd=self.tmp,
        )
        self.assertEqual(approved.returncode, 0, approved.stderr)
        self.assertEqual(read_approval(self.state_root, plan["approval_id"])["status"], "approved")

    def test_semantic_approval_rejects_negative_questions_and_action_mismatch(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        cases = {
            "negative": "先不要上 pre",
            "question": "可以上 pre 吗？",
            "read_only": "先看一下 pre 状态",
            "wrong_action": "确认重启 pre",
            "wrong_host": "可以，上 us",
            "wrong_ref": "可以，把 pre 上到 dea9136f36e5284e5173e2c2e0d5fdca83c159c3",
        }
        for label, message in cases.items():
            with self.subTest(label=label):
                plan = create_approval_record(scope, state_root=self.state_root)
                with self.assertRaisesRegex(ApprovalError, "negative|question|mismatch|ambiguous|scope"):
                    approve_plan_from_user_turn(
                        plan["approval_id"],
                        message,
                        user_turn_id=f"turn-{label}",
                        state_root=self.state_root,
                    )
                self.assertEqual(read_approval(self.state_root, plan["approval_id"])["status"], "pending")

    def test_approval_id_rejects_scope_and_hash_drift(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        plan = create_approval_record(scope, state_root=self.state_root)
        approve_plan_from_user_turn(
            plan["approval_id"],
            "确认部署到 pre",
            user_turn_id="turn-drift-001",
            state_root=self.state_root,
        )

        with self.assertRaisesRegex(ApprovalError, "mismatch"):
            consume_approval_record(
                plan["approval_id"],
                {"host": "us", "action": "deploy", "ref": scope["ref"]},
                state_root=self.state_root,
            )

        stored = read_approval(self.state_root, plan["approval_id"])
        stored["scope"] = {**scope, "ref": "dea9136f36e5284e5173e2c2e0d5fdca83c159c3"}
        write_approval(self.state_root, plan["approval_id"], stored)
        with self.assertRaisesRegex(ApprovalError, "plan hash"):
            consume_approval_record(plan["approval_id"], stored["scope"], state_root=self.state_root)

    def test_approval_id_expires_before_and_after_semantic_approval(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        plan = create_approval_record(scope, state_root=self.state_root)
        expired = read_approval(self.state_root, plan["approval_id"])
        expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(microsecond=0).isoformat()
        write_approval(self.state_root, plan["approval_id"], expired)

        with self.assertRaisesRegex(ApprovalError, "expired"):
            approve_plan_from_user_turn(
                plan["approval_id"],
                "可以，按这个计划执行",
                user_turn_id="turn-expired-before-approval",
                state_root=self.state_root,
            )

        fresh = create_approval_record(scope, state_root=self.state_root)
        approve_plan_from_user_turn(
            fresh["approval_id"],
            "可以，按这个计划执行",
            user_turn_id="turn-expired-after-approval",
            state_root=self.state_root,
        )
        stored = read_approval(self.state_root, fresh["approval_id"])
        stored["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(microsecond=0).isoformat()
        write_approval(self.state_root, fresh["approval_id"], stored)
        with self.assertRaisesRegex(ApprovalError, "expired"):
            consume_approval_record(fresh["approval_id"], scope, state_root=self.state_root)

    def test_opsctl_accepts_semantic_approval_id_but_legacy_token_still_works(self) -> None:
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        payload = json.loads(plan.stdout)
        approve_plan_from_user_turn(
            payload["approval_id"],
            "可以，部署到 staging",
            user_turn_id="turn-cli-approval-001",
            state_root=self.state_root,
        )

        approved = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "--fleet",
                "examples/fleet.example.json",
                "deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
                "--approval-id",
                payload["approval_id"],
            ],
            cwd=self.tmp,
        )
        self.assertEqual(approved.returncode, 0, approved.stderr)

        legacy = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "--fleet",
                "examples/fleet.example.json",
                "deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
                "--approval-token",
                "host=staging action=deploy ref=abcdef0",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(legacy.returncode, 0, legacy.stderr)

    def test_approval_record_binds_operation_and_run_ids_when_plan_supplies_them(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}

        for index, kwargs in enumerate((
            {"run_id": "run-pre-20260819"},
            {"operation_id": "op-pre-deploy-001"},
            {},
        )):
            with self.subTest(kwargs=kwargs):
                plan = create_approval_record(
                    scope,
                    operation_id="op-pre-deploy-001",
                    run_id="run-pre-20260819",
                    state_root=self.state_root,
                )
                approve_plan_from_user_turn(
                    plan["approval_id"],
                    "可以，部署到 pre",
                    user_turn_id=f"turn-operation-binding-omitted-{index}",
                    state_root=self.state_root,
                )
                with self.assertRaisesRegex(ApprovalError, "operation_id|run_id|required"):
                    consume_approval_record(plan["approval_id"], scope, state_root=self.state_root, **kwargs)

        plan = create_approval_record(
            scope,
            operation_id="op-pre-deploy-001",
            run_id="run-pre-20260819",
            state_root=self.state_root,
        )
        approve_plan_from_user_turn(
            plan["approval_id"],
            "可以，部署到 pre",
            user_turn_id="turn-operation-binding-mismatch",
            state_root=self.state_root,
        )
        stored = read_approval(self.state_root, plan["approval_id"])
        self.assertEqual(stored["operation_id"], "op-pre-deploy-001")
        self.assertEqual(stored["run_id"], "run-pre-20260819")
        with self.assertRaisesRegex(ApprovalError, "operation_id|run_id|scope"):
            consume_approval_record(
                plan["approval_id"],
                scope,
                operation_id="op-pre-deploy-002",
                run_id="run-pre-20260819",
                state_root=self.state_root,
            )

        plan = create_approval_record(
            scope,
            operation_id="op-pre-deploy-001",
            run_id="run-pre-20260819",
            state_root=self.state_root,
        )
        approve_plan_from_user_turn(
            plan["approval_id"],
            "可以，部署到 pre",
            user_turn_id="turn-operation-binding-success",
            state_root=self.state_root,
        )
        consume_approval_record(
            plan["approval_id"],
            scope,
            operation_id="op-pre-deploy-001",
            run_id="run-pre-20260819",
            state_root=self.state_root,
        )

    def test_opsctl_plan_and_apply_reuse_generated_operation_and_run_ids(self) -> None:
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        payload = json.loads(plan.stdout)
        self.assertIn("operation_id", payload)
        self.assertIn("run_id", payload)

        approve_plan_from_user_turn(
            payload["approval_id"],
            "可以，按刚才计划部署 staging",
            user_turn_id="turn-plan-apply-op-run-001",
            state_root=self.state_root,
        )
        apply_result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--dry-run",
                "--fleet",
                "examples/fleet.example.json",
                "deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
                "--approval-id",
                payload["approval_id"],
            ],
            cwd=self.tmp,
        )
        self.assertEqual(apply_result.returncode, 0, apply_result.stderr)
        applied = json.loads(apply_result.stdout)
        self.assertEqual(applied["operation_id"], payload["operation_id"])
        self.assertEqual(applied["run_id"], payload["run_id"])

    def test_plan_reference_phrase_does_not_override_contradictory_scope_words(self) -> None:
        scope = {"host": "pre", "action": "deploy", "ref": "1c7d60063aa8b0535602df9528feae2d878618cf"}
        messages = (
            "可以，按刚才计划上 us",
            "按刚才计划重启 pre",
            "按刚才计划上 pre，不过 ref 用 dea9136f36e5284e5173e2c2e0d5fdca83c159c3",
            "可以执行刚才计划，但不要部署 pre",
        )
        for index, message in enumerate(messages):
            with self.subTest(message=message):
                plan = create_approval_record(scope, state_root=self.state_root)
                with self.assertRaisesRegex(ApprovalError, "contradict|mismatch|negative|scope"):
                    approve_plan_from_user_turn(
                        plan["approval_id"],
                        message,
                        user_turn_id=f"turn-contradictory-{index}",
                        state_root=self.state_root,
                    )
                self.assertEqual(read_approval(self.state_root, plan["approval_id"])["status"], "pending")

    def test_approve_plan_cli_message_rejects_contradictory_scope_words(self) -> None:
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        payload = json.loads(plan.stdout)

        rejected = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "approve-plan",
                "--approval-id",
                payload["approval_id"],
                "--message",
                "可以，按刚才计划上 prod-us",
                "--user-turn-id",
                "turn-cli-contradictory-001",
            ],
            cwd=self.tmp,
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertRegex(rejected.stderr, "contradict|mismatch|scope")
        self.assertEqual(read_approval(self.state_root, payload["approval_id"])["status"], "pending")

    def test_approve_plan_cli_rejects_direct_message_compatibility(self) -> None:
        plan = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "plan-deploy",
                "--host",
                "staging",
                "--ref",
                "abcdef0",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        payload = json.loads(plan.stdout)

        rejected = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "approve-plan",
                "--approval-id",
                payload["approval_id"],
                "--message",
                "可以，按刚才计划部署 staging",
                "--user-turn-id",
                "turn-cli-message-disabled-001",
            ],
            cwd=self.tmp,
        )

        self.assertNotEqual(rejected.returncode, 0)
        self.assertRegex(rejected.stderr.lower(), "message|receipt|user-turn|unsupported|unrecognized")
        self.assertEqual(read_approval(self.state_root, payload["approval_id"])["status"], "pending")

    def test_hook_blocks_raw_write_and_records_evidence_without_raw_prompt(self) -> None:
        command = "ssh example-prod-us -- git -C /opt/project/aiserver reset --hard origin/pre"
        decision = decide_command(command, ROOT / "examples/fleet.example.json")
        self.assertFalse(decision.allowed)

        evidence = hook_block_evidence(
            command,
            decision,
            user_turn_id="turn-hook-block-001",
            operation_id="op-hook-block-001",
        )

        self.assertEqual(evidence["schema_version"], "guardedops.evidence/v1")
        self.assertEqual(evidence["source"], "ops-guard-hook")
        self.assertEqual(evidence["reason_code"], "hook_denied")
        self.assertEqual(evidence["operation_id"], "op-hook-block-001")
        self.assertIn("command_hash", evidence["details"])
        self.assertIn("user_turn_sha256", evidence["details"])
        rendered = json.dumps(evidence, ensure_ascii=False)
        self.assertNotIn(command, rendered)
        self.assertNotIn("reset --hard", rendered)
        self.assertNotIn("turn-hook-block-001", rendered)

    def test_hook_blocks_protected_ssh_writes_hidden_behind_separators_and_shells(self) -> None:
        commands = (
            "ssh example-prod-us -- 'cd /opt/project/aiserver && git reset --hard origin/pre'",
            "ssh example-prod-us -- 'cd /opt/project/aiserver; supervisorctl restart aiserver'",
            "ssh example-prod-us -- sh -lc 'git -C /opt/project/aiserver pull origin pre && supervisorctl restart aiserver'",
            "ssh example-prod-us -- bash -lc 'git fetch origin; git reset --hard origin/pre'",
            "ssh example-prod-us -- 'python3 -c \"open(\\\"/opt/project/aiserver/.env\\\", \\\"w\\\").write(\\\"x\\\")\"'",
            "bash -lc 'ssh example-prod-us -- \"cd /opt/project/aiserver && git pull origin pre\"'",
        )
        for command in commands:
            with self.subTest(command=command):
                decision = decide_command(command, ROOT / "examples/fleet.example.json")
                self.assertFalse(decision.allowed, decision.reason)

    def test_hook_blocks_protected_ssh_writes_hidden_behind_top_level_composition(self) -> None:
        blocked_commands = (
            "date ; ssh example-prod-us -- git -C /opt/project/aiserver reset --hard origin/pre",
            "true && ssh example-prod-us -- supervisorctl restart aiserver",
            "echo ok | ssh example-prod-us -- git -C /opt/project/aiserver reset --hard origin/pre",
            "opsctl observe --host staging ; ssh example-prod-us -- git -C /opt/project/aiserver reset --hard origin/pre",
            "sh -lc 'opsctl observe --host staging; ssh example-prod-us -- git -C /opt/project/aiserver reset --hard origin/pre'",
        )
        for command in blocked_commands:
            with self.subTest(command=command):
                decision = decide_command(command, ROOT / "examples/fleet.example.json")
                self.assertFalse(decision.allowed, decision.reason)

        allowed_commands = (
            "date",
            "true",
            "echo ok",
            "opsctl observe --host staging",
            "ssh example-prod-us -- hostname",
        )
        for command in allowed_commands:
            with self.subTest(command=command):
                decision = decide_command(command, ROOT / "examples/fleet.example.json")
                self.assertTrue(decision.allowed, decision.reason)

        for command in (
            "ssh example-prod-us -- cat /etc/shadow",
            "ssh example-prod-us -- grep password /etc/app.env",
            "ssh example-prod-us -- ls /var/log",
        ):
            with self.subTest(command=command):
                decision = decide_command(command, ROOT / "examples/fleet.example.json")
                self.assertFalse(decision.allowed, decision.reason)

    def test_hook_blocks_git_read_subcommands_with_write_capable_options(self) -> None:
        blocked_commands = (
            "ssh example-prod-us -- git -C /opt/project/aiserver diff --output=/tmp/guardedops-diff.txt",
            "ssh example-prod-us -- git -C /opt/project/aiserver diff --output /tmp/guardedops-diff.txt",
            "ssh example-prod-us -- git -C /opt/project/aiserver -c core.pager='touch /tmp/guardedops-pager' log -1",
            "ssh example-prod-us -- git -C /opt/project/aiserver -c core.externalDiff='touch /tmp/guardedops-diff' diff HEAD",
            "ssh example-prod-us -- git -C /opt/project/aiserver --unknown-option status",
            "ssh example-prod-us -- git -C /opt/project/aiserver status --unknown-option",
        )
        for command in blocked_commands:
            with self.subTest(command=command):
                decision = decide_command(command, ROOT / "examples/fleet.example.json")
                self.assertFalse(decision.allowed, decision.reason)

        allowed_commands = (
            "ssh example-prod-us -- git -C /opt/project/aiserver status --short",
            "ssh example-prod-us -- git -C /opt/project/aiserver rev-parse HEAD",
            "ssh example-prod-us -- git -C /opt/project/aiserver log -1 --oneline",
            "ssh example-prod-us -- git -C /opt/project/aiserver diff --stat HEAD~1 HEAD",
        )
        for command in allowed_commands:
            with self.subTest(command=command):
                decision = decide_command(command, ROOT / "examples/fleet.example.json")
                self.assertTrue(decision.allowed, decision.reason)

    def test_opsctl_rollback_reuses_bound_operation_and_run_ids(self) -> None:
        scope = {"host": "staging", "action": "rollback", "rollback_id": "rollback-20260819-001"}
        plan = create_approval_record(
            scope,
            operation_id="op-rollback-20260819-001",
            run_id="run-rollback-20260819",
            state_root=self.state_root,
        )
        turn = record_user_prompt_turn(
            "可以，按刚才计划回滚 staging",
            user_turn_id="turn-rollback-approval-001",
            state_root=self.state_root,
            approval_id=plan["approval_id"],
            plan_sha256=plan["plan_sha256"],
        )
        approve = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "approve-plan",
                "--approval-id",
                plan["approval_id"],
                "--receipt-id",
                turn["receipt_id"],
            ],
            cwd=self.tmp,
        )
        self.assertEqual(approve.returncode, 0, approve.stderr)

        applied = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.opsctl",
                "--fleet",
                "examples/fleet.example.json",
                "rollback",
                "--host",
                "staging",
                "--rollback-id",
                "rollback-20260819-001",
                "--approval-id",
                plan["approval_id"],
            ],
            cwd=self.tmp,
        )

        self.assertEqual(applied.returncode, 0, applied.stderr)
        payload = json.loads(applied.stdout)
        self.assertIn("operation_id", payload)
        self.assertIn("run_id", payload)
        self.assertEqual(payload["operation_id"], "op-rollback-20260819-001")
        self.assertEqual(payload["run_id"], "run-rollback-20260819")

        record_path = self.state_root / "records" / "rollback-rollback-20260819-001.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertIn("operation_id", record)
        self.assertIn("run_id", record)
        self.assertEqual(record["operation_id"], "op-rollback-20260819-001")
        self.assertEqual(record["run_id"], "run-rollback-20260819")
        self.assertEqual(read_approval(self.state_root, plan["approval_id"])["status"], "consumed")

    def test_ops_guard_hook_cli_persists_redacted_denial_evidence(self) -> None:
        evidence_path = self.tmp / "hook-evidence.jsonl"
        command = "ssh example-prod-us -- git -C /opt/project/aiserver reset --hard origin/pre"

        result = run_cli(
            [
                PYTHON,
                "-m",
                "guarded_ops.cli.ops_guard_hook",
                "--fleet",
                "examples/fleet.example.json",
                "--command",
                command,
                "--user-turn-id",
                "turn-hook-cli-001",
                "--operation-id",
                "op-hook-cli-001",
                "--evidence-output",
                str(evidence_path),
            ],
            cwd=self.tmp,
        )

        self.assertEqual(result.returncode, 2)
        self.assertTrue(evidence_path.exists())
        records = [json.loads(line) for line in evidence_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["operation_id"], "op-hook-cli-001")
        self.assertEqual(records[0]["reason_code"], "hook_denied")
        rendered = json.dumps(records[0], ensure_ascii=False)
        self.assertNotIn(command, rendered)
        self.assertNotIn("reset --hard", rendered)
        self.assertNotIn("turn-hook-cli-001", rendered)


if __name__ == "__main__":
    unittest.main()
