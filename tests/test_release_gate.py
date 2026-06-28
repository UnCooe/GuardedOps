from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseGateTests(unittest.TestCase):
    def test_public_leak_scan_passes_repository(self) -> None:
        shutil.rmtree(ROOT / ".guarded_ops", ignore_errors=True)
        shutil.rmtree(ROOT / "build", ignore_errors=True)
        shutil.rmtree(ROOT / "dist", ignore_errors=True)
        result = subprocess.run(["scripts/leak_scan.sh", "--public", "."], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_public_leak_scan_blocks_home_path_and_non_doc_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            bad_home = "/" + "home" + "/" + "example" + "/private"
            bad_ip = ".".join(["10", "1", "2", "3"])
            (path / "bad.txt").write_text(f"{bad_home}\n{bad_ip}\n", encoding="utf-8")
            result = subprocess.run(["scripts/leak_scan.sh", "--public", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("absolute home path", result.stdout)
            self.assertIn("non-documentation IPv4", result.stdout)

    def test_public_leak_scan_blocks_generated_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / ".guarded_ops").mkdir()
            result = subprocess.run(["scripts/leak_scan.sh", "--public", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("generated directory", result.stdout)

    def test_help_outputs_are_generic(self) -> None:
        env = {"PYTHONPATH": str(ROOT / "src")}
        for command in (
            [sys.executable, "-m", "guarded_ops.opsctl", "--help"],
            [sys.executable, "-m", "guarded_ops.route", "--help"],
            [sys.executable, "-m", "guarded_ops.review", "--help"],
            [sys.executable, "-m", "guarded_ops.cli.ops_guard_hook", "--help"],
        ):
            result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            lowered = result.stdout.lower()
            self.assertNotIn("internal_", lowered)
            self.assertNotIn("private_", lowered)
            self.assertNotIn("real_", lowered)


if __name__ == "__main__":
    unittest.main()
