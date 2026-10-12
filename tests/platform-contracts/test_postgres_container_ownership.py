"""Fake Docker control-flow tests; no Docker daemon or SQL semantics exercised."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["OWNERSHIP_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
mode = os.environ["OWNERSHIP_MODE"]
if args == ["info"]:
    sys.exit(0)
if args and args[0] == "create":
    if mode == "create-fails":
        print("a" * 64)  # partial stdout is never ownership
        sys.exit(9)
    print("not-an-id" if mode == "invalid-id" else "a" * 64)
    sys.exit(0)
if args == ["start", "a" * 64]:
    sys.exit(8)  # controlled early failure; never execute PostgreSQL
if args == ["rm", "-f", "a" * 64]:
    sys.exit(7 if mode == "cleanup-fails" else 0)
sys.exit(97)
'''

class OwnershipTests(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fake = base / "docker"
            fake.write_text(FAKE)
            fake.chmod(0o755)
            self.assertTrue(os.access(fake, os.X_OK))
            log = base / "calls.jsonl"
            env = dict(os.environ, PATH=str(base) + os.pathsep + os.environ["PATH"],
                       OWNERSHIP_MODE=mode, OWNERSHIP_LOG=str(log))
            result = subprocess.run(["bash", str(ROOT / "data/tests/integration-postgres.sh")],
                                    env=env, text=True, capture_output=True, timeout=10)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertFalse(any(call and call[0] == "exec" for call in calls))
            create = next(call for call in calls if call[0] == "create")
            name = create[create.index("--name") + 1]
            import uuid
            uuid.UUID(name.removeprefix("database-bootstrap-pg-"))
            return result, calls

    def test_failed_create_partial_stdout_never_deletes(self):
        result, calls = self.run_case("create-fails")
        self.assertEqual(result.returncode, 3)
        self.assertFalse(any(call[0] in ("rm", "start") for call in calls))

    def test_invalid_success_id_never_deletes_by_name(self):
        result, calls = self.run_case("invalid-id")
        self.assertEqual(result.returncode, 3)
        self.assertFalse(any(call[0] in ("rm", "start") for call in calls))

    def test_successful_create_cleans_only_exact_returned_id(self):
        result, calls = self.run_case("start-fails")
        self.assertEqual(result.returncode, 3)
        self.assertEqual([call for call in calls if call[0] == "rm"], [["rm", "-f", "a" * 64]])

    def test_cleanup_error_preserves_original_failure(self):
        result, calls = self.run_case("cleanup-fails")
        self.assertEqual(result.returncode, 3)
        self.assertIn("cleanup failed", result.stderr)
        self.assertIn("exit=7", result.stderr)

if __name__ == "__main__":
    unittest.main()
