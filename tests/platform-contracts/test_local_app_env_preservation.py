"""Local filesystem-only fixtures; no CLI, credentials, SDK or network."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "automation/init_local_app_env.py"
spec = importlib.util.spec_from_file_location("local_env", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TEMPLATE = b"DATABASE_URL=\nJWT_SECRET=\nCOOKIE_SECRET=\nREDIS_URL=redis://127.0.0.1:6379\n"

class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name).resolve()
        self.example = self.base / ".env.example"
        self.target = self.base / ".env"
        self.example.write_bytes(TEMPLATE)
        self.target.write_bytes(TEMPLATE)

    def test_first_use_mode_and_no_logged_values_then_retry_refused(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            module.initialize(self.target, self.example)
        actual = self.target.read_bytes()
        self.assertNotEqual(actual, TEMPLATE)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("medusa_local_password", output.getvalue())
        self.assertEqual(self.example.read_bytes(), TEMPLATE)
        with self.assertRaises(ValueError):
            module.initialize(self.target, self.example)
        self.assertEqual(self.target.read_bytes(), actual)

    def test_existing_credentials_and_nonempty_template_refused(self):
        for data in (TEMPLATE.replace(b"JWT_SECRET=\n", b"JWT_SECRET=existing\n"),
                     TEMPLATE + b"COOKIE_SECRET=\n"):
            self.example.write_bytes(data)
            self.target.write_bytes(data)
            with self.assertRaises(ValueError):
                module.initialize(self.target, self.example)
            self.assertEqual(self.target.read_bytes(), data)

    def test_target_and_parent_symlinks_refused(self):
        self.target.unlink()
        self.target.symlink_to(self.example)
        with self.assertRaises(ValueError):
            module.initialize(self.target, self.example)
        self.assertEqual(self.example.read_bytes(), TEMPLATE)
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            module.initialize(alias / ".env.example", self.example)

    def test_replace_failure_preserves_original_and_cleans_temporary(self):
        with patch.object(module.os, "replace", side_effect=OSError("controlled failure")):
            with self.assertRaises(OSError):
                module.initialize(self.target, self.example)
        self.assertEqual(self.target.read_bytes(), TEMPLATE)
        self.assertEqual(list(self.base.glob(".local-env-*")), [])

    def test_current_bytes_changed_before_replace_refused(self):
        native = module.regular_without_links
        calls = 0
        def change(path):
            nonlocal calls
            calls += 1
            if calls == 3:
                self.target.write_bytes(b"replacement owned by another editor\n")
            return native(path)
        with patch.object(module, "regular_without_links", side_effect=change):
            with self.assertRaises(ValueError):
                module.initialize(self.target, self.example)
        self.assertEqual(self.target.read_bytes(), b"replacement owned by another editor\n")
        self.assertEqual(list(self.base.glob(".local-env-*")), [])

if __name__ == "__main__":
    unittest.main()
