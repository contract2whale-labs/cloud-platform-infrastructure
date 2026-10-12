# -*- coding: utf-8 -*-
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location("context_writer",ROOT/"automation/incidents/write_context.py")
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class ContextTests(unittest.TestCase):
    def test_context_is_shell_literal_and_private(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"context.env"
            literal="probe ' $(touch /tmp/do-not-run)"
            MODULE.write_context(path,["INCIDENT_ID"],{"INCIDENT_ID":literal})
            result=subprocess.run(["bash","-c",'source "$1"; printf "%s" "$INCIDENT_ID"',"context",str(path)],capture_output=True,text=True,check=True)
            self.assertEqual(result.stdout,literal)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_existing_context_is_preserved_even_with_identical_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "context.env"
            MODULE.write_context(path, ["INCIDENT_ID"], {"INCIDENT_ID": "attempt-one"})
            original = path.read_bytes()
            for value in ("attempt-one", "attempt-two"):
                with self.assertRaises(FileExistsError):
                    MODULE.write_context(path, ["INCIDENT_ID"], {"INCIDENT_ID": value})
                self.assertEqual(path.read_bytes(), original)

    def test_dangling_symlink_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "context.env"
            target = Path(folder) / "absent.env"
            path.symlink_to(target)
            with self.assertRaises(FileExistsError):
                MODULE.write_context(path, ["INCIDENT_ID"], {"INCIDENT_ID": "attempt"})
            self.assertTrue(path.is_symlink())
            self.assertFalse(target.exists())

    def test_late_collision_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "context.env"
            real_open = MODULE.os.open
            def collide(*args, **kwargs):
                path.write_bytes(b"previous attempt\n")
                return real_open(*args, **kwargs)
            with mock.patch.object(MODULE.os, "open", side_effect=collide):
                with self.assertRaises(FileExistsError):
                    MODULE.write_context(path, ["INCIDENT_ID"], {"INCIDENT_ID": "new attempt"})
            self.assertEqual(path.read_bytes(), b"previous attempt\n")

    def test_new_context_is_private_under_restrictive_umask(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "context.env"
            previous = MODULE.os.umask(0o777)
            try:
                MODULE.write_context(path, ["INCIDENT_ID"], {"INCIDENT_ID": "new attempt"})
            finally:
                MODULE.os.umask(previous)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_secret_and_multiline_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"context.env"
            for name,value in [("ADMIN_PASSWORD","private"),("INCIDENT_TOKEN","private"),("INCIDENT_ID","line\nline")]:
                with self.assertRaises(ValueError):
                    MODULE.write_context(path,[name],{name:value})
            self.assertFalse(path.exists())

    def test_normal_queue_recovery_coordinates_reach_investigator_shell(self):
        # The recovery target was captured before fault injection; a new shell
        # must receive that value instead of rereading the failed replicas=0.
        expected={"TEMPO_RELEASE":"tempo-e2", "DRAIN_SOURCE":"managed",
                  "TRACE_TOPIC":"tempo-traces-e2", "BUILDER":"tempo-e2-block-builder",
                  "BUILDER_REPLICAS":"3"}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"context.env"
            MODULE.write_context(path,list(expected),expected)
            command='source "$1"; printf "%s\\n" "$TEMPO_RELEASE" "$DRAIN_SOURCE" "$TRACE_TOPIC" "$BUILDER" "$BUILDER_REPLICAS"'
            result=subprocess.run(["bash","-c",command,"context",str(path)],capture_output=True,text=True,check=True)
            self.assertEqual(result.stdout.splitlines(),list(expected.values()))
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_unreviewed_queue_field_stays_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"context.env"
            with self.assertRaises(ValueError):
                MODULE.write_context(path,["BUILDER_PASSWORD"],{"BUILDER_PASSWORD":"private"})
            self.assertFalse(path.exists())

if __name__=="__main__":unittest.main()
