import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('terraform_contracts', REPO / 'automation/check_terraform_contracts.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

BASE = '''terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "= 6.62.0"
    }
  }
}
'''
MOCK = 'mock_provider "aws" {}\nrun "contract" {\n  command = plan\n}\n'


class TerraformContractsTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.repo = Path(self.work.name)

    def write(self, relative, body):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return path

    def alias_target(self):
        target = self.repo / 'modules/edge'
        self.write('modules/edge/versions.tf', BASE.replace('version = "= 6.62.0"', 'version = "= 6.62.0"\n      configuration_aliases = [aws.global]'))
        return target

    def test_alias_suite_must_mock_the_global_provider(self):
        target = self.alias_target()
        suite = self.write('modules/edge/tests/edge.tftest.hcl', MOCK)
        with self.assertRaisesRegex(ValueError, 'aws.global'):
            CHECK.check_mock_suite(self.repo, target, suite)
        suite.write_text('mock_provider "aws" {\n  alias = "global"\n}\n' + MOCK)
        CHECK.check_mock_suite(self.repo, target, suite)

    def test_a_commented_mock_is_not_mock_coverage(self):
        target = self.repo / 'modules/example'
        self.write('modules/example/versions.tf', BASE)
        suite = self.write('modules/example/tests/example.tftest.hcl', '# mock_provider "aws" {}\nrun "contract" {\n  command = plan\n}\n')
        with self.assertRaisesRegex(ValueError, 'mock coverage missing'):
            CHECK.check_mock_suite(self.repo, target, suite)

    def test_real_provider_in_a_suite_is_rejected(self):
        target = self.repo / 'modules/example'
        self.write('modules/example/versions.tf', BASE)
        suite = self.write('modules/example/tests/example.tftest.hcl', 'provider "aws" {}\n' + MOCK)
        with self.assertRaisesRegex(ValueError, 'real provider'):
            CHECK.check_mock_suite(self.repo, target, suite)

    def test_source_symlink_is_rejected(self):
        root = self.repo / 'terraform/environments/dev/example'
        root.mkdir(parents=True)
        (root / 'main.tf').symlink_to('/etc/hosts')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            CHECK.discover(self.repo, 'terraform/environments')

    def test_missing_local_module_is_rejected(self):
        target = self.repo / 'terraform/environments/dev/example'
        self.write('terraform/environments/dev/example/main.tf', 'module "component" {\n  source = "../../../../modules/missing"\n}\n')
        with self.assertRaisesRegex(ValueError, 'local child module is missing'):
            CHECK.provider_contract(self.repo, target)

    def test_empty_repository_is_skip_without_terraform(self):
        with patch.object(CHECK.subprocess, 'run') as invoke, contextlib.redirect_stdout(io.StringIO()) as output:
            result = CHECK.main(['--repo', str(self.repo)])
        self.assertEqual(result, 0)
        self.assertIn('TF_CONTRACTS_SKIP', output.getvalue())
        invoke.assert_not_called()

    def test_uncovered_module_draft_fails_before_execution(self):
        self.write('modules/example/versions.tf', BASE)
        with patch.object(CHECK.subprocess, 'run') as invoke, contextlib.redirect_stderr(io.StringIO()):
            result = CHECK.main(['--repo', str(self.repo)])
        self.assertEqual(result, 1)
        invoke.assert_not_called()

    def test_native_commands_preserve_lock_and_do_not_validate_alias_module_as_root(self):
        self.write('terraform/environments/dev/example/main.tf', 'module "component" {\n  source = "../../../../modules/edge"\n  providers = { aws.global = aws.global }\n}\nprovider "aws" {\n  alias = "global"\n}\n')
        self.alias_target()
        self.write('modules/edge/tests/edge.tftest.hcl', 'mock_provider "aws" {\n  alias = "global"\n}\n' + MOCK)
        for relative in ['terraform/environments/dev/example', 'modules/edge']:
            self.write(relative + '/.terraform.lock.hcl', '# reviewed lock fixture\n')
        calls = []
        def invoke(command, **kwargs):
            calls.append((command, kwargs['env']))
            return CHECK.subprocess.CompletedProcess(command, 0, '')
        with patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'must-not-reach-child', 'AWS_PROFILE': 'must-not-reach-child', 'TF_VAR_secret': 'must-not-reach-child'}), patch.object(CHECK.subprocess, 'run', side_effect=invoke), contextlib.redirect_stdout(io.StringIO()):
            result = CHECK.main(['--repo', str(self.repo)])
        self.assertEqual(result, 0)
        for command, environment in calls:
            self.assertNotIn('AWS_ACCESS_KEY_ID', environment)
            self.assertNotIn('AWS_PROFILE', environment)
            self.assertNotIn('TF_VAR_secret', environment)
            self.assertEqual(environment['AWS_SHARED_CREDENTIALS_FILE'], os.devnull)
            self.assertEqual(environment['AWS_EC2_METADATA_DISABLED'], 'true')
            if 'init' in command:
                self.assertIn('-backend=false', command)
                self.assertIn('-lockfile=readonly', command)
            if str(self.repo / 'modules/edge') in command[1]:
                self.assertNotIn('validate', command)
        self.assertTrue(any('validate' in command for command, _ in calls))
        self.assertTrue(any('test' in command for command, _ in calls))

    def test_native_test_failure_is_ci_failure(self):
        self.write('terraform/environments/dev/example/main.tf', BASE)
        self.write('terraform/environments/dev/example/tests/example.tftest.hcl', MOCK)
        def invoke(command, **kwargs):
            return CHECK.subprocess.CompletedProcess(command, 1 if 'test' in command else 0, '')
        report = self.repo / 'result.json'
        with patch.object(CHECK.subprocess, 'run', side_effect=invoke), contextlib.redirect_stdout(io.StringIO()):
            result = CHECK.main(['--repo', str(self.repo), '--report', str(report)])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(report.read_text())['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
