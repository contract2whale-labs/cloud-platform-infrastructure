"""Credentialless release-gate unit tests; these cases never start a provider."""
import contextlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run_required as gate
from support import CI, PROCESS_FIXTURE, ROOT, TESTS


class RequiredRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='oidc-required-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def requirements(self, content='botocore==1.40.18\nsix==1.17.0\n'):
        path = self.root / 'requirements-test.txt'
        path.write_text(content)
        return path

    def toolchain(self):
        terraform = self.root / 'terraform'
        terraform.write_text('fake executable, never launched')
        terraform.chmod(0o700)
        provider = self.root / '6.62.0/linux_amd64/terraform-provider-aws_v6.62.0_x5'
        provider.parent.mkdir(parents=True)
        provider.write_text('fake executable, never launched')
        provider.chmod(0o700)
        return {'OIDC_TEST_TERRAFORM': str(terraform), 'OIDC_TEST_PROVIDER': str(provider)}

    def test_exact_dependency_versions_are_required(self):
        with patch.object(importlib.metadata, 'version', side_effect=['1.40.18', '1.17.0']) as version:
            gate.check_dependencies(self.requirements())
            self.assertEqual(version.call_count, 2)
        with patch.object(importlib.metadata, 'version', return_value='0.0.0'):
            with self.assertRaises(gate.GateError):
                gate.check_dependencies(self.requirements())

    def test_missing_dependency_fails_instead_of_skipping(self):
        with patch.object(importlib.metadata, 'version', side_effect=importlib.metadata.PackageNotFoundError):
            with self.assertRaises(gate.GateError):
                gate.check_dependencies(self.requirements())

    def test_unpinned_duplicate_or_absent_sdk_dependency_fails(self):
        for content in ('botocore>=1.40.18', 'botocore==1.40.18\nbotocore==1.40.18', '', '# no SDK'):
            with self.subTest(content=content), self.assertRaises(gate.GateError):
                gate.check_dependencies(self.requirements(content))

    def test_live_credential_and_oidc_environment_is_rejected_without_value_leak(self):
        for key in ('AWS_ACCESS_KEY_ID', 'AWS_PROFILE', 'AWS_FUTURE_SOURCE', 'AMAZON_TOKEN',
                    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'BOTO_CONFIG'):
            with self.subTest(key=key), self.assertRaises(gate.GateError) as raised:
                gate.check_credentialless({'HOME': str(self.root), key: 'SECRET-NOT-FOR-LOGS'})
            self.assertNotIn('SECRET-NOT-FOR-LOGS', str(raised.exception))
        gate.check_credentialless({'HOME': str(self.root)})

    def test_shared_aws_credentials_are_rejected(self):
        (self.root / '.aws').mkdir()
        (self.root / '.aws/credentials').write_text('[default]\naws_access_key_id=FAKE\n')
        with self.assertRaises(gate.GateError):
            gate.check_credentialless({'HOME': str(self.root)})

    def test_missing_and_nonexecutable_binaries_fail_instead_of_skipping(self):
        with self.assertRaises(gate.GateError):
            gate.check_toolchain({})
        env = self.toolchain()
        Path(env['OIDC_TEST_PROVIDER']).chmod(0o600)
        with self.assertRaises(gate.GateError):
            gate.check_toolchain(env)
        Path(env['OIDC_TEST_PROVIDER']).unlink()
        with self.assertRaises(gate.GateError):
            gate.check_toolchain(env)

    def test_terraform_and_provider_versions_are_pinned(self):
        env = self.toolchain()
        result = subprocess.CompletedProcess([], 0, json.dumps({'terraform_version': '1.16.0'}), '')
        with patch.object(gate.subprocess, 'run', return_value=result) as run:
            gate.check_toolchain(env)
            self.assertEqual(run.call_args.args[0][1:], ['version', '-json'])
        result.stdout = json.dumps({'terraform_version': '1.15.0'})
        with patch.object(gate.subprocess, 'run', return_value=result):
            with self.assertRaises(gate.GateError):
                gate.check_toolchain(env)
        result.stdout = json.dumps({'terraform_version': '1.16.0'})
        wrong = self.root / 'terraform-provider-aws_v6.61.0_x5'
        wrong.write_text('wrong provider')
        wrong.chmod(0o700)
        env['OIDC_TEST_PROVIDER'] = str(wrong)
        with patch.object(gate.subprocess, 'run', return_value=result):
            with self.assertRaises(gate.GateError):
                gate.check_toolchain(env)

    def test_skipped_test_makes_required_runner_nonzero(self):
        def skipped():
            raise unittest.SkipTest('Deliberate gate regression fixture')
        suite = unittest.TestSuite([unittest.FunctionTestCase(skipped)])
        self.assertEqual(gate.run_suite(suite, stream=io.StringIO(), required=frozenset()), 1)

    def test_expected_failure_is_not_a_green_release_gate(self):
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_example(self):
                self.fail('Deliberate gate regression fixture')
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ExpectedFailure)
        self.assertEqual(gate.run_suite(suite, stream=io.StringIO(), required=frozenset()), 1)

    def test_empty_or_incomplete_suite_is_rejected(self):
        with self.assertRaises(gate.GateError):
            gate.run_suite(unittest.TestSuite(), stream=io.StringIO())
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with self.assertRaises(gate.GateError):
            gate.run_suite(suite, stream=io.StringIO())
        self.assertEqual(len(gate.REQUIRED_CASES), 4)

    def test_normal_failures_return_nonzero_and_complete_success_returns_zero(self):
        def failed():
            self.fail('Deliberate gate regression fixture')
        for callback, expected in ((failed, 1), (lambda: None, 0)):
            suite = unittest.TestSuite([unittest.FunctionTestCase(callback)])
            self.assertEqual(gate.run_suite(suite, stream=io.StringIO(), required=frozenset()), expected)

    def test_cli_cannot_select_subset_or_allow_skips(self):
        with patch.object(sys, 'argv', ['run_required.py', '--allow-skips']), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(), 1)

    def test_shell_missing_terraform_fails_before_installation(self):
        binaries = self.root / 'bin'
        binaries.mkdir()
        (binaries / 'dirname').symlink_to(shutil.which('dirname'))
        (binaries / 'python3').symlink_to(sys.executable)
        result = subprocess.run(['/bin/bash', str(TESTS / 'run_required.sh')],
                                env=dict(os.environ, PATH=str(binaries)),
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.root.glob('oidc-required.*')), [])

    def test_shell_scrubs_credentials_and_cleans_failed_installs(self):
        # A fake Python stops at pip installation. No package install, provider,
        # network, or socket is used by this runner-control regression test.
        binaries = self.root / 'bin'
        binaries.mkdir()
        observed = self.root / 'observed-environment'
        work_path = self.root / 'observed-work-path'
        python = binaries / 'python3'
        python.write_text('''#!/bin/bash
set -euo pipefail
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin"
  cp "$0" "$3/bin/python"
  exit 0
fi
''' + f'/usr/bin/env > {shlex.quote(str(observed))}\n'
                          + f'printf "%s" "$OIDC_WORK" > {shlex.quote(str(work_path))}\n'
                          + 'exit 23\n')
        python.chmod(0o700)
        terraform = binaries / 'terraform'
        terraform.write_text('#!/bin/bash\nexit 99\n')
        terraform.chmod(0o700)
        env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.defpath,
                   TMPDIR=str(self.root), AWS_ACCESS_KEY_ID='FAKE-MUST-NOT-INHERIT',
                   ACTIONS_ID_TOKEN_REQUEST_TOKEN='FAKE-MUST-NOT-INHERIT',
                   TF_CLI_ARGS_init='POISON', PYTHONPATH='POISON')
        result = subprocess.run(['/bin/bash', str(TESTS / 'run_required.sh')], env=env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        clean = observed.read_text()
        for key in ('AWS_ACCESS_KEY_ID', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'TF_CLI_ARGS_init', 'PYTHONPATH'):
            self.assertNotIn(key + '=', clean)
        self.assertNotIn('FAKE-MUST-NOT-INHERIT', clean)
        self.assertFalse(Path(work_path.read_text()).exists())

    def test_preflight_failure_returns_nonzero_before_test_discovery(self):
        with patch.object(sys, 'argv', ['run_required.py']), \
                patch.object(gate, 'check_credentialless'), \
                patch.object(gate, 'check_dependencies', side_effect=gate.GateError('missing dependency')), \
                patch.object(gate.unittest.defaultTestLoader, 'discover') as discover, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(), 1)
            discover.assert_not_called()

    def test_source_and_installed_fixture_paths_use_the_production_helpers(self):
        self.assertEqual(CI, ROOT / 'ci')
        self.assertEqual(PROCESS_FIXTURE, TESTS / 'process_fixture.py')
        installed_ci = self.root / 'ci'
        installed_tests = installed_ci / 'oidc-tests'
        installed_tests.mkdir(parents=True)
        for name in ('oidc_process.py', 'run-lifecycle.py'):
            shutil.copy2(CI / name, installed_ci / name)
        for name in ('support.py', 'process_fixture.py', 'run_required.py'):
            shutil.copy2(TESTS / name, installed_tests / name)
        shutil.copy2(gate.requirements_path(), installed_tests / 'requirements-test.txt')
        code = ('import support, run_required; '
                'assert support.ROOT.name.startswith("oidc-required-unit-"); '
                'assert support.CI.name == "ci"; '
                'assert support.PROCESS_FIXTURE.parent.name == "oidc-tests"; '
                'assert run_required.requirements_path().parent.name == "oidc-tests"')
        result = subprocess.run([sys.executable, '-c', code], cwd=installed_tests,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, str(installed_tests / 'process_fixture.py'),
                                 str(self.root / 'counter'), 'botocore'],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['AccessKeyId'], 'ASIA0000000000000001')


if __name__ == '__main__':
    unittest.main()
