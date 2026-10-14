"""Wrapper subprocess tests use a fake Terraform executable; never call AWS."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from support import ROOT, environment, oidc, wrapper

LOCK = '''provider "registry.terraform.io/hashicorp/aws" {
  version = "6.62.0"
  constraints = "6.62.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "zh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ]
}
'''

CONTROLLER = '''
import json, os, pathlib, sys
stage = sys.argv[1]
assert os.environ['AWS_PROFILE'] == 'course-lifecycle'
assert os.environ['AWS_EC2_METADATA_DISABLED'] == 'true'
assert not any(k in os.environ for k in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'TF_REATTACH_PROVIDERS', 'TF_CLI_ARGS_plan'])
assert os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN'] == 'LOCAL-FAKE-OIDC-REQUEST-CREDENTIAL'
config = pathlib.Path(os.environ['AWS_CONFIG_FILE'])
assert config.is_file()
assert pathlib.Path(os.environ['AWS_SHARED_CREDENTIALS_FILE']).read_bytes() == b''
with open('stages.txt', 'a') as output:
    output.write(stage + '\\n')
if stage == 'select' and os.environ.get('FIXTURE_FAIL') == 'registry':
    sys.exit(7)
if stage == 'inspect':
    print(json.dumps({'environment': 'dev', 'blockers': [], 'roots': ['terraform/environments/dev/network/vpc']}))
'''

TERRAFORM = '''#!/usr/bin/env python3
import json, os, pathlib, sys
command = sys.argv[1]
root = pathlib.Path.cwd()
with open(pathlib.Path(os.environ['GITHUB_WORKSPACE']) / 'stages.txt', 'a') as output:
    output.write('tf-' + command + '\\n')
assert os.environ['AWS_PROFILE'] == 'course-lifecycle'
assert os.environ['AWS_DEFAULT_PROFILE'] == 'course-lifecycle'
assert os.environ['AWS_EC2_METADATA_DISABLED'] == 'true'
assert os.environ['AWS_IGNORE_CONFIGURED_ENDPOINT_URLS'] == 'true'
assert os.environ['AWS_ROLE_ARN'].endswith('gha-infra-dev-' + os.environ['FIXTURE_MODE'])
assert not any(k.startswith(('TF_LOG', 'TF_CLI_ARGS')) for k in os.environ)
assert not any(k in os.environ for k in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'TF_REATTACH_PROVIDERS', 'TF_DATA_DIR', 'TF_PLUGIN_CACHE_DIR'])
assert pathlib.Path(os.environ['AWS_SHARED_CREDENTIALS_FILE']).read_bytes() == b''
config = pathlib.Path(os.environ['AWS_CONFIG_FILE']).read_text()
assert 'credential_process = ' in config and ' -I ' in config and 'source_profile' not in config
assert pathlib.Path(os.environ['TF_CLI_CONFIG_FILE']).read_text() == 'disable_checkpoint = true\\nprovider_installation { direct {} }\\n'
mode = os.environ.get('FIXTURE_FAIL', '')
# Deliberately hostile stderr must stay private even when the command fails.
print('SECRET_SENTINEL_BEARER_AND_SESSION', file=sys.stderr)
if command == 'version':
    print(json.dumps({'terraform_version': '9.99.9' if mode == 'version' else '1.16.0', 'platform': 'linux_amd64'}))
elif command == 'init':
    assert '-backend=false' in sys.argv and '-lockfile=readonly' in sys.argv
    assert (root / '.terraform.lock.hcl').is_file()
    config = json.loads((root / 'main.tf.json').read_text())
    assert config['terraform']['required_providers']['aws']['version'] == '= 6.62.0'
    assert set(config) == {'terraform', 'provider', 'data', 'output'}
    provider = config['provider']['aws']
    assert set(provider) == {'region', 'profile', 'shared_config_files', 'shared_credentials_files', 'skip_metadata_api_check', 'skip_credentials_validation', 'skip_requesting_account_id'}
    assert provider['shared_config_files'] == [os.environ['AWS_CONFIG_FILE']]
    assert provider['shared_credentials_files'] == [os.environ['AWS_SHARED_CREDENTIALS_FILE']]
    print('SECRET_SENTINEL_BEARER_AND_SESSION')
    if mode == 'init': sys.exit(8)
elif command == 'plan':
    assert '-lock=false' in sys.argv and '-out=identity.plan' in sys.argv
    if mode == 'plan': sys.exit(9)
    (root / 'identity.plan').write_bytes(b'PRIVATE_PLAN_SENTINEL')
    print('SECRET_SENTINEL_BEARER_AND_SESSION')
elif command == 'show':
    account = '999999999999' if mode == 'account' else os.environ['EXPECTED_ACCOUNT_ID']
    role = 'evil-role' if mode == 'role' else 'gha-infra-dev-' + os.environ['FIXTURE_MODE']
    session = 'fallback-session' if mode == 'fallback' else 'gha-456-1-' + os.environ['FIXTURE_STAGE']
    arn = 'arn:aws:sts::' + account + ':assumed-role/' + role + '/' + session
    if mode == 'user': arn = 'arn:aws:iam::123456789012:user/static-fallback'
    resource = {'mode': 'managed' if mode == 'managed' else 'data', 'type': 'aws_caller_identity'}
    print(json.dumps({'planned_values': {'outputs': {'account': {'value': account}, 'arn': {'value': arn}}, 'root_module': {'resources': [resource]}}}))
else:
    raise AssertionError('Unexpected command')
'''


class SameJobWrapper(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, stage='plan', failure='', changed_lock=None):
        with tempfile.TemporaryDirectory(prefix='oidc-wrapper-') as temp:
            root = Path(temp)
            (root / 'ci').mkdir()
            runner = root / 'runner'
            runner.mkdir()
            (root / 'ci/terraform-lifecycle.py').write_text(CONTROLLER)
            lock = root / 'terraform/environments/dev/network/vpc/.terraform.lock.hcl'
            lock.parent.mkdir(parents=True)
            lock.write_text(LOCK)
            for args in [['init', '-q'], ['add', '.'], ['-c', 'user.name=Offline Test', '-c', 'user.email=offline@example.invalid', 'commit', '-qm', 'fixture']]:
                subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
            sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            if changed_lock is not None:
                lock.write_text(changed_lock)
            binary = root / 'bin'
            binary.mkdir()
            (binary / 'terraform').write_text(TERRAFORM)
            (binary / 'terraform').chmod(0o700)
            env = dict(dict(os.environ, **environment(stage)), GITHUB_SHA=sha, GITHUB_WORKSPACE=str(root), RUNNER_TEMP=str(runner),
                       PATH=str(binary) + os.pathsep + os.environ['PATH'], FIXTURE_FAIL=failure,
                       FIXTURE_MODE=oidc.STAGE_MODE[stage], FIXTURE_STAGE=stage,
                       AWS_ACCESS_KEY_ID='POISON_STATIC', AWS_SECRET_ACCESS_KEY='POISON_STATIC', AWS_SESSION_TOKEN='POISON_SESSION',
                       AWS_WEB_IDENTITY_TOKEN_FILE='/poison', AWS_CONTAINER_CREDENTIALS_FULL_URI='http://127.0.0.1:9',
                       TF_LOG='TRACE', TF_CLI_ARGS_plan='-destroy', TF_REATTACH_PROVIDERS='POISON', TF_DATA_DIR='/poison',
                       TF_PLUGIN_CACHE_DIR='/poison', TF_CLI_CONFIG_FILE='/poison')
            yield root, runner, env

    def run_wrapper(self, root, env, stage='plan'):
        result = subprocess.run([sys.executable, '-I', str(ROOT / 'ci/run-lifecycle.py'), stage], env=env,
                                text=True, capture_output=True, timeout=30)
        self.assertNotIn('SECRET_SENTINEL', result.stdout + result.stderr)
        self.assertNotIn('PRIVATE_PLAN_SENTINEL', result.stdout + result.stderr)
        self.assertNotIn('LOCAL-FAKE', result.stdout + result.stderr)
        self.assertEqual(list((root / 'runner').iterdir()), [])
        return result

    def test_every_stage_smokes_same_clean_profile_before_central_mutation(self):
        for stage in ('start', 'plan', 'apply', 'up'):
            with self.subTest(stage=stage), self.fixture(stage=stage) as (root, runner, env):
                result = self.run_wrapper(root, env, stage)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / 'stages.txt').read_text(), 'select\ninspect\ntf-version\ntf-init\ntf-plan\ntf-show\n' + stage + '\n')
                self.assertEqual(result.stdout, 'Read-only refreshable provider identity smoke passed.\n')

    def test_registry_failure_stops_before_smoke_or_credential_process(self):
        with self.fixture(failure='registry') as (root, runner, env):
            result = self.run_wrapper(root, env)
            self.assertEqual(result.returncode, 7)
            self.assertEqual((root / 'stages.txt').read_text(), 'select\n')

    def test_smoke_failure_wrong_identity_and_static_fallback_block_mutation(self):
        for failure in ('init', 'plan', 'version', 'account', 'role', 'fallback', 'user', 'managed'):
            with self.subTest(failure=failure), self.fixture(failure=failure) as (root, runner, env):
                result = self.run_wrapper(root, env)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'Private lifecycle credential setup failed; no fallback is permitted.\n')
                self.assertNotIn('plan\n', (root / 'stages.txt').read_text().splitlines(keepends=True))

    def test_missing_or_uncommitted_lock_blocks_before_provider(self):
        for change in ('missing', 'modified'):
            with self.subTest(change=change), self.fixture() as (root, runner, env):
                lock = root / 'terraform/environments/dev/network/vpc/.terraform.lock.hcl'
                if change == 'missing':
                    lock.unlink()
                else:
                    lock.write_text(LOCK.replace('6.62.0', '6.61.0'))
                result = self.run_wrapper(root, env)
                self.assertEqual(result.returncode, 1)
                self.assertEqual((root / 'stages.txt').read_text(), 'select\ninspect\n')

    def test_wrong_version_missing_hash_and_duplicate_lock_rejected(self):
        for raw in (LOCK.replace('6.62.0', '6.61.0'), LOCK.replace('zh:', 'other:'), LOCK + LOCK):
            with self.subTest(raw=raw), self.assertRaises(wrapper.oidc.CredentialError):
                wrapper.provider_lock(raw.encode())

    def test_selected_root_checksum_conflict_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='oidc-locks-') as temp:
            workspace = Path(temp)
            roots = ['terraform/environments/dev/network/vpc', 'terraform/environments/dev/network/peer']
            locks = []
            for root in roots:
                lock = workspace / root / '.terraform.lock.hcl'
                lock.parent.mkdir(parents=True)
                lock.write_text(LOCK)
                locks.append(lock)
            binding = oidc.make_binding(environment(), 'plan')

            def read_only(command, *_args, **_kwargs):
                if command[-1] == 'inspect':
                    return json.dumps({'environment': 'dev', 'blockers': [], 'roots': roots}).encode()
                if command[:2] == ['git', 'rev-parse']:
                    return binding['sha'].encode()
                return (workspace / command[-1].removeprefix('HEAD:')).read_bytes()

            with patch.object(wrapper, 'private_command', side_effect=read_only):
                # Different platform h1 hash is allowed, with the same archive boundary.
                locks[1].write_text(LOCK.replace('h1:A', 'h1:B'))
                self.assertEqual(wrapper.selected_provider_lock(Path('/controller'), binding, {}, workspace, workspace),
                                 wrapper.provider_lock(LOCK.encode()))
                locks[1].write_text(LOCK.replace('zh:a', 'zh:b'))
                with self.assertRaises(wrapper.oidc.CredentialError):
                    wrapper.selected_provider_lock(Path('/controller'), binding, {}, workspace, workspace)
                locks[1].unlink()
                locks[1].symlink_to(locks[0])
                with self.assertRaises(wrapper.oidc.CredentialError):
                    wrapper.selected_provider_lock(Path('/controller'), binding, {}, workspace, workspace)

    def test_timeout_keeps_output_private_and_cleans_child(self):
        with tempfile.TemporaryDirectory(prefix='oidc-timeout-') as temp:
            root = Path(temp)
            with self.assertRaises(subprocess.TimeoutExpired):
                wrapper.private_command([sys.executable, '-c',
                    'import sys,time; print("PRIVATE_TIMEOUT_SENTINEL", file=sys.stderr, flush=True); time.sleep(60)'],
                    os.environ.copy(), root, root, 'timeout', timeout=0.1)
            self.assertEqual((root / 'timeout.stdout').read_bytes(), b'')
            self.assertEqual((root / 'timeout.stderr').read_text(), 'PRIVATE_TIMEOUT_SENTINEL\n')
            self.assertEqual((root / 'timeout.stderr').stat().st_mode & 0o777, 0o600)

    def test_arbitrary_cli_command_rejected(self):
        result = subprocess.run([sys.executable, '-I', str(ROOT / 'ci/run-lifecycle.py'), 'bash', '-c', 'exit 0'],
                                env=dict(os.environ, **environment()), text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('LOCAL-FAKE', result.stderr)


if __name__ == '__main__':
    unittest.main()
