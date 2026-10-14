#!/usr/bin/env python3
"""Required credentialless suite: unavailable tools, missing cases, and skips fail.

Use run_required.sh to install the reviewed toolchain and exact Python pins in
an empty home. This entry point deliberately has no subset/skip/allow-failure
options. It never obtains real GitHub OIDC or AWS credentials.
"""
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

TESTS = Path(__file__).resolve().parent
TERRAFORM_VERSION = '1.16.0'
PROVIDER_VERSION = '6.62.0'
REQUIRED_CASES = frozenset({
    'test_sdk_chain.ActualSDKChain.test_real_process_chain_and_refresh',
    'test_sdk_chain.ActualSDKChain.test_mandatory_refresh_failure_does_not_fall_back',
    'test_terraform_provider.ActualTerraformProvider.test_real_provider_process_chain_and_in_process_expiry_refresh',
    'test_terraform_provider.ActualTerraformProvider.test_real_provider_expired_refresh_failure_stops_plan',
})


class GateError(RuntimeError):
    pass


def requirements_path():
    installed = TESTS / 'requirements-test.txt'
    return installed if installed.is_file() else TESTS.parent / 'requirements-test.txt'


def check_dependencies(path):
    pins = {}
    for raw in path.read_text().splitlines():
        line = raw.partition('#')[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)', line)
        if not match or match[1] in pins:
            raise GateError('Every test dependency must have one exact version pin.')
        pins[match[1]] = match[2]
    if not pins or 'botocore' not in pins:
        raise GateError('Mandatory botocore dependency pin is missing.')
    for name, expected in pins.items():
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise GateError(f'Required test dependency is missing: {name}=={expected}') from error
        if actual != expected:
            raise GateError(f'Wrong test dependency version: {name}; expected {expected}, found {actual}')


def check_credentialless(env):
    # Do not silently allow the credentialless check to inherit live credentials
    # or a GitHub OIDC grant. Only names, never environment values, enter errors.
    forbidden = sorted(key for key in env if key.startswith(
        ('AWS_', 'AMAZON_', 'ACTIONS_ID_TOKEN_REQUEST_', 'BOTO_')))
    if forbidden:
        raise GateError('Credentialless gate received forbidden environment keys: ' + ', '.join(forbidden))
    home = Path(env.get('HOME', '~')).expanduser()
    for relative in ('.aws/config', '.aws/credentials', '.boto'):
        path = home / relative
        if path.exists() and path.stat().st_size:
            raise GateError('Credentialless gate requires an empty AWS configuration home.')


def check_toolchain(env):
    paths = {}
    for name in ('OIDC_TEST_TERRAFORM', 'OIDC_TEST_PROVIDER'):
        value = env.get(name)
        if not value:
            raise GateError(f'Required binary path is not set: {name}; use run_required.sh')
        path = Path(value)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise GateError(f'Required executable is unavailable: {name}')
        paths[name] = path
    result = subprocess.run([str(paths['OIDC_TEST_TERRAFORM']), 'version', '-json'],
                            env=env, text=True, capture_output=True, timeout=30, check=True)
    if json.loads(result.stdout).get('terraform_version') != TERRAFORM_VERSION:
        raise GateError(f'Required Terraform version is {TERRAFORM_VERSION}.')
    provider = paths['OIDC_TEST_PROVIDER']
    if (provider.name != f'terraform-provider-aws_v{PROVIDER_VERSION}_x5'
            or provider.parent.name != 'linux_amd64'
            or provider.parent.parent.name != PROVIDER_VERSION):
        raise GateError(f'Required AWS provider is {PROVIDER_VERSION} for linux_amd64.')


class NoSkipResult(unittest.TextTestResult):
    def wasSuccessful(self):
        return super().wasSuccessful() and not self.skipped and not self.expectedFailures


def case_ids(suite):
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            yield from case_ids(case)
        else:
            yield case.id()


def run_suite(suite, stream=None, required=REQUIRED_CASES):
    ids = set(case_ids(suite))
    if not ids:
        raise GateError('Required suite discovered no tests.')
    missing = required - ids
    if missing:
        raise GateError('Required integration cases are absent: ' + ', '.join(sorted(missing)))
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=NoSkipResult).run(suite)
    if not result.wasSuccessful():
        return 1
    return 0


def main():
    try:
        if len(sys.argv) != 1:
            raise GateError('Required runner accepts no test selection or skip arguments.')
        check_credentialless(os.environ)
        check_dependencies(requirements_path())
        check_toolchain(os.environ)
        os.environ['OIDC_REQUIRE_TERRAFORM'] = '1'
        # All tests and fixtures are siblings in both supported layouts.
        sys.path.insert(0, str(TESTS))
        suite = unittest.defaultTestLoader.discover(str(TESTS), pattern='test_*.py')
        status = run_suite(suite)
        if not status:
            print('PASS: required credentialless OIDC suite completed with zero skipped tests.')
        return status
    except (GateError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Required credentialless OIDC gate failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
