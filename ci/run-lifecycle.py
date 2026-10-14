#!/usr/bin/env python3
"""Run the one central lifecycle stage with a private, refreshable AWS profile."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('course_oidc_process', HERE / 'oidc_process.py')
oidc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oidc)
TERRAFORM_VERSION = '1.16.0'
AWS_PROVIDER_VERSION = '6.62.0'


def clean_environment(source, binding):
    # Remove ALL inherited AWS_* rather than trying to enumerate every current
    # or future static/container/SSO/web-identity/profile/endpoint override.
    env = {key: value for key, value in source.items()
           if not key.startswith(('AWS_', 'AMAZON_', 'TF_LOG', 'TF_CLI_ARGS', 'TF_TOKEN_'))}
    for key in ('BOTO_CONFIG', 'BOTO_PATH', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONINSPECT',
                'SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG', 'LD_DEBUG_OUTPUT',
                'TF_CLI_CONFIG_FILE', 'TF_DATA_DIR', 'TF_PLUGIN_CACHE_DIR',
                'TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE', 'TF_REATTACH_PROVIDERS'):
        env.pop(key, None)
    # Fixed role is application metadata required by existing saved-plan.py,
    # NOT a web-identity source: no token file/source_profile is configured.
    apply_mode = 'lifecycle-destroy' if binding['mode'] == 'lifecycle-destroy' else 'apply'
    env.update(EXPECTED_APPLY_ROLE_ARN=f"arn:aws:iam::{binding['account']}:role/gha-infra-{binding['environment']}-{apply_mode}",
               AWS_ROLE_ARN=binding['role'], AWS_REGION=binding['region'], AWS_DEFAULT_REGION=binding['region'],
               AWS_PROFILE=oidc.PROFILE, AWS_DEFAULT_PROFILE=oidc.PROFILE, AWS_SDK_LOAD_CONFIG='1',
               AWS_EC2_METADATA_DISABLED='true', AWS_IGNORE_CONFIGURED_ENDPOINT_URLS='true',
               AWS_STS_REGIONAL_ENDPOINTS='regional', BOTO_CONFIG=os.devnull)
    return env


def quote_path(path):
    text = str(Path(path).resolve())
    oidc.require(bool(__import__('re').fullmatch(r'[A-Za-z0-9_/ .-]+', text)), 'Unsafe process path.')
    return '"' + text + '"'


def locked_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


@contextlib.contextmanager
def private_profile(binding, source, directory=None):
    with tempfile.TemporaryDirectory(prefix='course-oidc-', dir=directory) as temp:
        path = Path(temp)
        path.chmod(0o700)
        locked_file(path / 'oidc_process.py', (HERE / 'oidc_process.py').read_bytes())
        raw = oidc.canonical(binding)
        locked_file(path / 'binding.json', raw)
        digest = hashlib.sha256(raw).hexdigest()
        command = f'{quote_path(sys.executable)} -I {quote_path(path / "oidc_process.py")} {quote_path(path / "binding.json")} {digest}'
        config = f'[profile {oidc.PROFILE}]\nregion = {oidc.REGION}\ncredential_process = {command}\n'
        locked_file(path / 'config', config.encode())
        locked_file(path / 'credentials', b'')
        locked_file(path / 'terraform.rc', oidc.TERRAFORM_CONFIG)
        env = clean_environment(source, binding)
        env.update(AWS_CONFIG_FILE=str(path / 'config'), AWS_SHARED_CREDENTIALS_FILE=str(path / 'credentials'),
                   TF_CLI_CONFIG_FILE=str(path / 'terraform.rc'), TF_IN_AUTOMATION='true', CHECKPOINT_DISABLE='1')
        oidc.validate_private_profile(env)
        yield env


def run_child(command, env, cwd, *, stdout=None, stderr=None, timeout=None):
    child = subprocess.Popen(command, env=env, cwd=cwd, start_new_session=True, stdout=stdout, stderr=stderr)
    previous = {}
    def forward(signum, _frame):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, forward)
    try:
        return child.wait(timeout=timeout)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()


def private_command(command, env, cwd, directory, label, timeout=30):
    """Never echo provider/process output, including on an exception or timeout."""
    output = directory / (label + '.stdout')
    error = directory / (label + '.stderr')
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
        with os.fdopen(os.open(error, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as err:
            status = run_child(command, env, cwd, stdout=out, stderr=err, timeout=timeout)
    oidc.require(status == 0, 'Private read-only provider check failed.')
    oidc.require(output.stat().st_size <= 8 * 1024 * 1024, 'Private check output too large.')
    return output.read_bytes()


def provider_lock(raw):
    return oidc.provider_lock(raw)


def selected_provider_lock(controller, binding, env, workspace, private):
    # Use the central registry's read-only selection, never a second chapter map.
    selection = oidc.parse_json(private_command([sys.executable, '-I', str(controller), 'inspect'],
                                               env, workspace, private, 'selection'))
    roots = selection.get('roots') if isinstance(selection, dict) else None
    oidc.require(selection.get('environment') == binding['environment'] and selection.get('blockers') == [] and
                 isinstance(roots, list) and roots and len(roots) == len(set(roots)), 'Invalid central selection.')
    sha = private_command(['git', 'rev-parse', 'HEAD'], env, workspace, private, 'head').decode().strip()
    oidc.require(sha == binding['sha'], 'Smoke requires the exact checked-out job revision.')
    result = None
    for index, root in enumerate(roots):
        oidc.require(isinstance(root, str) and re.fullmatch(r'terraform/environments/' + binding['environment'] + r'/[a-z0-9][a-z0-9/_-]*', root)
                     and '..' not in root.split('/'), 'Invalid selected root path.')
        lock = workspace / root / '.terraform.lock.hcl'
        oidc.require(lock.is_file() and lock.resolve() == lock, 'Selected root reviewed lock missing or redirected.')
        raw = lock.read_bytes()
        tracked = private_command(['git', 'show', 'HEAD:' + root + '/.terraform.lock.hcl'],
                                  env, workspace, private, 'lock-' + str(index))
        oidc.require(raw == tracked, 'Selected root lock is not unchanged committed source.')
        block = provider_lock(raw)
        # Exact shared provider checksum contract, not merely the same version.
        if result is None:
            result = block
        else:
            # Platform-specific h1 additions may differ; reviewed official zip
            # checksum sets must agree before sharing this provider binary.
            hashes = lambda value: set(re.findall(rb'"zh:[^"\n]+"', value))
            oidc.require(hashes(result) == hashes(block), 'Selected root provider checksums differ; review locks together.')
    return result


def smoke_identity(plan, binding):
    expected_arn = f"arn:aws:sts::{binding['account']}:assumed-role/gha-infra-{binding['environment']}-{binding['mode']}/{binding['session']}"
    values = plan.get('planned_values', {}) if isinstance(plan, dict) else {}
    outputs = values.get('outputs', {})
    oidc.require(set(outputs) == {'account', 'arn'} and
                 outputs['account'].get('value') == binding['account'] and
                 outputs['arn'].get('value') == expected_arn,
                 'Read-only provider identity does not match the exact job role.')
    resources = values.get('root_module', {}).get('resources', [])
    oidc.require(len(resources) == 1 and resources[0].get('mode') == 'data' and
                 resources[0].get('type') == 'aws_caller_identity', 'Unexpected smoke resource.')
    oidc.require(all(row.get('mode') == 'data' for row in plan.get('resource_changes', [])),
                 'Smoke cannot contain managed resource changes.')


def provider_smoke(controller, binding, env, workspace):
    private = Path(env['AWS_CONFIG_FILE']).parent / 'provider-smoke'
    private.mkdir(mode=0o700)
    lock = selected_provider_lock(controller, binding, env, workspace, private)
    terraform = shutil.which('terraform', path=env.get('PATH'))
    oidc.require(terraform is not None, 'Pinned Terraform is required for the identity smoke.')
    version = oidc.parse_json(private_command([terraform, 'version', '-json'], env, private, private, 'version'))
    oidc.require(version.get('terraform_version') == TERRAFORM_VERSION and version.get('platform') == 'linux_amd64',
                 'Identity smoke requires the pinned Linux Terraform toolchain.')
    config = {
        'terraform': {'required_version': '= ' + TERRAFORM_VERSION,
                      'required_providers': {'aws': {'source': 'hashicorp/aws', 'version': '= ' + AWS_PROVIDER_VERSION}}},
        'provider': {'aws': {'region': binding['region'], 'profile': oidc.PROFILE,
                             'shared_config_files': [env['AWS_CONFIG_FILE']],
                             'shared_credentials_files': [env['AWS_SHARED_CREDENTIALS_FILE']],
                             'skip_metadata_api_check': True, 'skip_credentials_validation': True,
                             'skip_requesting_account_id': True}},
        'data': {'aws_caller_identity': {'current': {}}},
        'output': {'account': {'value': '${data.aws_caller_identity.current.account_id}'},
                   'arn': {'value': '${data.aws_caller_identity.current.arn}'}}}
    locked_file(private / 'main.tf.json', oidc.canonical(config))
    locked_file(private / '.terraform.lock.hcl', lock)
    private_command([terraform, 'init', '-backend=false', '-input=false', '-no-color', '-lockfile=readonly'],
                    env, private, private, 'init', timeout=180)
    private_command([terraform, 'plan', '-input=false', '-no-color', '-lock=false', '-out=identity.plan'],
                    env, private, private, 'plan', timeout=120)
    plan = oidc.parse_json(private_command([terraform, 'show', '-json', 'identity.plan'], env, private, private, 'show'))
    smoke_identity(plan, binding)
    # No plan, state, identity, provider log, or credential is published.
    print('Read-only refreshable provider identity smoke passed.')


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        oidc.require(len(sys.argv) == 2, 'One lifecycle stage is required.')
        stage = sys.argv[1]
        binding = oidc.make_binding(os.environ, stage)
        workspace = Path(oidc.required(os.environ, 'GITHUB_WORKSPACE')).resolve(strict=True)
        controller = workspace / 'ci' / 'terraform-lifecycle.py'
        oidc.require(controller.is_file() and controller.resolve() == controller, 'Central controller missing or redirected.')
        # No AWS request until the actual central registry rejects unsupported
        # chapters/stages; this must remain a read-only selection operation.
        with private_profile(binding, os.environ, directory=oidc.required(os.environ, 'RUNNER_TEMP')) as env:
            status = run_child([sys.executable, '-I', str(controller), 'select'], env, workspace)
            if status:
                return status
            provider_smoke(controller, binding, env, workspace)
            return run_child([sys.executable, '-I', str(controller), stage], env, workspace)
    except BaseException:
        sys.stderr.write('Private lifecycle credential setup failed; no fallback is permitted.\n')
        return 1


if __name__ == '__main__':
    sys.exit(main())
