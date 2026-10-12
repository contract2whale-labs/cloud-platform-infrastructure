#!/usr/bin/env python3
"""Run native schema and mock contracts for the Terraform source currently present."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import hcl2
from lark.exceptions import LarkError


EXCLUDED = {'.git', '.terraform', '.terraform-plugin-cache', 'tests', 'examples'}


def checked_path(repo, path):
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(repo):
        raise ValueError(f'path escapes repository: {path}')
    current = repo
    for part in path.relative_to(repo).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f'symlink is not a source path: {current.relative_to(repo)}')
    return path


def read_hcl(repo, path):
    try:
        return hcl2.loads(checked_path(repo, path).read_text())
    except LarkError as error:
        raise ValueError(f'invalid HCL: {path.relative_to(repo)}: {error}') from error


def discover(repo, base):
    directory = checked_path(repo, repo / base)
    if not directory.exists():
        return []
    targets = []
    for current, folders, files in os.walk(directory, followlinks=False):
        parent = Path(current)
        for name in folders:
            if name not in EXCLUDED:
                checked_path(repo, parent / name)
        folders[:] = sorted(name for name in folders if name not in EXCLUDED)
        source = sorted(name for name in files if name.endswith('.tf'))
        if any(name.endswith('.tf.json') for name in files):
            raise ValueError(f'use reviewed HCL source rather than unregistered JSON configuration: {parent.relative_to(repo)}')
        if source:
            for name in source:
                checked_path(repo, parent / name)
            targets.append(parent)
    return targets


def provider_contract(repo, target, seen=None):
    """Include provider aliases required by local child modules, without validating them as roots."""
    seen = set() if seen is None else seen
    checked_path(repo, target)
    if target in seen:
        return set()
    seen.add(target)
    required = {'aws'}
    for path in sorted(target.glob('*.tf')):
        source = read_hcl(repo, path)
        for block in source.get('provider', []):
            for name, configuration in block.items():
                if name != 'aws':
                    raise ValueError(f'provider needs an explicit mock policy: {path.relative_to(repo)}: {name}')
                alias = configuration.get('alias')
                required.add(f'aws.{alias}' if alias else 'aws')
        for terraform in source.get('terraform', []):
            for providers in terraform.get('required_providers', []):
                for name, configuration in providers.items():
                    if name != 'aws' or configuration.get('source', 'hashicorp/aws') != 'hashicorp/aws':
                        raise ValueError(f'provider needs an explicit mock policy: {path.relative_to(repo)}: {name}')
                    aliases = configuration.get('configuration_aliases', '')
                    required.update(re.findall(r'\baws\.[A-Za-z_][A-Za-z0-9_]*\b', str(aliases)))
        for module in source.get('module', []):
            for configuration in module.values():
                location = configuration.get('source', '')
                if isinstance(location, str) and location.startswith('.'):
                    child = checked_path(repo, target / location)
                    if not child.is_dir():
                        raise ValueError(f'local child module is missing: {child.relative_to(repo)}')
                    required.update(provider_contract(repo, child, seen))
    return required


def suites_for(repo, target):
    folder = checked_path(repo, target / 'tests')
    if not folder.exists():
        return []
    for current, folders, files in os.walk(folder, followlinks=False):
        for name in folders + files:
            checked_path(repo, Path(current) / name)
        if Path(current) != folder and any(name.endswith('.tftest.hcl') for name in files):
            raise ValueError(f'nested suite is outside the native default test directory: {Path(current).relative_to(repo)}')
    return sorted(folder.glob('*.tftest.hcl'))


def check_mock_suite(repo, target, suite):
    source = read_hcl(repo, suite)
    if source.get('provider'):
        raise ValueError(f'real provider configuration is forbidden in CI mock suite: {suite.relative_to(repo)}')
    mocked = set()
    for block in source.get('mock_provider', []):
        for name, configuration in block.items():
            if name != 'aws':
                raise ValueError(f'unsupported mock provider: {suite.relative_to(repo)}: {name}')
            alias = configuration.get('alias')
            mocked.add(f'aws.{alias}' if alias else 'aws')
    required = provider_contract(repo, target)
    for run in source.get('run', []):
        for configuration in run.values():
            for module in configuration.get('module', []):
                location = module.get('source', '')
                if not isinstance(location, str) or not location.startswith('.'):
                    raise ValueError(f'test module must be a local reviewed path: {suite.relative_to(repo)}')
                required.update(provider_contract(repo, checked_path(repo, target / location)))
            for value in configuration.get('providers', {}).values():
                reference = str(value).removeprefix('${').removesuffix('}').strip()
                if reference not in mocked:
                    raise ValueError(f'test provider is not mocked: {suite.relative_to(repo)}: {reference}')
    if not source.get('run') or not required.issubset(mocked):
        raise ValueError(f'mock coverage missing in {suite.relative_to(repo)}: {sorted(required - mocked)}')


def clean_environment():
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('AWS_', 'TF_VAR_', 'TF_CLI_ARGS', 'TF_TOKEN_'))
                   and key not in {'TF_DATA_DIR', 'TF_WORKSPACE', 'TF_LOG', 'TF_LOG_PATH'}}
    environment.update(AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                       AWS_EC2_METADATA_DISABLED='true', TF_IN_AUTOMATION='true', TF_INPUT='0',
                       CHECKPOINT_DISABLE='1')
    return environment


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--terraform', default='terraform')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    repo = args.repo.resolve(strict=True)
    report = {'status': 'FAIL', 'scope': 'Native Terraform schema and mock contracts; no backend or live AWS execution.', 'targets': []}
    try:
        roots = discover(repo, 'terraform/environments')
        modules = discover(repo, 'modules')
        if not roots and not modules:
            report['status'] = 'SKIP_NO_TERRAFORM_SOURCE'
            print('TF_CONTRACTS_SKIP: no authored Terraform configuration is present yet; no schema or mock test was run.')
            return 0
        targets = []
        covered_modules = set()
        for target in roots:
            visited = set()
            provider_contract(repo, target, visited)
            covered_modules.update(visited - {target})
        # Check every suite before executing any Terraform command.
        for target in roots + modules:
            suites = suites_for(repo, target)
            if target in modules and not suites and target not in covered_modules:
                raise ValueError(f'module has no native mock suite or consuming root yet: {target.relative_to(repo)}; keep this change as a draft')
            for suite in suites:
                check_mock_suite(repo, target, suite)
            targets.append((target, suites))
        environment = clean_environment()
        failed = False
        for target, suites in targets:
            relative = str(target.relative_to(repo))
            lockfile = checked_path(repo, target / '.terraform.lock.hcl')
            lock_before = hashlib.sha256(lockfile.read_bytes()).hexdigest() if lockfile.is_file() else None
            record = {'path': relative, 'kind': 'root' if target in roots else 'module',
                      'source_sha256': {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest()
                                        for path in sorted(target.glob('*.tf'))},
                      'suite_sha256': {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest() for path in suites},
                      'steps': []}
            report['targets'].append(record)
            commands = [('init', ['init', '-backend=false', '-input=false', '-no-color'])]
            if lock_before is not None:
                commands[0][1].append('-lockfile=readonly')
            if target in roots:
                commands.append(('validate', ['validate', '-no-color']))
            commands.extend((f'test:{suite.name}', ['test', f'-filter=tests/{suite.name}', '-no-color']) for suite in suites)
            for name, arguments in commands:
                result = subprocess.run([args.terraform, f'-chdir={target}', *arguments], env=environment,
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                record['steps'].append({'name': name, 'exit': result.returncode})
                print(f'TF_CONTRACTS {name} {relative} exit={result.returncode}', flush=True)
                print(result.stdout, end='', flush=True)
                if result.returncode:
                    failed = True
                    if name == 'init':
                        break
            if lock_before is not None and (not lockfile.is_file() or hashlib.sha256(lockfile.read_bytes()).hexdigest() != lock_before):
                failed = True
                record['lockfile_changed'] = True
                print(f'TF_CONTRACTS FAIL: reviewed lockfile changed: {relative}', file=sys.stderr)
            if target in modules:
                print(f'TF_CONTRACTS module coverage: {relative}; consuming_root={target in covered_modules} mock_suites={bool(suites)}; no standalone module validate', flush=True)
        report['status'] = 'FAIL' if failed else 'PASS'
        print(f'TF_CONTRACTS {report["status"]}: inspect the named schema and mock results above; live plan/apply was not run.')
        return int(failed)
    except (OSError, ValueError) as error:
        report['error'] = str(error)
        print(f'TF_CONTRACTS FAIL: {error}', file=sys.stderr)
        return 1
    finally:
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
