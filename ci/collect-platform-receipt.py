#!/usr/bin/env python3
"""Build a legacy typed consumer receipt from one proven CI apply; never apply."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True

ROOT_PATHS = {'network':'network/vpc','core':'platform/core','gateway':'platform/gateway','operations':'platform/operations','observability':'platform/observability','queue-managed':'platform/queue','delivery':'delivery','data':'data','identity':'identity','app-auth':'platform/app-auth','alerting':'platform/alerting'}
SHA = re.compile(r'^[0-9a-f]{40}$')
HASH = re.compile(r'^[0-9a-f]{64}$')
SOURCE_FILES = ('automation/platform_input_registry.py','automation/platform_inputs.py','automation/update_objstore_revision.py','automation/platform-input-mappings.json','schemas/platform-inputs.schema.json')

class ReceiptError(Exception):
    """A fixed diagnostic safe to print without source/State/credential contents."""

def need(condition, message):
    if not condition:
        raise ReceiptError(message)

def execute(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True)
    need(result.returncode == 0, 'A read-only source/API check failed. Inspect it in an authorized private session.')
    return result.stdout

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def check_source(repo, revision):
    need(execute(['git','rev-parse','HEAD'], repo).decode().strip() == revision, 'Checkout differs from the successful deployment SHA.')
    execute(['git','diff','--no-ext-diff','--no-textconv','--exit-code'], repo)
    execute(['git','diff','--no-ext-diff','--no-textconv','--cached','--exit-code'], repo)
    # Ignored caches and modules can shadow dependencies just like untracked files.
    for flags in ([], ['--ignored']):
        unexpected = execute(['git','ls-files','--others',*flags,'--exclude-standard','--','automation','schemas'], repo)
        need(not unexpected.strip(), 'Untracked or ignored source-scope files are forbidden; use a clean approved checkout.')
    for relative in SOURCE_FILES:
        current = repo
        for part in Path(relative).parts:
            current = current / part
            need(not current.is_symlink(), 'Symlink source helper or parent directory is forbidden.')
        need(current.is_file() and current.resolve().is_relative_to(repo.resolve()), 'A reviewed source helper is missing or outside checkout.')
        execute(['git','ls-files','--error-unmatch','--',relative], repo)

def check_completion(completion, run, expected):
    need(completion.get('schema') == 1 and completion.get('kind') == 'apply-completion', 'A successful apply completion is required.')
    context = completion.get('context', {})
    for key in ('repository','repository_id','run_id','run_attempt','sha','root','environment','account'):
        need(str(context.get(key)) == str(expected[key]), 'Completion context differs from the requested deployment.')
    need(context.get('backend', {}).get('bucket') == expected['bucket'] and context['backend'].get('key') == expected['state_key'], 'Completion backend differs from the selected root.')
    need(context['backend'].get('region') == 'ap-northeast-2' and context.get('workspace') == 'default', 'Completion region/workspace differs.')
    need(run.get('status') == 'completed', 'The requested deployment attempt has not completed.')
    need(run.get('head_branch') == 'main' and run.get('head_sha') == expected['sha'], 'Deployment must originate from the selected main SHA.')
    need(run.get('event') in ('push','workflow_dispatch'), 'Unexpected deployment trigger.')
    need(run.get('path', '').split('@')[0] == '.github/workflows/terraform-apply.yml', 'Unexpected deployment workflow.')
    need(str(run.get('run_attempt')) == expected['run_attempt'], 'Deployment attempt differs.')
    need(str(run.get('repository', {}).get('id')) == expected['repository_id'], 'Deployment repository differs.')
    need(HASH.fullmatch(str(completion.get('plan_sha', ''))) is not None, 'Invalid applied plan digest.')
    state = completion.get('state', {})
    try:
        lineage = str(uuid.UUID(state['lineage']))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ReceiptError('Invalid post-apply State lineage.') from None
    need(type(state.get('serial')) is int and state['serial'] >= 0, 'Invalid post-apply State serial.')
    need(bool(state.get('version')) and state['version'] != 'null' and bool(state.get('etag')), 'Versioned post-apply State is required.')
    outputs = completion.get('outputs', {})
    need(outputs.get('key') == expected['prefix'] + 'outputs.json', 'Output object belongs to another deployment.')
    need(bool(outputs.get('version')) and outputs['version'] != 'null' and HASH.fullmatch(str(outputs.get('sha256', ''))) is not None, 'Versioned, hashed outputs are required.')
    return lineage, state['serial']

def pointer(value, path):
    for key in path.lstrip('/').split('/') if path else []:
        key = key.replace('~1','/').replace('~0','~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value

def build_receipt(metadata, outputs, entries, validate_value):
    need(bool(entries) and len({entry['field'] for entry in entries}) == len(entries), 'A unique active field registry is required.')
    values = {}
    for entry in entries:
        source = entry['source']
        if 'metadata' in source:
            need(source['metadata'] in ('region','account_id','environment'), 'Unsupported metadata field.')
            value = metadata[source['metadata']]
        else:
            item = outputs[source['output']]
            need(item.get('sensitive') is False, 'A registered output is sensitive or its sensitivity is unknown.')
            value = pointer(item['value'], source.get('pointer', ''))
        validate_value(entry['field'], value, entry['type'], metadata)
        values[entry['field']] = value
    return {**metadata, 'values': values}

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def write_new(path, receipt):
    need(not path.exists() and not path.is_symlink(), 'Receipt already exists; preserve it and choose a new path.')
    need(not any(parent.is_symlink() for parent in path.absolute().parents), 'Symlink receipt directory is forbidden.')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n')

def main():
    need(sys.flags.isolated == 1, 'Run this collector with python3 -I in the approved toolchain.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--root', choices=ROOT_PATHS, required=True)
    parser.add_argument('--environment', choices=['dev','prod'], required=True)
    parser.add_argument('--expect-account', required=True)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--apply-run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    parser.add_argument('--state-bucket', required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--completion-version', required=True)
    parser.add_argument('--completion-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    repo = args.repo.resolve()
    need(SHA.fullmatch(args.expect_revision) is not None and re.fullmatch(r'\d{12}', args.expect_account) is not None, 'Invalid expected source/account.')
    need(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository) is not None, 'Invalid repository name.')
    need(args.apply_run_id.isdigit() and args.run_attempt.isdigit(), 'Explicit numeric run/attempt are required.')
    need(HASH.fullmatch(args.completion_sha256) is not None and bool(args.completion_version), 'Exact completion version/hash are required.')
    need(not args.output.exists() and not args.output.is_symlink(), 'Receipt already exists; do not overwrite an earlier attempt.')
    # Only reviewed, tracked helpers/registry are imported; no downloaded code is executed.
    check_source(repo, args.expect_revision)
    aws_base = ['aws','--profile',args.profile,'--region','ap-northeast-2']
    def aws(service, operation, *parameters):
        return json.loads(execute(aws_base+[service,operation,*parameters,'--output','json','--no-cli-pager']) or b'{}')
    need(aws('sts','get-caller-identity').get('Account') == args.expect_account, 'Read-only AWS identity is in another account.')
    repository = json.loads(execute(['gh','api','repos/'+args.repository], repo))
    run = json.loads(execute(['gh','api',f'repos/{args.repository}/actions/runs/{args.apply_run_id}/attempts/{args.run_attempt}'], repo))
    relative = ROOT_PATHS[args.root]
    prefix = f"ci-logs/{repository['id']}/{args.apply_run_id}/{args.run_attempt}/{args.expect_revision}/{args.environment}/{relative}/apply/"
    expected = {'repository':args.repository,'repository_id':str(repository['id']),'run_id':args.apply_run_id,'run_attempt':args.run_attempt,'sha':args.expect_revision,'root':f'terraform/environments/{args.environment}/{relative}','environment':args.environment,'account':args.expect_account,'bucket':args.state_bucket,'state_key':relative+'/terraform.tfstate','prefix':prefix}
    def download(key, version, checksum, target):
        result = aws('s3api','get-object','--bucket',args.state_bucket,'--expected-bucket-owner',args.expect_account,'--key',key,'--version-id',version,str(target))
        need(result.get('VersionId') == version and result.get('ServerSideEncryption') in ('AES256','aws:kms','aws:kms:dsse'), 'Private object version/encryption differs.')
        data = target.read_bytes()
        need(sha256(data) == checksum, 'Private object checksum differs.')
        return json.loads(data)
    with tempfile.TemporaryDirectory(prefix='ci-receipt-') as temporary:
        work = Path(temporary)
        completion = download(prefix+'completion.json',args.completion_version,args.completion_sha256,work/'completion.json')
        lineage, serial = check_completion(completion, run, expected)
        current = aws('s3api','head-object','--bucket',args.state_bucket,'--expected-bucket-owner',args.expect_account,'--key',expected['state_key'])
        need(current.get('VersionId') == completion['state']['version'] and current.get('ETag') == completion['state']['etag'], 'State changed after this apply; do not publish a stale receipt.')
        descriptor = completion['outputs']
        outputs = download(descriptor['key'],descriptor['version'],descriptor['sha256'],work/'outputs.json')
        metadata = {'schema_version':1,'environment':args.environment,'account_id':args.expect_account,'region':'ap-northeast-2','root':args.root,'apply_revision':args.expect_revision,'base_revision':args.expect_revision,'state_lineage':lineage,'state_serial':serial}
        check_source(repo, args.expect_revision)
        sys.path.insert(0, str(repo/'automation'))
        registry_module = load_module(repo/'automation/platform_input_registry.py','platform_input_registry')
        validator_module = load_module(repo/'automation/platform_inputs.py','platform_inputs')
        registry = json.loads((repo/'automation/platform-input-mappings.json').read_text())
        entries = registry_module.active_entries(registry,args.root,args.environment)
        receipt = build_receipt(metadata,outputs,entries,validator_module.validate_value)
        from jsonschema import Draft202012Validator, FormatChecker
        Draft202012Validator(json.loads((repo/'schemas/platform-inputs.schema.json').read_text()),format_checker=FormatChecker()).validate(receipt)
        check_source(repo, args.expect_revision)
        final_state = aws('s3api','head-object','--bucket',args.state_bucket,'--expected-bucket-owner',args.expect_account,'--key',expected['state_key'])
        need(final_state.get('VersionId') == completion['state']['version'] and final_state.get('ETag') == completion['state']['etag'], 'State changed while collecting; do not publish a stale receipt.')
        write_new(args.output, receipt)
    print('Verified CI apply receipt collected. No Terraform command or cloud write was executed.')

if __name__ == '__main__':
    try:
        main()
    except ReceiptError as exc:
        print('Receipt collection stopped: '+str(exc), file=sys.stderr)
        sys.exit(2)
    except Exception:
        print('Receipt collection stopped. Check approved source, protected evidence, registry, and local dependencies; do not repeat apply.',file=sys.stderr)
        sys.exit(2)
