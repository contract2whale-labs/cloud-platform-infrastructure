#!/usr/bin/env python3
"""Cumulative Dev later runtime adapter: retained snapshot, exact saved plans, fail closed.

The controller selects a reviewed root and owns bundle approval/checkpoints.
This adapter never edits retained storage or broadens a partial-down identity map.
"""
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ((Path(__file__).parent if (Path(__file__).parent / filename).exists() else Path(__file__).parent.parent / 'ci') / filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

h = load('vpc_saved_plan', 'saved-plan.py')
c = load('vpc_control', 'lifecycle-state.py')
ROOTS = frozenset('terraform/environments/'+env+'/'+suffix for env in ('dev','prod') for suffix in ('data','delivery','platform/queue'))
ENVIRONMENT = 'dev'
ROOT = 'terraform/environments/dev/data'
KEY = 'data/terraform.tfstate'


def configure():
    global ROOT, KEY, ENVIRONMENT
    ENVIRONMENT = os.environ.get('LIFECYCLE_ENVIRONMENT','dev')
    h.require(ENVIRONMENT in ('dev','prod'), 'Unregistered lifecycle environment.')
    ROOT = h.required('ROOT_PATH')
    h.require(ROOT in ROOTS and ROOT.split('/')[2] == ENVIRONMENT, 'Unregistered network lifecycle root.')
    h.require(h.required('LIFECYCLE_ENGINE') == ENVIRONMENT+'-later-runtime-v1', 'Unregistered network lifecycle engine.')
    h.require(re.fullmatch('[0-9a-f]{64}', h.required('LIFECYCLE_CONFIG_SHA256')) is not None, 'Invalid lifecycle registry digest.')
    selected = json.loads(h.required('LIFECYCLE_SELECTED_ROOTS'))
    h.require(isinstance(selected, list) and all(isinstance(item, str) and re.fullmatch(r'terraform/environments/'+ENVIRONMENT+r'/[a-z0-9][a-z0-9/_-]*', item) and '..' not in item.split('/') for item in selected) and len(selected) == len(set(selected)) and ROOT in selected,
              'Invalid selected network lifecycle roots.')
    KEY = '/'.join(ROOT.split('/')[3:]) + '/terraform.tfstate'
    c.ROOT, c.KEY = ROOT, KEY
    h.require(re.fullmatch('[0-9a-f]{40}', h.required('LIFECYCLE_SNAPSHOT_SHA')) is not None and re.fullmatch('[0-9]+-[0-9]+', h.required('LIFECYCLE_GENERATION')) is not None, 'Invalid retained course session.')
    return selected


def marker_key(repository_id):
    h.require(str(repository_id).isdigit(), 'Invalid repository ID.')
    return f"ci-lifecycle/{repository_id}/{ENVIRONMENT}/{'-'.join(ROOT.split('/')[3:])}.json"


def guard_module():
    return load('cumulative_network_guard', 'runtime-lifecycle-guard.py')



def environment():
    h.refresh_profile_guard()
    h.require(os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Later runtime lifecycle must run from main.')
    h.require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Later runtime lifecycle requires workflow_dispatch.')
    h.require(os.environ.get('OPERATION') in ('down', 'up'), 'Only down/up is supported.')
    h.require(not any(k.startswith('TF_VAR_') or k.startswith('TF_CLI_ARGS') or k in ('TF_DATA_DIR', 'TF_WORKSPACE', 'TF_REATTACH_PROVIDERS', 'TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE', 'TF_LOG', 'TF_LOG_PATH') for k in os.environ), 'Inherited Terraform overrides are forbidden.')
    workspace = Path(h.required('GITHUB_WORKSPACE')).resolve()
    sha = h.required('GITHUB_SHA')
    h.require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'Invalid workflow SHA.')
    h.require(h.execute(['git', 'rev-parse', 'HEAD'], cwd=workspace).decode().strip() == sha, 'Current helper checkout mismatch.')
    h.ensure_current_main({'sha': sha})
    repo, account, bucket, region = (h.required(x) for x in ('GITHUB_REPOSITORY_ID', 'EXPECTED_ACCOUNT_ID', 'STATE_BUCKET', 'AWS_REGION'))
    h.require(repo.isdigit() and region == 'ap-northeast-2', 'Only the configured Seoul Dev network is supported.')
    h.check_identity(account, h.required('AWS_ROLE_ARN'))
    store = h.Store(bucket, account); store.check()
    check_retention(store, marker_key(repo))
    return workspace, store, {'repository_id': repo, 'account': account, 'bucket': bucket, 'region': region}


def check_retention(store, key):
    # ci-plans/ci-logs의 짧은 보존기간이 pause/snapshot을 지우지 않아야 합니다.
    rules = store.call('get-bucket-lifecycle-configuration').get('Rules')
    h.require(isinstance(rules, list), 'Bucket lifecycle retention could not be verified.')
    for rule in rules:
        if rule.get('Status') != 'Enabled' or not any(x in rule for x in ('Expiration', 'NoncurrentVersionExpiration')):
            continue
        condition = rule.get('Filter', {})
        prefix = condition.get('Prefix', condition.get('And', {}).get('Prefix', rule.get('Prefix', '')))
        h.require(isinstance(prefix, str) and not key.startswith(prefix), 'An expiration rule may remove the lifecycle marker/snapshot; administrator correction is required.')


def initial_state(target):
    guard = guard_module()
    item = guard.VersionedStateReader(target['bucket'], target['account'], target['region'])(KEY)
    return item['state'], item['fingerprint']


def current_inputs():
    value = json.loads(h.required('TF_VARS_JSON'))
    h.require(isinstance(value, dict) and isinstance(value.get('/'.join(ROOT.split('/')[3:])), dict), 'Protected network root inputs are required.')
    return value['/'.join(ROOT.split('/')[3:])]


def assert_snapshot_current(workspace, record):
    """현재 helper는 허용하되 재개 직후 다른 인프라가 배포되는 혼선을 막습니다."""
    sha = record['snapshot_sha']
    h.execute(['git', 'merge-base', '--is-ancestor', sha, h.required('GITHUB_SHA')], cwd=workspace)
    h.execute(['git', 'diff', '--quiet', sha, h.required('GITHUB_SHA'), '--', 'terraform', 'modules'], cwd=workspace)


def validate_state_identity(state, record):
    h.require(state.get('version') == 4 and isinstance(state.get('lineage'), str) and type(state.get('serial')) is int,
              'Network State identity is missing.')
    original = record.get('original_state_identity')
    h.require(isinstance(original, dict) and state['lineage'] == original.get('lineage') and state['serial'] >= original.get('serial', -1),
              'Network State lineage changed or serial rolled back; separate recovery is required.')


def checked_record(store, target):
    record, info = c.read_json(store, marker_key(target['repository_id']))
    h.require(record is not None, 'Lifecycle control is missing; do not infer a completed down.')
    c.validate(record, **target)
    h.require(isinstance(record.get('original_resources'), list) and isinstance(record.get('original_state_identity'), dict), 'Original network State identity is missing; separate reviewed recovery is required.')
    h.require(record['snapshot_sha'] == h.required('LIFECYCLE_SNAPSHOT_SHA') and record['generation'] == h.required('LIFECYCLE_GENERATION'), 'Per-root snapshot differs from the retained course session.')
    h.require(record['phase'] == 'paused', 'Network root is not lifecycle-paused.')
    h.require(record.get('request_run') == h.required('GITHUB_RUN_ID') and record.get('request_attempt') == h.required('GITHUB_RUN_ATTEMPT')
              and record.get('operation') == h.required('OPERATION') and record.get('workflow_sha') == h.required('GITHUB_SHA'), 'Lifecycle request ownership changed; start a new run.')
    h.require(h.canonical(current_inputs()) == h.canonical(record['inputs']), 'Protected inputs changed from the retained snapshot; restore the approved input before retry.')
    h.require(h.canonical(record.get('lifecycle_contract')) == h.canonical(json.loads(h.required('LIFECYCLE_LATER_CONTRACT'))), 'Lifecycle data decision changed.')
    return record, info


def settings():
    h.require(h.required('GITHUB_REF') == 'refs/heads/main', 'Lifecycle must be dispatched on main.')
    name = 'infra-'+ENVIRONMENT+('-destroy' if os.environ.get('OPERATION')=='down' else '-apply')
    endpoint = 'repos/' + h.required('GITHUB_REPOSITORY') + '/environments/' + name
    value = json.loads(h.execute(['gh', 'api', endpoint]))
    reviews = [r for r in value.get('protection_rules', []) if r.get('type') == 'required_reviewers']
    h.require(any(r.get('reviewers') for r in reviews), 'Destroy review Environment must have required reviewers.')
    h.require(value.get('can_admins_bypass') is False, 'Disable administrator bypass for destroy review.')
    policy = value.get('deployment_branch_policy') or {}
    h.require(policy.get('custom_branch_policies') is True, 'Destroy review must restrict deployment to main.')
    branches = json.loads(h.execute(['gh', 'api', endpoint + '/deployment-branch-policies?per_page=100']))
    rows = branches.get('branch_policies', [])
    h.require(branches.get('total_count') == 1 and len(rows) == 1 and rows[0].get('name') == 'main' and rows[0].get('type', 'branch') == 'branch', 'Destroy review must allow only the main branch.')
    print('Required destroy review and main-only protection verified. Self-review follows the documented one-person lab choice.')


def start():
    configure()
    workspace, store, target = environment()
    operation = h.required('OPERATION'); key = marker_key(target['repository_id'])
    record, previous = c.read_json(store, key)
    if record is not None:
        c.validate(record, **target)
    if record is None or record['phase'] == 'active':
        h.require(operation == 'down', 'No paused network snapshot exists for up.')
        lock = workspace / ROOT / '.terraform.lock.hcl'
        h.require(lock.is_file(), 'The committed network provider lock is required.')
        h.execute(['git', 'ls-files', '--error-unmatch', ROOT + '/.terraform.lock.hcl'], cwd=workspace)
        record = dict(schema=1, root=ROOT, phase='paused', **target,
                      generation=h.required('LIFECYCLE_GENERATION'),
                      snapshot_sha=h.required('LIFECYCLE_SNAPSHOT_SHA'), lock_sha256=h.digest(lock.read_bytes()), inputs=current_inputs(),
                      original_resources=None, lifecycle_contract=json.loads(h.required('LIFECYCLE_LATER_CONTRACT')), last_result='not-applied')
    else:
        assert_snapshot_current(workspace, record)
        h.require(h.canonical(record['inputs']) == h.canonical(current_inputs()), 'Retry/up must retain the original protected network inputs.')
    h.require(record['snapshot_sha'] == h.required('LIFECYCLE_SNAPSHOT_SHA') and record['generation'] == h.required('LIFECYCLE_GENERATION'), 'Per-root snapshot differs from the retained course session; separate recovery is required.')
    h.require(h.canonical(record['lifecycle_contract']) == h.canonical(json.loads(h.required('LIFECYCLE_LATER_CONTRACT'))), 'Lifecycle data decision/provenance changed from original checkpoint.')
    guard_module().validate_contract(record['lifecycle_contract'], ROOT)
    record.update(phase='paused', operation=operation, request_run=h.required('GITHUB_RUN_ID'),
                  request_attempt=h.required('GITHUB_RUN_ATTEMPT'), workflow_sha=h.required('GITHUB_SHA'))
    # 검사·승인·취소·부분 실패 중에도 이 guard는 자동으로 해제하지 않습니다.
    info = c.update(store, key, record, previous)
    if record.get('original_resources') is None:
        state, original_state = initial_state(target)
        h.require(state is not None, 'An exact existing network State is required; pause remains set.')
        guard = guard_module()
        guard.validate_contract_state(record['lifecycle_contract'], ROOT, state)
        record['original_state_fingerprint'] = original_state
        record['original_state_identity'] = {'lineage': state['lineage'], 'serial': state['serial']}
        record['original_resources'] = guard.normalize_resources(state)
        h.require(bool(record['original_resources']), 'An existing managed network snapshot is required; pause remains set.')
        c.update(store, key, record, info)
    h.emit({'snapshot_sha': record['snapshot_sha']})
    print('Network pause is persistent. Plan/approval failure does not re-enable ordinary deployment.')


def payload(workspace, directory, record, target):
    sha = record['snapshot_sha']; h.require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'Invalid retained source SHA.')
    assert_snapshot_current(workspace, record)
    # 옛 CI 코드/워크플로는 실행하지 않습니다. 승인된 Terraform 소스만 추출합니다.
    trees = h.execute(['git', 'ls-tree', '-d', '--name-only', sha, '--', 'terraform', 'modules'], cwd=workspace).decode().splitlines()
    h.require('terraform' in trees and set(trees) <= {'terraform', 'modules'}, 'Retained Terraform source tree is missing.')
    archive = h.execute(['git', 'archive', sha, '--', *trees], cwd=workspace)
    base = directory / 'payload'; base.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as stream:
        stream.extractall(base, filter='data')
    for candidate in base.rglob('*'):
        h.require(not candidate.is_symlink(), 'Terraform payload symlinks are not supported.')
        h.require('.terraform' not in candidate.parts and not candidate.name.endswith(('.tfstate', '.tfstate.backup', '.tfplan')), 'Terraform cache/State/plan files must not be committed.')
    root = base / ROOT
    h.require(root.is_dir() and root.resolve().is_relative_to(base.resolve()), 'Network payload is outside its source tree.')
    h.require(not (root / 'terraform.tfvars').exists() and not (root / 'terraform.tfvars.json').exists(), 'Committed private input files are forbidden.')
    lock = root / '.terraform.lock.hcl'
    h.require(lock.is_file() and h.digest(lock.read_bytes()) == record['lock_sha256'], 'Retained provider lock mismatch.')
    (root / 'terraform.tfvars.json').write_bytes(h.canonical(record['inputs']))
    backend = {'bucket': target['bucket'], 'key': KEY, 'region': target['region'], 'encrypt': True,
               'use_lockfile': True, 'allowed_account_ids': [target['account']]}
    backend_file = directory / 'backend.hcl'
    backend_file.write_text('\n'.join(f'{k} = {json.dumps(v)}' for k, v in backend.items()) + '\n')
    h.require(json.loads(h.execute(['terraform', 'version', '-json']))['terraform_version'] == '1.16.0', 'Terraform 1.16.0 is required.')
    context = dict(repository=h.required('GITHUB_REPOSITORY'), repository_id=target['repository_id'],
                   run_id=h.required('GITHUB_RUN_ID'), run_attempt=h.required('GITHUB_RUN_ATTEMPT'), sha=h.required('GITHUB_SHA'),
                   source_sha=sha, root=ROOT, environment=ENVIRONMENT, account=target['account'], backend=backend, workspace='default',
                   terraform_version='1.16.0', lock_sha256=record['lock_sha256'], input_sha256=h.digest(h.canonical(record['inputs'])),
                   tracked_auto_inputs={p.name: h.digest(p.read_bytes()) for p in sorted(root.iterdir()) if p.name.endswith(('.auto.tfvars', '.auto.tfvars.json'))},
                   apply_role_arn=os.environ.get('EXPECTED_APPLY_ROLE_ARN') or h.required('AWS_ROLE_ARN'), operation=h.required('OPERATION'), generation=record['generation'])
    if os.environ.get('LIFECYCLE_CONFIG_SHA256'):
        context['lifecycle_registry_sha256'] = os.environ['LIFECYCLE_CONFIG_SHA256']
        context['lifecycle_engine'] = h.required('LIFECYCLE_ENGINE')
        context['contract_sha256'] = h.digest(h.canonical(record['lifecycle_contract']))
        context['selected_roots'] = json.loads(h.required('LIFECYCLE_SELECTED_ROOTS'))
    namespace = 'ci-up-plans' if context['operation'] == 'up' else 'ci-plans'
    context['prefix'] = f"{namespace}/{target['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{ENVIRONMENT}/{'/'.join(ROOT.split('/')[3:])}/lifecycle-{context['operation']}/"
    return root, backend_file, context


def validate_supported_plan(plan, guard):
    h.require(isinstance(plan, dict) and str(plan.get('format_version', '')).split('.')[0] == '1' and
              plan.get('errored', False) is False and plan.get('complete', True) is True and not plan.get('deferred_changes'),
              'The network plan is incomplete, deferred or unsupported.')
    def values(module):
        for item in module.get('resources', []):
            if item.get('mode') != 'data':
                h.require(item.get('type') in guard.allowed_types(ROOT), 'Evaluated source contains unsupported managed resources.')
        for child in module.get('child_modules', []): values(child)
    values(plan.get('planned_values', {}).get('root_module', {}))
    for item in plan.get('resource_changes', []):
        if item.get('mode') != 'data':
            h.require(item.get('type') in guard.allowed_types(ROOT), 'Evaluated source contains unsupported managed resources.')


def validate_up(plan, guard):
    validate_supported_plan(plan, guard)
    # 이 첫 재개 기능은 삭제/교체를 하지 않습니다. 일반 main 배포 정책에는 영향을 주지 않습니다.
    allowed = guard.allowed_types(ROOT)
    for item in plan.get('resource_changes', []):
        if item.get('mode') == 'data':
            continue
        h.require(item.get('type') in allowed, 'Up plan contains unsupported managed resources.')
        h.require(item.get('change', {}).get('actions') in (['no-op'], ['create'], ['update']), 'Network Up accepts creation/update only; deletion, replacement, forgetting or unknown actions require separate review.')



def validate_up_completion(plan, state, guard):
    expected = {}
    def visit(module):
        for row in module.get('resources', []):
            if row.get('mode') == 'managed':
                address = row.get('address')
                h.require(isinstance(address, str) and address not in expected, 'Up plan has an ambiguous resource address.')
                expected[address] = row.get('type')
        for child in module.get('child_modules', []): visit(child)
    visit(plan.get('planned_values', {}).get('root_module', {}))
    actual = {row['address']: row['type'] for row in guard.managed_resources(state)}
    h.require(bool(expected) and actual == expected, 'Up State differs from the complete approved plan; pause remains set.')

def run(stage):
    configure()
    if stage == 'settings':
        return settings()
    if stage == 'start':
        return start()
    h.require(stage in ('plan', 'verify', 'apply'), 'Unknown lifecycle stage.')
    workspace, store, target = environment(); record, control = checked_record(store, target)
    guard = guard_module()
    with tempfile.TemporaryDirectory(prefix='later-runtime-lifecycle-') as directory:
        temp = Path(directory); context = None
        try:
            root, backend, context = payload(workspace, temp, record, target)
            guard.bind(context, record['lifecycle_contract'], record['original_resources'])
            h.initialize(root, backend, temp, stage)
            state = store.state(KEY)
            raw_state = json.loads(h.execute(['terraform', 'state', 'pull'], cwd=root) or b'{}')
            h.require(state.get('exists') and state.get('version') not in (None, '', 'null'), 'An exact versioned network State is required.')
            validate_state_identity(raw_state, record)
            upstream = guard.read_upstreams(workspace, context)
            upstream_fingerprints = {key: value['fingerprint'] for key, value in upstream.items()}
            plan_path = temp / 'change.tfplan'
            if stage == 'plan':
                if context['operation'] == 'down':
                    # destroy가 무시하는 미적용 확장도 먼저 평가하여 복구 불가능한 snapshot을 막습니다.
                    scope_path = temp / 'source-scope.tfplan'
                    h.execute(['terraform', 'plan', '-input=false', '-no-color', '-lock-timeout=5m', f'-out={scope_path}'], cwd=root, log=temp/'source-scope.log')
                    scope_plan = json.loads(h.execute(['terraform', 'show', '-json', str(scope_path)], cwd=root))
                    h.validate_effective_inputs(scope_plan, context)
                    validate_supported_plan(scope_plan, guard)
                    guard.validate_plan_contracts(context, scope_plan, upstream)
                command = ['terraform', 'plan', '-input=false', '-no-color', '-lock-timeout=5m', f'-out={plan_path}']
                if context['operation'] == 'down': command.append('-destroy')
                h.execute(command, cwd=root, log=temp / 'plan.log')
                plan = json.loads(h.execute(['terraform', 'show', '-json', str(plan_path)], cwd=root))
                h.validate_effective_inputs(plan, context)
                if context['operation'] == 'down':
                    evidence = guard.guard_destroy(workspace, context, raw_state, plan, expected_resources=record['original_resources'], upstream_states=upstream, stage='plan')
                else:
                    guard.validate_state(context, raw_state, expected_resources=None, upstream_states=upstream)
                    validate_up(plan, guard); guard.validate_plan_contracts(context, plan, upstream); evidence = {'mode': 'creation-update-only'}
                h.require(store.state(KEY) == state and guard.upstream_fingerprints(workspace, context) == upstream_fingerprints, 'Network State or upstream changed during plan.')
                latest, latest_info = checked_record(store, target)
                h.require(latest_info == control and latest == record, 'Lifecycle control changed during plan.')
                h.ensure_current_main(context)
                review = temp / 'review.txt'; review.write_bytes(h.canonical({'context': context, 'guard_evidence': evidence, 'lifecycle_contract': record['lifecycle_contract']}) + b'\n' + h.execute(['terraform', 'show', '-no-color', str(plan_path)], cwd=root))
                now = int(dt.datetime.now(dt.timezone.utc).timestamp())
                manifest = dict(schema=1, kind='later-runtime-lifecycle', context=context, state=state, control=control,
                                created_at=now, expires_at=now+h.TTL_SECONDS, evidence=evidence, upstream_states=upstream_fingerprints,
                                plan=store.put(context['prefix']+'change.tfplan', plan_path), review=store.put(context['prefix']+'review.txt', review),
                                counts={a: sum(a in r.get('change', {}).get('actions', []) for r in plan.get('resource_changes', [])) for a in ('create','update','delete')})
                mp=temp/'manifest.json'; mp.write_bytes(h.canonical(manifest)); descriptor=store.put(context['prefix']+'manifest.json', mp)
                h.emit(dict(manifest_key=descriptor['key'], manifest_version=descriptor['version'], manifest_sha=descriptor['sha256'], plan_sha=manifest['plan']['sha256']))
                # 공통 다운로드 명령을 쓰되 Dev 일반 자동 적용 문구는 붙이지 않습니다.
                h.publish_summary(context, {**manifest, 'kind': 'later-runtime-lifecycle'}, descriptor)
                with open(h.required('GITHUB_STEP_SUMMARY'),'a') as out:
                    out.write('\nLive consumer inventory is deferred until immediately before this root apply. No unknown resource will be deleted.\n' if evidence.get('deferred_runtime_consumer_check') else '')
                    out.write('\nLater runtime lifecycle: down은 infra-dev-destroy의 필수 승인 뒤 동일 plan을 적용합니다. up은 보존한 소스/입력으로 만든 새 plan입니다.\n')
                return
            descriptor={'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('EXPECTED_MANIFEST_SHA')}
            h.require(descriptor['key']==context['prefix']+'manifest.json', 'Lifecycle manifest belongs to another run.')
            mp=temp/'manifest.json';store.get(descriptor,mp);manifest=json.loads(mp.read_bytes())
            h.require(manifest.get('schema')==1 and manifest.get('kind')=='later-runtime-lifecycle' and manifest.get('context')==context, 'Lifecycle manifest context mismatch.')
            now=int(dt.datetime.now(dt.timezone.utc).timestamp())
            h.require(manifest['created_at']<=now<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==h.TTL_SECONDS, 'Lifecycle plan expired; start a new run.')
            h.require(manifest['control']==control and manifest['state']==state and manifest.get('upstream_states')==upstream_fingerprints, 'Lifecycle control or Network State changed; create a fresh plan.')
            h.require(manifest['plan']['key']==context['prefix']+'change.tfplan' and manifest['plan']['sha256']==h.required('EXPECTED_PLAN_SHA'), 'Lifecycle saved plan mismatch.')
            store.get(manifest['plan'],plan_path)
            plan=json.loads(h.execute(['terraform','show','-json',str(plan_path)],cwd=root))
            h.validate_effective_inputs(plan,context)
            if context['operation']=='down':
                current_evidence = guard.guard_destroy(workspace,context,raw_state,plan,expected_resources=record['original_resources'],upstream_states=upstream,stage='plan' if stage == 'verify' else 'apply')
                if stage == 'verify':
                    h.require(current_evidence.get('deferred_consumers') == manifest.get('evidence', {}).get('deferred_consumers'), 'Selected consumer descriptors changed from this root plan; create a fresh bundle.')
            else:
                guard.validate_state(context, raw_state, expected_resources=None, upstream_states=upstream)
                validate_up(plan,guard); guard.validate_plan_contracts(context,plan,upstream)
                if stage == 'apply': current_evidence = guard.require_barriers(context)
            latest,latest_info=checked_record(store,target)
            h.require(latest==record and latest_info==control and store.state(KEY)==state and guard.upstream_fingerprints(workspace,context)==upstream_fingerprints,'A lifecycle precondition changed before apply.')
            h.ensure_current_main(context)
            if stage == 'verify':
                print('Exact saved network plan verified without applying or changing lifecycle control.')
                return
            # 실제 apply 시작을 먼저 기록합니다. 오류/로그 실패를 '미실행'으로 오해하지 않습니다.
            record.update(last_result=context['operation']+'_applying', applying_plan_sha=manifest['plan']['sha256'])
            control=c.update(store,marker_key(target['repository_id']),record,control)
            h.execute(['terraform','apply','-input=false','-no-color','-lock-timeout=5m',str(plan_path)],cwd=root,log=temp/'apply.log')
            # 성공한 변경의 receipt가 실패해도 이전 plan을 다시 적용하지 않습니다.
            after=json.loads(h.execute(['terraform','state','pull'],cwd=root) or b'{}')
            validate_state_identity(after, record)
            managed=[r for r in after.get('resources',[]) if r.get('mode')=='managed' and r.get('instances')]
            if context['operation']=='down':
                h.require(not managed,'Down apply finished with managed resources remaining; keep pause and investigate.')
                completion_evidence = guard.verify_absent(context, record['original_resources'])
            else:
                h.require(bool(managed),'Up did not restore managed network infrastructure; keep pause.')
                guard.validate_state(context, after, upstream_states=upstream)
                validate_up_completion(plan, after, guard)
                completion_evidence = guard.verify_present(context, after)
            outputs=temp/'outputs.json';outputs.write_bytes(h.execute(['terraform','output','-json'],cwd=root))
            receipt={'schema':1,'kind':'later-runtime-lifecycle-completion','context':context,'plan_sha':manifest['plan']['sha256'],
                     'state':store.state(KEY),'service_evidence':completion_evidence,'preapply_evidence':current_evidence,'completed_at':int(dt.datetime.now(dt.timezone.utc).timestamp())}
            prefix=context['prefix'].replace('ci-up-plans/','ci-logs/',1).replace('ci-plans/','ci-logs/',1)+'apply/'
            receipt['outputs']=store.put(prefix+'outputs.json',outputs)
            rp=temp/'completion.json';rp.write_bytes(h.canonical(receipt));receipt_descriptor=store.put(prefix+'completion.json',rp)
            record.update(last_result=context['operation']+'_complete',completion=receipt_descriptor,
                          phase='active' if context['operation']=='up' else 'paused')
            c.update(store,marker_key(target['repository_id']),record,control)
            with open(h.required('GITHUB_STEP_SUMMARY'), 'a') as out:
                out.write('\n### Later runtime lifecycle completion\n')
                out.write(f"operation: {context['operation']} / phase: {record['phase']}\n\n")
                out.write(f"completion key: `{receipt_descriptor['key']}`\n\nVersionId: `{receipt_descriptor['version']}`\n\nSHA-256: `{receipt_descriptor['sha256']}`\n")
            print('Later runtime lifecycle completed. Down stays paused; only successful up clears the pause.')
        except Exception as error:
            (temp / 'failure.log').write_text(type(error).__name__ + ': ' + str(error))
            raise
        finally:
            if context and stage != 'verify':
                for path in temp.glob('*.log'):
                    try:
                        log_stage = 'apply' if context['operation'] == 'up' else stage
                        log_name = ('up-' + stage + '-' if context['operation'] == 'up' else '') + path.name
                        store.put(context['prefix'].replace('ci-up-plans/','ci-logs/',1).replace('ci-plans/','ci-logs/',1)+log_stage+'/'+log_name,path)
                    except Exception: print('Private diagnostic upload failed; no raw output was published.')

if __name__=='__main__':
    os.umask(0o077)
    try:
        h.require(len(sys.argv)==2,'Expected start, plan, verify or apply.');run(sys.argv[1])
    except h.SafeError as error:
        print('::error::' + str(error))
        sys.exit(1)
    except Exception:
        # 비밀 입력/State/서비스 응답과 예외 원문은 공개 로그에 남기지 않습니다.
        print('::error::Later runtime lifecycle stopped. Pause may remain set. Inspect private evidence; use a fresh run, never replay the old plan.')
        sys.exit(1)
