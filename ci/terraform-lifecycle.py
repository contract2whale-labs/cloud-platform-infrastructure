#!/usr/bin/env python3
"""Cumulative course lifecycle. One workflow; reviewed, static adapters only.

Down: one private saved-plan bundle, one real Environment approval, reverse DAG.
Up: a fresh plan and identical apply per root, forward DAG, Dev automatic policy.
The map describes the whole course; missing adapters/hooks block before AWS access.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = load('course_saved_plan', 'saved-plan.py')
c = load('course_control', 'lifecycle-state.py')
b = load('course_barriers', 'lifecycle-barriers.py')
o = load('course_obligations', 'lifecycle-obligations.py')
SelectionError = h.SafeError
# Adding a JSON row does not enable execution. Each adapter needs a reviewed
# implementation, resource-retention guard and integration tests here as well.
ENGINES = {
    'dev-vpc-v1': {'module': 'vpc-lifecycle.py', 'roots': (c.ROOT,)},
    'prod-network-v2': {'module':'network-lifecycle.py','roots':('terraform/environments/prod/network/vpc',)},
    'dev-network-v2': {'module': 'network-lifecycle.py', 'roots': tuple('terraform/environments/dev/network/' + name for name in ('vpc', 'peer', 'transit'))},

}
# Hook wrappers are registered here only after their bounded action/ownership
# tests pass; registry text alone cannot supply executable code.
HOOK_ENGINES = {
    environment+'-gitops-v1': {'module':'gitops/gitops-lifecycle.py',
        'hooks':tuple(step.removeprefix('hook:') for step in sorted(b.BASIC_HOOKS)),
        'owner_root':'terraform/environments/'+environment+'/eks'}
    for environment in ('dev','prod')
}
HOOK_ENGINES.update({
    environment+'-application-v1': {'module':'gitops/application-lifecycle.py',
        'hooks':tuple(step.removeprefix('hook:') for step in sorted(b.APPLICATION_HOOKS)),
        'owner_root':'terraform/environments/'+environment+'/eks'}
    for environment in ('dev','prod')
})
ENGINES.update({environment+'-later-runtime-v1': {
    'module':'runtime-lifecycle.py','contract_env':'LIFECYCLE_LATER_CONTRACT','derive_completion_sha256':True,
    'roots':tuple('terraform/environments/'+environment+'/'+suffix for suffix in ('data','delivery','platform/queue'))}
    for environment in ('dev','prod')})
HOOK_ENGINES.update({environment+'-network-probes-v1': {
    'module':'eks-probe-lifecycle.py','hooks':('node-network-probes','cluster-private-api-check'),
    'owner_root':'terraform/environments/'+environment+'/eks'} for environment in ('dev','prod')})
ENGINES.update({environment+'-eks-v1': {'module':'eks-lifecycle.py',
    'roots':tuple('terraform/environments/'+environment+'/'+suffix for suffix in ('platform/private-api','eks')),
    'integrated_hooks':{name:('terraform/environments/'+environment+'/eks',) for name in ('cluster-owned-external-inventory','node-addon-readiness')}}
    for environment in ('dev','prod')})
REGISTERED_SUFFIXES={
    'dev':('account-integrations','identity','platform/alerting','platform/core','platform/dev-app-access','platform/edge','platform/gateway','platform/observability','platform/operations','platform/queue-association','platform/queue-secrets'),
    'prod':('identity','platform/alerting','platform/core','platform/edge','platform/gateway','platform/observability','platform/operations','platform/queue-association','platform/queue-secrets')}
ENGINES.update({environment+'-registered-root-v1': {'module':'registered-root-lifecycle.py',
    'roots':tuple('terraform/environments/'+environment+'/'+suffix for suffix in suffixes)}
    for environment,suffixes in REGISTERED_SUFFIXES.items()})
ENGINES['dev-registered-root-v1']['integrated_hooks']={'dev-app-sessions-closed':('terraform/environments/dev/platform/dev-app-access',)}
ENGINES['prod-registered-root-v1']['integrated_hooks']={'prod-edge-publication':('terraform/environments/prod/platform/edge',)}
HOOK_ENGINES.update({environment+'-semantic-v1': {'module':'lifecycle-obligations.py',
    'hooks':tuple(step.removeprefix('hook:') for step in sorted(o.HOOKS)),
    'owner_root':'terraform/environments/'+environment+'/eks'} for environment in ('dev','prod')})
HOOK_ENGINES.update({environment+'-velero-v1': {'module':'velero-lifecycle.py','hooks':('velero-backup-restore',),'owner_root':'terraform/environments/'+environment+'/eks'} for environment in ('dev','prod')})
MAX_UP_LEVELS = 24
STAGES = {'inspect', 'select', 'settings', 'preview', 'start', 'plan', 'apply', 'up', 'up-plan', 'up-apply', 'prepare', 'destroy-apply'}
ENVIRONMENTS = {'plan_environment': 'infra-dev-plan',
                'apply_environment': 'infra-dev-apply',
                'destroy_environment': 'infra-dev-destroy'}


def require(value, message):
    h.require(value, message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate lifecycle registry keys are forbidden.')
        result[key] = value
    return result


def read_registry():
    environment = os.environ.get('LIFECYCLE_ENVIRONMENT', 'dev')
    require(environment in ('dev', 'prod'), 'Unknown lifecycle environment.')
    name = 'lifecycle-targets.json' if environment == 'dev' else 'lifecycle-targets-prod.json'
    return json.loads((HERE / name).read_text(), object_pairs_hook=unique_object)


def validate_registry(registry):
    require(isinstance(registry, dict) and set(registry) == {'schema', 'chapter_order', 'chapters', 'roots', 'hooks'}, 'Invalid chapter registry schema.')
    require(type(registry['schema']) is int and registry['schema'] == 2, 'Unsupported chapter registry version.')
    order, chapters, roots, hooks = (registry[key] for key in ('chapter_order', 'chapters', 'roots', 'hooks'))
    require(isinstance(order, list) and order and len(order) == len(set(order)) and all(isinstance(x, str) and re.fullmatch(r'BU\d\d[ABC]?', x) for x in order), 'Invalid chapter order.')
    require(isinstance(chapters, dict) and set(chapters) == set(order) and isinstance(roots, dict) and isinstance(hooks, dict), 'Incomplete chapter registry.')
    for root, row in roots.items():
        require(isinstance(root, str) and re.fullmatch(r'terraform/environments/(?:dev|prod)/[a-z0-9][a-z0-9/_-]*', root) and '..' not in root.split('/'), 'Unknown lifecycle root/environment.')
        require(isinstance(row, dict) and set(row) == {'mode', 'engine', 'dependencies', 'reason'}, 'Invalid root support contract.')
        require(row['mode'] in ('retain', 'adapter', 'blocked') and isinstance(row['reason'], str), 'Invalid root retention policy.')
        require(isinstance(row['dependencies'], list) and len(row['dependencies']) == len(set(row['dependencies'])) and all(dep in roots and dep != root for dep in row['dependencies']), 'Unknown or duplicate root dependency.')
        if row['mode'] == 'adapter':
            require(row['engine'] in ENGINES and root in ENGINES[row['engine']]['roots'], 'Registry cannot enable an unimplemented engine or redirect it to another root.')
        else:
            require(row['engine'] is None, 'Retained or blocked roots cannot select an engine.')
    for hook, row in hooks.items():
        require(re.fullmatch('[a-z][a-z0-9-]*', hook) and isinstance(row, dict) and isinstance(row.get('reason'), str), 'Invalid lifecycle hook declaration.')
        if row.get('status') == 'blocked':
            require(set(row) == {'status', 'reason'}, 'Blocked hooks cannot contain executable commands.')
            continue
        if row.get('status') == 'alias':
            require(set(row)=={'status','reason','provider_hooks','retained_roots'} and hook in o.ALIASES and
                    row['provider_hooks']==o.ALIASES[hook]['provider_hooks'] and row['retained_roots']==o.ALIASES[hook]['retained_roots'],
                    'Alias must match its reviewed concrete capability provider.')
            continue
        if row.get('status') == 'integrated':
            require(set(row) == {'status', 'reason', 'engine', 'roots'} and row.get('engine') in ENGINES and
                    row.get('roots') == list(ENGINES[row['engine']].get('integrated_hooks', {}).get(hook, ())) and row['roots'] and
                    all(root in roots and roots[root]['mode'] == 'adapter' and roots[root]['engine'] == row['engine'] for root in row['roots']),
                    'An integrated check requires its reviewed selected execution adapter.')
            continue
        require(set(row) == {'status', 'reason', 'engine', 'dependencies', 'required_by'} and row.get('status') == 'adapter' and row.get('engine') in HOOK_ENGINES, 'Executable hooks require a reviewed implementation; a registry command is not executable.')
        require(hook in HOOK_ENGINES[row['engine']]['hooks'], 'Hook is outside its static implementation contract.')
        known = set(roots) | {'hook:' + name for name in hooks}
        for field in ('dependencies', 'required_by'):
            require(isinstance(row[field], list) and len(row[field]) == len(set(row[field])) and all(value in known and value != 'hook:' + hook for value in row[field]), 'Unknown, self-referencing or duplicated hook dependency.')
    for chapter, row in chapters.items():
        require(isinstance(row, dict) and set(row) == {'roots', 'hooks', 'blockers'}, 'Invalid chapter definition.')
        for key, allowed in (('roots', roots), ('hooks', hooks)):
            require(isinstance(row[key], list) and all(name in allowed for name in row[key]), 'Chapter refers to an unknown root or hook.')
        require(isinstance(row['blockers'], list) and all(isinstance(x, str) and x for x in row['blockers']), 'Invalid chapter blockers.')
    require(len({root.split('/')[2] for root in roots}) == 1, 'Mixed-account registries are forbidden.')
    topological(roots, roots)


def topological(selected, roots):
    """Stable dependency order; each shared root occurs exactly once."""
    selected = set(selected)
    require(selected <= set(roots), 'Unknown selected root.')
    result, visiting, visited = [], set(), set()
    def visit(root):
        require(root not in visiting, 'Lifecycle root dependency cycle.')
        if root in visited:
            return
        visiting.add(root)
        for dependency in sorted(roots[root]['dependencies']):
            require(dependency in roots, 'Unknown root dependency.')
            if dependency in selected:
                visit(dependency)
        visiting.remove(root)
        visited.add(root)
        result.append(root)
    preferred = {f'terraform/environments/dev/network/{name}': index for index, name in enumerate(('vpc', 'peer', 'transit'))}
    for root in sorted(selected, key=lambda value: (preferred.get(value, 3), value)):
        visit(root)
    return result


def execution_graph(root_order, hooks, registry):
    """Compose reviewed hook edges with the real root DAG; no kind-based waves."""
    graph = {root: {'dependencies': list(registry['roots'][root]['dependencies'])} for root in root_order}
    for hook in sorted(hooks):
        row = registry['hooks'][hook]
        if row['status'] != 'adapter':
            continue
        step = 'hook:' + hook
        graph[step] = {'dependencies': list(row['dependencies'])}
    for hook in sorted(hooks):
        row = registry['hooks'][hook]
        if row['status'] != 'adapter':
            continue
        step = 'hook:' + hook
        require(all(dependency in graph for dependency in row['dependencies']), 'Selected hook requires a step outside this completed chapter.')
        for dependent in row['required_by']:
            # A later chapter consumer is not selected yet; it adds its edge when
            # that chapter is actually in scope, never an early create/delete.
            if dependent in graph:
                graph[dependent]['dependencies'].append(step)
    return graph


def resolve(operation, environment, chapter, registry, *, executable=True):
    require(operation in ('down', 'up'), 'Unsupported operation; choose down or up.')
    require(environment in ('dev', 'prod'), 'Unknown lifecycle environment; no AWS access was attempted.')
    validate_registry(registry)
    require(chapter in registry['chapters'], 'Unknown completed chapter; no AWS access was attempted.')
    require(all(root.split('/')[2] == environment for root in registry['roots']), 'Registry environment mismatch.')
    registry_sha256=h.digest(h.canonical(registry))
    # BU02 source predates the BU03 retained log producer. This is the one
    # reviewed chapter-specific edge, not inference from directory existence.
    if environment=='dev' and registry['chapter_order'].index(chapter)<registry['chapter_order'].index('BU03'):
        registry=copy.deepcopy(registry)
        row=registry['roots']['terraform/environments/dev/network/vpc']
        row['dependencies']=[root for root in row['dependencies'] if root!='terraform/environments/dev/network/log-storage']
    roots, hooks, blockers = set(), set(), []
    for name in registry['chapter_order'][:registry['chapter_order'].index(chapter) + 1]:
        row = registry['chapters'][name]
        roots.update(row['roots']); hooks.update(row['hooks'])
        blockers.extend(f'{name}: {reason}' for reason in row['blockers'])
    # Include dependencies without duplicate root execution (BU06/BU07 share EKS).
    while True:
        expanded = roots | {dependency for root in roots for dependency in registry['roots'][root]['dependencies']}
        if expanded == roots:
            break
        roots = expanded
    if environment == 'prod' and registry['chapter_order'].index(chapter) < registry['chapter_order'].index('BU15'):
        blockers.append('Prod disposable lifecycle starts at the verified BU15 completion.')
    order = topological(roots, registry['roots'])
    for root in order:
        row = registry['roots'][root]
        if row['mode'] == 'blocked':
            blockers.append(root + ': ' + row['reason'])
    blockers.extend(hook + ': ' + registry['hooks'][hook]['reason'] for hook in sorted(hooks) if registry['hooks'][hook]['status'] == 'blocked')
    for hook in sorted(hooks):
        row = registry['hooks'][hook]
        if row['status'] == 'integrated':
            require(set(row['roots']) <= roots, 'An integrated check is outside the selected chapter roots.')
        if row['status'] == 'alias':
            require(set(row['provider_hooks'])<=hooks and all(registry['hooks'][name]['status']=='adapter' for name in row['provider_hooks']), 'Alias has no selected executable capability provider.')
            require(all('terraform/environments/'+environment+'/'+suffix in roots and registry['roots']['terraform/environments/'+environment+'/'+suffix]['mode']=='retain' for suffix in row['retained_roots']), 'Alias retention prerequisite is missing.')
    selection = dict(environment=environment, completed_chapter=chapter,
                     roots=order, retained=[root for root in order if registry['roots'][root]['mode'] == 'retain'],
                     up_order=[root for root in order if registry['roots'][root]['mode'] != 'retain'],
                     hooks=sorted(hooks), blockers=list(dict.fromkeys(blockers)), **environment_names(environment))
    selection['down_order'] = list(reversed(selection['up_order']))
    step_graph = execution_graph(order, hooks, registry)
    steps = topological(step_graph, step_graph)
    selection['up_steps'] = [step for step in steps if step.startswith('hook:') or registry['roots'][step]['mode'] != 'retain']
    selection['up_levels'] = dependency_levels(step_graph, selection['up_steps'])
    require(len(selection['up_levels']) <= MAX_UP_LEVELS, 'Reviewed dependency depth exceeds the fixed workflow bound.')
    if environment == 'prod':
        selection['up_steps'] = [step for level in selection['up_levels'] for step in level]
        selection['up_order'] = [step for step in selection['up_steps'] if not step.startswith('hook:')]
        selection['down_order'] = list(reversed(selection['up_order']))
    selection['down_steps'] = list(reversed(selection['up_steps']))
    selection['privileged_destroy'] = bool(hooks or 'terraform/environments/' + environment + '/eks' in roots)
    selection['registry_sha256'] = registry_sha256
    if executable:
        require(not selection['blockers'], 'This cumulative chapter is not executable: ' + '; '.join(selection['blockers']))
    return selection



def environment_names(environment):
    require(environment in ('dev', 'prod'), 'Unknown lifecycle environment.')
    return {kind + '_environment': 'infra-' + environment + '-' + kind for kind in ('plan', 'apply', 'destroy')}


def dependency_levels(graph, selected):
    """Independent work is bundled; retained prerequisites do not create gates."""
    chosen = set(selected); levels = []; completed = set(graph) - chosen
    while chosen:
        ready = [step for step in selected if step in chosen and set(graph[step]['dependencies']) <= completed]
        require(ready, 'Lifecycle execution dependency cycle.')
        levels.append(ready); chosen -= set(ready); completed.update(ready)
    return levels


def marker(target):
    return c.course_marker_key(target['repository_id'], target.get('environment', 'dev'))


def selected(stage):
    require(stage in STAGES, 'Unknown lifecycle stage.')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Dispatch lifecycle from main.')
    registry = read_registry()
    selection = resolve(os.environ.get('OPERATION'), os.environ.get('LIFECYCLE_ENVIRONMENT'), os.environ.get('COMPLETED_CHAPTER'), registry, executable=stage != 'inspect')
    require(not (HERE.parent / '.github/workflows/vpc-lifecycle.yml').exists(), 'Remove the retired VPC workflow before using the common lifecycle entrypoint.')
    os.environ['LIFECYCLE_CONFIG_SHA256'] = selection['registry_sha256']
    os.environ['LIFECYCLE_SELECTED_ROOTS'] = json.dumps(selection['up_order'])
    return registry, selection


def load_engine(name):
    require(name in ENGINES, 'Unimplemented execution adapter.')
    return load('course_' + name.replace('-', '_'), ENGINES[name]['module'])


def invoke(registry, root, stage, *, descriptor=None, bundle_descriptors=None, barrier_receipts=None, root_contract=None):
    """Capture only fixed job outputs. Never parse public Terraform output."""
    hook = root.removeprefix('hook:') if root.startswith('hook:') else None
    row = registry['hooks'][hook] if hook else registry['roots'][root]
    require(row.get('status' if hook else 'mode') == 'adapter', 'Retained or unknown steps must never execute.')
    before = dict(os.environ)
    try:
        os.environ['LIFECYCLE_ENGINE'] = row['engine']
        os.environ['LIFECYCLE_STEP_ID'] = root
        os.environ['LIFECYCLE_BUNDLE_DESCRIPTORS'] = h.canonical(bundle_descriptors or {}).decode()
        os.environ['LIFECYCLE_BARRIER_RECEIPTS'] = h.canonical(barrier_receipts or {}).decode()
        if hook:
            contract = HOOK_ENGINES[row['engine']]
            os.environ['ROOT_PATH'] = contract['owner_root']
            engine = load('course_hook_' + row['engine'].replace('-', '_'), contract['module'])
        else:
            os.environ['ROOT_PATH'] = root
            engine = load_engine(row['engine'])
            contract_env = ENGINES[row['engine']].get('contract_env')
            if contract_env:
                require(isinstance(root_contract, dict), 'Selected root lacks its retained lifecycle contract.')
                os.environ[contract_env] = h.canonical(root_contract).decode()
        if descriptor:
            os.environ.update(MANIFEST_KEY=descriptor['manifest_key'], MANIFEST_VERSION=descriptor['manifest_version'],
                              EXPECTED_MANIFEST_SHA=descriptor['manifest_sha'], EXPECTED_PLAN_SHA=descriptor['plan_sha'])
        with tempfile.TemporaryDirectory(prefix='private-root-output-') as directory:
            output = Path(directory) / 'outputs'; output.touch()
            os.environ['GITHUB_OUTPUT'] = str(output)
            engine.run(stage)
            values = {}
            for line in output.read_text().splitlines():
                key, value = line.split('=', 1)
                require(key not in values, 'Duplicate execution adapter output.')
                values[key] = value
            return values
    except Exception as error:
        if os.environ.get('OPERATION')=='up' and 'bootstrap handoff required' in str(error).lower():
            publish_bootstrap_handoff(registry)
            raise SelectionError('Fresh-cluster Up is paused. This run now releases the shared mutex; use the exact protected bootstrap command in Summary, then resume the same Up checkpoint.') from None
        raise
    finally:
        os.environ.clear(); os.environ.update(before)


def publish_bootstrap_handoff(registry):
    """Publish exact nonsecret checkpoint descriptors; never wait while holding the mutex."""
    environment=h.required('LIFECYCLE_ENVIRONMENT')
    selection=resolve('up',environment,h.required('COMPLETED_CHAPTER'),registry)
    _,store,target=target_environment(selection)
    record,info=checked_record(store,target,selection)
    require(record['operation']=='up' and 'terraform/environments/'+environment+'/eks' in record['completed'], 'Bootstrap handoff requires completed fresh EKS infrastructure in this exact Up checkpoint.')
    bundle=Path(h.required('GITHUB_WORKSPACE'))/'ci/operations-access/bundles'/environment/'access-manifest.json'
    require(bundle.is_file() and not bundle.is_symlink(),'Generate and commit the reviewed operation-access bundle before cluster restoration.')
    bundle_sha=h.digest(bundle.read_bytes());checkpoint_sha=h.digest(h.canonical(record))
    require(isinstance(info.get('version'),str) and info['version'] not in ('','null'),'Handoff checkpoint version is missing.')
    command=['gh','workflow','run','gitops-access-bootstrap.yml','--ref','main','-f','environment='+environment,
             '-f','bundle_sha256='+bundle_sha,'-f','checkpoint_version='+info['version'],
             '-f','checkpoint_sha256='+checkpoint_sha,'-f','generation='+record['generation']]
    publish_checkpoint_summary(selection,record,'bootstrap_handoff')
    path=os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path,'a') as out:
            out.write('\n### 새 EKS의 보호된 초기 설치\n\n이번 Up이 종료된 뒤 아래 작업을 실행하고 `gitops-'+environment+'-bootstrap` 승인을 진행합니다. 완료되면 위의 동일 Up 명령으로 이어갑니다. 대기 중 mutex를 잡아 두지 않습니다.\n\n```bash\n'+shlex.join(command)+'\n```\n')
            out.write('\n이 값은 지금 저장된 checkpoint의 버전과 해시입니다. State/입력값/Secret 내용은 공개하지 않습니다.\n')
    print('LIFECYCLE_BOOTSTRAP_COMMAND='+shlex.join(command))


def target_environment(selection):
    engine = load_engine('dev-vpc-v1')
    if selection['environment'] == 'dev':
        workspace, store, target = engine.environment()
    else:
        h.refresh_profile_guard()
        require(h.required('GITHUB_REF') == 'refs/heads/main' and h.required('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Lifecycle requires protected main dispatch.')
        require(not any(key.startswith(('TF_VAR_', 'TF_CLI_ARGS', 'TF_LOG')) or key in ('TF_DATA_DIR','TF_WORKSPACE','TF_REATTACH_PROVIDERS') for key in os.environ), 'Inherited Terraform overrides are forbidden.')
        workspace = Path(h.required('GITHUB_WORKSPACE')).resolve()
        require(h.execute(['git','rev-parse','HEAD'], cwd=workspace).decode().strip() == h.required('GITHUB_SHA'), 'Current helper checkout mismatch.')
        h.ensure_current_main({'sha': h.required('GITHUB_SHA')})
        repo, account, bucket, region = (h.required(key) for key in ('GITHUB_REPOSITORY_ID','EXPECTED_ACCOUNT_ID','STATE_BUCKET','AWS_REGION'))
        require(repo.isdigit() and re.fullmatch('[0-9]{12}', account) and region == 'ap-northeast-2', 'Invalid registered Prod target.')
        require(h.required('AWS_ROLE_ARN') in {f'arn:aws:iam::{account}:role/gha-infra-prod-' + mode for mode in ('plan','apply','lifecycle-destroy')}, 'Exact isolated Prod role required.')
        h.check_identity(account, h.required('AWS_ROLE_ARN'))
        store = h.Store(bucket, account); store.check()
        target = dict(repository_id=repo, account=account, bucket=bucket, region=region, environment='prod')
    engine.check_retention(store, marker(target))
    c.assert_incident_clear(store, {'root': 'terraform/environments/' + selection['environment'] + '/network/vpc', 'repository_id': target['repository_id'], 'account': target['account'],
                                  'backend': {'bucket': target['bucket'], 'region': target['region']}})
    return workspace, store, target


def settings(selection):
    engine = load_engine('dev-vpc-v1')
    engine.settings(selection['destroy_environment'])
    if selection['environment'] == 'prod':
        engine.settings(selection['apply_environment'])
    image = os.environ.get('LIFECYCLE_TOOLCHAIN_IMAGE', '')
    needs_tools = selection['environment'] == 'prod' or any(registry_engine not in ('dev-network-v2','dev-vpc-v1',None) for registry_engine in (read_registry()['roots'][root]['engine'] for root in selection['up_order']))
    if needs_tools:
        require(re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/platform-toolchain@sha256:[0-9a-f]{64}', image), 'The registered immutable lifecycle toolchain image is required.')
    else:
        image = ''
    h.emit({**environment_names(selection['environment']), 'toolchain_image': image, 'registry_sha256': selection['registry_sha256'], 'completed_chapter': selection['completed_chapter'],
            'root_count': len(selection['up_order']), 'privileged_destroy': 'true' if selection['privileged_destroy'] else 'false', 'up_level_count': len(selection['up_levels'])})


def validate_transition(record, operation):
    # Hooks retain original UIDs. A partial Up has new incarnations, so its
    # reversal cannot reuse the previous Down action snapshot or proof set.
    require(not (record is not None and record['phase'] == 'paused' and
                 record['operation'] == 'up' and operation == 'down'),
            'Partial Up must resume Up with the same checkpoint before a new Down; original Down identities cannot authorize newly restored objects.')


def preview(registry, selection):
    """Read-only pre-gate account/source summary. Never creates or clears pause."""
    _, store, target = target_environment(selection)
    record, _ = c.read_json(store, marker(target))
    if record is not None:
        c.validate_course(record, **target)
    validate_transition(record, h.required('OPERATION'))
    if record is None or record['phase'] == 'active':
        require(h.required('OPERATION') == 'down', 'Up requires its actual paused checkpoint.')
        source = h.required('GITHUB_SHA'); generation = h.required('GITHUB_RUN_ID') + '-' + h.required('GITHUB_RUN_ATTEMPT')
    else:
        require(record['completed_chapter'] == selection['completed_chapter'] and record['roots'] == selection['roots'] and record['registry_sha256'] == selection['registry_sha256'], 'Paused source/map differs from requested completion.')
        source, generation = record['snapshot_sha'], record['generation']
    h.emit({'snapshot_sha': source, 'generation': generation})
    with open(h.required('GITHUB_STEP_SUMMARY'),'a') as out:
        out.write('\n## Checkpoint metadata approval\n\n')
        out.write(f"Environment: `{selection['environment']}` / completed chapter: `{selection['completed_chapter']}` / operation: `{h.required('OPERATION')}`\n\n")
        out.write(f"Restore source SHA: `{source}` / generation: `{generation}`\n\n")
        out.write('This first approval permits only persistent checkpoint metadata and read-only inventory. It does not apply infrastructure. Subsequent protected jobs review private saved plans and apply those exact plans.\n')


def validate_record(record, target, selection):
    c.validate_course(record, **target)
    require(record['completed_chapter'] == selection['completed_chapter'] and record['registry_sha256'] == selection['registry_sha256'] and record['roots'] == selection['roots'] and record.get('steps', selection['up_steps']) == selection['up_steps'], 'Chapter, map or root scope differs from the retained checkpoint.')
    require(record['operation'] == h.required('OPERATION') and record['request_run'] == h.required('GITHUB_RUN_ID') and record['request_attempt'] == h.required('GITHUB_RUN_ATTEMPT') and record['workflow_sha'] == h.required('GITHUB_SHA'), 'Checkpoint belongs to another run/attempt; start a fresh run.')


def checked_record(store, target, selection):
    record, info = c.read_json(store, marker(target))
    require(record is not None, 'Course checkpoint is missing; do not infer an earlier successful down.')
    validate_record(record, target, selection)
    require(record['phase'] == 'paused', 'Course lifecycle is not paused.')
    return record, info


def checkpoint_inputs(selection):
    inputs = json.loads(h.required('TF_VARS_JSON'))
    require(isinstance(inputs, dict), 'Protected root inputs must be an object.')
    result = {}
    for root in selection['up_order']:
        name = '/'.join(root.split('/')[3:])
        require(isinstance(inputs.get(name), dict), 'Protected input is missing for a selected root.')
        result[root] = inputs[name]
    return result


def checkpoint_contracts(registry, selection):
    required_roots = [root for root in selection['up_order'] if ENGINES.get(registry['roots'][root].get('engine'), {}).get('contract_env')]
    if not required_roots:
        return {}
    source = json.loads(h.required('LIFECYCLE_ROOT_CONTRACTS'))
    known = {'/'.join(root.split('/')[3:]): root for root, row in registry['roots'].items()
             if ENGINES.get(row.get('engine'), {}).get('contract_env')}
    require(isinstance(source, dict) and set(source) <= set(known) and all(isinstance(value, dict) for value in source.values()), 'Invalid protected lifecycle root-contract map.')
    result = {}
    for root in required_roots:
        relative = '/'.join(root.split('/')[3:])
        require(relative in source, 'A selected root lifecycle contract is missing.')
        result[root] = source[relative]
    return result


def normalize_contracts(registry, contracts, source_sha, inputs, locks):
    result = copy.deepcopy(contracts)
    for root, contract in result.items():
        engine = ENGINES[registry['roots'][root]['engine']]
        if engine.get('derive_completion_sha256'):
            value = h.digest(h.canonical({'root': root, 'source_sha': source_sha, 'inputs': inputs[root], 'lock_sha256': locks[root]}))
            require('completion_sha256' not in contract or contract['completion_sha256'] == value, 'Root completion metadata differs from retained Terraform source/input/lock.')
            contract['completion_sha256'] = value
    return result


def publish_checkpoint_summary(selection, record, status):
    """Only metadata is public. Protected input values never enter this path."""
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    require(not repository or re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'Invalid repository identity for the lifecycle summary.')
    operation = record['operation']
    next_operation = 'up' if status == 'down_complete' else 'down' if status == 'up_complete' else operation
    command = ['gh', 'workflow', 'run', 'terraform-lifecycle.yml']
    if repository:
        command += ['--repo', repository]
    command += ['--ref', 'main', '-f', 'operation=' + next_operation,
                '-f', 'environment=' + selection['environment'], '-f', 'completed_chapter=' + record['completed_chapter']]
    labels = [('COMPLETED_CHAPTER',record['completed_chapter']), ('CHECKPOINT',record['generation']),
              ('SNAPSHOT_SHA',record['snapshot_sha']), ('WORKFLOW_SHA',record['workflow_sha']), ('STATUS',status)]
    for key,value in labels:
        print('LIFECYCLE_' + key + '=' + value)
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if not path:
        return
    with open(path, 'a') as out:
        out.write('\n## 누적 lifecycle checkpoint\n\n')
        out.write(f"- 완료 장: `{record['completed_chapter']}` / operation: `{operation}` / status: `{status}`\n")
        out.write(f"- Checkpoint generation: `{record['generation']}`\n")
        out.write(f"- 원래 Terraform source SHA: `{record['snapshot_sha']}`\n")
        out.write(f"- 이번 workflow/helper SHA: `{record['workflow_sha']}`\n")
        out.write('- 실행 순서: ' + ' → '.join('`' + '/'.join(root.split('/')[3:]) + '`' for root in selection[operation + '_steps']) + '\n')
        out.write('- 보존: ' + ', '.join('`' + '/'.join(root.split('/')[3:]) + '`' for root in selection['retained']) + '\n')
        out.write('- 완료한 root: ' + (', '.join('`' + '/'.join(root.split('/')[3:]) + '`' for root in record['completed']) or '없음') + '\n')
        out.write('\n다음 동일 범위 실행 명령 (source SHA를 입력하지 않습니다):\n\n```bash\n' + shlex.join(command) + '\n```\n')
        out.write('\nUI: Actions → terraform-lifecycle → 해당 run → Summary에서 위 값을 확인합니다. Head SHA는 workflow/helper SHA이며 복구 원본 SHA로 추정하지 않습니다.\n')
        run_id = os.environ.get('GITHUB_RUN_ID', '')
        if run_id.isdigit():
            lookup = ['gh','run','view',run_id]
            if repository: lookup += ['--repo',repository]
            lookup += ['--log']
            out.write('\nCLI metadata 확인:\n\n```bash\n' + shlex.join(lookup) + " | grep -E 'LIFECYCLE_(COMPLETED_CHAPTER|CHECKPOINT|SNAPSHOT_SHA|WORKFLOW_SHA|STATUS)='\n```\n")


def start(registry, selection):
    workspace, store, target = target_environment(selection)
    key = marker(target)
    record, info = c.read_json(store, key)
    operation, inputs = h.required('OPERATION'), checkpoint_inputs(selection)
    contracts = checkpoint_contracts(registry, selection)
    if record is not None:
        c.validate_course(record, **target)
    validate_transition(record, h.required('OPERATION'))
    if record is None or record['phase'] == 'active':
        require(operation == 'down', 'No paused chapter checkpoint exists for up.')
        locks = {}
        for root in selection['up_order']:
            lock = workspace / root / '.terraform.lock.hcl'
            require(lock.is_file(), 'A selected root has no committed provider lock.')
            h.execute(['git', 'ls-files', '--error-unmatch', root + '/.terraform.lock.hcl'], cwd=workspace)
            locks[root] = h.digest(lock.read_bytes())
        contracts = normalize_contracts(registry, contracts, h.required('GITHUB_SHA'), inputs, locks)
        record = dict(schema=2, kind='course-lifecycle', phase='paused', **target,
                      completed_chapter=selection['completed_chapter'], roots=selection['roots'], steps=selection['up_steps'],
                      retained_roots=selection['retained'], registry_sha256=selection['registry_sha256'],
                      generation=h.required('GITHUB_RUN_ID') + '-' + h.required('GITHUB_RUN_ATTEMPT'),
                      snapshot_sha=h.required('GITHUB_SHA'), inputs=inputs, locks=locks, contracts=contracts,
                      operation=operation, completed=[], events=[], barriers={}, last_result='not-applied')
    else:
        require(record['completed_chapter'] == selection['completed_chapter'] and record['roots'] == selection['roots'] and record.get('steps', selection['up_steps']) == selection['up_steps'] and record['registry_sha256'] == selection['registry_sha256'], 'Resume must use the recorded chapter/map; do not widen a paused checkpoint.')
        require(record['inputs'] == inputs, 'Resume must use the original protected inputs.')
        contracts = normalize_contracts(registry, contracts, record['snapshot_sha'], record['inputs'], record['locks'])
        require(record.get('contracts', {}) == contracts, 'Resume must use the original root lifecycle contracts.')
        load_engine('dev-vpc-v1').assert_snapshot_current(workspace, record)
        # Reversing a partial Down restores the original dependency graph.
        # A partial Up must finish first; validate_transition rejects reversal.
        if record['operation'] != operation:
            record['completed'] = []
    record.update(operation=operation, request_run=h.required('GITHUB_RUN_ID'), request_attempt=h.required('GITHUB_RUN_ATTEMPT'), workflow_sha=h.required('GITHUB_SHA'), phase='paused')
    info = c.update(store, key, record, info)
    session(record)
    h.emit({'generation': record['generation'], 'snapshot_sha': record['snapshot_sha']})
    publish_checkpoint_summary(selection, record, 'paused')
    for root in pending(record, selection):
        # Up hooks need the freshly restored API and start only at their DAG step.
        if operation == 'down' or selection['environment'] == 'prod' or not root.startswith('hook:'):
            invoke(registry, root, 'start', root_contract=record.get('contracts', {}).get(root))
    print('Chapter checkpoint is persistent. Failure or cancellation does not clear the CI pause.')


def session(record):
    os.environ['LIFECYCLE_SNAPSHOT_SHA'] = record['snapshot_sha']
    os.environ['LIFECYCLE_GENERATION'] = record['generation']


def pending(record, selection):
    order = selection['down_steps' if record['operation'] == 'down' else 'up_steps']
    completed = record['completed']
    require(isinstance(completed, list) and completed == order[:len(completed)], 'Completed roots are not a valid dependency-order prefix.')
    return order[len(completed):]


def bundle_prefix(target):
    return f"ci-plans/{target['repository_id']}/{h.required('GITHUB_RUN_ID')}/{h.required('GITHUB_RUN_ATTEMPT')}/{h.required('GITHUB_SHA')}/{target.get('environment', 'dev')}/course-lifecycle/"


def plan(registry, selection):
    require(h.required('OPERATION') == 'down', 'Up plans are created immediately before each automatic Dev apply.')
    _, store, target = target_environment(selection)
    record, control = checked_record(store, target, selection)
    session(record)
    plans = []
    for root in pending(record, selection):
        descriptor = invoke(registry, root, 'plan', bundle_descriptors=bundle_descriptors(plans), barrier_receipts=barrier_receipts(record), root_contract=record.get('contracts', {}).get(root))
        require(set(descriptor) == {'manifest_key', 'manifest_version', 'manifest_sha', 'plan_sha'}, 'Incomplete private root plan.')
        plans.append({'root': root, **descriptor})
    latest, latest_info = checked_record(store, target, selection)
    require(latest == record and latest_info == control, 'Checkpoint changed during bundle planning.')
    with tempfile.TemporaryDirectory(prefix='private-bundle-') as directory:
        path = Path(directory) / 'bundle.json'
        bundle = dict(schema=1, kind='course-down-bundle', generation=record['generation'], control=control,
                      registry_sha256=selection['registry_sha256'], chapter=selection['completed_chapter'],
                      run_id=h.required('GITHUB_RUN_ID'), run_attempt=h.required('GITHUB_RUN_ATTEMPT'), workflow_sha=h.required('GITHUB_SHA'),
                      roots=pending(record, selection), plans=plans)
        path.write_bytes(h.canonical(bundle))
        descriptor = store.put(bundle_prefix(target) + 'bundle.json', path)
    h.emit({'bundle_key': descriptor['key'], 'bundle_version': descriptor['version'], 'bundle_sha': descriptor['sha256']})
    with open(h.required('GITHUB_STEP_SUMMARY'), 'a') as out:
        out.write('\n## 누적 Down 승인\n\n위의 모든 비공개 root review를 검토한 뒤 선택한 환경의 destroy Environment를 한 번 승인합니다.\n')
        out.write('승인 후 새 plan을 만들지 않으며, 상태 변경·만료·실패 시 중단하고 새 실행에서 다시 계획합니다.\n')
        out.write(f"\nBundle SHA-256: `{descriptor['sha256']}`\n완료 장: `{selection['completed_chapter']}`\n")


def bundle_descriptors(plans):
    """Only authenticated fixed descriptors enter dependent-root proof guards."""
    require(isinstance(plans, list), 'Invalid private root-plan list.')
    result = {}
    for row in plans:
        require(isinstance(row, dict) and set(row) == {'root', 'manifest_key', 'manifest_version', 'manifest_sha', 'plan_sha'}, 'Invalid private root-plan descriptor.')
        require(isinstance(row['root'], str) and row['root'] not in result and all(isinstance(value, str) and value for value in row.values()), 'Invalid or duplicate private root descriptor.')
        result[row['root']] = {key: value for key, value in row.items() if key != 'root'}
    return result


def barrier_receipts(record):
    return {step: proof['receipt'] for step, proof in record.get('barriers', {}).items()}


def completed_barrier(store, target, record, root, planned, outputs):
    if not root.startswith('hook:'):
        return None
    proof = {'plan': {key: planned[key] for key in b.PLAN_FIELDS}, 'receipt': outputs, 'operation': record['operation']}
    b.authenticate(store, record, target, root, proof)
    return proof


def mark_root(store, target, selection, record, info, root, result, barrier=None):
    latest, current = checked_record(store, target, selection)
    require(latest == record and current == info, 'Checkpoint changed before root result recording.')
    if barrier is not None:
        record.setdefault('barriers', {})[root] = barrier
    if result == 'complete':
        require(pending(record, selection)[0] == root, 'Root completed outside dependency order.')
        record['completed'].append(root)
    record['last_result'] = result
    record['events'].append({'root': root, 'operation': record['operation'], 'result': result,
                             'run_id': h.required('GITHUB_RUN_ID'), 'attempt': h.required('GITHUB_RUN_ATTEMPT')})
    return c.update(store, marker(target), record, info)


def finish(store, target, selection, record, info):
    require(not pending(record, selection), 'Not all selected roots completed.')
    record['last_result'] = record['operation'] + '_complete'
    record['phase'] = 'active' if record['operation'] == 'up' else 'paused'
    c.update(store, marker(target), record, info)
    publish_checkpoint_summary(selection, record, record['last_result'])
    print('Chapter lifecycle completed. Down remains paused; successful full Up re-enables ordinary CI.')


def apply(registry, selection):
    require(h.required('OPERATION') == 'down', 'Use the sequential up stage for Dev restoration.')
    _, store, target = target_environment(selection)
    record, info = checked_record(store, target, selection)
    session(record)
    descriptor = dict(key=h.required('BUNDLE_KEY'), version=h.required('BUNDLE_VERSION'), sha256=h.required('EXPECTED_BUNDLE_SHA'))
    require(descriptor['key'] == bundle_prefix(target) + 'bundle.json', 'Bundle belongs to another run/attempt.')
    with tempfile.TemporaryDirectory(prefix='private-bundle-read-') as directory:
        path = Path(directory) / 'bundle.json'; store.get(descriptor, path); bundle = json.loads(path.read_bytes())
    expected = dict(schema=1, kind='course-down-bundle', generation=record['generation'], control=info,
                    registry_sha256=selection['registry_sha256'], chapter=selection['completed_chapter'],
                    run_id=h.required('GITHUB_RUN_ID'), run_attempt=h.required('GITHUB_RUN_ATTEMPT'), workflow_sha=h.required('GITHUB_SHA'), roots=pending(record, selection))
    require(isinstance(bundle, dict) and set(bundle) == set(expected) | {'plans'} and all(bundle[key] == value for key, value in expected.items()), 'Reviewed bundle checkpoint/run/map mismatch.')
    descriptors = bundle_descriptors(bundle['plans'])
    require(list(descriptors) == expected['roots'], 'Reviewed root order or plan count differs.')
    # Validate the ENTIRE reviewed bundle before the first destructive action.
    # The adapter checks current State/upstream identities again at each apply.
    for row in bundle['plans']:
        invoke(registry, row['root'], 'verify', descriptor=row, bundle_descriptors=descriptors, barrier_receipts=barrier_receipts(record), root_contract=record.get('contracts', {}).get(row['root']))
    for row in bundle['plans']:
        root = row['root']
        info = mark_root(store, target, selection, record, info, root, 'applying')
        # Adapter re-verifies own State, upstream states, original identities,
        # saved source/input/lock hashes, expiry and exact binary before apply.
        outputs = invoke(registry, root, 'apply', descriptor=row, bundle_descriptors=descriptors, barrier_receipts=barrier_receipts(record), root_contract=record.get('contracts', {}).get(root))
        proof = completed_barrier(store, target, record, root, row, outputs)
        info = mark_root(store, target, selection, record, info, root, 'complete', barrier=proof)
    finish(store, target, selection, record, info)


def up(registry, selection):
    require(h.required('OPERATION') == 'up' and selection['environment'] == 'dev', 'Automatic restoration is Dev-only; Prod requires reviewed dependency levels.')
    _, store, target = target_environment(selection)
    record, info = checked_record(store, target, selection)
    session(record)
    for root in pending(record, selection):
        if root.startswith('hook:'):
            invoke(registry, root, 'start', root_contract=record.get('contracts', {}).get(root))
        descriptor = invoke(registry, root, 'plan', barrier_receipts=barrier_receipts(record), root_contract=record.get('contracts', {}).get(root))
        require(set(descriptor) == {'manifest_key', 'manifest_version', 'manifest_sha', 'plan_sha'}, 'Incomplete restoration plan.')
        info = mark_root(store, target, selection, record, info, root, 'applying')
        outputs = invoke(registry, root, 'apply', descriptor=descriptor, barrier_receipts=barrier_receipts(record), root_contract=record.get('contracts', {}).get(root))
        proof = completed_barrier(store, target, record, root, descriptor, outputs)
        info = mark_root(store, target, selection, record, info, root, 'complete', barrier=proof)
    finish(store, target, selection, record, info)



def selected_level(selection):
    require(selection['environment'] == 'prod' and h.required('OPERATION') == 'up', 'Reviewed level restoration is Prod Up only.')
    value = h.required('LIFECYCLE_LEVEL')
    require(re.fullmatch('[1-9][0-9]*', value) and 1 <= int(value) <= MAX_UP_LEVELS, 'Invalid fixed restoration level.')
    index = int(value) - 1
    require(index < len(selection['up_levels']), 'Restoration level exceeds the selected dependency graph.')
    return index, selection['up_levels'][index]


def level_record(store, target, selection, index):
    record, info = c.read_json(store, marker(target))
    require(record is not None, 'Course checkpoint is missing.')
    validate_record(record, target, selection)
    before = [step for level in selection['up_levels'][:index] for step in level]
    level = selection['up_levels'][index]
    require(record['completed'][:len(before)] == before and len(record['completed']) >= len(before), 'A prerequisite restoration level is incomplete.')
    # Already completed levels are read-only skips during a fresh resume run.
    if len(record['completed']) >= len(before) + len(level):
        require(record['completed'][len(before):len(before)+len(level)] == level, 'Completed restoration level differs.')
        return record, info, []
    require(record['phase'] == 'paused', 'Incomplete restoration cannot be active.')
    remaining = pending(record, selection)
    selected = level[len(record['completed'])-len(before):]
    require(remaining[:len(selected)] == selected, 'Restoration level is outside the retained prefix.')
    return record, info, selected


def level_prefix(target, index):
    return bundle_prefix(target).replace('ci-plans/', 'ci-up-plans/', 1) + 'up-level-' + str(index+1) + '/'


def up_plan(registry, selection):
    index, _ = selected_level(selection)
    _, store, target = target_environment(selection)
    record, control, roots = level_record(store, target, selection, index)
    session(record)
    if not roots:
        return h.emit({'has_work':'false'})
    plans=[]
    for root in roots:
        descriptor=invoke(registry, root, 'plan', barrier_receipts=barrier_receipts(record), root_contract=record.get('contracts',{}).get(root))
        require(set(descriptor)=={'manifest_key','manifest_version','manifest_sha','plan_sha'}, 'Incomplete restoration plan.')
        plans.append({'root':root, **descriptor})
    latest, latest_info, latest_roots=level_record(store,target,selection,index)
    require(latest==record and latest_info==control and latest_roots==roots, 'Checkpoint changed during restoration planning.')
    bundle=dict(schema=1,kind='course-up-level-bundle',level=index+1,generation=record['generation'],control=control,
                registry_sha256=selection['registry_sha256'],chapter=selection['completed_chapter'],environment='prod',
                run_id=h.required('GITHUB_RUN_ID'),run_attempt=h.required('GITHUB_RUN_ATTEMPT'),workflow_sha=h.required('GITHUB_SHA'),roots=roots,plans=plans)
    with tempfile.TemporaryDirectory(prefix='private-up-level-') as directory:
        path=Path(directory)/'bundle.json';path.write_bytes(h.canonical(bundle));descriptor=store.put(level_prefix(target,index)+'bundle.json',path)
    h.emit({'has_work':'true','bundle_key':descriptor['key'],'bundle_version':descriptor['version'],'bundle_sha':descriptor['sha256']})
    with open(h.required('GITHUB_STEP_SUMMARY'),'a') as out:
        out.write(f"\n## Prod saved-plan approval: dependency level {index+1}\n\n")
        out.write('Review every private root/action plan above. The protected apply job uses these identical plans; it never replans after approval.\n')
        out.write('Roots: '+', '.join(roots)+'\n\nBundle SHA-256: `'+descriptor['sha256']+'`\n')


def up_apply(registry, selection):
    index, _=selected_level(selection)
    _,store,target=target_environment(selection)
    record,info,roots=level_record(store,target,selection,index)
    require(roots, 'An already completed level cannot replay an approved bundle.')
    session(record)
    descriptor=dict(key=h.required('BUNDLE_KEY'),version=h.required('BUNDLE_VERSION'),sha256=h.required('EXPECTED_BUNDLE_SHA'))
    require(descriptor['key']==level_prefix(target,index)+'bundle.json','Restoration bundle belongs to another run or level.')
    with tempfile.TemporaryDirectory(prefix='private-up-level-read-') as directory:
        path=Path(directory)/'bundle.json';store.get(descriptor,path);bundle=json.loads(path.read_bytes())
    expected=dict(schema=1,kind='course-up-level-bundle',level=index+1,generation=record['generation'],control=info,
                registry_sha256=selection['registry_sha256'],chapter=selection['completed_chapter'],environment='prod',
                run_id=h.required('GITHUB_RUN_ID'),run_attempt=h.required('GITHUB_RUN_ATTEMPT'),workflow_sha=h.required('GITHUB_SHA'),roots=roots)
    require(isinstance(bundle,dict) and set(bundle)==set(expected)|{'plans'} and all(bundle[key]==value for key,value in expected.items()),'Restoration bundle checkpoint/run/level mismatch.')
    descriptors=bundle_descriptors(bundle['plans']);require(list(descriptors)==roots,'Restoration level scope differs.')
    for row in bundle['plans']:
        invoke(registry,row['root'],'verify',descriptor=row,barrier_receipts=barrier_receipts(record),root_contract=record.get('contracts',{}).get(row['root']))
    for row in bundle['plans']:
        root=row['root'];info=mark_root(store,target,selection,record,info,root,'applying')
        outputs=invoke(registry,root,'apply',descriptor=row,barrier_receipts=barrier_receipts(record),root_contract=record.get('contracts',{}).get(root))
        proof=completed_barrier(store,target,record,root,row,outputs)
        info=mark_root(store,target,selection,record,info,root,'complete',barrier=proof)
    if not pending(record,selection):finish(store,target,selection,record,info)
    else:publish_checkpoint_summary(selection,record,'up_level_complete')



def prepare(registry, selection):
    require(h.required('OPERATION') == 'down' and selection['privileged_destroy'], 'Privileged preparation is bounded to registered cluster teardown.')
    require(h.required('AWS_ROLE_ARN').endswith(':role/gha-infra-' + selection['environment'] + '-lifecycle-destroy'), 'Dedicated protected destruction identity required.')
    start(registry, selection)
    plan(registry, selection)


def destroy_apply(registry, selection):
    require(h.required('OPERATION') == 'down' and selection['privileged_destroy'], 'Privileged apply is bounded to registered cluster teardown.')
    require(h.required('AWS_ROLE_ARN').endswith(':role/gha-infra-' + selection['environment'] + '-lifecycle-destroy'), 'Dedicated protected destruction identity required.')
    apply(registry, selection)


def run(stage):
    registry, selection = selected(stage)
    if stage == 'inspect':
        print(json.dumps(selection, indent=2, ensure_ascii=False)); return
    if stage == 'select':
        return h.emit({**environment_names(selection['environment']), 'registry_sha256': selection['registry_sha256']})
    if stage == 'settings':
        return settings(selection)
    return globals()[stage.replace('-', '_')](registry, selection)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        require(len(sys.argv) == 2, 'Expected inspect, settings, start, plan, apply or up.')
        run(sys.argv[1])
    except h.SafeError as error:
        print('::error::' + str(error)); sys.exit(1)
    except Exception:
        print('::error::Chapter lifecycle stopped. Pause may remain set. Use a fresh run and current State; never replay an old plan.'); sys.exit(1)
