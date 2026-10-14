#!/usr/bin/env python3
"""Exact private saved-plan proofs for selected, still-live network consumers.

This helper only reads. A proof permits a declared preplan runtime-check deferral;
it never permits applying a VPC destroy while any dependent State remains live.
Engine kinds/roots are code-reviewed here; registry text cannot load arbitrary code.
"""
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


h = load('consumer_proof_saved_plan', 'saved-plan.py')
g = load('consumer_proof_state', 'vpc-lifecycle-guard.py')
ENGINE_CONTRACTS = {
    'dev-registered-root-v1': {'kind': 'registered-root-lifecycle', 'roots': frozenset(('terraform/environments/dev/platform/core', 'terraform/environments/dev/platform/gateway', 'terraform/environments/dev/platform/dev-app-access', 'terraform/environments/dev/platform/alerting', 'terraform/environments/dev/platform/queue-secrets', 'terraform/environments/dev/platform/queue-association', 'terraform/environments/dev/identity', 'terraform/environments/dev/platform/edge'))},
    'dev-eks-v1': {'kind': 'eks-lifecycle', 'roots': frozenset({'terraform/environments/dev/eks', 'terraform/environments/dev/platform/private-api'})},
    'dev-network-v2': {'kind': 'network-lifecycle', 'roots': frozenset(
        'terraform/environments/dev/network/' + name for name in ('vpc', 'peer', 'transit'))},
}
ENGINE_CONTRACTS.update({environment+'-later-runtime-v1': {'kind':'later-runtime-lifecycle','roots':frozenset('terraform/environments/'+environment+'/'+suffix for suffix in ('data','delivery','platform/queue'))} for environment in ('dev','prod')})
ENGINE_CONTRACTS['prod-eks-v1']={'kind':'eks-lifecycle','roots':frozenset({'terraform/environments/prod/eks','terraform/environments/prod/platform/private-api'})}
ENGINE_CONTRACTS['prod-network-v2']={'kind':'network-lifecycle','roots':frozenset({'terraform/environments/prod/network/vpc'})}
REGISTERED_SUFFIXES={
    'dev':('account-integrations','identity','platform/alerting','platform/core','platform/dev-app-access','platform/edge','platform/gateway','platform/observability','platform/operations','platform/queue-association','platform/queue-secrets'),
    'prod':('identity','platform/alerting','platform/core','platform/edge','platform/gateway','platform/observability','platform/operations','platform/queue-association','platform/queue-secrets')}
ENGINE_CONTRACTS.update({environment+'-registered-root-v1': {'kind':'registered-root-lifecycle',
    'roots':frozenset('terraform/environments/'+environment+'/'+suffix for suffix in suffixes)}
    for environment,suffixes in REGISTERED_SUFFIXES.items()})
DESCRIPTOR_FIELDS = frozenset({'manifest_key', 'manifest_version', 'manifest_sha', 'plan_sha'})


def selected_descriptors():
    value = json.loads(os.environ.get('LIFECYCLE_BUNDLE_DESCRIPTORS', '{}'))
    h.require(isinstance(value, dict), 'Selected consumer descriptors must be an object.')
    return value


def validate_delete_plan(state, plan):
    return _validate_delete_plan(state,plan,None)


def _validate_delete_plan(state, plan, notification_address):
    rows = g.managed_resources(state)
    h.require(all(not row['type'].startswith('aws_s3_') or (row['type']=='aws_s3_bucket_notification' and row['address']==notification_address) for row in rows),
              'A selected consumer still owns S3 resources; preserve and separate them before lifecycle use.')
    h.require(isinstance(plan, dict) and str(plan.get('format_version', '')).split('.')[0] == '1' and
              plan.get('errored', False) is False and plan.get('complete', True) is True and not plan.get('deferred_changes'),
              'Selected consumer destroy plan is incomplete or unsupported.')
    actual = {row['address']: (row['type'], row['values'].get('id')) for row in rows}
    h.require(all(isinstance(identity[1], str) and identity[1] for identity in actual.values()), 'Selected consumer State identity is missing.')
    prior = [] if not rows and 'prior_state' not in plan else g.managed_resources(g.object_value(plan.get('prior_state')))
    h.require({row['address']: (row['type'], row['values'].get('id')) for row in prior} == actual,
              'Selected consumer plan prior-State identities differ from current State.')
    changes = {}
    for row in g.array(plan.get('resource_changes', [])):
        row = g.object_value(row)
        h.require(row.get('mode') in ('managed', 'data'), 'Selected consumer planned resource mode is invalid.')
        if row['mode'] == 'data': continue
        h.require(not row.get('deposed') and not row.get('previous_address'), 'Selected consumer moved/deposed resources require separate recovery.')
        detail = g.object_value(row.get('change')); before = g.object_value(detail.get('before'))
        h.require(detail.get('actions') == ['delete'] and detail.get('after') is None,
                  'Selected consumers require complete delete-only saved plans.')
        address = row.get('address')
        h.require(isinstance(address, str) and address not in changes, 'Selected consumer planned identity is duplicated or invalid.')
        changes[address] = (row.get('type'), before.get('id'))
    h.require(changes == actual, 'Every selected consumer State object must match the saved destroy plan.')
    h.require(not g.managed_resources({'format_version': '1.0', 'values': g.object_value(plan.get('planned_values'))}),
              'Selected consumer destroy plan leaves managed resources behind.')
    return {'managed_count': len(rows), 'identity_sha256': h.digest(h.canonical(g.normalize_resources(state)))}


def validate_registered_delete_plan(state,plan,context):
    """One source-pinned exception, never a general protected-type bypass.

    The caller is either the registered adapter after payload validation or the
    selected-consumer flow after immutable manifest/source/binary verification.
    """
    rows=g.managed_resources(state)
    if not any(row['type'].startswith('aws_s3_') for row in rows):return validate_delete_plan(state,plan)
    guard=load('consumer_registered_notification_guard','registered-root-guard.py')
    root=context.get('root');guard.validate_context(context)
    h.require(root=='terraform/environments/dev/account-integrations' and context.get('operation')=='down' and context.get('lifecycle_engine')==guard.engine(root), 'S3 notification exception is outside its actual registered course root.')
    h.require(context.get('registered_catalog_sha256')==h.digest((HERE/'registered-root-catalog.json').read_bytes()) and isinstance(context.get('registered_source_sha256'),str) and re.fullmatch('[0-9a-f]{64}',context['registered_source_sha256']), 'Notification source/catalog binding is missing or changed.')
    guard.validate_state(context,state);guard.validate_supported_plan(plan,root,context)
    notification=load('consumer_exact_notification','notification-lifecycle-guard.py')
    h.require(all(not row['type'].startswith('aws_s3_') or (row['type']=='aws_s3_bucket_notification' and row['address']==notification.ADDRESS) for row in rows),'Other retained S3 resources remain forbidden.')
    notification.verify(context,plan,h.aws)
    return _validate_delete_plan(state,plan,notification.ADDRESS)


def terraform_plan_json(workspace, directory, manifest, binary, inputs):
    """Initialize only the pinned consumer source/providers, without its backend."""
    context = manifest['context']; sha = context['source_sha']
    h.require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'Invalid selected consumer source revision.')
    h.execute(['git', 'merge-base', '--is-ancestor', sha, context['sha']], cwd=workspace)
    h.execute(['git', 'diff', '--quiet', sha, context['sha'], '--', 'terraform', 'modules'], cwd=workspace)
    trees = h.execute(['git', 'ls-tree', '-d', '--name-only', sha, '--', 'terraform', 'modules'], cwd=workspace).decode().splitlines()
    h.require('terraform' in trees and set(trees) <= {'terraform', 'modules'}, 'Selected consumer source tree is missing.')
    archive = h.execute(['git', 'archive', sha, '--', *trees], cwd=workspace)
    base = directory / 'source'; base.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as stream:
        stream.extractall(base, filter='data')
    for path in base.rglob('*'):
        h.require(not path.is_symlink() and '.terraform' not in path.parts and not path.name.endswith(('.tfstate', '.tfstate.backup', '.tfplan')),
                  'Selected consumer payload contains unsupported cache/State/plan or symlink content.')
    root = base / context['root']
    h.require(root.is_dir() and root.resolve().is_relative_to(base.resolve()), 'Selected consumer source root is missing.')
    h.require(not (root / 'terraform.tfvars').exists() and not (root / 'terraform.tfvars.json').exists(), 'Committed private consumer inputs are forbidden.')
    if manifest.get('kind')=='registered-root-lifecycle':
        guard=load('consumer_registered_source','registered-root-guard.py')
        h.require(context.get('registered_catalog_sha256')==h.digest((HERE/'registered-root-catalog.json').read_bytes()) and context.get('registered_source_sha256')==guard.validate_source(base,context['root']), 'Selected registered consumer source/catalog differs from the approved manifest.')
    lock = root / '.terraform.lock.hcl'
    h.require(lock.is_file() and h.digest(lock.read_bytes()) == context['lock_sha256'], 'Selected consumer provider lock differs from its saved plan.')
    automatic = {path.name: h.digest(path.read_bytes()) for path in sorted(root.iterdir()) if path.name.endswith(('.auto.tfvars', '.auto.tfvars.json'))}
    h.require(automatic == context.get('tracked_auto_inputs'), 'Selected consumer automatic input files changed.')
    (root / 'terraform.tfvars.json').write_bytes(h.canonical(inputs))
    h.require(json.loads(h.execute(['terraform', 'version', '-json']))['terraform_version'] == context['terraform_version'] == '1.16.0',
              'Selected consumer Terraform version differs from the approved toolchain.')
    h.refresh_profile_guard(root)
    h.execute(['terraform', 'init', '-backend=false', '-input=false', '-no-color', '-lockfile=readonly'], cwd=root, log=directory / 'consumer-init.log')
    return json.loads(h.execute(['terraform', 'show', '-json', str(binary)], cwd=root))


def prove_consumers(workspace, context, consumers, descriptors, *, store=None, plan_reader=None, now=None):
    """Return only the exact consumed dependency subset; no writes or apply calls."""
    environment=context.get('environment')
    h.require(environment in ('dev','prod'),'Unknown consumer environment.')
    registry_name='lifecycle-targets.json' if environment=='dev' else 'lifecycle-targets-prod.json'
    registry = json.loads((Path(workspace) / 'ci' / registry_name).read_text())
    h.require(h.digest(h.canonical(registry)) == context['lifecycle_registry_sha256'], 'Selected consumer registry differs from the approved bundle.')
    h.require(isinstance(consumers, dict) and isinstance(descriptors, dict), 'Invalid selected consumer proof request.')
    state_graph = json.loads((Path(workspace) / 'ci/deploy-roots.json').read_text())['dependencies']
    h.require(isinstance(state_graph, dict), 'The approved State dependency graph is missing or invalid.')
    selected = set(context.get('selected_roots', []))
    h.require(set(consumers) <= selected and set(consumers) <= set(descriptors), 'A live consumer lacks its selected saved-plan descriptor.')
    store = store or h.Store(context['backend']['bucket'], context['account'])
    plan_reader = plan_reader or terraform_plan_json
    current = int(dt.datetime.now(dt.timezone.utc).timestamp()) if now is None else now
    protected_inputs = json.loads(h.required('TF_VARS_JSON'))
    evidence = {}
    for root, item in sorted(consumers.items()):
        row = registry.get('roots', {}).get(root, {})
        contract = ENGINE_CONTRACTS.get(row.get('engine'))
        h.require(row.get('mode') == 'adapter' and contract is not None and root in contract['roots'],
                  'An unregistered consumer engine/root cannot be deferred.')
        descriptor = descriptors[root]
        h.require(isinstance(descriptor, dict) and set(descriptor) == DESCRIPTOR_FIELDS and all(isinstance(value, str) and value for value in descriptor.values()) and
                  descriptor['manifest_version'] != 'null' and all(re.fullmatch('[0-9a-f]{64}', descriptor[field]) for field in ('manifest_sha', 'plan_sha')),
                  'Selected consumer descriptor is incomplete or invalid.')
        h.require(root.startswith('terraform/environments/'+environment+'/'),'Cross-account consumer proof is forbidden.')
        relative = root.removeprefix('terraform/environments/'+environment+'/')
        prefix = f"ci-plans/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{environment}/{relative}/lifecycle-down/"
        h.require(descriptor['manifest_key'] == prefix + 'manifest.json', 'Selected consumer manifest belongs to another run/root.')
        state, fingerprint = item.get('state'), item.get('fingerprint')
        h.require(isinstance(state, dict) and isinstance(fingerprint, dict) and fingerprint.get('exists') is True and
                  fingerprint.get('version') not in (None, '', 'null'), 'Selected consumer State is not pinned to an exact version.')
        with tempfile.TemporaryDirectory(prefix='private-consumer-proof-') as temporary:
            directory = Path(temporary); path = directory / 'manifest.json'
            store.get({'key': descriptor['manifest_key'], 'version': descriptor['manifest_version'], 'sha256': descriptor['manifest_sha']}, path)
            manifest = json.loads(path.read_bytes()); saved = manifest.get('context', {})
            h.require(manifest.get('schema') == 1 and manifest.get('kind') == contract['kind'] and isinstance(saved, dict),
                      'Selected consumer manifest kind is not its registered implementation.')
            expected = {field: context[field] for field in ('repository', 'repository_id', 'run_id', 'run_attempt', 'sha', 'source_sha', 'generation', 'account', 'lifecycle_registry_sha256', 'selected_roots', 'apply_role_arn')}
            expected.update(root=root, environment=environment, workspace='default', operation='down', prefix=prefix,
                            lifecycle_engine=row['engine'], terraform_version='1.16.0', backend={**context['backend'], 'key': relative + '/terraform.tfstate'})
            h.require(all(saved.get(field) == value for field, value in expected.items()), 'Selected consumer source/session/account/backend context differs from the bundle.')
            inputs = protected_inputs.get(relative)
            h.require(isinstance(inputs, dict) and saved.get('input_sha256') == h.digest(h.canonical(inputs)),
                      'Selected consumer inputs differ from the retained protected inputs.')
            h.require(isinstance(saved.get('lock_sha256'), str) and re.fullmatch('[0-9a-f]{64}', saved['lock_sha256']) and
                      isinstance(saved.get('tracked_auto_inputs'), dict), 'Selected consumer source/lock/input binding is incomplete.')
            h.require(type(manifest.get('created_at')) in (int,float) and type(manifest.get('expires_at')) in (int,float) and
                      manifest['created_at'] <= current < manifest['expires_at'] and manifest['expires_at'] - manifest['created_at'] == h.TTL_SECONDS,
                      'Selected consumer plan expired; start a fresh run.')
            marker = f"ci-lifecycle/{context['repository_id']}/{environment}/{relative.replace('/', '-')}.json"
            h.require(manifest.get('state') == fingerprint and manifest.get('control') == store.state(marker),
                      'Selected consumer State or lifecycle control changed since its saved plan.')
            upstream = manifest.get('upstream_states')
            required_upstreams = state_graph.get(root)
            h.require(isinstance(required_upstreams, list) and all(isinstance(name, str) for name in required_upstreams), 'Selected consumer is absent from the approved State dependency graph.')
            optional_upstreams = {'terraform/environments/dev/network/log-storage'} if root == 'terraform/environments/dev/network/vpc' else set()
            h.require(isinstance(upstream, dict) and set(required_upstreams) <= set(upstream) <= set(required_upstreams) | optional_upstreams,
                      'Selected consumer upstream State binding is incomplete or outside the approved State dependency graph.')
            def check_upstreams():
                for upstream_root, pinned in upstream.items():
                    h.require(upstream_root in registry.get('roots', {}) and upstream_root != root and
                              isinstance(upstream_root, str) and re.fullmatch(r'terraform/environments/'+environment+r'/[a-z0-9][a-z0-9/_-]*', upstream_root) and
                              isinstance(pinned, dict) and type(pinned.get('exists')) is bool and
                              (not pinned['exists'] or pinned.get('version') not in (None, '', 'null')),
                              'Selected consumer upstream State identity is invalid.')
                    upstream_key = upstream_root.removeprefix('terraform/environments/'+environment+'/') + '/terraform.tfstate'
                    h.require(store.state(upstream_key) == pinned, 'Selected consumer upstream State changed after its saved plan.')
            check_upstreams()
            binary_info = manifest.get('plan', {})
            h.require(isinstance(binary_info, dict) and binary_info.get('key') == prefix + 'change.tfplan' and
                      binary_info.get('sha256') == descriptor['plan_sha'] and binary_info.get('version') not in (None, '', 'null'),
                      'Selected consumer binary plan descriptor differs from the approved bundle.')
            binary = directory / 'change.tfplan'; store.get(binary_info, binary)
            plan = plan_reader(Path(workspace), directory, manifest, binary, inputs)
            h.validate_effective_inputs(plan, saved)
            proof = validate_registered_delete_plan(state,plan,saved) if contract['kind']=='registered-root-lifecycle' else validate_delete_plan(state, plan)
            h.require(store.state(relative + '/terraform.tfstate') == fingerprint and store.state(marker) == manifest['control'],
                      'Selected consumer State/control changed during proof; create fresh plans.')
            check_upstreams()
            evidence[root] = {'descriptor': dict(descriptor), 'state': fingerprint, 'control': manifest['control'], **proof}
    return evidence
