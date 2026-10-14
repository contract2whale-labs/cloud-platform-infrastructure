#!/usr/bin/env python3
"""Finite BU01–16 semantic preflights; immutable plans and independent CAS.

This module never deletes cloud resources or runs caller-provided commands. Its
completion claims are deliberately narrower than account-wide service absence.
PITR ownership is proven by fixed-operation receipts and exact resource IDs;
tags can reject an unknown clone, but can never authorize any operation.
"""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

h = load('semantic_saved_plan', 'saved-plan.py')
c = load('semantic_control', 'lifecycle-state.py')
v = load('semantic_state', 'vpc-lifecycle-guard.py')
HOOKS = frozenset('hook:' + x for x in (
    'external-log-consumer-drain', 'incident-quiescence-and-baseline',
    'out-of-state-pitr-inventory', 'reviewed-cleanup', 'service-absence-audit'))
AGGREGATES = frozenset({'hook:reviewed-cleanup', 'hook:service-absence-audit'})
# An alias is a capability provided by a selected, authenticated execution step,
# never an extra shell action or a fabricated successful no-op receipt.
ALIASES = {
    'minimum-argo-bootstrap': {'provider_hooks': ['platform-core'], 'retained_roots': [],
        'source': 'gitops/gitops-lifecycle.py:run -> operations-access.verify_bootstrap_receipt'},
    'prod-minimum-argo-bootstrap': {'provider_hooks': ['platform-core'], 'retained_roots': [],
        'source': 'gitops/gitops-lifecycle.py:run -> operations-access.verify_bootstrap_receipt'},
    'app-auth-provision-and-securitypolicy': {'provider_hooks': ['platform-gateway'],
        'retained_roots': ['platform/app-auth'],
        'source': 'gitops/lifecycle_hooks.py:GATEWAY includes gateway-auth; Cognito and verifier Secret root retained'},
}
MAX_OBJECTS = 10000
MAX_VERSIONS = 30000


def descriptor(value):
    h.require(isinstance(value, dict) and set(value) == {'key', 'version', 'sha256'} and
              all(isinstance(x, str) and x for x in value.values()) and value['version'] != 'null' and
              re.fullmatch('[0-9a-f]{64}', value['sha256']), 'Exact immutable private descriptor required.')
    return value


def read(store, value):
    descriptor(value)
    with tempfile.TemporaryDirectory(prefix='private-semantic-proof-') as directory:
        path = Path(directory) / 'proof.json'; store.get(value, path)
        return json.loads(path.read_bytes())


def listing(store, prefix, versions=False):
    """Explicit pagination with cycle/size fences; never silently truncate."""
    result = []; cursor = (); seen = set()
    while True:
        args = ['--prefix', prefix, '--max-keys', '1000', '--no-paginate', *cursor]
        value = store.call('list-object-versions' if versions else 'list-objects-v2', *args)
        field = 'Versions' if versions else 'Contents'
        rows = value.get(field, [])
        h.require(isinstance(rows, list), 'Invalid private inventory response.')
        h.require(not value.get('DeleteMarkers'), 'Deleted retained incident history requires explicit reconciliation.')
        for row in rows:
            h.require(isinstance(row, dict) and isinstance(row.get('Key'), str) and row['Key'].startswith(prefix), 'Private inventory escaped its prefix.')
            if versions:
                h.require(isinstance(row.get('VersionId'), str) and row['VersionId'] not in ('', 'null'), 'Unversioned incident history.')
            result.append(row)
        h.require(len(result) <= (MAX_VERSIONS if versions else MAX_OBJECTS), 'Private inventory bound exceeded; review exact history separately.')
        if value.get('IsTruncated') is False:
            break
        h.require(value.get('IsTruncated') is True, 'Private listing completeness is unknown.')
        token = ((value.get('NextKeyMarker'), value.get('NextVersionIdMarker')) if versions
                 else (value.get('NextContinuationToken'),))
        h.require(all(isinstance(x, str) and x for x in token) and token not in seen, 'Private pagination token is missing or cyclic.')
        seen.add(token)
        cursor = (('--key-marker', token[0], '--version-id-marker', token[1]) if versions
                  else ('--continuation-token', token[0]))
    keys = [(r['Key'], r.get('VersionId')) for r in result]
    h.require(len(keys) == len(set(keys)), 'Duplicate private inventory identity.')
    return result


def version_json(store, key, version):
    with tempfile.TemporaryDirectory(prefix='private-semantic-marker-') as directory:
        path = Path(directory) / 'marker.json'
        metadata = store.call('get-object', '--key', key, '--version-id', version, str(path))
        h.require(metadata.get('VersionId') == version and metadata.get('ServerSideEncryption') in h.ENCRYPTION, 'Incident history version/encryption changed.')
        raw = path.read_bytes()
        return json.loads(raw), {'key': key, 'version': version, 'sha256': h.digest(raw)}


def retained_scope(context, course):
    return {'step_id': context['step_id'], 'snapshot_sha': context['snapshot_sha'],
            'generation': context['generation'], 'roots': course['roots'],
            'retained_roots': course['retained_roots'], 'steps': course['steps'],
            'input_sha256': h.digest(h.canonical(course['inputs'])),
            'claims': 'finite registered source ownership; retained storage may incur cost; no account-wide absence claim'}


def incident_clear(store, context):
    c.assert_incident_clear(store, context)
    key = c.incident_marker_key(context['repository_id'], context['environment'])
    record, info = c.read_json(store, key)
    return {'shared_marker': info, 'phase': 'never-started' if record is None else record['phase'],
            'scope': 'shared fixed-operation recovery owner is idle; individual object cleanup is checked by owner hooks'}


def external_consumer(store, context, course, reader=None):
    root = 'terraform/environments/' + context['environment'] + '/account-integrations'
    inputs = course['inputs'].get(root)
    h.require(isinstance(inputs, dict), 'Retained account-integrations inputs are missing.')
    enabled = inputs.get('enable_external_log_consumer')
    if 'enable_external_log_consumer' not in inputs:
        source = h.execute(['git','show',context['snapshot_sha'] + ':modules/account-integrations/variables.tf'], cwd=Path(h.required('GITHUB_WORKSPACE'))).decode()
        declarations = re.findall(r'variable\s+"enable_external_log_consumer"\s*\{([^{}]*)\}', source)
        h.require(len(declarations) == 1 and re.search(r'(?m)^\s*default\s*=\s*false\s*(?:#.*)?$', declarations[0]) is not None, 'Cannot establish actual optional-consumer source default.')
        enabled = False
    h.require(enabled is False,
              'Enabled external log consumer requires an implemented producer freeze and recipient drain; lifecycle cannot assert it from queue depth.')
    reader = reader or v.VersionedStateReader(store.bucket, context['account'], context['backend']['region'])
    current = reader('account-integrations/terraform.tfstate')
    h.require(current['state'] is not None, 'Account-integrations State is unavailable; absence is not a disabled-feature proof.')
    rows = v.managed_resources(current['state'])
    forbidden = {'aws_sqs_queue', 'aws_sqs_queue_policy', 'aws_s3_bucket_notification'}
    for row in rows:
        h.require(row['type'] not in forbidden and row.get('name') not in ('external_log_consumer', 'log_queue_age'),
                  'External consumer resources remain despite disabled checkpoint; exact drain/reconciliation required.')
    return {'source_flag': False, 'state': current['fingerprint'], 'external_resources': [],
            'scope': 'optional BU11 consumer disabled; S3 logs retained'}


def fixed_receipt(store, desc, context, operation):
    value = read(store, desc)
    rc = value.get('context', {}); request = value.get('request', {})
    h.require(isinstance(rc, dict) and isinstance(request, dict) and value.get('status') == 'verified', 'Fixed AWS operation has no verified completion.')
    h.require(rc.get('repository_id') == context['repository_id'] and rc.get('account') == context['account'] and
              rc.get('operation') == operation and request.get('operation') == operation and
              request.get('account') == context['account'] and request.get('environment') == 'dev' and
              request.get('region') == context['backend']['region'] and request.get('incident_run') == rc.get('incident_run'),
              'Fixed AWS operation receipt belongs to another target.')
    h.require(all(isinstance(rc.get(k), str) and rc[k].isdigit() for k in ('run_id', 'run_attempt')) and
              re.fullmatch('[0-9a-f]{40}', rc.get('sha', '')) and
              re.fullmatch('[0-9a-f-]{36}', rc.get('incident_run', '')), 'Invalid original AWS operation run identity.')
    suffix = f"{rc['repository_id']}/{rc['run_id']}/{rc['run_attempt']}/{rc['sha']}/dev/incident/{operation}/"
    h.require(desc['key'] == 'ci-logs/' + suffix + 'apply/receipt.json', 'Fixed receipt namespace mismatch.')
    plan_desc = descriptor(value.get('plan'))
    h.require(plan_desc['key'] == 'ci-plans/' + suffix + 'plan.json', 'Fixed plan namespace mismatch.')
    plan = read(store, plan_desc)
    h.require(plan.get('schema') == 1 and plan.get('kind') == 'incident-fixed-action' and plan.get('context') == rc and
              plan.get('request') == request and rc.get('request_sha256') == h.digest(h.canonical(request)), 'Original fixed action differs from its verified receipt.')
    when = dt.datetime.fromisoformat(value['completed_at'].replace('Z', '+00:00')).timestamp()
    h.require(type(plan.get('created_at')) in (int, float) and type(plan.get('expires_at')) in (int, float) and
              plan['created_at'] <= when and plan['created_at'] < plan['expires_at'] <= plan['created_at'] + h.TTL_SECONDS,
              'Invalid fixed-action timing.')
    return value, plan


def aws_list(context, service, operation, field, *args):
    value = h.aws(service, operation, *args, '--region', context['backend']['region'])
    h.require(isinstance(value, dict) and not any(value.get(k) for k in ('Marker', 'NextMarker', 'NextToken', 'IsTruncated')) and
              isinstance(value.get(field), list), 'Incomplete authenticated service inventory; absence remains unknown.')
    return value[field]


def pitr_inventory(store, context):
    """All retained AWS marker versions, not just last action or current tags."""
    if context['environment'] == 'prod':
        return {'scope': 'BU16 fixed PITR producer is Dev-only', 'clones': [], 'unknown_tagged_clones': []}
    prefix = f"ci-lifecycle/{context['repository_id']}/dev/incident-aws-"
    load('pitr_history_retention','eks-lifecycle.py').check_retention(store, prefix)
    history = listing(store, prefix, versions=True)
    latest = {}; completions = {}; identities = []
    for row in history:
        h.require(re.fullmatch(re.escape(prefix) + r'[0-9a-f-]{36}\.json', row['Key']), 'Unknown fixed AWS marker key.')
        marker, desc = version_json(store, row['Key'], row['VersionId'])
        rc = marker.get('context', {})
        h.require(marker.get('schema') == 1 and rc.get('repository_id') == context['repository_id'] and
                  rc.get('account') == context['account'] and row['Key'] == prefix + rc.get('incident_run', '') + '.json', 'Fixed AWS history ownership mismatch.')
        if row.get('IsLatest') is True:
            h.require(row['Key'] not in latest and marker.get('phase') == 'idle', 'AWS fixed operation is pending/uncertain; reconcile exact owner before lifecycle.')
            latest[row['Key']] = desc
        if marker.get('phase') == 'idle' and rc.get('operation') in ('rds-pitr-create', 'rds-clone-delete'):
            d = descriptor(marker.get('completion')); completions[(d['key'], d['version'])] = d
        identities.append(desc)
    h.require(set(latest) == {r['Key'] for r in history}, 'Fixed operation history lacks a current idle owner.')
    created = {}; deleted = {}
    for desc in completions.values():
        operation = 'rds-pitr-create' if '/rds-pitr-create/' in desc['key'] else 'rds-clone-delete'
        receipt, plan = fixed_receipt(store, desc, context, operation)
        request = receipt['request']; db = receipt.get('result', {}).get('DBInstance', {})
        key = (db.get('DBInstanceArn'), db.get('DbiResourceId'))
        h.require(all(isinstance(x, str) and x for x in key) and db.get('DBInstanceIdentifier') == request['target_db_identifier'], 'Clone receipt has no exact created resource identity.')
        if operation == 'rds-pitr-create':
            h.require(receipt.get('observations', {}).get('status') == 'available', 'Clone creation was not observed.')
            created[key] = {'receipt': desc, 'request': request, 'database': db}
        else:
            source, _ = fixed_receipt(store, descriptor(request.get('creation_receipt')), context, 'rds-pitr-create')
            original = source.get('result', {}).get('DBInstance', {})
            h.require((original.get('DBInstanceArn'), original.get('DbiResourceId')) == key and
                      request['target_db_identifier'] == source['request']['target_db_identifier'] and
                      receipt.get('observations', {}).get('status') == 'absent' and
                      request.get('retain_all_s3_and_existing_backups') is True,
                      'Deleted clone does not match original creation/retention proof.')
            h.require(plan.get('observation', {}).get('identity', {}).get('target_resource_id') == key[1], 'Delete plan exact clone resource ID is missing.')
            deleted[key] = {'receipt': desc, 'request': request, 'database': db, 'observations': receipt['observations']}
    h.require(set(deleted) <= set(created), 'Clone deletion has no retained creation checkpoint history.')
    live = aws_list(context, 'rds', 'describe-db-instances', 'DBInstances')
    proof = []
    for key, item in created.items():
        h.require(key in deleted, 'Out-of-State PITR clone has no exact verified cleanup receipt; use its fixed deletion workflow before Down.')
        h.require(not any(x.get('DBInstanceArn') == key[0] or x.get('DbiResourceId') == key[1] or
                          x.get('DBInstanceIdentifier') == item['request']['target_db_identifier'] for x in live), 'PITR target still exists or its name was reused.')
        removal = deleted[key]; request = removal['request']
        snapshots = aws_list(context, 'rds', 'describe-db-snapshots', 'DBSnapshots', '--db-snapshot-identifier', request['final_snapshot_identifier'])
        h.require(len(snapshots) == 1, 'Retained final PITR snapshot is unavailable.')
        snap = snapshots[0]
        h.require(snap.get('DBSnapshotArn') == removal['observations'].get('retained_final_snapshot_arn') and
                  snap.get('DbiResourceId') == key[1] and snap.get('DBInstanceIdentifier') == request['target_db_identifier'] and
                  snap.get('Status') == 'available' and snap.get('Encrypted') is True and
                  snap.get('KmsKeyId') == removal['observations'].get('kms_key'), 'Final PITR snapshot identity/status/key differs.')
        proof.append({'clone_arn': key[0], 'resource_id': key[1], 'status': 'absent', 'creation': item['receipt'],
                      'deletion': removal['receipt'], 'retained_snapshot_arn': snap['DBSnapshotArn'], 'kms_key': snap['KmsKeyId']})
    for db in live:
        tags = aws_list(context, 'rds', 'list-tags-for-resource', 'TagList', '--resource-name', db['DBInstanceArn'])
        # A tag is a rejection signal only. It cannot approve adoption/deletion.
        tags = {x['Key']: x['Value'] for x in tags}
        h.require(tags.get('Purpose') != 'incident-pitr-drill', 'An unaccounted or live tagged PITR clone requires exact receipt reconciliation.')
    return {'scope': 'all retained fixed AWS marker versions and exact course PITR resource identities',
            'marker_versions': sorted(identities, key=lambda x: (x['key'], x['version'])),
            'clones': sorted(proof, key=lambda x: x['clone_arn']), 'unknown_tagged_clones': []}


def root_completion(store, context, course, root):
    env = context['environment']; suffix = '/'.join(root.split('/')[3:])
    marker, _ = c.read_json(store, f"ci-lifecycle/{context['repository_id']}/{env}/{suffix.replace('/', '-')}.json")
    h.require(isinstance(marker, dict) and marker.get('root') == root and marker.get('snapshot_sha') == context['snapshot_sha'] and
              marker.get('generation') == context['generation'] and marker.get('operation') == context['operation'] and
              marker.get('last_result') == context['operation'] + '_complete', 'Root has no exact completed lifecycle owner checkpoint.')
    desc = descriptor(marker.get('completion')); receipt = read(store, desc); rc = receipt.get('context', {})
    h.require(receipt.get('schema') == 1 and receipt.get('kind') in (
        'vpc-lifecycle-completion', 'network-lifecycle-completion', 'eks-lifecycle-completion',
        'registered-root-lifecycle-completion', 'later-runtime-lifecycle-completion') and
        all(rc.get(k) == context[k] for k in ('repository_id', 'account', 'generation', 'operation', 'environment')) and
        rc.get('root') == root and rc.get('source_sha') == context['snapshot_sha'], 'Root completion receipt scope differs.')
    expected = f"ci-logs/{context['repository_id']}/{rc['run_id']}/{rc['run_attempt']}/{rc['sha']}/{env}/{suffix}/lifecycle-{context['operation']}/apply/completion.json"
    h.require(desc['key'] == expected, 'Root completion namespace differs.')
    state = receipt.get('state'); h.require(isinstance(state, dict) and state.get('exists') is True and state.get('version') not in (None, '', 'null'), 'Root completion State version is missing.')
    h.require(store.state(suffix + '/terraform.tfstate') == state, 'Root State changed after its completion proof.')
    evidence = receipt.get('service_evidence', receipt.get('completion_evidence'))
    return {'root': root, 'receipt': desc, 'state': state, 'evidence': evidence,
            'scope': 'exact-approved-managed-state-only' if receipt['kind'] == 'registered-root-lifecycle-completion' else
                     'own-adapter-service-observations', 'account_wide_absence': False}


def aggregate(store, context, course):
    roots = [r for r in course['steps'] if not r.startswith('hook:')]
    if context['operation'] == 'up':
        # Reverse-DAG audits run first on Up, validating the retained Down result.
        return {'scope': 'retained cleanup contract; each owning Up step must produce its own fresh completion',
                'planned_roots': roots, 'completed_roots': [], 'retained_roots': course['retained_roots'], 'account_wide_absence': False}
    h.require(set(roots) <= set(course['completed']), 'Audit must run after every selected runtime root completion.')
    results = [root_completion(store, context, course, root) for root in roots]
    return {'scope': 'registered source root completion receipts with explicitly bounded per-root evidence',
            'planned_roots': roots, 'completed_roots': results, 'retained_roots': course['retained_roots'], 'account_wide_absence': False}


def observation(store, context, course, final=False):
    step = context['step_id']; shared = incident_clear(store, context)
    if step == 'hook:external-log-consumer-drain': details = external_consumer(store, context, course)
    elif step == 'hook:out-of-state-pitr-inventory': details = pitr_inventory(store, context)
    elif step in AGGREGATES:
        details = aggregate(store, context, course) if final else {'deferred': True, 'scope': 'final ordered-prefix completion audit'}
    else: details = {'scope': 'shared incident owner quiescence; out-of-State operations have their own required inventory hook'}
    return {'incident': shared, 'details': details}


def settings(stage):
    step = h.required('LIFECYCLE_STEP_ID'); h.require(step in HOOKS, 'Unregistered semantic hook.')
    env = h.required('LIFECYCLE_ENVIRONMENT'); h.require(env in ('dev', 'prod'), 'Unknown semantic environment.')
    op = h.required('OPERATION'); h.require(op in ('down', 'up'), 'Unknown semantic operation.')
    h.require(h.required('GITHUB_ACTIONS') == 'true' and h.required('GITHUB_REF') == 'refs/heads/main' and h.required('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Semantic hooks require protected trusted CI dispatch.')
    context = {k: h.required(x) for k, x in {'repository_id':'GITHUB_REPOSITORY_ID', 'run_id':'GITHUB_RUN_ID', 'run_attempt':'GITHUB_RUN_ATTEMPT', 'sha':'GITHUB_SHA', 'snapshot_sha':'LIFECYCLE_SNAPSHOT_SHA', 'generation':'LIFECYCLE_GENERATION', 'registry_sha256':'LIFECYCLE_CONFIG_SHA256', 'completed_chapter':'COMPLETED_CHAPTER'}.items()}
    h.require(all(context[k].isdigit() for k in ('repository_id','run_id','run_attempt')) and all(re.fullmatch('[0-9a-f]{40}', context[k]) for k in ('sha','snapshot_sha')) and re.fullmatch(r'\d+-\d+', context['generation']) and re.fullmatch('[0-9a-f]{64}', context['registry_sha256']), 'Invalid semantic checkpoint identity.')
    account = h.required('EXPECTED_ACCOUNT_ID'); region = h.required('AWS_REGION'); bucket = h.required('STATE_BUCKET')
    h.require(re.fullmatch(r'\d{12}', account) and region == 'ap-northeast-2', 'Unknown semantic account/region.')
    role = 'lifecycle-destroy' if op == 'down' else 'plan' if env == 'prod' and stage == 'plan' else 'apply'
    expected = f'arn:aws:iam::{account}:role/gha-infra-{env}-{role}'
    h.require(h.required('AWS_ROLE_ARN') == expected, 'Semantic execution role mismatch.')
    h.refresh_profile_guard(); h.check_identity(account, expected)
    workspace = Path(h.required('GITHUB_WORKSPACE')).resolve()
    h.require(h.execute(['git','rev-parse','HEAD'], cwd=workspace).decode().strip() == context['sha'], 'Semantic helper checkout differs.')
    h.execute(['git','merge-base','--is-ancestor',context['snapshot_sha'],context['sha']], cwd=workspace)
    h.execute(['git','diff','--quiet',context['snapshot_sha'],context['sha'],'--','terraform','modules'], cwd=workspace)
    h.ensure_current_main(context)
    context.update(step_id=step, environment=env, operation=op, account=account,
                   root=f'terraform/environments/{env}/eks', backend={'bucket':bucket,'region':region},
                   registration_sha256=h.digest(Path(__file__).read_bytes()))
    namespace = 'ci-plans' if op == 'down' else 'ci-up-plans'
    context['prefix'] = f"{namespace}/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{env}/hooks/{step[5:]}/lifecycle-{op}/"
    store = h.Store(bucket, account); store.check()
    key = f"ci-lifecycle/{context['repository_id']}/{env}/hook-{step[5:]}.json"
    load('semantic_retention','eks-lifecycle.py').check_retention(store, key)
    course = course_record(store, context)
    return store, key, context, course


def course_record(store, context):
    course, _ = c.read_json(store, c.course_marker_key(context['repository_id'], context['environment']))
    c.validate_course(course, context['repository_id'], context['account'], context['backend']['bucket'], context['backend']['region'], context['environment'])
    h.require(course['phase'] == 'paused' and all(course[k] == context[k] for k in ('operation','generation','snapshot_sha','registry_sha256','completed_chapter')) and context['step_id'] in course['steps'], 'Semantic hook differs from retained course owner.')
    order = list(reversed(course['steps'])) if context['operation'] == 'down' else course['steps']
    h.require(course['completed'] == order[:len(course['completed'])], 'Invalid ordered completed prefix.')
    return course


def validate_record(record, context, scope):
    h.require(isinstance(record, dict) and record.get('schema') == 1 and
              all(record.get(k) == context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')) and
              record.get('original') == scope, 'Semantic checkpoint/source/registration changed.')


def validate_result(step, operation, snapshot, result, generation, context=None, binding=None):
    h.require(step in HOOKS and isinstance(result, dict) and result.get('checkpoint_generation') == generation and
              result.get('semantic_contract') == snapshot and result.get('no_cloud_mutation') is True and
              result.get('account_wide_absence') is False and isinstance(result.get('observation'), dict), 'Semantic completion contract differs.')
    details = result['observation'].get('details', {})
    h.require(details.get('deferred') is not True, 'Deferred semantic checks cannot become completion.')
    h.require(result['observation'].get('incident', {}).get('phase') in ('idle','never-started'), 'Incident quiescence is missing.')
    if step == 'hook:out-of-state-pitr-inventory':
        h.require(isinstance(details.get('clones'), list) and details.get('unknown_tagged_clones') == [] and all(x.get('status') == 'absent' for x in details['clones']), 'PITR exact absence proof is missing.')
    if step == 'hook:external-log-consumer-drain':
        h.require(details.get('source_flag') is False and details.get('external_resources') == [], 'Enabled consumer cannot use disabled no-op proof.')
    if step in AGGREGATES and operation == 'down':
        h.require([x.get('root') for x in details.get('completed_roots', [])] == details.get('planned_roots') and details.get('account_wide_absence') is False, 'Finite root audit is incomplete.')


def run(stage):
    h.require(stage in ('start','plan','verify','apply'), 'Unknown semantic lifecycle stage.')
    os.umask(0o077)
    store, key, context, course = settings(stage); record, control = c.read_json(store, key)
    scope = retained_scope(context, course); op = context['operation']
    if stage == 'start':
        if record is None or (record.get('phase') == 'active' and op == 'down'):
            h.require(op == 'down', 'No retained semantic Down checkpoint exists for Up.')
            record = {'schema':1, **{k:context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')}, 'original':scope, 'phase':'paused'}
        validate_record(record, context, scope)
        # Read-only checks may be safely repeated; no arbitrary ownership takeover.
        record.update(request_context=context, operation=op, phase='paused')
        c.update(store, key, record, control); h.emit({'snapshot_sha':context['snapshot_sha']}); return
    validate_record(record, context, scope)
    h.require(record.get('request_context') == context and record.get('operation') == op and record.get('phase') == 'paused', 'Semantic request owner changed.')
    observed = observation(store, context, course)
    binding = {'contract_sha256':h.digest(h.canonical(scope))}
    payload = {'step_id':context['step_id'], 'operation':op, 'snapshot':scope}
    prefix = context['prefix']
    with tempfile.TemporaryDirectory(prefix='private-semantic-plan-') as directory:
        temp = Path(directory)
        if stage == 'plan':
            stamp = dt.datetime.now(dt.timezone.utc).timestamp()
            path = temp/'actions.json'; path.write_bytes(h.canonical(payload))
            review = temp/'review.json'; review.write_bytes(h.canonical({'context':context,'contract':scope,'preflight':observed,'effect':'read-only completion/preflight; only private CAS metadata writes'}))
            manifest = {'schema':1,'kind':'gitops-lifecycle','context':context,'control':control,'binding':binding,'created_at':stamp,'expires_at':stamp+h.TTL_SECONDS,'plan':store.put(prefix+'actions.json',path),'review':store.put(prefix+'review.json',review)}
            path = temp/'manifest.json'; path.write_bytes(h.canonical(manifest)); d = store.put(prefix+'manifest.json',path)
            h.emit({'manifest_key':d['key'],'manifest_version':d['version'],'manifest_sha':d['sha256'],'plan_sha':manifest['plan']['sha256']}); return
        desc = {'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('EXPECTED_MANIFEST_SHA')}
        h.require(desc['key'] == prefix+'manifest.json', 'Semantic manifest belongs to another run.')
        manifest = read(store, desc); now = dt.datetime.now(dt.timezone.utc).timestamp()
        h.require(manifest.get('schema') == 1 and manifest.get('kind') == 'gitops-lifecycle' and manifest.get('context') == context and manifest.get('control') == control and manifest.get('binding') == binding and manifest['created_at'] <= now < manifest['expires_at'] and manifest['expires_at']-manifest['created_at'] == h.TTL_SECONDS, 'Semantic manifest control/source/TTL changed.')
        h.require(manifest['plan']['key'] == prefix+'actions.json' and manifest['plan']['sha256'] == h.required('EXPECTED_PLAN_SHA') and read(store, manifest['plan']) == payload, 'Semantic approved action bytes differ.')
        if stage == 'verify': return
        h.ensure_current_main(context)
        latest, info = c.read_json(store, key); h.require(latest == record and info == control, 'Semantic CAS owner changed before completion.')
        course = course_record(store, context)
        record.update(last_result=op+'-applying', claimed_manifest=desc)
        control = c.update(store, key, record, control)
        observed = observation(store, context, course, final=True)
        result = {'checkpoint_generation':context['generation'],'semantic_contract':scope,'no_cloud_mutation':True,'account_wide_absence':False,'observation':observed}
        validate_result(context['step_id'],op,scope,result,context['generation'],context,binding)
        completed = dt.datetime.now(dt.timezone.utc).timestamp(); h.require(completed < manifest['expires_at'], 'Semantic observation exceeded reviewed plan TTL.')
        path = temp/'receipt.json'; path.write_bytes(h.canonical({'schema':1,'kind':'gitops-lifecycle-completion','context':context,'plan_sha':manifest['plan']['sha256'],'completed_at':completed,'result':result}))
        rd = store.put(prefix.replace('ci-up-plans/','ci-logs/',1).replace('ci-plans/','ci-logs/',1)+'apply/receipt.json',path)
        record.update(last_result=op+'-complete',receipt=rd,phase='active' if op == 'up' else 'paused')
        c.update(store,key,record,control)
        h.emit({'receipt_key':rd['key'],'receipt_version':rd['version'],'receipt_sha':rd['sha256']})

if __name__ == '__main__':
    try: run(sys.argv[1])
    except Exception: raise SystemExit('Semantic lifecycle check stopped; retain pause and review exact private evidence. No cloud cleanup was inferred.')
