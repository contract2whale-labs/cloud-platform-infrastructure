#!/usr/bin/env python3
"""VPC 수명주기 제어 기록. 비만료 private S3, apply 역할만 CAS 갱신."""
import importlib.util
import json
import re
from pathlib import Path
import tempfile

ROOT = 'terraform/environments/dev/network/vpc'
KEY = 'network/vpc/terraform.tfstate'

def helper():
    spec = importlib.util.spec_from_file_location('saved_plan_lifecycle', Path(__file__).with_name('saved-plan.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def marker_key(repo_id):
    if not str(repo_id).isdigit():
        raise ValueError('Invalid repository ID.')
    return f'ci-lifecycle/{repo_id}/dev/network-vpc.json'


def course_marker_key(repo_id, environment='dev'):
    if not str(repo_id).isdigit() or environment not in ('dev', 'prod'):
        raise ValueError('Invalid repository ID.')
    return f'ci-lifecycle/{repo_id}/{environment}/course.json'


def incident_marker_key(repo_id, environment):
    if not str(repo_id).isdigit() or environment not in ('dev', 'prod'):
        raise ValueError('Invalid incident repository/environment.')
    return f'ci-incidents/{repo_id}/{environment}/active.json'


def assert_incident_clear(store, context):
    """Only the incident owner's fixed recovery workflow may resolve its marker."""
    h = helper()
    parts = context['root'].split('/')
    h.require(len(parts) >= 4 and parts[:2] == ['terraform', 'environments'] and parts[2] in ('dev', 'prod'), 'Invalid incident target root.')
    environment = parts[2]
    record, _ = read_json(store, incident_marker_key(context['repository_id'], environment))
    if record is None:
        return
    expected = dict(repository_id=context['repository_id'], environment=environment, account=context['account'],
                    bucket=context['backend']['bucket'], region=context['backend']['region'])
    h.require(isinstance(record, dict) and type(record.get('schema')) is int and record['schema'] == 1 and
              all(record.get(key) == value for key, value in expected.items()) and
              record.get('owner') in ('aws-fixed-operations', 'kubernetes-fixed-operations') and
              record.get('phase') in ('idle', 'active', 'recovery-required') and
              isinstance(record.get('generation'), str) and re.fullmatch(r'\d+-\d+', record['generation']) and
              isinstance(record.get('operation'), str) and record['operation'] and
              isinstance(record.get('request_context'), dict) and isinstance(record.get('target'), dict),
              'Invalid incident checkpoint; fixed owner-aware recovery is required.')
    h.require(record['phase'] == 'idle', 'An incident is active or needs recovery. Complete its matching fixed recovery operation before Terraform or lifecycle changes.')


def validate_course(record, repository_id, account, bucket, region, environment="dev"):
    h = helper()
    h.require(isinstance(record, dict) and record.get('schema') == 2 and
              record.get('kind') == 'course-lifecycle' and record.get('repository_id') == str(repository_id) and
              record.get('account') == account and record.get('bucket') == bucket and record.get('region') == region and
              record.get('phase') in ('paused', 'active') and record.get('operation') in ('down', 'up'),
              'Invalid course lifecycle checkpoint; administrator review is required.')
    h.require(isinstance(record.get('completed_chapter'), str) and re.fullmatch(r'BU\d\d[ABC]?', record['completed_chapter']) and
              isinstance(record.get('snapshot_sha'), str) and re.fullmatch('[0-9a-f]{40}', record['snapshot_sha']) and
              isinstance(record.get('registry_sha256'), str) and re.fullmatch('[0-9a-f]{64}', record['registry_sha256']) and
              isinstance(record.get('generation'), str) and re.fullmatch(r'\d+-\d+', record['generation']),
              'Incomplete course source/map checkpoint.')
    h.require(environment in ('dev', 'prod') and record.get('environment', 'dev') == environment, 'Course checkpoint environment mismatch.')
    roots = record.get('roots')
    h.require(isinstance(roots, list) and len(roots) == len(set(roots)) and all(isinstance(root, str) and
              re.fullmatch('terraform/environments/' + environment + '/[a-z0-9][a-z0-9/_-]*', root) and '..' not in root.split('/') for root in roots),
              'Invalid checkpoint root inventory.')
    h.require(isinstance(record.get('retained_roots'), list) and set(record['retained_roots']) <= set(roots) and
              isinstance(record.get('inputs'), dict) and set(record['inputs']) <= set(roots) and
              all(isinstance(value, dict) for value in record['inputs'].values()) and
              isinstance(record.get('locks'), dict) and set(record['locks']) == set(record['inputs']) and
              all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in record['locks'].values()) and
              isinstance(record.get('completed'), list) and set(record['completed']) <= set(record.get('steps', record['inputs'])) and
              isinstance(record.get('events'), list), 'Invalid retained root/input/completion checkpoint.')
    steps = record.get('steps', list(record['inputs']))
    h.require(isinstance(steps, list) and len(steps) == len(set(steps)) and all(isinstance(step, str) and
              (step in record['inputs'] or re.fullmatch('hook:[a-z][a-z0-9-]*', step)) for step in steps), 'Invalid lifecycle step inventory.')
    barriers = record.get('barriers', {})
    h.require(isinstance(barriers, dict) and all(step in steps and step.startswith('hook:') and isinstance(proof, dict) and set(proof) == {'plan', 'receipt', 'operation'} and proof['operation'] in ('down', 'up') and isinstance(proof['plan'], dict) and isinstance(proof['receipt'], dict) for step, proof in barriers.items()), 'Invalid completed hook barrier inventory.')
    contracts = record.get('contracts', {})
    h.require(isinstance(contracts, dict) and set(contracts) <= set(record['inputs']) and all(isinstance(value, dict) for value in contracts.values()), 'Invalid retained root lifecycle contracts.')


def read_json(store, key):
    """403/조회 실패를 부재로 바꾸지 않고, head로 고정한 버전만 읽습니다."""
    h = helper(); info = store.state(key)
    if not info['exists']:
        return None, info
    h.require(bool(info.get('version')) and info['version'] != 'null', 'Versioned lifecycle object required.')
    with tempfile.TemporaryDirectory(prefix='private-lifecycle-read-') as directory:
        path = Path(directory) / 'object.json'
        meta = store.call('get-object', '--key', key, '--version-id', info['version'], str(path))
        h.require(meta.get('VersionId') == info['version'] and meta.get('ServerSideEncryption') in h.ENCRYPTION, 'Lifecycle object version/encryption mismatch.')
        return json.loads(path.read_bytes()), info


def validate(record, repository_id, account, bucket, region):
    h = helper()
    h.require(isinstance(record, dict) and record.get('schema') == 1 and record.get('root') == ROOT
              and record.get('repository_id') == str(repository_id) and record.get('account') == account
              and record.get('bucket') == bucket and record.get('region') == region
              and record.get('phase') in ('paused', 'active'), 'Invalid lifecycle control record; administrator review required.')
    h.require(isinstance(record.get('inputs'), dict) and isinstance(record.get('snapshot_sha'), str) and re.fullmatch('[0-9a-f]{40}', record['snapshot_sha'])
              and isinstance(record.get('generation'), str), 'Incomplete lifecycle snapshot.')


def update(store, key, record, previous):
    """기록 삭제 없이 갱신하며 다른 실행의 변경을 덮어쓰지 않습니다."""
    h = helper()
    with tempfile.TemporaryDirectory(prefix='private-lifecycle-write-') as directory:
        path = Path(directory) / 'control.json'; path.write_bytes(h.canonical(record))
        condition = ['--if-match', previous['etag']] if previous.get('exists') else ['--if-none-match', '*']
        result = store.call('put-object', '--key', key, '--body', str(path), *condition)
        h.require(result.get('VersionId') not in (None, '', 'null') and result.get('ServerSideEncryption') in h.ENCRYPTION, 'Lifecycle control write was not verified; stop.')
        return {'exists': True, 'version': result['VersionId'], 'etag': result['ETag'], 'size': path.stat().st_size}


def affected(workspace, root):
    graph = json.loads((Path(workspace) / 'ci/deploy-roots.json').read_text())['dependencies']
    reached = {ROOT}
    while True:
        extra = {name for name, deps in graph.items() if set(deps) & reached}
        if extra <= reached:
            return root in reached
        reached |= extra


def assert_normal_allowed(store, context, workspace):
    assert_incident_clear(store, context)
    # A multi-root Down stays paused across failures and all later Up roots.
    # Retained foundations are also frozen: they carry the restore identity/data.
    environment = context['root'].split('/')[2]
    if environment in ('dev', 'prod'):
        course, _ = read_json(store, course_marker_key(context['repository_id'], environment))
        if course is not None:
            validate_course(course, context['repository_id'], context['account'], context['backend']['bucket'], context['backend']['region'], environment)
            helper().require(course['phase'] == 'active', 'The completed chapter is lifecycle-paused. Use the matching common Up workflow; ordinary deployment remains blocked.')
    if not affected(workspace, context['root']):
        return
    record, _ = read_json(store, marker_key(context['repository_id']))
    if record is None:
        return
    validate(record, context['repository_id'], context['account'], context['backend']['bucket'], context['backend']['region'])
    helper().require(record['phase'] == 'active', 'Dev VPC is lifecycle-paused. Ordinary VPC/consumer deployment is blocked; use the VPC up workflow.')
