"""T8 single-node drain via exact UID Evictions, with bounded cordon recovery.

Never uses drain/delete/force, never expands a reviewed Pod set, never edits PDBs.
"""
import copy
import hashlib
import json
import re
import time

IDS = ('node-drain-cycle', 'node-drain-restore')
NS = 'contract2whale-demo'
GROUP = 'contract2whale-dev-eks-app'
LOCK = 'course.openai.com/drain-owner'
LOCK_PATH = '/metadata/annotations/course.openai.com~1drain-owner'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identity(obj):
    md = obj['metadata']
    return {'name': md['name'], 'namespace': md.get('namespace', ''), 'uid': md['uid'],
            'spec_sha256': digest(obj.get('spec', {})),
            'metadata_sha256': digest({k: md.get(k) for k in ('labels', 'annotations', 'ownerReferences')})}


def run(io, args, **kwargs):
    # Every API request is bounded, including restoration after an expired drain.
    return io.ops.run([args[0], '--request-timeout=5s'] + args[1:], **kwargs)


def kube(io, kind, namespace, name, optional=False):
    args = ['kubectl'] + (['-n', namespace] if namespace else []) + ['get', kind, name, '-o', 'json']
    if optional: args.append('--ignore-not-found')
    raw = run(io, args)
    return json.loads(raw) if raw.strip() else None


def inventory(io, node):
    return json.loads(run(io, ['kubectl', 'get', 'pods', '-A', '--field-selector',
                                 'spec.nodeName=' + node, '-o', 'json']))['items']


def pdbs(io):
    return json.loads(run(io, ['kubectl', '-n', NS, 'get', 'pdb', '-o', 'json']))['items']


def ordered(rows):
    return sorted(rows, key=lambda x: (x['namespace'], x['name'], x['uid']))


def matches(io, selector, labels):
    # policy/v1 empty selector selects all; null selects none.
    if selector is None:
        return False
    io.require(set(selector) <= {'matchLabels', 'matchExpressions'}, 'Unsupported PDB selector')
    if any(labels.get(k) != v for k, v in selector.get('matchLabels', {}).items()):
        return False
    for expr in selector.get('matchExpressions', []):
        key, op, values = expr['key'], expr['operator'], expr.get('values', [])
        io.require(op in ('In', 'NotIn', 'Exists', 'DoesNotExist'), 'Unknown PDB selector operator')
        if op == 'In' and (key not in labels or labels[key] not in values): return False
        if op == 'NotIn' and key in labels and labels[key] in values: return False
        if op == 'Exists' and key not in labels: return False
        if op == 'DoesNotExist' and key in labels: return False
    return True


def check_pdbs(io, target, pod=None):
    actual = pdbs(io)
    io.require(ordered([identity(x) for x in actual]) == ordered(target['pdbs']), 'PDB inventory/spec/ownership drift')
    if pod is not None:
        selected = [x for x in actual if matches(io, x['spec'].get('selector'), pod['metadata'].get('labels', {}))]
        io.require(len(selected) == 1, 'Each evicted Pod requires exactly one reviewed PDB; overlaps blocked')
        pdb = selected[0]
        io.require(pdb.get('status', {}).get('observedGeneration', -1) >= pdb['metadata'].get('generation', 1)
                   and pdb.get('status', {}).get('disruptionsAllowed', 0) > 0, 'PDB stale or disruption budget exhausted')
    return actual


def node_current(io, target):
    row = target['node']
    node = kube(io, 'nodes', '', row['name'])
    md, spec = node['metadata'], node['spec']
    io.require(md['uid'] == row['uid'] and spec.get('providerID') == row['provider_id']
               and md.get('labels', {}).get('workload') == 'app'
               and md.get('labels', {}).get('eks.amazonaws.com/nodegroup') == GROUP, 'Original Node identity/ownership changed')
    return node


def check_peer(io, target):
    peer = node_current(io, {'node': target['peer_node']})
    io.require(peer['spec'].get('unschedulable') is not True and any(
        x.get('type') == 'Ready' and x.get('status') == 'True'
        for x in peer.get('status', {}).get('conditions', [])), 'Reviewed remaining Node is not Ready/schedulable')


def cordon(io, target, restore=False):
    node = node_current(io, target)
    md, spec = node['metadata'], node['spec']
    owner = md.get('annotations', {}).get(LOCK)
    before = target['node']['before']
    current = spec.get('unschedulable')
    if restore and owner is None:
        io.require(current == before, 'Cordon changed without this operation lock; preserve it')
        return
    io.require(owner == target['lock'] if restore else owner is None, 'Another drain owner or missing recovery lock')
    io.require(current is True if restore else current == before, 'Another writer changed cordon state')
    actions = [{'op': 'test', 'path': '/metadata/uid', 'value': md['uid']},
               {'op': 'test', 'path': '/metadata/resourceVersion', 'value': md['resourceVersion']}]
    if restore:
        actions += [{'op': 'test', 'path': LOCK_PATH, 'value': target['lock']}, {'op': 'remove', 'path': LOCK_PATH}]
        actions.append({'op': 'remove', 'path': '/spec/unschedulable'} if before is None else
                       {'op': 'add', 'path': '/spec/unschedulable', 'value': before})
    else:
        if 'annotations' not in md: actions.append({'op': 'add', 'path': '/metadata/annotations', 'value': {}})
        actions += [{'op': 'add', 'path': LOCK_PATH, 'value': target['lock']},
                    {'op': 'add', 'path': '/spec/unschedulable', 'value': True}]
    run(io, ['kubectl', 'patch', 'node', md['name'], '--type=json', '-p', json.dumps(actions)])
    after = node_current(io, target)
    io.require(after['spec'].get('unschedulable') == (before if restore else True)
               and after['metadata'].get('annotations', {}).get(LOCK) == (None if restore else target['lock']), 'Cordon write not verified')


def snapshot(io, operation, r, c, marker):
    if operation == 'node-drain-restore':
        io.require(marker and marker.get('operation') in IDS and marker.get('phase') in ('active', 'recovery-required'), 'Original active drain marker required')
        target = copy.deepcopy(marker['target'])
        node = node_current(io, target)
        owner = node['metadata'].get('annotations', {}).get(LOCK)
        io.require((owner == target['lock'] and node['spec'].get('unschedulable') is True) or
                   (owner is None and node['spec'].get('unschedulable') == target['node']['before']), 'Recovery ownership/cordon drift')
        return target
    io.require(operation == 'node-drain-cycle', 'Unknown drain operation')
    io.require(type(r.get('timeout_seconds')) is int and 1 <= r['timeout_seconds'] <= 180, 'Drain timeout must be 1–180 seconds')
    io.require(r.get('restore_original_cordon') is True, 'Review must explicitly authorize original cordon recovery')
    requested = r['node']
    io.require(set(requested) == {'name', 'uid', 'provider_id'} and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]', requested['name']), 'Exact valid Node name/UID/provider review required')
    node = kube(io, 'nodes', '', requested['name'])
    md, spec = node['metadata'], node['spec']
    io.require(md['uid'] == requested['uid'] and spec.get('providerID') == requested['provider_id'], 'Reviewed Node UID/provider differs')
    io.require((spec.get('unschedulable') is None or type(spec.get('unschedulable')) is bool) and LOCK not in md.get('annotations', {}), 'Invalid cordon or existing drain lock')
    io.require(any(x.get('type') == 'Ready' and x.get('status') == 'True' for x in node.get('status', {}).get('conditions', [])), 'Target Node not Ready; no new drain')
    target = {'node': dict(requested, before=spec.get('unschedulable')), 'timeout_seconds': r['timeout_seconds'],
              'pods': copy.deepcopy(r['pods']), 'pdbs': copy.deepcopy(r['pdbs']),
              'peer_node': copy.deepcopy(r['peer_node']),
              'lock': digest({'node': requested, 'request': r})}
    io.require(set(target['peer_node']) == {'name', 'uid', 'provider_id'} and target['peer_node']['name'] != requested['name'] and target['peer_node']['uid'] != requested['uid'] and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]', target['peer_node']['name']), 'One distinct reviewed remaining Node required')
    node_current(io, target)
    check_peer(io, target)
    actual = inventory(io, md['name'])
    io.require(len(actual) <= 100 and len(r['pods']) == len(actual), 'Missing/oversized full Node Pod review')
    reviewed = ordered([{k: v for k, v in x.items() if k not in ('disposition', 'disposable_emptydir')} for x in r['pods']])
    io.require(reviewed == ordered([identity(x) for x in actual]), 'Full Node Pod inventory drift')
    by_uid = {x['metadata']['uid']: x for x in actual}
    evict_count = 0
    for row in target['pods']:
        pod = by_uid[row['uid']]
        owners = [x for x in pod['metadata'].get('ownerReferences', []) if x.get('controller')]
        io.require(len(owners) == 1 and owners[0].get('uid'), 'Unmanaged/ambiguous Pod; no force drain')
        io.require('kubernetes.io/config.mirror' not in pod['metadata'].get('annotations', {}), 'Static/mirror Pod requires separate review')
        if owners[0]['kind'] == 'DaemonSet':
            io.require(row['disposition'] == 'skip-daemonset' and row['disposable_emptydir'] == [], 'DaemonSet must remain untouched')
            continue
        evict_count += 1
        io.require(row['namespace'] == NS and owners[0]['kind'] == 'ReplicaSet' and row['disposition'] == 'evict', 'Only reviewed demo ReplicaSet Pods can be evicted')
        volumes = pod['spec'].get('volumes', [])
        io.require(not any('hostPath' in v for v in volumes), 'hostPath data is not disposable by this operation')
        io.require(sorted(row['disposable_emptydir']) == sorted(v['name'] for v in volumes if 'emptyDir' in v), 'Every emptyDir needs exact disposable-data approval')
        io.require(pod.get('status', {}).get('phase') == 'Running' and not pod['metadata'].get('deletionTimestamp'), 'Only live Running Pods may enter drain review')
        check_pdbs(io, target, pod)
    io.require(evict_count > 0, 'No reviewed workload to drain')
    check_pdbs(io, target)
    return target


def check_remaining(io, target, completed):
    actual = inventory(io, target['node']['name'])
    expected = {x['uid']: x for x in target['pods']}
    for pod in actual:
        uid = pod['metadata']['uid']
        io.require(uid in expected and uid not in completed, 'Unreviewed/new Pod on draining Node')
        row = expected[uid]
        io.require(identity(pod) == {k: v for k, v in row.items() if k not in ('disposition', 'disposable_emptydir')}, 'Reviewed Pod spec/ownership drift')
    io.require(set(expected) - set(completed) == {x['metadata']['uid'] for x in actual}, 'Reviewed Pod disappeared unexpectedly')
    return {x['metadata']['uid']: x for x in actual}


def apply(io, operation, target, r, mark):
    target = copy.deepcopy(target)
    if operation == 'node-drain-cycle':
        target['progress'] = {'attempted_pod_uids': [], 'evicted_pod_uids': []}
    mark('active', target)
    completed = list(target.get('progress', {}).get('evicted_pod_uids', []))
    try:
        if operation == 'node-drain-cycle':
            deadline = time.monotonic() + target['timeout_seconds']
            check_remaining(io, target, completed)
            check_pdbs(io, target)
            check_peer(io, target)
            io.require(time.monotonic() < deadline, 'Drain deadline exceeded before cordon')
            cordon(io, target)
            for row in target['pods']:
                if row['disposition'] == 'skip-daemonset': continue
                io.require(time.monotonic() < deadline, 'Drain deadline exceeded')
                node = node_current(io, target)
                io.require(node['spec'].get('unschedulable') is True and node['metadata'].get('annotations', {}).get(LOCK) == target['lock'], 'Cordon/lock drift during drain')
                pod = check_remaining(io, target, completed)[row['uid']]
                check_pdbs(io, target, pod)
                check_peer(io, target)
                io.require(time.monotonic() < deadline, 'Drain deadline exceeded before eviction')
                body = {'apiVersion': 'policy/v1', 'kind': 'Eviction',
                        'metadata': {'name': row['name'], 'namespace': row['namespace']},
                        'deleteOptions': {'preconditions': {'uid': row['uid'], 'resourceVersion': pod['metadata']['resourceVersion']}}}
                target['progress']['attempted_pod_uids'].append(row['uid'])
                mark('active', target)  # Persist intent before any possibly ambiguous API response.
                io.require(time.monotonic() < deadline, 'Drain deadline exceeded before eviction submission')
                # Exact subresource + UID/RV preconditions; server admission enforces PDB.
                run(io, ['kubectl', 'create', '--raw',
                            '/api/v1/namespaces/' + NS + '/pods/' + row['name'] + '/eviction', '-f', '-'],
                           content=json.dumps(body).encode())
                while True:
                    live = kube(io, 'pods', NS, row['name'], True)
                    if live is None: break
                    io.require(live['metadata']['uid'] == row['uid'], 'Pod name replaced during eviction; stop')
                    io.require(time.monotonic() < deadline, 'Eviction deletion deadline exceeded')
                    time.sleep(1)
                completed.append(row['uid'])
                target['progress']['evicted_pod_uids'] = list(completed)
                mark('active', target)
            remaining = check_remaining(io, target, completed)
            target['drain_observation'] = {'observed_at_unix': int(time.time()), 'remaining_pod_uids': sorted(remaining), 'evicted_pod_uids': list(completed)}
            mark('active', target)
    finally:
        try:
            cordon(io, target, restore=True)
            mark('idle', target)
        except Exception:
            mark('recovery-required', target)
            raise
    return {'evicted_pod_uids': completed, 'restored_node_uid': target['node']['uid'],
            'original_cordon': target['node']['before'], 'application_recovery': 'NOT_MEASURED'}
