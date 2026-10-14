"""Seven reviewed source operations: bounded selective sync or UID-bound retirement.

Called only by the incident saved-plan dispatcher. No CLI, shell, caller manifest,
Application deletion, automated sync, blanket prune, or arbitrary resource selector.
"""
import copy
import hashlib
import json
import pathlib
import re
import tempfile
import time
import uuid

IDS = ('argo-collection-log-retire', 'argo-queue-admin-dev-retire',
       'argo-queue-admin-prod-retire', 'argo-backup-probe-retire',
       'argo-commerce-config-retire', 'argo-platform-policies-selective',
       'argo-collection-log-prod-retire')
PROD_IDS = IDS[2:]
# Environment, exact source Application, exact source path, fixed resources.
SCOPES = {
    IDS[0]: ('dev', 'platform-collection-policy-dev', 'gitops/platform/collection-policy/overlays/dev',
             [('v1', 'Pod', 'team-platform-check', 'agent-log-check')]),
    IDS[6]: ('prod', 'platform-collection-policy-prod', 'gitops/platform/collection-policy/overlays/prod',
             [('v1', 'Pod', 'team-platform-check', 'agent-log-check')]),
    IDS[1]: ('dev', 'platform-queue-admin-dev', 'gitops/platform/queue-admin/requests/dev',
             [('v1', 'Pod', 'monitoring', 'queue-admin'), ('networking.k8s.io/v1', 'NetworkPolicy', 'monitoring', 'queue-admin')]),
    IDS[2]: ('prod', 'platform-queue-admin-prod', 'gitops/platform/queue-admin/requests/prod',
             [('v1', 'Pod', 'monitoring', 'queue-admin'), ('networking.k8s.io/v1', 'NetworkPolicy', 'monitoring', 'queue-admin')]),
    IDS[3]: ('prod', 'platform-backup-probe-prod', 'gitops/platform/backup-probe/overlays/prod',
             [('v1', 'Pod', 'backup-probe', 'writer'), ('v1', 'PersistentVolumeClaim', 'backup-probe', 'data')]),
    IDS[4]: ('prod', 'commerce-web-prod', 'gitops/apps/commerce-web/overlays/prod', []),
    IDS[5]: ('prod', 'platform-policies', 'gitops/platform/overlays/prod',
             [('v1', 'ConfigMap', 'argocd', 'delivery-env')]
             + [('kyverno.io/v1', 'ClusterPolicy', '', name) for name in
                ('verify-image-signature', 'restrict-image-registries', 'require-image-digest')]),
}
RESOURCE = {'Pod': 'pods', 'NetworkPolicy': 'networkpolicies',
            'PersistentVolumeClaim': 'persistentvolumeclaims', 'ConfigMap': 'configmaps',
            'ClusterPolicy': 'clusterpolicies'}
DECISIONS = {IDS[0]: 'delete-exact-agent-log-check-pod',
             IDS[6]: 'delete-exact-agent-log-check-pod',
             IDS[1]: 'delete-exact-queue-admin-pod-and-networkpolicy',
             IDS[2]: 'delete-exact-queue-admin-pod-and-networkpolicy',
             IDS[3]: 'delete-exact-original-disposable-probe-pod-pvc-and-volume',
             IDS[4]: 'delete-exact-unreferenced-old-commerce-configmap',
             IDS[5]: 'sync-only-delivery-env-and-three-image-policies'}
SHA = re.compile(r'[0-9a-f]{40}')
CLUSTER_KINDS = {'Namespace', 'Node', 'PersistentVolume', 'ClusterRole', 'ClusterRoleBinding',
                 'CustomResourceDefinition', 'StorageClass', 'PriorityClass', 'GatewayClass',
                 'ClusterIssuer', 'ClusterPolicy', 'ValidatingAdmissionPolicy',
                 'ValidatingAdmissionPolicyBinding', 'MutatingWebhookConfiguration',
                 'ValidatingWebhookConfiguration', 'VolumeSnapshotClass', 'VolumeSnapshotContent'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def key(obj, default_namespace=''):
    md = obj['metadata']
    group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
    namespace = md.get('namespace', '' if obj['kind'] in CLUSTER_KINDS else default_namespace)
    return (group, obj['kind'], namespace, md['name'])


def coordinate(api_version, kind, namespace, name):
    group = api_version.split('/')[0] if '/' in api_version else ''
    resource = RESOURCE[kind]
    return {'apiVersion': api_version, 'kind': kind, 'namespace': namespace, 'name': name,
            'resource': resource + ('.' + group if group else ''),
            'key': '/'.join((group, kind, namespace, name)),
            'api_path': ('/apis/' + api_version if group else '/api/v1')
                        + ('/namespaces/' + namespace if namespace else '') + '/' + resource + '/' + name}


def scope(io, operation, r, c):
    io.require(operation in IDS, 'Unregistered reviewed Argo operation.')
    env, app, path, resources = SCOPES[operation]
    if operation == IDS[3]:
        io.require(c['environment'] in ('dev', 'prod'), 'Unknown backup retirement environment.')
        env = c['environment']; app = 'platform-backup-probe-' + env
        path = 'gitops/platform/backup-probe/overlays/' + env
    io.require(c['environment'] == env, 'Reviewed Argo environment differs.')
    io.require(SHA.fullmatch(r['source_sha']), 'Immutable approved Git revision required.')
    io.require(r.get('data_decision') == DECISIONS[operation], 'Exact reviewed data decision required.')
    resources = list(resources)
    if operation == IDS[4]:
        old = r.get('old_configmap_name', '')
        io.require(re.fullmatch(r'commerce-web-config-[a-z0-9]{10}', old), 'Exact old hashed commerce ConfigMap required.')
        resources.append(('v1', 'ConfigMap', 'contract2whale-demo', old))
    return app, path, [coordinate(*row) for row in resources]


def app_identity(io, app):
    # operation is transient controller work, not the retained App declaration.
    return io.identity({k: v for k, v in app.items() if k != 'operation'})


def quiet(io, app):
    auto = app['spec'].get('syncPolicy', {}).get('automated')
    io.require(auto is None or auto.get('enabled') is False, 'Automatic reconciliation must remain disabled.')
    io.require(not app.get('operation') and app.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
               'Concurrent Application operation blocks reviewed mutation.')


def completed_revision(io, app):
    state = app.get('status', {}).get('operationState', {})
    result = state.get('syncResult', {})
    actual = result.get('revisions') or [result.get('revision')]
    expected = [s['targetRevision'] for s in io.ops.sources(app['spec'])]
    io.require(state.get('phase') == 'Succeeded' and actual == expected,
               'Retained authority/leaf must have completed its exact registered revisions.')


def authority_snapshot(io, c, name, revision, app_uid, allow_running=False, selective=False):
    io.ops.validate_authorities(c, c['environment'])
    declarations = {a['metadata']['name']: a for a in c['applications'] + c['authority_applications']}
    owners = {child: parent for parent, children in c['authority_children'].items() for child in children}
    io.require(name in declarations and name in owners, 'Leaf needs a retained source app-of-apps owner.')
    chain = []
    current = name
    while current:
        wanted = declarations[current]
        live = io.kube('applications.argoproj.io', 'argocd', current)
        io.require(live['spec'] == wanted['spec'], 'Application differs from reviewed source authority declaration.')
        if current == name:
            io.require(live['metadata']['uid'] == app_uid, 'Reviewed leaf Application UID changed.')
            src = io.ops.sources(live['spec'])
            io.require(len(src) == 1 and src[0]['targetRevision'] == revision, 'Leaf must use one exact approved Git revision.')
        if not (current == name and allow_running):
            quiet(io, live)
        else:
            auto = live['spec'].get('syncPolicy', {}).get('automated')
            io.require(auto is None or auto.get('enabled') is False, 'Automatic sync appeared during selective recovery.')
        if current != name or not selective:
            completed_revision(io, live)
        parent = owners.get(current)
        if parent:
            expected = parent + ':argoproj.io/Application:argocd/' + current
            io.require(live['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == expected,
                       'Source root ownership/tracking identity differs.')
        chain.append({'name': current, 'identity': app_identity(io, live), 'spec': copy.deepcopy(live['spec'])})
        current = parent
    return chain


def rendered(io, c, app, revision):
    import yaml
    with tempfile.TemporaryDirectory(prefix='reviewed-argo-') as tmp:
        with io.ops.argo_connection(c, pathlib.Path(tmp)) as command:
            raw = io.ops.run(command + ['app', 'manifests', app, '--revision', revision])
            # This is read-only; both outputs stay in the private same-action plan.
            diff = io.ops.run(command + ['app', 'diff', app, '--revision', revision, '--exit-code=false'])
    docs = [x for x in yaml.safe_load_all(raw) if x is not None]
    io.ops.validate_images(docs)
    io.ops.validate_ownership(docs)
    for obj in docs:
        md = obj.get('metadata', {})
        ann = md.get('annotations', {})
        io.require(md.get('name') and not md.get('generateName'), 'Generated/unnamed resource unsupported.')
        io.require(not ann.get('argocd.argoproj.io/hook'), 'Reviewed operations never execute hooks.')
        options = {x.strip() for x in ann.get('argocd.argoproj.io/sync-options', '').split(',')}
        io.require(not options & {'Force=true', 'Replace=true', 'Prune=true'}, 'Force/replace/prune option prohibited.')
    if isinstance(diff, bytes):
        diff = diff.decode()
    return docs, diff


def application_resource_keys(io, app):
    status = app.get('status', {})
    rows = status.get('resources')
    io.require(isinstance(rows, list), 'Complete Argo comparison resource inventory unavailable.')
    io.require(not any(x.get('type') in ('ComparisonError', 'InvalidSpecError', 'UnknownError') for x in status.get('conditions', [])),
               'Argo comparison error prevents a complete reviewed inventory.')
    keys = {(x.get('group', ''), x['kind'], x.get('namespace', ''), x['name']) for x in rows}
    io.require(len(keys) == len(rows), 'Duplicate Argo comparison resource.')
    return keys


def inventory(io, operation):
    # Finite Kubernetes list permissions. Never cluster-wide API discovery or Secret reads.
    env, app, path, resources = SCOPES[operation]
    kinds = {(coordinate(api, kind, ns, name)['resource'], ns) for api, kind, ns, name in resources}
    if operation == IDS[4]:
        kinds = {('configmaps', 'contract2whale-demo'), ('pods', 'contract2whale-demo')}
    if operation == IDS[5]:
        return []  # Exact selected object GETs below; unrelated policy resources are not fetched.
    result = []
    for resource, ns in sorted(kinds):
        raw = json.loads(io.ops.run(['kubectl', '-n', ns, 'get', resource, '-o', 'json']))
        io.require(not raw.get('metadata', {}).get('continue'), 'Incomplete scoped resource inventory.')
        result.extend({'object': obj} for obj in raw['items'])
    return result


def tracked(io, objects, app):
    rows = {}
    for item in objects:
        obj = item['object']
        track = obj.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id', '')
        if track.startswith(app + ':'):
            k = key(obj)
            io.require(k not in rows, 'Duplicate tracked resource identity.')
            expected = app + ':' + k[0] + '/' + k[1] + ':' + k[2] + '/' + k[3]
            io.require(track == expected, 'Malformed/foreign tracking identity.')
            rows[k] = obj
    return rows


def references_configmap(value, name):
    if isinstance(value, dict):
        for field in ('configMapRef', 'configMapKeyRef', 'configMap'):
            if isinstance(value.get(field), dict) and value[field].get('name') == name:
                return True
        return any(references_configmap(x, name) for x in value.values())
    return isinstance(value, list) and any(references_configmap(x, name) for x in value)


def no_config_consumers(io, objects, namespace, name):
    # Includes Pending, completed and terminating Pods; old ReplicaSet history may remain.
    pods = [x['object'] for x in objects if x['object']['kind'] == 'Pod'
            and x['object']['metadata'].get('namespace') == namespace]
    io.require(not any(references_configmap(p.get('spec', {}), name) for p in pods),
               'A live/terminating Pod still references the old ConfigMap.')
    return sorted([io.identity(p) for p in pods], key=lambda p: p['name'])


def recovery_authorized(operation, r, marker):
    if operation not in IDS or not marker or marker.get('owner') != 'kubernetes-fixed-operations' or marker.get('operation') != operation:
        return False
    t = marker.get('target', {})
    return (t.get('source_sha') == r.get('source_sha') and t.get('application_uid') == r.get('application_uid')
            and t.get('request_uids') == r.get('target_uids')
            and t.get('request_id') == r.get('request_id') and t.get('data_decision') == r.get('data_decision'))


def snapshot(io, operation, r, c, marker, store=None):
    app, path, rows = scope(io, operation, r, c)
    request_id = str(uuid.UUID(r['request_id']))
    io.require(request_id == r['request_id'], 'Canonical request UUID required for exact recovery identity.')
    previous = None
    if marker and marker.get('phase') != 'idle':
        io.require(recovery_authorized(operation, r, marker), 'Only exact original reviewed Argo recovery may continue.')
        previous = marker['target']
    selective = operation == IDS[5]
    if selective:
        io.require(app in c.get('deferred_applications', []),
                   'Selective stage requires reviewed deferred_applications registration to prevent ordinary full sync.')
    observing = bool(selective and previous and previous.get('sync_requested'))
    chain = authority_snapshot(io, c, app, r['source_sha'], r['application_uid'], observing, selective)
    source = io.ops.sources(chain[0]['spec'])[0]
    io.require(source['path'] == path and source['repoURL'] == c['repository'], 'Unregistered Argo source path/repository.')
    docs, diff = rendered(io, c, app, r['source_sha'])
    if previous:
        io.require(chain == previous['authority_chain'] and digest(docs) == previous['render_sha256'],
                   'Original authority identities or approved rendered source changed during recovery.')
    default_namespace = chain[0]['spec']['destination']['namespace']
    desired = {key(x, default_namespace): x for x in docs}
    io.require(len(desired) == len(docs), 'Ambiguous duplicate desired resource.')
    objects = inventory(io, operation)
    live = tracked(io, objects, app)
    application = io.kube('applications.argoproj.io', 'argocd', app)
    status_keys = application_resource_keys(io, application)
    io.require(application.get('status', {}).get('sync', {}).get('revision') == r['source_sha'],
               'Argo current comparison revision differs from approved source.')
    selected = {tuple(row['key'].split('/')) for row in rows}
    expected_uids = r.get('target_uids')
    io.require(isinstance(expected_uids, dict) and set(expected_uids) == {row['key'] for row in rows},
               'Request must enumerate every exact fixed target UID (null only for selective creation).')
    if selective:
        io.require(selected <= set(desired), 'All four selected resources must be in approved desired Git.')
    else:
        io.require(not selected & set(desired), 'Retiring object is still declared by approved Git.')
        # The complete actual tracked prune difference, not just status.resources.
        io.require((set(live) | status_keys) - set(desired) <= selected, 'Additional unapproved stale/prune resource found.')
        if operation in (IDS[1], IDS[2], IDS[3]):
            io.require(not desired, 'Queue/backup retirement requires exact empty desired request.')
    completed = list(previous.get('completed', [])) if previous else []
    prior_rows = {row['key']: row for row in previous['resources']} if previous else {}
    for row in rows:
        k = tuple(row['key'].split('/'))
        obj = io.kube(row['resource'], row['namespace'], row['name'], True)
        uid = expected_uids[row['key']]
        if selective and obj is not None:
            live.update(tracked(io, [{'object': obj}], app))
        if observing:
            # Observe the original operation only. Never resubmit an uncertain sync.
            row.update(copy.deepcopy(prior_rows[row['key']]))
            continue
        if obj is None and not selective:
            known = previous and (row['key'] in completed or previous.get('pending_delete') == row['key'])
            io.require(known, 'Missing retirement object has no original UID-bound deletion intent.')
            row.update(copy.deepcopy(prior_rows[row['key']]))
            if row['key'] not in completed:
                completed.append(row['key'])
            continue
        if obj is None:
            io.require(uid is None, 'Selective creation must explicitly approve absent UID null.')
        else:
            io.require(obj['metadata']['uid'] == uid and k in live and io.identity(live[k]) == io.identity(obj),
                       'Target UID/tracking ownership changed; never adopt another resource.')
            io.require(not obj['metadata'].get('ownerReferences'), 'Controlled child is not a direct reviewed target.')
            io.require(not obj['metadata'].get('deletionTimestamp'), 'Target already deleting; use original recovery evidence.')
            if previous:
                io.require(io.identity(obj) == prior_rows[row['key']]['identity'], 'Original recovery object changed/replaced.')
        row['identity'] = io.identity(obj) if obj is not None else None
        if selective:
            row['desired'] = copy.deepcopy(desired[k])
    result = {'operation': operation, 'source_sha': r['source_sha'], 'request_id': request_id,
              'data_decision': r['data_decision'], 'application': app, 'application_uid': r['application_uid'],
              'authority_chain': chain, 'resources': rows, 'request_uids': expected_uids,
              'render_sha256': digest(docs), 'desired_manifests': docs,
              'application_resources': sorted('/'.join(k) for k in status_keys),
              'diff_sha256': hashlib.sha256(diff.encode()).hexdigest(), 'reviewed_diff': diff,
              'tracked_inventory': sorted([{'key': '/'.join(k), 'identity': io.identity(obj)} for k, obj in live.items()], key=lambda x: x['key']),
              'completed': completed, 'environment': c['environment'], 'account': c['account_id'],
              'region': c['region'], 'selective': selective}
    namespaces = {row['namespace'] for row in rows if row['namespace']}
    result['namespaces'] = {ns: io.identity(io.kube('namespaces', '', ns)) for ns in sorted(namespaces)}
    if previous:
        io.require(result['namespaces'] == previous['namespaces'], 'Original namespace identity changed during recovery.')
    if operation == IDS[4]:
        result['pod_inventory'] = no_config_consumers(io, objects, 'contract2whale-demo', r['old_configmap_name'])
        io.require(any(k[1] == 'ConfigMap' and k[2] == 'contract2whale-demo' and re.fullmatch(r'commerce-web-config-[a-z0-9]{10}', k[3]) for k in desired),
                   'Current replacement hashed ConfigMap must remain declared.')
    if operation == IDS[3]:
        import velero_ops
        result['storage_proof'] = velero_ops.original_retirement_proof(io, r, c, store, previous)
    if selective:
        result['sync_token'] = previous['sync_token'] if observing else digest({'request_id': request_id, 'source': r['source_sha'], 'resources': rows, 'app_uid': r['application_uid']})
        result['sync_requested'] = observing
    return result


def guard(io, target, allow_running=False):
    for row in target['authority_chain']:
        live = io.kube('applications.argoproj.io', 'argocd', row['name'])
        io.require(app_identity(io, live) == row['identity'] and live['spec'] == row['spec'], 'Source authority/leaf changed after review.')
        if not (allow_running and row['name'] == target['application']):
            quiet(io, live)
        if row['name'] == target['application'] and not target['selective']:
            desired = {key(x, live['spec']['destination']['namespace']) for x in target['desired_manifests']}
            selected = {tuple(x['key'].split('/')) for x in target['resources']}
            io.require(application_resource_keys(io, live) - desired <= selected, 'Additional Argo prune candidate appeared.')
    for ns, identity in target['namespaces'].items():
        io.require(io.identity(io.kube('namespaces', '', ns)) == identity, 'Namespace identity changed.')


def delete_exact(io, row):
    obj = io.kube(row['resource'], row['namespace'], row['name'])
    io.require(io.identity(obj) == row['identity'], 'Retirement target changed/replaced.')
    options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
               'preconditions': {'uid': row['identity']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']}}
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / 'delete.json'
        path.write_bytes(io.h.canonical(options))
        io.ops.run(['kubectl', 'delete', '--raw', row['api_path'], '-f', str(path)])
    for _ in range(120):
        current = io.kube(row['resource'], row['namespace'], row['name'], True)
        if current is None:
            return
        io.require(current['metadata']['uid'] == row['identity']['uid'], 'Replacement object appeared; no repeated delete.')
        time.sleep(5)
    raise io.h.SafeError('Exact retirement not complete; retain recovery marker, never force finalizers.')


def subset(expected, actual):
    """Server defaults may add fields; every approved desired field must match."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and subset(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(subset(x, y) for x, y in zip(expected, actual))
    return expected == actual


def selective_sync(io, target, mark):
    if not target.get('sync_requested'):
        guard(io, target)
        app = io.kube('applications.argoproj.io', 'argocd', target['application'])
        for row in target['resources']:
            live = io.kube(row['resource'], row['namespace'], row['name'], True)
            io.require((io.identity(live) if live else None) == row['identity'], 'Selected resource changed after review.')
        selectors = [{'group': row['key'].split('/')[0], 'kind': row['kind'], 'namespace': row['namespace'], 'name': row['name']} for row in target['resources']]
        operation = {'initiatedBy': {'username': 'course-reviewed-ci'},
                     'info': [{'name': 'course-reviewed-action', 'value': target['sync_token']}],
                     'sync': {'revision': target['source_sha'], 'prune': False, 'resources': selectors,
                              'syncOptions': ['ServerSideApply=true']}}
        # Durable intent BEFORE the API call. Ambiguous response is observe-only recovery.
        target['sync_requested'] = True
        mark('active', target)
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': target['application_uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': app['metadata']['resourceVersion']},
                 {'op': 'test', 'path': '/spec', 'value': app['spec']},
                 {'op': 'add', 'path': '/operation', 'value': operation}]
        io.ops.run(['kubectl', '-n', 'argocd', 'patch', 'applications.argoproj.io', target['application'], '--type=json', '-p', json.dumps(patch)])
    for _ in range(120):
        guard(io, target, allow_running=True)
        app = io.kube('applications.argoproj.io', 'argocd', target['application'])
        state = app.get('status', {}).get('operationState', {})
        info = state.get('operation', {}).get('info', [])
        matching = {'name': 'course-reviewed-action', 'value': target['sync_token']} in info
        if matching and state.get('phase') in ('Failed', 'Error', 'Terminating'):
            raise io.h.SafeError('Exact selective operation failed; review original operation, no full sync fallback.')
        if matching and state.get('phase') == 'Succeeded' and not app.get('operation'):
            result = state.get('syncResult', {})
            io.require((result.get('revisions') or [result.get('revision')]) == [target['source_sha']], 'Selective operation revision differs.')
            actual = result.get('resources', [])
            keys = {(x.get('group', ''), x['kind'], x.get('namespace', ''), x['name']) for x in actual}
            wanted = {tuple(row['key'].split('/')) for row in target['resources']}
            io.require(keys == wanted and len(actual) == len(wanted) and all(x.get('status') == 'Synced' for x in actual), 'Selective result includes missing, failed, or extra resources.')
            for row in target['resources']:
                obj = io.kube(row['resource'], row['namespace'], row['name'])
                io.require(subset(row['desired'], obj), 'Selected desired resource not verified in live API.')
                expected_tracking = target['application'] + ':' + row['key'].split('/')[0] + '/' + row['kind'] + ':' + row['namespace'] + '/' + row['name']
                io.require(obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == expected_tracking, 'Selected resource ownership differs.')
            return {'selective_completed': True, 'resource_count': 4, 'full_application_health_claimed': False}
        time.sleep(5)
    raise io.h.SafeError('Selective operation outcome pending/unknown; observe original marker, never resubmit.')


def apply(io, operation, target, r, mark):
    io.require(operation in IDS and target['operation'] == operation and target['source_sha'] == r['source_sha'], 'Reviewed action identity differs.')
    mark('active', target)
    try:
        if target['selective']:
            result = selective_sync(io, target, mark)
        else:
            for row in target['resources']:
                guard(io, target)
                if row['key'] in target['completed']:
                    io.require(io.kube(row['resource'], row['namespace'], row['name'], True) is None, 'Previously deleted target reappeared; no new deletion.')
                    continue
                if operation == IDS[4]:
                    no_config_consumers(io, inventory(io, operation), row['namespace'], row['name'])
                if operation == IDS[3]:
                    import velero_ops
                    velero_ops.verify_original_retirement(io, target['storage_proof'], target['completed'])
                target['pending_delete'] = row['key']
                mark('active', target)
                delete_exact(io, row)
                target['completed'].append(row['key'])
                target.pop('pending_delete', None)
                mark('active', target)
            if operation == IDS[3]:
                import velero_ops
                velero_ops.verify_original_volume_absent(io, target['storage_proof'])
            guard(io, target)
            for row in target['resources']:
                io.require(io.kube(row['resource'], row['namespace'], row['name'], True) is None, 'Retired target reappeared before completion.')
            result = {'retired': target['completed'], 'source_sha': target['source_sha'], 'blanket_prune_used': False,
                      'retained_applications': [x['name'] for x in target['authority_chain']]}
        mark('idle', target)
        return result
    except Exception:
        mark('recovery-required', target)
        raise
