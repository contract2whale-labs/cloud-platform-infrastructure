import copy
import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

P = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
import argo_reviewed_ops as m


def require(ok, message):
    if not ok:
        raise ValueError(message)


def ident(obj):
    md = obj['metadata']
    return {'uid': md['uid'], 'name': md['name'], 'namespace': md.get('namespace', ''),
            'body_sha256': m.digest({k: v for k, v in obj.items() if k not in ('metadata', 'status')}),
            'metadata_sha256': m.digest({k: md.get(k) for k in ('labels', 'annotations', 'ownerReferences')})}


def obj(kind, namespace, name, uid='original', app=None, api='v1'):
    result = {'apiVersion': api, 'kind': kind,
              'metadata': {'name': name, 'uid': uid, 'resourceVersion': '7'}}
    if namespace:
        result['metadata']['namespace'] = namespace
    if app:
        group = api.split('/')[0] if '/' in api else ''
        result['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': app + ':' + group + '/' + kind + ':' + namespace + '/' + name}
    return result


class ArgoTests(unittest.TestCase):
    def fixture(self, operation=m.IDS[0]):
        env, name, path, resources = m.SCOPES[operation]
        root = 'platform-root-' + env
        sha = 'a' * 40
        leaf = obj('Application', 'argocd', name, 'app-uid', root, 'argoproj.io/v1alpha1')
        leaf['spec'] = {'project': 'platform', 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                        'source': {'repoURL': 'repo', 'targetRevision': sha, 'path': path}}
        leaf['status'] = {'operationState': {'phase': 'Succeeded', 'syncResult': {'revision': sha}}, 'sync': {'revision': sha}, 'resources': []}
        parent = obj('Application', 'argocd', root, 'root-uid', api='argoproj.io/v1alpha1')
        parent['spec'] = {'source': {'targetRevision': sha}}
        parent['status'] = copy.deepcopy(leaf['status'])
        objects = {}
        objects[('applications.argoproj.io', 'argocd', name)] = leaf
        objects[('applications.argoproj.io', 'argocd', root)] = parent
        tracked = []
        uids = {}
        for api, kind, ns, resname in resources:
            row = m.coordinate(api, kind, ns, resname)
            value = obj(kind, ns, resname, 'uid-' + resname, name, api)
            objects[(row['resource'], ns, resname)] = value
            if ns:
                objects[('namespaces', '', ns)] = obj('Namespace', '', ns, 'ns-' + ns)
            tracked.append({'object': value})
            group = api.split('/')[0] if '/' in api else ''
            leaf['status']['resources'].append({'group': group, 'kind': kind, 'namespace': ns, 'name': resname})
            uids[row['key']] = value['metadata']['uid']
        calls = []
        io = types.SimpleNamespace(require=require, identity=ident,
             kube=lambda kind, ns, name, optional=False: copy.deepcopy(objects.get((kind, ns, name))),
             h=types.SimpleNamespace(canonical=lambda x: json.dumps(x).encode(), SafeError=ValueError),
             ops=types.SimpleNamespace(run=lambda *a, **kw: calls.append((a, kw)),
                  sources=lambda spec: spec.get('sources') or [spec['source']],
                  validate_authorities=lambda *a: None))
        c = {'environment': env, 'account_id': '123456789012', 'region': 'ap-northeast-2', 'repository': 'repo',
             'applications': [{'metadata': {'name': name}, 'spec': leaf['spec']}],
             'authority_applications': [{'metadata': {'name': root}, 'spec': parent['spec']}],
             'authority_children': {root: [name]}, 'deferred_applications': [name] if operation == m.IDS[5] else []}
        r = {'source_sha': sha, 'application_uid': 'app-uid', 'data_decision': m.DECISIONS[operation],
             'request_id': '00000000-0000-4000-8000-000000000001', 'target_uids': uids}
        return io, c, r, objects, tracked, calls

    def snapshot(self, io, c, r, tracked, operation=m.IDS[0], docs=None, marker=None):
        with patch.object(m, 'rendered', return_value=(docs or [], 'private diff')), patch.object(m, 'inventory', return_value=tracked):
            return m.snapshot(io, operation, r, c, marker)

    def test_seven_fixed_scopes(self):
        self.assertEqual(len(m.IDS), 7)
        self.assertEqual(len(m.PROD_IDS), 5)
        self.assertEqual(len(m.SCOPES[m.IDS[5]][3]), 4)
        self.assertNotIn('Namespace', m.RESOURCE)

    def test_snapshot_is_read_only_and_deterministic(self):
        io, c, r, objects, tracked, calls = self.fixture()
        self.assertEqual(self.snapshot(io, c, r, tracked), self.snapshot(io, c, r, tracked))
        self.assertEqual(calls, [])

    def test_wrong_environment_rejected_before_reads(self):
        io, c, r, *_ = self.fixture()
        c['environment'] = 'prod'
        with self.assertRaisesRegex(ValueError, 'environment'):
            m.snapshot(io, m.IDS[0], r, c, None)

    def test_wrong_data_decision(self):
        io, c, r, *_ = self.fixture()
        r['data_decision'] = 'delete-everything'
        with self.assertRaisesRegex(ValueError, 'data decision'):
            m.snapshot(io, m.IDS[0], r, c, None)

    def test_resource_still_desired_blocks_retirement(self):
        io, c, r, _, tracked, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, 'still declared'):
            self.snapshot(io, c, r, tracked, docs=[tracked[0]['object']])

    def test_additional_prune_candidate_is_rejected(self):
        io, c, r, _, tracked, _ = self.fixture()
        tracked.append({'object': obj('Pod', 'team-platform-check', 'unapproved', app=m.SCOPES[m.IDS[0]][1])})
        with self.assertRaisesRegex(ValueError, 'Additional'):
            self.snapshot(io, c, r, tracked)

    def test_request_cannot_add_arbitrary_resource(self):
        io, c, r, _, tracked, _ = self.fixture()
        r['target_uids']['/Secret/argocd/credential'] = 'u'
        with self.assertRaisesRegex(ValueError, 'every exact fixed'):
            self.snapshot(io, c, r, tracked)

    def test_replaced_uid_rejected(self):
        io, c, r, objects, tracked, _ = self.fixture()
        objects[('pods', 'team-platform-check', 'agent-log-check')]['metadata']['uid'] = 'replacement'
        with self.assertRaisesRegex(ValueError, 'UID/tracking'):
            self.snapshot(io, c, r, tracked)

    def test_unowned_target_rejected(self):
        io, c, r, _, tracked, _ = self.fixture()
        tracked[0]['object']['metadata'].pop('annotations')
        with self.assertRaisesRegex(ValueError, 'UID/tracking'):
            self.snapshot(io, c, r, tracked)

    def test_automatic_sync_rejected(self):
        io, c, r, _, tracked, _ = self.fixture()
        c['applications'][0]['spec']['syncPolicy'] = {'automated': {'selfHeal': True}}
        with self.assertRaisesRegex(ValueError, 'Automatic'):
            self.snapshot(io, c, r, tracked)

    def test_wrong_authority_tracking_rejected(self):
        io, c, r, objects, tracked, _ = self.fixture()
        objects[('applications.argoproj.io', 'argocd', m.SCOPES[m.IDS[0]][1])]['metadata']['annotations'] = {}
        with self.assertRaisesRegex(ValueError, 'root ownership'):
            self.snapshot(io, c, r, tracked)

    def test_root_must_have_completed_exact_source(self):
        io, c, r, objects, tracked, _ = self.fixture()
        objects[('applications.argoproj.io', 'argocd', 'platform-root-dev')]['status']['operationState']['syncResult']['revision'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'completed'):
            self.snapshot(io, c, r, tracked)

    def test_missing_object_is_not_adopted_as_success(self):
        io, c, r, objects, tracked, _ = self.fixture()
        del objects[('pods', 'team-platform-check', 'agent-log-check')]
        with self.assertRaisesRegex(ValueError, 'Missing retirement'):
            self.snapshot(io, c, r, [])

    def test_absence_after_saved_deletion_intent_is_recoverable(self):
        io, c, r, objects, tracked, _ = self.fixture()
        target = self.snapshot(io, c, r, tracked)
        target['pending_delete'] = target['resources'][0]['key']
        marker = {'owner': 'kubernetes-fixed-operations', 'phase': 'recovery-required', 'operation': m.IDS[0], 'target': target}
        del objects[('pods', 'team-platform-check', 'agent-log-check')]
        recovered = self.snapshot(io, c, r, [], marker=marker)
        self.assertEqual(recovered['completed'], [target['pending_delete']])

    def test_recovery_cannot_change_original_revision_or_uid(self):
        io, c, r, _, tracked, _ = self.fixture()
        target = self.snapshot(io, c, r, tracked)
        marker = {'owner': 'kubernetes-fixed-operations', 'phase': 'recovery-required', 'operation': m.IDS[0], 'target': target}
        r['source_sha'] = 'b' * 40
        self.assertFalse(m.recovery_authorized(m.IDS[0], r, marker))

    def test_configmap_consumer_checks_init_env_and_projected_volume(self):
        name = 'commerce-web-config-abcdefghij'
        for spec in ({'initContainers': [{'env': [{'valueFrom': {'configMapKeyRef': {'name': name}}}]}]},
                     {'volumes': [{'projected': {'sources': [{'configMap': {'name': name}}]}}]},
                     {'containers': [{'envFrom': [{'configMapRef': {'name': name}}]}]}):
            self.assertTrue(m.references_configmap(spec, name))

    def test_cluster_namespace_not_defaulted(self):
        self.assertEqual(m.key({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': 'read'}}, 'argocd')[2], '')

    def test_delete_uses_uid_and_resourceversion(self):
        io, c, r, objects, tracked, calls = self.fixture()
        row = self.snapshot(io, c, r, tracked)['resources'][0]
        live = objects[('pods', 'team-platform-check', 'agent-log-check')]
        sequence = iter([live, None])
        io.kube = lambda *a, **k: next(sequence)
        seen = []
        io.ops.run = lambda args, **kw: seen.append((args, json.loads(pathlib.Path(args[-1]).read_text())))
        m.delete_exact(io, row)
        self.assertEqual(seen[0][1]['preconditions'], {'uid': 'uid-agent-log-check', 'resourceVersion': '7'})
        self.assertEqual(seen[0][0][3], '/api/v1/namespaces/team-platform-check/pods/agent-log-check')
        self.assertNotIn('--prune', seen[0][0])

    def test_delete_replacement_has_no_mutation(self):
        io, c, r, objects, tracked, calls = self.fixture()
        row = self.snapshot(io, c, r, tracked)['resources'][0]
        objects[('pods', 'team-platform-check', 'agent-log-check')]['metadata']['uid'] = 'new'
        with self.assertRaisesRegex(ValueError, 'changed/replaced'):
            m.delete_exact(io, row)
        self.assertEqual(calls, [])

    def test_failure_keeps_durable_recovery_marker(self):
        io, c, r, _, tracked, _ = self.fixture()
        target = self.snapshot(io, c, r, tracked)
        marks = []
        with patch.object(m, 'delete_exact', side_effect=ValueError('interrupted')):
            with self.assertRaisesRegex(ValueError, 'interrupted'):
                m.apply(io, m.IDS[0], target, r, lambda phase, t: marks.append((phase, copy.deepcopy(t))))
        self.assertEqual(marks[-1][0], 'recovery-required')
        self.assertEqual(marks[-1][1]['pending_delete'], target['resources'][0]['key'])
        self.assertNotIn('idle', [phase for phase, _ in marks])

    def test_selective_requires_all_four_desired_resources(self):
        io, c, r, _, tracked, _ = self.fixture(m.IDS[5])
        with self.assertRaisesRegex(ValueError, 'All four'):
            self.snapshot(io, c, r, tracked, m.IDS[5])

    def test_selective_has_exact_four_targets_and_no_whole_app_sync(self):
        io, c, r, _, tracked, _ = self.fixture(m.IDS[5])
        docs = [{k: v for k, v in x['object'].items()} for x in tracked]
        target = self.snapshot(io, c, r, tracked, m.IDS[5], docs)
        self.assertEqual(len(target['resources']), 4)
        self.assertTrue(target['selective'])
        self.assertFalse(target['sync_requested'])

    def test_selective_submits_fixed_cas_and_proves_exact_results(self):
        io, c, r, objects, tracked, calls = self.fixture(m.IDS[5])
        docs = [copy.deepcopy(x['object']) for x in tracked]
        target = self.snapshot(io, c, r, tracked, m.IDS[5], docs)
        patches = []
        def run(args, **kw):
            change = json.loads(args[-1])
            patches.append(change)
            operation = change[-1]['value']
            app = objects[('applications.argoproj.io', 'argocd', 'platform-policies')]
            app['status']['operationState'] = {'phase': 'Succeeded', 'operation': operation,
                'syncResult': {'revision': r['source_sha'], 'resources': [dict(x, status='Synced') for x in operation['sync']['resources']]}}
        io.ops.run = run
        marks = []
        result = m.apply(io, m.IDS[5], target, r, lambda phase, value: marks.append(phase))
        self.assertTrue(result['selective_completed'])
        operation = patches[0][-1]['value']
        self.assertFalse(operation['sync']['prune'])
        self.assertEqual(len(operation['sync']['resources']), 4)
        self.assertEqual(patches[0][0]['path'], '/metadata/uid')
        self.assertEqual(patches[0][1]['path'], '/metadata/resourceVersion')
        self.assertEqual(patches[0][2]['path'], '/spec')
        self.assertEqual(marks[-1], 'idle')

    def test_selective_ambiguous_submit_keeps_observe_only_intent(self):
        io, c, r, objects, tracked, calls = self.fixture(m.IDS[5])
        target = self.snapshot(io, c, r, tracked, m.IDS[5], [copy.deepcopy(x['object']) for x in tracked])
        def fail(*args, **kwargs):
            raise ValueError('network failure')
        io.ops.run = fail
        marks = []
        with self.assertRaisesRegex(ValueError, 'network failure'):
            m.apply(io, m.IDS[5], target, r, lambda phase, value: marks.append((phase, copy.deepcopy(value))))
        self.assertEqual(marks[-1][0], 'recovery-required')
        self.assertTrue(marks[-1][1]['sync_requested'])
        self.assertEqual(marks[-1][1]['sync_token'], target['sync_token'])

    def test_recovery_does_not_adopt_replacement_root(self):
        io, c, r, objects, tracked, _ = self.fixture()
        target = self.snapshot(io, c, r, tracked)
        marker = {'owner': 'kubernetes-fixed-operations', 'phase': 'recovery-required', 'operation': m.IDS[0], 'target': target}
        objects[('applications.argoproj.io', 'argocd', 'platform-root-dev')]['metadata']['uid'] = 'replacement-root'
        with self.assertRaisesRegex(ValueError, 'Original authority'):
            self.snapshot(io, c, r, tracked, marker=marker)

    def test_unknown_argo_status_prune_candidate_is_rejected(self):
        io, c, r, objects, tracked, _ = self.fixture()
        app = objects[('applications.argoproj.io', 'argocd', m.SCOPES[m.IDS[0]][1])]
        app['status']['resources'].append({'group': '', 'kind': 'Secret', 'namespace': 'team-platform-check', 'name': 'unapproved'})
        with self.assertRaisesRegex(ValueError, 'Additional'):
            self.snapshot(io, c, r, tracked)

    def test_scoped_inventory_never_discovers_or_lists_secrets(self):
        io, *_ = self.fixture(m.IDS[2])
        calls = []
        def run(command):
            calls.append(command)
            return json.dumps({'items': []})
        io.ops.run = run
        self.assertEqual(m.inventory(io, m.IDS[2]), [])
        self.assertEqual({x[4] for x in calls}, {'pods', 'networkpolicies.networking.k8s.io'})
        self.assertTrue(all(x[:3] == ['kubectl', '-n', 'monitoring'] for x in calls))
        self.assertTrue(all('--raw' not in x and '--all-namespaces' not in x for x in calls))

    def test_prod_collection_has_exact_prod_source_and_target(self):
        io, c, r, objects, tracked, _ = self.fixture(m.IDS[6])
        target = self.snapshot(io, c, r, tracked, m.IDS[6])
        self.assertEqual(target['application'], 'platform-collection-policy-prod')
        self.assertEqual(target['resources'][0]['key'], '/Pod/team-platform-check/agent-log-check')
        self.assertEqual(target['environment'], 'prod')

    def test_selective_rejects_ordinary_full_sync_registration(self):
        io, c, r, _, tracked, _ = self.fixture(m.IDS[5])
        c['deferred_applications'] = []
        with self.assertRaisesRegex(ValueError, 'deferred_applications'):
            self.snapshot(io, c, r, tracked, m.IDS[5], [x['object'] for x in tracked])

    def test_application_identity_ignores_controller_operation_only(self):
        io, *_ = self.fixture()
        app = obj('Application', 'argocd', 'x')
        old = m.app_identity(io, app)
        app['operation'] = {'sync': {'revision': 'a' * 40}}
        self.assertEqual(m.app_identity(io, app), old)
        app['spec'] = {'malicious': 'change'}
        self.assertNotEqual(m.app_identity(io, app), old)


if __name__ == '__main__':
    unittest.main()
