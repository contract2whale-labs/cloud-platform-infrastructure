import copy
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import drain_ops as m

class Blocked(Exception): pass

def require(ok, message):
    if not ok: raise Blocked(message)

class Drain(unittest.TestCase):
    def setUp(self):
        self.node = {'metadata': {'name': 'node-a', 'uid': 'node-uid', 'resourceVersion': '1', 'labels': {'workload': 'app', 'eks.amazonaws.com/nodegroup': m.GROUP}}, 'spec': {'providerID': 'aws:///az/i-ab'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        self.peer = copy.deepcopy(self.node)
        self.peer['metadata'].update(name='node-b', uid='peer-uid')
        self.peer['spec']['providerID'] = 'aws:///az/i-cd'
        self.pod = {'metadata': {'name': 'web-a', 'namespace': m.NS, 'uid': 'pod-uid', 'resourceVersion': '2', 'labels': {'app': 'web'}, 'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'web-rs', 'uid': 'rs-uid', 'controller': True}]}, 'spec': {'nodeName': 'node-a', 'volumes': [{'name': 'cache', 'emptyDir': {}}]}, 'status': {'phase': 'Running'}}
        self.pods = [self.pod]
        self.pdb = {'metadata': {'name': 'web-pdb', 'namespace': m.NS, 'uid': 'pdb-uid', 'generation': 1}, 'spec': {'maxUnavailable': 1, 'selector': {'matchLabels': {'app': 'web'}}}, 'status': {'observedGeneration': 1, 'disruptionsAllowed': 1}}
        self.budgets = [self.pdb]
        self.calls = []
        self.io = types.SimpleNamespace(require=require, ops=types.SimpleNamespace(run=self.run_command))
        self.request = {'node': {'name': 'node-a', 'uid': 'node-uid', 'provider_id': 'aws:///az/i-ab'}, 'timeout_seconds': 180, 'restore_original_cordon': True}
        self.request['peer_node'] = {'name': 'node-b', 'uid': 'peer-uid', 'provider_id': 'aws:///az/i-cd'}
        self.review()

    def review(self):
        self.request['pods'] = [dict(m.identity(p), disposition='evict', disposable_emptydir=['cache']) for p in self.pods]
        self.request['pdbs'] = [m.identity(p) for p in self.budgets]

    def run_command(self, args, **kw):
        self.calls.append((args, kw))
        self.assertIn('--request-timeout=5s', args)
        if 'patch' in args:
            for action in json.loads(args[-1]):
                parts = [x.replace('~1', '/').replace('~0', '~') for x in action['path'].split('/')[1:]]
                parent = self.node
                for key in parts[:-1]: parent = parent[key]
                key = parts[-1]
                if action['op'] == 'test': require(parent[key] == action['value'], 'CAS failed')
                elif action['op'] == 'add': parent[key] = action['value']
                elif action['op'] == 'remove': del parent[key]
            return b'{}'
        if 'create' in args:
            body = json.loads(kw['content'])
            self.assertEqual(body['kind'], 'Eviction')
            self.assertEqual(body['deleteOptions']['preconditions'], {'uid': 'pod-uid', 'resourceVersion': '2'})
            self.pods = []
            return b'{}'
        if 'nodes' in args: return json.dumps(self.peer if 'node-b' in args else self.node).encode()
        if 'pdb' in args: return json.dumps({'items': self.budgets}).encode()
        if '--field-selector' in args: return json.dumps({'items': self.pods}).encode()
        if 'pods' in args:
            result = next((p for p in self.pods if p['metadata']['name'] == args[args.index('pods')+1]), None)
            return json.dumps(result).encode() if result else b''
        raise AssertionError(args)

    def snapshot(self): return m.snapshot(self.io, 'node-drain-cycle', self.request, {}, None)
    def cycle(self):
        target = self.snapshot(); marks = []
        result = m.apply(self.io, 'node-drain-cycle', target, self.request, lambda phase, target: marks.append(phase))
        return target, result, marks

    def test_full_cycle_exact_eviction_restores_absent(self):
        _, result, marks = self.cycle()
        self.assertEqual(marks[0], 'active'); self.assertEqual(marks[-1], 'idle')
        self.assertNotIn('unschedulable', self.node['spec'])
        self.assertNotIn(m.LOCK, self.node['metadata']['annotations'])
        self.assertEqual(result['evicted_pod_uids'], ['pod-uid'])
        self.assertEqual(result['application_recovery'], 'NOT_MEASURED')
        commands = [x[0] for x in self.calls]
        self.assertFalse(any('drain' in x or 'delete' in x or '--force' in x or '--disable-eviction' in x for x in commands))

    def test_false_and_true_baselines_preserved(self):
        for before in (False, True):
            self.setUp(); self.node['spec']['unschedulable'] = before
            self.cycle(); self.assertIs(self.node['spec']['unschedulable'], before)

    def test_replaced_node_blocks(self):
        self.node['metadata']['uid'] = 'replacement'
        with self.assertRaises(Blocked): self.snapshot()

    def test_wrong_nodegroup_blocks(self):
        self.node['metadata']['labels']['eks.amazonaws.com/nodegroup'] = 'other'
        with self.assertRaises(Blocked): self.snapshot()

    def test_unready_peer_blocks(self):
        self.peer['status']['conditions'][0]['status'] = 'False'
        with self.assertRaises(Blocked): self.snapshot()

    def test_missing_pod_review_blocks(self):
        self.request['pods'] = []
        with self.assertRaises(Blocked): self.snapshot()

    def test_pod_spec_drift_blocks(self):
        self.pod['spec']['volumes'].append({'name': 'new', 'emptyDir': {}})
        with self.assertRaises(Blocked): self.snapshot()

    def test_emptydir_unapproved_blocks(self):
        self.request['pods'][0]['disposable_emptydir'] = []
        with self.assertRaises(Blocked): self.snapshot()

    def test_hostpath_blocks_even_reviewed(self):
        self.pod['spec']['volumes'].append({'name': 'host', 'hostPath': {'path': '/data'}}); self.review()
        with self.assertRaises(Blocked): self.snapshot()

    def test_unmanaged_pod_blocks(self):
        self.pod['metadata']['ownerReferences'] = []; self.review()
        with self.assertRaises(Blocked): self.snapshot()

    def test_pdb_omission_and_drift_block(self):
        self.request['pdbs'] = []
        with self.assertRaises(Blocked): self.snapshot()
        self.review(); self.pdb['spec']['maxUnavailable'] = 2
        with self.assertRaises(Blocked): self.snapshot()

    def test_exhausted_or_stale_pdb_blocks(self):
        for key, value in [('disruptionsAllowed', 0), ('observedGeneration', 0)]:
            self.setUp(); self.pdb['status'][key] = value
            with self.assertRaises(Blocked): self.snapshot()

    def test_empty_selector_matches_and_overlap_blocks(self):
        self.pdb['spec']['selector'] = {}; self.review(); self.snapshot()
        other = copy.deepcopy(self.pdb); other['metadata'].update(name='second', uid='second')
        self.budgets.append(other); self.review()
        with self.assertRaises(Blocked): self.snapshot()

    def test_selector_expressions(self):
        self.assertTrue(m.matches(self.io, {'matchExpressions': [{'key':'app','operator':'In','values':['web']}]}, {'app':'web'}))
        self.assertTrue(m.matches(self.io, {'matchExpressions': [{'key':'other','operator':'NotIn','values':['x']}]}, {}))
        self.assertFalse(m.matches(self.io, None, {}))

    def test_timeout_range(self):
        for value in (0, 181, True, '180'):
            self.request['timeout_seconds'] = value
            with self.assertRaises(Blocked): self.snapshot()

    def test_failed_eviction_still_restores(self):
        target = self.snapshot(); marks = []; original = self.run_command
        def fail(args, **kw):
            if 'create' in args: raise Blocked('PDB HTTP 429')
            return original(args, **kw)
        self.io.ops.run = fail
        with self.assertRaises(Blocked): m.apply(self.io, 'node-drain-cycle', target, self.request, lambda phase, t: marks.append(phase))
        self.assertEqual(marks[0], 'active'); self.assertEqual(marks[-1], 'idle'); self.assertNotIn('unschedulable', self.node['spec'])

    def test_new_pod_after_review_stops_before_eviction(self):
        target = self.snapshot(); self.pods.append(dict(copy.deepcopy(self.pod), metadata=dict(self.pod['metadata'], uid='new-pod', name='new-pod')))
        with self.assertRaises(Blocked): m.apply(self.io, 'node-drain-cycle', target, self.request, lambda *a: None)
        self.assertFalse(any('create' in c[0] for c in self.calls))

    def test_restore_after_runner_cancellation(self):
        target = self.snapshot(); m.cordon(self.io, target)
        marker = {'operation': 'node-drain-cycle', 'phase': 'recovery-required', 'target': target}
        reviewed = m.snapshot(self.io, 'node-drain-restore', {}, {}, marker)
        result = m.apply(self.io, 'node-drain-restore', reviewed, {}, lambda *a: None)
        self.assertEqual(result['evicted_pod_uids'], [])
        self.assertNotIn('unschedulable', self.node['spec'])

    def test_foreign_lock_preserved_with_recovery_marker(self):
        target = self.snapshot(); m.cordon(self.io, target); self.node['metadata']['annotations'][m.LOCK] = 'other'
        marks = []
        with self.assertRaises(Blocked): m.apply(self.io, 'node-drain-restore', target, {}, lambda phase, t: marks.append(phase))
        self.assertEqual(marks, ['active', 'recovery-required'])
        self.assertEqual(self.node['metadata']['annotations'][m.LOCK], 'other')

    def test_missing_lock_changed_state_blocks(self):
        target = self.snapshot(); self.node['spec']['unschedulable'] = True
        with self.assertRaises(Blocked): m.cordon(self.io, target, restore=True)

    def test_restore_requires_active_marker(self):
        target = self.snapshot()
        with self.assertRaises(Blocked): m.snapshot(self.io, 'node-drain-restore', {}, {}, {'operation':'node-drain-cycle','phase':'idle','target':target})

if __name__ == '__main__': unittest.main()
