import copy
import hashlib
import inspect
import json
import pathlib
import re
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import velero_ops as m


def require(ok, message):
    if not ok:
        raise ValueError(message)


class VeleroRetirementTests(unittest.TestCase):
    def io(self, runner=lambda *a, **k: b''):
        return types.SimpleNamespace(require=require, ops=types.SimpleNamespace(run=runner),
             identity=lambda x: x['metadata'], h=types.SimpleNamespace(SafeError=ValueError))

    def proof_fixture(self):
        run='00000000-0000-4000-8000-000000000001'
        original={'pod': {'namespace':'backup-probe','name':'writer','uid':'pod'},
                  'pvc': {'namespace':'backup-probe','name':'data','uid':'pvc'},
                  'pv': {'name':'pv-original','uid':'pv'}, 'volume_id':'vol-123', 'reclaim_policy':'Delete'}
        restored=copy.deepcopy(original)
        restored.update(volume_id='vol-456')
        restored['pod']={'namespace':'backup-probe-restored','name':'writer','uid':'rp'}
        restored['pvc']={'namespace':'backup-probe-restored','name':'data','uid':'rc'}
        restored['pv']={'name':'pv-restored','uid':'rv'}
        receipt={'run':run,'account':'123456789012','region':'ap-northeast-2','expected_sha256':hashlib.sha256((run+'\n').encode()).hexdigest(),
                 'original':original,'restored':restored,'backup':{'uid':'backup'},'restore':{'uid':'restore'},
                 'snapshot':{'SnapshotId':'snap-123','VolumeId':'vol-123','OwnerId':'123456789012','VolumeSize':1,'StartTime':'2026-10-13T00:00:00Z'}}
        request={'experiment_id':run,'data_decision':'delete-exact-original-disposable-probe-pod-pvc-and-volume',
                 'creation_receipt':{'key':'receipt','version':'v1','sha256':'f'*64}}
        config={'environment':'prod','account_id':'123456789012','region':'ap-northeast-2'}
        volume={'VolumeId':'vol-123','CreateTime':'2026-10-12T00:00:00Z','Size':1,'AvailabilityZone':'ap-northeast-2a','VolumeType':'gp3','Encrypted':True}
        inventory=[{'resource':'persistentvolumeclaims','identity':original['pvc']},{'resource':'pods','identity':original['pod']}]
        return receipt,request,config,volume,inventory

    def test_lab_lists_only_fixed_pod_pvc_kinds(self):
        calls=[]
        def run(command):
            calls.append(command)
            name='writer' if command[4]=='pods' else 'data'
            return json.dumps({'items':[{'metadata':{'name':name,'uid':name}}]})
        rows=m.lab_inventory(self.io(run),'backup-probe')
        self.assertEqual(len(rows),2)
        self.assertEqual({x[4] for x in calls},{'pods','persistentvolumeclaims'})
        self.assertTrue(all('--all-namespaces' not in x and '--raw' not in x for x in calls))

    def test_foreign_lab_pvc_is_rejected(self):
        io=self.io(lambda *a:json.dumps({'items':[{'metadata':{'name':'business-data'}}]}))
        with self.assertRaisesRegex(ValueError,'Foreign'):
            m.lab_inventory(io,'backup-probe')

    def test_partial_lab_inventory_is_rejected(self):
        io=self.io(lambda *a:json.dumps({'items':[],'metadata':{'continue':'next'}}))
        with self.assertRaisesRegex(ValueError,'Incomplete'):
            m.lab_inventory(io,'backup-probe')

    def test_unregistered_namespace_rejected_before_read(self):
        calls=[]
        with self.assertRaisesRegex(ValueError,'Unregistered'):
            m.lab_inventory(self.io(lambda *a:calls.append(a)),'production')
        self.assertEqual(calls,[])

    def test_plan_proof_has_no_exec_and_binds_receipt(self):
        prior,r,c,volume,inventory=self.proof_fixture();calls=[]
        def run(command):
            calls.append(command)
            return json.dumps({'Volumes':[volume]})
        with patch.object(m,'receipt',return_value=prior), patch.object(m,'volume',return_value=prior['original']), \
             patch.object(m,'lab_inventory',return_value=inventory), patch.object(m,'retained_restore') as retained, \
             patch.object(m,'synthetic_files',side_effect=AssertionError('plan must not exec')):
            proof=m.original_retirement_proof(self.io(run),r,c,object())
        self.assertEqual(proof['creation_receipt'],r['creation_receipt'])
        self.assertEqual(proof['original_volume'],volume)
        retained.assert_called_once_with(unittest.mock.ANY,proof,check_files=False)
        self.assertTrue(all(command[:3]==['aws','ec2','describe-volumes'] for command in calls))

    def test_same_original_and_restore_volume_is_rejected(self):
        prior,r,c,volume,inventory=self.proof_fixture()
        prior['restored']['volume_id']=prior['original']['volume_id']
        with patch.object(m,'receipt',return_value=prior),patch.object(m,'volume',return_value=prior['original']):
            with self.assertRaisesRegex(ValueError,'distinct'):
                m.original_retirement_proof(self.io(),r,c,object())

    def test_wrong_experiment_receipt_is_rejected(self):
        prior,r,c,volume,inventory=self.proof_fixture();r['experiment_id']='00000000-0000-4000-8000-000000000002'
        with patch.object(m,'receipt',return_value=prior):
            with self.assertRaisesRegex(ValueError,'exact synthetic'):
                m.original_retirement_proof(self.io(),r,c,object())

    def test_retain_reclaim_policy_blocks_original_retirement(self):
        prior,r,c,volume,inventory=self.proof_fixture();prior['original']['reclaim_policy']='Retain'
        with patch.object(m,'receipt',return_value=prior),patch.object(m,'volume',return_value=prior['original']):
            with self.assertRaisesRegex(ValueError,'reclaim policy'):
                m.original_retirement_proof(self.io(),r,c,object())

    def test_extra_files_fail_before_any_write(self):
        calls=[]
        def run(command):
            calls.append(command);return b'probe.txt\ncustomer-data.csv\n'
        with self.assertRaisesRegex(ValueError,'Unregistered files'):
            m.disposable_files(self.io(run),'backup-probe')
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][-3:],['ls','-A','/data'])

    def test_symlink_probe_fails_before_write(self):
        answers=iter([b'probe.txt\n',b'symbolic link\n'])
        with self.assertRaisesRegex(ValueError,'Symlink'):
            m.disposable_files(self.io(lambda *a:next(answers)),'backup-probe')

    def test_restored_content_checked_before_original_delete(self):
        prior,r,c,volume,inventory=self.proof_fixture()
        proof=dict(prior,original_inventory=inventory,original_volume=volume)
        io=self.io(lambda *a:json.dumps({'Volumes':[volume]}))
        io.kube=lambda resource,*a:{'metadata':prior['original']['pvc' if resource=='persistentvolumeclaims' else 'pv']}
        with patch.object(m,'retained_restore') as retained,patch.object(m,'lab_inventory',return_value=inventory), \
             patch.object(m,'volume',return_value=prior['original']),patch.object(m,'synthetic_files') as files:
            m.verify_original_retirement(io,proof,[])
        retained.assert_called_once_with(io,proof,check_files=True)
        files.assert_called_once_with(io,'backup-probe',proof['expected_sha256'])

    def test_plan_snapshot_never_executes_file_checks(self):
        body=inspect.getsource(m.snapshot)
        self.assertNotIn("'exec'",body)
        self.assertNotIn('hash_file(',body)
        self.assertNotIn('synthetic_files(',body)
        self.assertNotIn('lifecycle_hooks',inspect.getsource(m.lab_inventory))

    def test_original_reclaim_observer_never_deletes_aws_storage(self):
        body=inspect.getsource(m.verify_original_volume_absent)
        self.assertIn('describe-volumes',body)
        self.assertNotIn('delete-volume',body)
        self.assertNotIn('delete-snapshot',body)


if __name__=='__main__':unittest.main()
