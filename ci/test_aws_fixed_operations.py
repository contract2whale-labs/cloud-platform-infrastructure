import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import yaml

BASE = Path(__file__).resolve().parents[1]

class FixedOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); root=Path(cls.temp.name)
        for file in ('saved-plan.py','lifecycle-state.py'):
            shutil.copy((BASE/'ci'/file if (BASE/'ci'/file).exists() else BASE.parent/'ci'/file),root/file)
        shutil.copy(BASE/'ci/aws-fixed-operations.py',root/'aws-fixed-operations.py')
        spec=importlib.util.spec_from_file_location('ops_test',root/'aws-fixed-operations.py');cls.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.m)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.ctx={'repository_id':'123','environment':'dev','account':'111111111111','bucket':'state','region':'ap-northeast-2','operation':'metrics-deny-remove'}
        self.doc={'Version':'2012-10-17','Statement':[{'Effect':'Deny','Action':['s3:PutObject'],'Resource':['arn:aws:s3:::cp-dev-observability-metrics-111111111111-ap-northeast-2/dev/metrics/*'],'Condition':{'DateLessThan':{'aws:CurrentTime':'2099-01-01T00:00:00Z'}}}]}
        self.item={**{k:self.ctx[k] for k in ('account','region')},'role':'cp-dev-observability-writer','arn':'arn:aws:iam::111111111111:role/platform/cp-dev-observability-writer','role_id':'AROAEXAMPLE123','policy_name':'incident-20261013-1600','document':self.doc,'object_arn':self.doc['Statement'][0]['Resource'][0],'approval_reference':'review-1','exclusive_window':True,'valid_until':self.m.now()+3600}
        self.before={'arn':self.item['arn'],'role_id':self.item['role_id'],'document':self.doc}
    def marker(self,phase='active',operation='metrics-deny-remove'):
        return {**self.ctx,'schema':1,'phase':phase,'owner':self.m.OWNER,'operation':operation,'target':self.m.target_identity(self.item),'baseline':self.before}
    def test_request_rejects_ci_role_and_other_bucket(self):
        for changed in ({'role':'gha-identity-dev-apply'},{'object_arn':'arn:aws:s3:::other/dev/metrics/*'},{'role_id':'bad'},{'exclusive_window':False},{'valid_until':0}):
            with self.subTest(changed=changed),patch.dict(os.environ,{'AWS_OPERATIONS_JSON':json.dumps({'schema':1,'enabled':True,'targets':{'metrics':{**self.item,**changed}}})}):
                with self.assertRaises(self.m.h.SafeError):self.m.request(self.ctx)
    def test_request_approved_exact_metrics(self):
        with patch.dict(os.environ,{'AWS_OPERATIONS_JSON':json.dumps({'schema':1,'enabled':True,'targets':{'metrics':self.item}})}):self.assertEqual(self.m.request(self.ctx),self.item)
    def test_allow_or_extra_statement_rejected(self):
        for doc in ({**self.doc,'Statement':[dict(self.doc['Statement'][0],Effect='Allow')]},{**self.doc,'Statement':self.doc['Statement']*2}):
            with self.assertRaises(self.m.h.SafeError):self.m.validate_deny(doc,self.item['object_arn'])
    def test_current_document_must_match_whole(self):
        changed=copy.deepcopy(self.before);changed['document']['Statement'][0]['Action']=['s3:*']
        with self.assertRaises(self.m.h.SafeError):self.m.desired(changed,self.item,'metrics-deny-remove',None)
    def test_remove_and_exact_rollback(self):
        after=self.m.desired(self.before,self.item,'metrics-deny-remove',None)
        self.assertIsNone(after['document'])
        self.assertEqual(self.m.desired(after,self.item,'metrics-deny-rollback',self.marker('idle')),self.before)
    def test_rollback_requires_completed_original(self):
        with self.assertRaises(self.m.h.SafeError):self.m.desired({**self.before,'document':None},self.item,'metrics-deny-rollback',self.marker('active'))
        with self.assertRaises(self.m.h.SafeError):self.m.check_marker(None,{**self.ctx,'operation':'metrics-deny-rollback'},self.item)
    def test_other_owner_or_target_blocks(self):
        for change in ({'owner':'gitops'},{'target':{}},{'account':'222222222222'},{'schema':2}):
            with self.assertRaises(self.m.h.SafeError):self.m.check_marker({**self.marker(),**change},self.ctx,self.item)
    def test_remove_after_rollback_permitted(self):
        self.m.check_marker(self.marker('active','metrics-deny-rollback'),self.ctx,self.item)
    def test_absence_only_recovery_not_new_success(self):
        absent={**self.before,'document':None}
        with self.assertRaises(self.m.h.SafeError):self.m.desired(absent,self.item,'metrics-deny-remove',None)
        self.assertEqual(self.m.desired(absent,self.item,'metrics-deny-remove',self.marker()),absent)
    def test_limit_preserves_min_and_desired(self):
        before={'arn':'group','scaling':{'minSize':2,'maxSize':3,'desiredSize':2}}
        item={'incident_max':2,'approved_max':3}
        after=self.m.desired(before,item,'nodegroup-limit',None)
        self.assertEqual(after['scaling'],{'minSize':2,'maxSize':2,'desiredSize':2})
        self.assertEqual(self.m.desired(after,item,'nodegroup-restore',{'baseline':before}),before)
        before['scaling']['desiredSize']=3
        with self.assertRaises(self.m.h.SafeError):self.m.desired(before,item,'nodegroup-limit',None)
    def test_mutation_is_fixed_max_only_with_idempotency_token(self):
        item={'region':'ap-northeast-2','cluster':'contract2whale-dev-eks','nodegroup':'contract2whale-dev-eks-app'}
        with patch.object(self.m.h,'aws',return_value={'update':{'id':'id1'}}) as aws:
            self.m.mutate(item,'nodegroup-limit',{'scaling':{'maxSize':2}},Path(self.temp.name),'token')
            args=aws.call_args.args
            self.assertIn('maxSize=2',args);self.assertIn('--client-request-token',args)
            self.assertFalse(any('desiredSize=' in str(x) for x in args))
    def test_observe_replacement_role_fails(self):
        with patch.object(self.m.h,'aws',return_value={'Role':{'Arn':self.item['arn'],'RoleId':'AROAOTHER'}}):
            with self.assertRaises(self.m.h.SafeError):self.m.observe(self.item,'metrics')
    def test_read_error_is_not_absence(self):
        with patch.object(self.m.h,'aws',side_effect=self.m.h.SafeError('failed')):
            with self.assertRaises(self.m.h.SafeError):self.m.observe(self.item,'metrics')
    def test_marker_expiration_rejected(self):
        from unittest.mock import Mock
        store=Mock();store.call.return_value={'Rules':[{'Status':'Enabled','Filter':{'Prefix':'ci-incidents/'},'Expiration':{'Days':1}}]}
        with self.assertRaises(self.m.h.SafeError):self.m.check_retention(store,self.ctx)
        store.call.return_value={'Rules':[{'Status':'Enabled','Filter':{'Prefix':'ci-ops-plans/'},'Expiration':{'Days':1}}]}
        self.m.check_retention(store,self.ctx)
    def test_plan_apply_end_to_end_and_drift(self):
        from unittest.mock import Mock
        ctx={**self.ctx,'source_sha':'a'*40,'run_id':'1','run_attempt':'1','repository':'owner/repo'}
        objects={};store=Mock();marker=[None,{'exists':False}]
        def put(key,path):
            data=path.read_bytes();objects[key]=data
            return {'key':key,'version':'v1','sha256':self.m.h.digest(data)}
        def get(desc,path):
            self.assertEqual(desc['sha256'],self.m.h.digest(objects[desc['key']]))
            path.write_bytes(objects[desc['key']])
        def update(store,key,value,previous):
            self.assertEqual(previous,marker[1]);marker[:]=[value,{'exists':True,'version':str(len(objects)),'etag':str(id(value))}]
            return marker[1]
        store.put.side_effect=put;store.get.side_effect=get
        output={}
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'GITHUB_STEP_SUMMARY':d+'/summary'}), \
             patch.object(self.m,'context',return_value=ctx),patch.object(self.m,'request',return_value=self.item), \
             patch.object(self.m.h,'Store',return_value=store),patch.object(self.m,'check_retention'),patch.object(self.m,'check_course'), \
             patch.object(self.m.h,'ensure_current_main'),patch.object(self.m.lc,'read_json',side_effect=lambda *args:tuple(marker)), \
             patch.object(self.m.lc,'update',side_effect=update),patch.object(self.m.h,'emit',side_effect=lambda x:output.update(x)), \
             patch.object(self.m,'observe',return_value=self.before) as observe,patch.object(self.m,'mutate',return_value={}) as mutate, \
             patch.object(self.m,'wait_result',return_value={**self.before,'document':None}):
            self.m.run('plan');self.assertFalse(mutate.called)
            with patch.dict(os.environ,{k.upper():v for k,v in output.items()}):
                observe.return_value={**self.before,'role_id':'AROAOTHER'}
                with self.assertRaises(self.m.h.SafeError):self.m.run('apply')
                self.assertFalse(mutate.called)
                observe.return_value=self.before
                self.m.run('apply')
            self.assertEqual(marker[0]['phase'],'idle')
            self.assertEqual(mutate.call_count,1)
            receipts=[key for key in objects if key.startswith('ci-ops-receipts/')]
            self.assertEqual(len(receipts),1)
            self.assertTrue(json.loads(objects[receipts[0]])['mutation_requested'])

    def test_workflow_contract(self):
        w=yaml.safe_load((BASE/'.github/workflows/aws-fixed-operations.yml').read_text())
        self.assertEqual(set(w['on']),{'workflow_dispatch'})
        self.assertEqual(set(w['on']['workflow_dispatch']['inputs']),{'operation'})
        self.assertEqual(set(w['on']['workflow_dispatch']['inputs']['operation']['options']),set(self.m.OPERATIONS))
        self.assertFalse(w['concurrency']['cancel-in-progress'])
        self.assertEqual(w['jobs']['apply']['needs'],'plan')
        for mode in ('plan','apply'):
            job=w['jobs'][mode];self.assertIn("github.ref == 'refs/heads/main'",job['if'])
            self.assertEqual(job['environment'],'aws-ops-dev-'+mode)
            self.assertLessEqual(job['timeout-minutes'],45)
            self.assertFalse(job['steps'][0]['with']['persist-credentials'])
    def test_iam_exact_targets_no_identity_admin(self):
        s=(BASE/'ci/fixtures/aws-fixed-operations.tf').read_text()
        self.assertIn('role/platform/cp-dev-observability-writer',s)
        self.assertIn('"NeverMutateTargets"',s)
        for bad in ('AdministratorAccess','iam:UpdateAssumeRolePolicy','iam:AttachRolePolicy','iam:CreateRole'):
            self.assertNotIn(bad,s)

if __name__=='__main__':unittest.main()
