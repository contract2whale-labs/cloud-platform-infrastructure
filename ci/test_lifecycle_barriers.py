import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
b=load('barrier_test','lifecycle-barriers.py')
f=load('barrier_fixtures','test_vpc_lifecycle.py')

class BarrierTests(unittest.TestCase):
    def setUp(self):
        self.store=f.Store();self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name);self.step='hook:platform-core';self.target=dict(repository_id='17',account='123456789012',bucket='private-state',region='ap-northeast-2')
        self.course=dict(schema=2,kind='course-lifecycle',**self.target,phase='paused',operation='down',completed_chapter='BU08',snapshot_sha='a'*40,registry_sha256='b'*64,generation='10-1',roots=[],retained_roots=[],inputs={},locks={},steps=[self.step],completed=[self.step],events=[])
        suffix='17/10/1/'+'c'*40+'/dev/hooks/platform-core/lifecycle-down/'
        self.context=dict(repository_id='17',account=self.target['account'],environment='dev',step_id=self.step,snapshot_sha='a'*40,generation='10-1',registry_sha256='b'*64,completed_chapter='BU08',operation='down',run_id='10',run_attempt='1',sha='c'*40,registration_sha256='d'*64,prefix='ci-plans/'+suffix)
        self.residual=dict(schema_version=1,cluster_arn='arn:aws:eks:ap-northeast-2:123456789012:cluster/course',cluster_created_at='2026-01-01T00:00:00Z',source_sha='a'*40,generation='10-1',approved_residuals=[dict(resource='namespaces',namespace='',name='argocd',uid='exact-uid',spec_sha256='e'*64)])
        self.payload={'step_id':self.step,'operation':'down','snapshot':{'residual_contract':self.residual}}
        action=self.put(self.context['prefix']+'actions.json',self.payload)
        self.manifest={'schema':1,'kind':'gitops-lifecycle','context':self.context,'created_at':10,'expires_at':10+b.h.TTL_SECONDS,'plan':action}
        manifest=self.put(self.context['prefix']+'manifest.json',self.manifest)
        self.receipt={'schema':1,'kind':'gitops-lifecycle-completion','context':self.context,'plan_sha':action['sha256'],'completed_at':20,'result':{'load_balancers_absent':True,'residual_contract':self.residual}}
        receipt=self.put('ci-logs/'+suffix+'apply/receipt.json',self.receipt)
        self.proof={'operation':'down','plan':dict(manifest_key=manifest['key'],manifest_version=manifest['version'],manifest_sha=manifest['sha256'],plan_sha=action['sha256']), 'receipt':dict(receipt_key=receipt['key'],receipt_version=receipt['version'],receipt_sha=receipt['sha256'])}
        self.marker={'operation':'down','request_context':self.context,'step_id':self.step,'generation':'10-1','snapshot_sha':'a'*40,'registration_sha256':'d'*64,'last_result':'down-complete','receipt':receipt}
        b.c.update(self.store,'ci-lifecycle/17/dev/hook-platform-core.json',self.marker,{'exists':False})
        self.course['barriers']={self.step:self.proof}
        b.c.update(self.store,b.c.course_marker_key('17'),self.course,{'exists':False})
    def put(self,key,data):
        path=self.directory/'private.json';path.write_bytes(b.h.canonical(data));return self.store.put(key,path)
    def auth(self):return b.authenticate(self.store,self.course,self.target,self.step,self.proof)
    def change_receipt(self,fn):
        value=copy.deepcopy(self.receipt);fn(value);info=self.put(self.proof['receipt']['receipt_key'],value)
        self.proof['receipt']=dict(receipt_key=info['key'],receipt_version=info['version'],receipt_sha=info['sha256'])
        marker,old=b.c.read_json(self.store,'ci-lifecycle/17/dev/hook-platform-core.json');marker['receipt']=info
        b.c.update(self.store,'ci-lifecycle/17/dev/hook-platform-core.json',marker,old)
    def test_exact_completion_is_authentic_after_review_ttl_elapsed(self):
        self.assertEqual(self.auth()['residual_contract'],self.residual)
    def test_unchanged_subset_not_expansion_or_mutation(self):
        survivor=copy.deepcopy(self.residual);survivor['approved_residuals']=[];b.unchanged_subset(self.residual,survivor)
        for field in ('uid','name','spec_sha256'):
            survivor=copy.deepcopy(self.residual);survivor['approved_residuals'][0][field]='f'*64
            with self.subTest(field=field),self.assertRaises(b.h.SafeError):b.unchanged_subset(self.residual,survivor)
    def test_receipt_rejects_plan_and_cluster_and_source_mismatch(self):
        for field,value in [('source_sha','f'*40),('generation','999-1'),('cluster_arn','foreign')]:
            with self.subTest(field=field):
                value_copy=copy.deepcopy(self.residual);value_copy[field]=value
                with self.assertRaises(b.h.SafeError):b.unchanged_subset(self.residual,value_copy)
    def test_unreviewed_completion_time_and_missing_lb_evidence_block(self):
        for change in (lambda r:r.update(completed_at=9),lambda r:r.update(completed_at=10+b.h.TTL_SECONDS),lambda r:r['result'].update(load_balancers_absent=False)):
            self.change_receipt(change)
            with self.assertRaises(b.h.SafeError):self.auth()
    def test_hash_and_foreign_namespace_fail(self):
        for key,value in [('receipt_sha','0'*64),('receipt_key','ci-logs/foreign/receipt.json')]:
            proof=copy.deepcopy(self.proof);proof['receipt'][key]=value
            with self.subTest(key=key),self.assertRaises(Exception):b.authenticate(self.store,self.course,self.target,self.step,proof)
    def test_missing_or_replaced_completion_marker_blocks(self):
        marker,info=b.c.read_json(self.store,'ci-lifecycle/17/dev/hook-platform-core.json');marker['last_result']='down-applying'
        b.c.update(self.store,'ci-lifecycle/17/dev/hook-platform-core.json',marker,info)
        with self.assertRaises(b.h.SafeError):self.auth()
    def test_consumer_cannot_supply_arbitrary_env_receipt(self):
        ctx=dict(repository_id='17',account=self.target['account'],backend={'bucket':self.target['bucket'],'region':self.target['region']},operation='down',generation='10-1',source_sha='a'*40,lifecycle_registry_sha256='b'*64)
        descriptors={self.step:self.proof['receipt']}
        self.assertEqual(b.for_consumer(self.store,ctx,descriptors)['residual_contract'],self.residual)
        descriptors[self.step]={**descriptors[self.step],'receipt_sha':'0'*64}
        with self.assertRaises(b.h.SafeError):b.for_consumer(self.store,ctx,descriptors)
    def test_unknown_hook_never_accepted(self):
        with self.assertRaises(b.h.SafeError):b.authenticate(self.store,self.course,self.target,'hook:arbitrary',self.proof)

class ApplicationCompletionTests(unittest.TestCase):
    def setUp(self):
        self.rows=[{'name':'platform-first-dev','retained_until_cluster_deletion':False},
                   {'name':'platform-kept-dev','retained_until_cluster_deletion':True},
                   {'name':'platform-last-dev','retained_until_cluster_deletion':False}]
        self.snapshot={'applications':self.rows,'retained_assets':{},'disposable_volumes':[]}
        self.result={'retired':['platform-last-dev','platform-first-dev'],'retained_until_cluster_deletion':['platform-kept-dev'],'retained_assets':{}}
    def check(self,result=None):b.validate_result('hook:platform-operations','down',self.snapshot,result or self.result,'4-1')
    def test_exact_retired_order_and_retained_scope(self):self.check()
    def test_extra_or_reordered_or_missing_retirement_blocks(self):
        for value in ([],list(reversed(self.result['retired'])),self.result['retired']+['foreign']):
            with self.subTest(value=value),self.assertRaises(b.h.SafeError):self.check({**self.result,'retired':value})
    def test_retained_identity_expansion_blocks(self):
        with self.assertRaises(b.h.SafeError):self.check({**self.result,'retained_until_cluster_deletion':['foreign']})
    def test_assets_cannot_change(self):
        self.snapshot['retained_assets']={'writer':{'version_id':'old'}}
        with self.assertRaises(b.h.SafeError):self.check()
    def test_volume_completion_binds_exact_ids(self):
        self.snapshot['disposable_volumes']=[{'contract':{'volume_id':'vol-owned'}}]
        with self.assertRaises(b.h.SafeError):self.check()
        self.check({**self.result,'volumes':{'deleted_volume_ids':['vol-owned']}})
    def test_up_exact_names_and_generation(self):
        result={'restored':[r['name'] for r in self.rows],'checkpoint_generation':'4-1'}
        b.validate_result('hook:platform-operations','up',self.snapshot,result,'4-1')
        for field,value in [('restored',[]),('checkpoint_generation','other')]:
            with self.subTest(field=field),self.assertRaises(b.h.SafeError):b.validate_result('hook:platform-operations','up',self.snapshot,{**result,field:value},'4-1')
    def test_asset_up_does_not_claim_app_mutation(self):
        self.snapshot['retained_assets']={'writer':{'version_id':'same'}}
        result={'restored':[],'checkpoint_generation':'4-1','retained_assets':self.snapshot['retained_assets']}
        b.validate_result('hook:queue-credentials-provision','up',self.snapshot,result,'4-1')
        with self.assertRaises(b.h.SafeError):b.validate_result('hook:queue-credentials-provision','up',self.snapshot,{**result,'restored':['platform-first-dev']},'4-1')

class DatabaseActionTests(unittest.TestCase):
    def setUp(self):
        name='database-bootstrap-00000000-0000-4000-8000-000000000001'
        self.target={'source_sha':'a'*40,'bootstrap_run_id':name.removeprefix('database-bootstrap-'),'region':'ap-northeast-2','db':{'arn':'arn:aws:rds:ap-northeast-2:123456789012:db:course','resource_id':'db-fresh'},'job':{'metadata':{'name':name}},'configmap':{'metadata':{'name':name}}}
        self.context={'snapshot_sha':'a'*40,'account':'123456789012'}
        self.done={'complete':True,'raw_job_logs_published':False,'database':self.target['db'],'source_sha':'a'*40,'bootstrap_run_id':self.target['bootstrap_run_id'],'target_sha256':b.h.digest(b.h.canonical(self.target))}
        for field,uid in [('created_job','job-uid'),('created_configmap','cm-uid')]:
            self.done[field]={'uid':uid,'name':name,'namespace':'contract2whale-demo','body_sha256':'b'*64,'metadata_sha256':'c'*64}
        self.result={'database_bootstrap':self.done,'bootstrap_job_uid':'job-uid'}
        self.marker={'database_bootstrap':{'phase':'idle','target':dict(self.target,created_job=self.done['created_job'],created_configmap=self.done['created_configmap'],result=self.done)}}
        self.payload={'database_bootstrap':{'mode':'create','target':self.target}}
    def verify(self):b.validate_database_action('up',self.payload,self.result,self.context,self.marker)
    def test_fresh_exact_creation_receipt(self):self.verify()
    def test_stale_db_identity_rejected(self):
        self.result=copy.deepcopy(self.result);self.result['database_bootstrap']['database']['resource_id']='db-old'
        with self.assertRaises(b.h.SafeError):self.verify()
    def test_changed_action_source_or_uid_rejected(self):
        for field,value in [('target_sha256','d'*64),('source_sha','e'*40),('created_job',dict(self.done['created_job'],uid='replacement'))]:
            original=self.result;self.result=copy.deepcopy(original);self.result['database_bootstrap'][field]=value
            with self.subTest(field=field),self.assertRaises(b.h.SafeError):self.verify()
            self.result=original
    def test_incomplete_durable_owner_rejected(self):
        self.marker['database_bootstrap']['phase']='active'
        with self.assertRaises(b.h.SafeError):self.verify()
    def test_reviewed_cleanup_exact_objects(self):
        target={'created_job':self.done['created_job'],'created_configmap':self.done['created_configmap'],'bootstrap_run_id':self.target['bootstrap_run_id'],'creation_receipt':{'key':'private','version':'1','sha256':'d'*64}}
        result={'deleted_uids':['job-uid','cm-uid'],'creation_receipt':target['creation_receipt'],'bootstrap_run_id':target['bootstrap_run_id']}
        marker={'database_bootstrap_cleanup':{'phase':'idle','target':dict(target,result=result)}}
        b.validate_database_action('down',{'database_bootstrap_cleanup':target},{'bootstrap_cleanup':result},self.context,marker)
        result['deleted_uids']=['foreign']
        with self.assertRaises(b.h.SafeError):b.validate_database_action('down',{'database_bootstrap_cleanup':target},{'bootstrap_cleanup':result},self.context,marker)

if __name__=='__main__':unittest.main()
