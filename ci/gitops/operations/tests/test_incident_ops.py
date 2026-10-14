import copy, importlib.util, json, os, pathlib, sys, unittest
from unittest.mock import patch
p=pathlib.Path(__file__).resolve().parents[1]/'incident_ops.py'
spec=importlib.util.spec_from_file_location('incident_ops_test',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
UUID='12345678-1234-4234-8234-123456789abc'
def app(auto):
    return {'spec':{'source':{'targetRevision':'a'*40},'syncPolicy':{'automated':auto}},'status':{'operationState':{'phase':'Succeeded','syncResult':{'revision':'a'*40}}}}
def workload():return {'apiVersion':'apps/v1','kind':'StatefulSet','metadata':{'name':'platform-tempo-e3-block-builder','namespace':'monitoring','uid':'u1','resourceVersion':'7'},'spec':{'replicas':3,'template':{'spec':{'containers':[]}}}}
def target():
    x=workload();return {'kind':'statefulsets.apps','namespace':'monitoring','name':x['metadata']['name'],'object':m.identity(x),'spec':x['spec'],'normal_replicas':3,'injected_replicas':0}
class Tests(unittest.TestCase):
    def test_empty_automated_means_enabled(self):
        with self.assertRaises(m.h.SafeError):m.verify_app(app({}),'a'*40)
    def test_suspended_builder(self):m.verify_app(app({'enabled':False}),'a'*40)
    def test_selfheal_requires_enabled_flag(self):
        with self.assertRaises(m.h.SafeError):m.verify_app(app({'enabled':False,'selfHeal':True}),'a'*40,True)
    def test_source_revision_mismatch(self):
        with self.assertRaises(m.h.SafeError):m.verify_app(app({'enabled':False}),'b'*40)
    def test_patch_is_uid_and_version_bound(self):
        with patch.object(m,'kube',return_value=workload()),patch.object(m.ops,'run') as call:m.patch_replicas(target(),3,0)
        payload=json.loads(call.call_args.args[0][-1]);self.assertEqual(payload[0],{'op':'test','path':'/metadata/uid','value':'u1'});self.assertEqual(payload[1]['path'],'/metadata/resourceVersion');self.assertEqual(payload[-1]['value'],0)
    def test_changed_uid_never_patched(self):
        obj=workload();obj['metadata']['uid']='foreign'
        with patch.object(m,'kube',return_value=obj),patch.object(m.ops,'run') as call:
            with self.assertRaises(m.h.SafeError):m.patch_replicas(target(),3,0)
            call.assert_not_called()
    def test_nonreplica_changes_block(self):
        obj=workload();obj['spec']['template']['spec']['hostNetwork']=True
        with patch.object(m,'kube',return_value=obj),patch.object(m.ops,'run') as call:
            with self.assertRaises(m.h.SafeError):m.patch_replicas(target(),3,0)
            call.assert_not_called()
    def test_cycle_finally_restores(self):
        marks=[]
        with patch.object(m,'patch_replicas'),patch.object(m,'wait_replicas',side_effect=m.h.SafeError('test')),patch.object(m,'restore') as restore:
            with self.assertRaises(m.h.SafeError):m.run_replica('builder-cycle',target(),{'hold_seconds':1},lambda p,t:marks.append(p))
            restore.assert_called_once();self.assertEqual(marks,['active','idle'])
    def test_failed_restore_keeps_recovery(self):
        marks=[]
        with patch.object(m,'patch_replicas'),patch.object(m,'wait_replicas'),patch.object(m.time,'sleep'),patch.object(m,'restore',side_effect=m.h.SafeError('test')):
            with self.assertRaises(m.h.SafeError):m.run_replica('builder-cycle',target(),{'hold_seconds':1},lambda p,t:marks.append(p))
        self.assertEqual(marks[-1],'recovery-required')
    def test_no_arbitrary_op(self):self.assertNotIn('shell',m.OPERATION_IDS)
    def test_wrong_marker_owner_blocks_recovery(self):self.assertFalse(m.recovery_authorized('builder-restore',{}, {'phase':'active','owner':'aws-fixed-operations','operation':'builder-cycle'}))
    def test_exact_builder_marker_recovers(self):self.assertTrue(m.recovery_authorized('builder-restore',{}, {'phase':'active','owner':'kubernetes-fixed-operations','operation':'builder-cycle'}))
    def test_job_recovery_only_original_uid(self):
        marker={'phase':'recovery-required','owner':'kubernetes-fixed-operations','target':{'created_job':{'name':'incident-x','uid':'old'}}}
        self.assertFalse(m.recovery_authorized('job-cleanup',{'jobs':[{'name':'incident-x','uid':'new'}]},marker))
        self.assertTrue(m.recovery_authorized('job-cleanup',{'jobs':[{'name':'incident-x','uid':'old'}]},marker))
    def test_ecr_recovery_cannot_expand_scope(self):
        marker={'phase':'active','owner':'kubernetes-fixed-operations','operation':'ecr-cleanup','target':{'repositories':[{'name':'commerce-web','delete_digests':['sha256:a']}]}}
        self.assertFalse(m.recovery_authorized('ecr-cleanup',{'repositories':{'commerce-web':{'delete_digests':['sha256:b']}}},marker))
    def test_manifest_binding_and_expiry(self):
        x={'schema':1,'kind':'incident-plan','context':{'operation':'selfheal-demo'},'marker':{'etag':'a'},'bindings':{'state':'1'},'created_at':0,'expires_at':3600}
        m.validate_manifest(x,x['context'],x['marker'],x['bindings'],1)
        for ctx,mark,bind,stamp in [({},x['marker'],x['bindings'],1),(x['context'],{'etag':'b'},x['bindings'],1),(x['context'],x['marker'],{'state':'2'},1),(x['context'],x['marker'],x['bindings'],3600)]:
            with self.assertRaises(m.h.SafeError):m.validate_manifest(x,ctx,mark,bind,stamp)
    def request(self):return {'experiment_id':UUID,'job_name':'incident-read-source-'+UUID,'operator_image':'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/contract2whale/database-operator@sha256:'+'b'*64,'sample_handle':'synthetic-item-1','db_host':'sample.abc.ap-northeast-2.rds.amazonaws.com','runtime_secret_arn':'arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:runtime-Abc123','source_sha':'a'*40}
    def test_fixed_read_template(self):
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'1'}):x=m.fill_template('pitr-read-source',self.request(),{'account_id':'123456789012','region':'ap-northeast-2'})
        self.assertEqual(x['spec']['template']['spec']['serviceAccountName'],'database-operator');self.assertFalse(x['spec']['template']['spec']['automountServiceAccountToken'])
    def test_sql_injection_rejected(self):
        r=self.request();r['sample_handle']="x'; DROP TABLE product;--"
        with self.assertRaises(m.h.SafeError):m.fill_template('pitr-read-source',r,{'account_id':'123456789012','region':'ap-northeast-2'})
    def test_crossaccount_image_rejected(self):
        r=self.request();r['operator_image']=r['operator_image'].replace('123456789012','999999999999')
        with self.assertRaises(m.h.SafeError):m.fill_template('pitr-read-source',r,{'account_id':'123456789012','region':'ap-northeast-2'})
    def test_job_cleanup_uid_mismatch(self):
        obj={'metadata':{'uid':'new','labels':{'recovery.course/experiment-id':UUID}}}
        with patch.object(m,'kube',return_value=obj):
            with self.assertRaises(m.h.SafeError):m.job_snapshot({'experiment_id':UUID,'jobs':[{'name':'incident-read-source-'+UUID,'uid':'old'}]})
    def test_ecr_partial_failure_preserves_marker(self):
        marks=[];t={'repositories':[{'url':'repo','name':'commerce-web','delete_digests':['sha256:'+'a'*64],'retain_digests':[]}]}
        with patch.object(m,'repository_consumers_absent'),patch.object(m.ops,'run',return_value=b'{"failures":[{"failureCode":"X"}],"imageIds":[]}'):
            with self.assertRaises(m.h.SafeError):m.delete_ecr({'account_id':'123456789012','region':'ap-northeast-2'},t,lambda p,t:marks.append(p))
        self.assertEqual(marks,['active','recovery-required'])
if __name__=='__main__':unittest.main()

class TemporarySelfHeal(unittest.TestCase):
    def test_restores_original_policy_with_uid_preconditions(self):
        before={'source':{'targetRevision':'a'*40},'syncPolicy':{'syncOptions':['ServerSideApply=true']}}
        fault=copy.deepcopy(before);fault['syncPolicy']['automated']={'enabled':True,'selfHeal':True,'prune':False,'allowEmpty':False}
        live={'metadata':{'name':'commerce-web-dev','namespace':'argocd','uid':'app1','resourceVersion':'9'},'spec':fault}
        recovered=copy.deepcopy(live);recovered['spec']=before
        target={'temporary_selfheal':True,'application_name':'commerce-web-dev','application_spec':before,'application':{'uid':'app1'}}
        with patch.object(m,'kube',side_effect=[live,recovered]),patch.object(m.ops,'run') as call:m.selfheal_policy(target,False)
        actions=json.loads(call.call_args.args[0][-1]);self.assertEqual(actions[0]['value'],'app1');self.assertEqual(actions[-1]['value'],before)
    def test_unrelated_app_change_blocks_recovery(self):
        target={'temporary_selfheal':True,'application_name':'commerce-web-dev','application_spec':{'source':{}},'application':{'uid':'app1'}}
        live={'metadata':{'uid':'app1'},'spec':{'source':{'targetRevision':'foreign'}}}
        with patch.object(m,'kube',return_value=live):
            with self.assertRaises(m.h.SafeError):m.selfheal_policy(target,False)
