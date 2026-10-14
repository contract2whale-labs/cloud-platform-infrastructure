import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('saved_plan',HERE/'saved-plan.py')
plan=importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


class FakeStore:
    def __init__(self):
        self.objects={}
        self.current={'exists':True,'version':'state-v1','etag':'etag1','size':100}
    def put(self,key,path):
        if key in self.objects: raise plan.SafeError('Conditional write refused overwrite.')
        data=path.read_bytes(); self.objects[key]=data
        return {'key':key,'version':'version-1','sha256':plan.digest(data)}
    def get(self,item,path):
        plan.require(item['version']=='version-1','Wrong object version.')
        data=self.objects[item['key']]
        plan.require(plan.digest(data)==item['sha256'],'Private object checksum mismatch.')
        path.write_bytes(data)
    def state(self,key): return copy.deepcopy(self.current)


class SavedPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.workspace=Path(self.tmp.name); self.root=self.workspace/'terraform/environments/dev/network/vpc'; self.root.mkdir(parents=True)
        self.store=FakeStore(); self.calls=[]
        self.context={'prefix':'ci-plans/10/20/1/'+'a'*40+'/dev/network/vpc/','root':'terraform/environments/dev/network/vpc','sha':'a'*40,'run_id':'20','run_attempt':'1','environment':'dev','backend':{'key':'network/vpc/terraform.tfstate','bucket':'private-state','region':'ap-northeast-2'},'input_sha256':'inputs','account':'123456789012'}
        self.env={'GITHUB_WORKSPACE':str(self.workspace),'ROOT_PATH':self.context['root'],'GITHUB_OUTPUT':str(self.workspace/'output'),'GITHUB_STEP_SUMMARY':str(self.workspace/'summary'),'AWS_ROLE_ARN':'arn:aws:iam::123456789012:role/plan','GITHUB_REPOSITORY':'example/infra'}
        self.upstream={}

    def execute(self,args,**kwargs):
        self.calls.append(args)
        if args[:2]==['gh','api']: return ('a'*40).encode()
        if kwargs.get('log'): Path(kwargs['log']).write_text('PRIVATE_TEST_VALUE')
        if args[:2]==['terraform','plan']:
            Path(next(a[5:] for a in args if a.startswith('-out='))).write_bytes(b'EXACT_ORIGINAL_BINARY_PLAN')
            return b''
        if args[:3]==['terraform','show','-json']:
            return b'{"resource_changes":[{"change":{"actions":["delete","create"]}}]}'
        if args[:2]==['terraform','show']: return b'PRIVATE_TEST_VALUE'
        if args[:2]==['terraform','apply']:
            self.assertEqual(Path(args[-1]).read_bytes(),b'EXACT_ORIGINAL_BINARY_PLAN'); return b''
        if args[:2]==['terraform','output']: return b'{"private_output":{"value":"PRIVATE_TEST_VALUE"}}'
        raise AssertionError(args)

    def perform(self,mode):
        with patch.dict(os.environ,self.env,clear=True), patch.object(plan,'lifecycle_gate'), patch.object(plan,'prepare',return_value=(self.root,self.workspace/'backend',self.context,self.store,'arn:aws:sts::123456789012:assumed-role/plan/session')), patch.object(plan,'initialize'), patch.object(plan,'upstream_states',side_effect=lambda *a:copy.deepcopy(self.upstream)), patch.object(plan,'execute',side_effect=self.execute), patch.object(plan,'read_state_memory',side_effect=lambda *a: ({'version':self.store.current['version'],'etag':self.store.current['etag'],'lineage':'lineage-1','serial':7},copy.deepcopy(self.store.current))):
            output=io.StringIO()
            with contextlib.redirect_stdout(output): plan.run(mode)
            self.assertNotIn('PRIVATE_TEST_VALUE',output.getvalue())
        self.assertNotIn('PRIVATE_TEST_VALUE',(self.workspace/'summary').read_text())

    def make_plan(self,mode='plan'):
        self.perform(mode)
        values=dict(line.split('=',1) for line in (self.workspace/'output').read_text().splitlines())
        self.env.update(MANIFEST_KEY=values['manifest_key'],MANIFEST_VERSION=values['manifest_version'],EXPECTED_MANIFEST_SHA=values['manifest_sha'],EXPECTED_PLAN_SHA=values['plan_sha'])
        return json.loads(self.store.objects[values['manifest_key']])

    def test_apply_uses_original_binary_without_replan_and_keeps_logs_private(self):
        self.make_plan(); self.calls.clear(); self.perform('apply')
        self.assertFalse(any(a[:2]==['terraform','plan'] for a in self.calls))
        self.assertTrue(any(key.endswith('/apply/outputs.json') for key in self.store.objects))
        completion=json.loads(next(value for key,value in self.store.objects.items() if key.endswith('/apply/completion.json')))
        self.assertEqual(completion['kind'],'apply-completion')
        self.assertEqual(completion['state'],{'version':'state-v1','etag':'etag1','lineage':'lineage-1','serial':7})
        self.assertEqual(completion['context'],self.context)
        self.assertEqual(completion['outputs']['sha256'],plan.digest(self.store.objects[completion['outputs']['key']]))
        self.assertTrue(any(b'PRIVATE_TEST_VALUE' in value for key,value in self.store.objects.items() if key.startswith('ci-logs/')))

    def test_stale_main_is_rejected(self):
        with patch.dict(os.environ,self.env,clear=True), patch.object(plan,'execute',return_value=b'b'*40):
            with self.assertRaises(plan.SafeError): plan.ensure_current_main(self.context)

    def test_audit_has_no_apply(self):
        manifest=self.make_plan('audit')
        self.assertEqual(manifest['kind'],'audit')
        self.assertFalse(any(a[:2]==['terraform','apply'] for a in self.calls))
        with self.assertRaises(plan.SafeError): self.perform('apply')

    def test_failed_output_upload_does_not_publish_completion_or_reapply(self):
        self.make_plan()
        original=self.store.put
        def put(key,path):
            if key.endswith('/outputs.json'):raise plan.SafeError('Upload failed')
            return original(key,path)
        with patch.object(self.store,'put',side_effect=put):
            with self.assertRaises(plan.SafeError):self.perform('apply')
        self.assertFalse(any(key.endswith('/completion.json') for key in self.store.objects))
        self.assertEqual(sum(a[:2]==['terraform','apply'] for a in self.calls),1)

    def test_changed_state_stops_before_apply(self):
        self.make_plan(); self.store.current['version']='state-v2'; self.calls.clear()
        with self.assertRaises(plan.SafeError): self.perform('apply')
        self.assertFalse(any(a[:2]==['terraform','apply'] for a in self.calls))

    def test_changed_upstream_stops_before_apply(self):
        self.make_plan(); self.upstream={'upstream':{'version':'changed'}}
        with self.assertRaises(plan.SafeError): self.perform('apply')

    def test_object_tamper_rejected(self):
        manifest=self.make_plan(); self.store.objects[manifest['plan']['key']]=b'TAMPERED'
        with self.assertRaises(plan.SafeError): self.perform('apply')

    def test_preview_cannot_apply(self):
        self.make_plan('preview')
        with self.assertRaises(plan.SafeError): self.perform('apply')

    def test_rerun_attempt_context_rejected(self):
        self.make_plan(); self.context['run_attempt']='2'; self.context['prefix']=self.context['prefix'].replace('/20/1/','/20/2/')
        with self.assertRaises(plan.SafeError): self.perform('apply')

    def test_expiry_hash_and_context_guards(self):
        manifest=self.make_plan(); now=int(time.time())
        for context,sha,when in [(dict(self.context,input_sha256='changed'),manifest['plan']['sha256'],now),(self.context,'0'*64,now),(self.context,manifest['plan']['sha256'],manifest['expires_at'])]:
            with self.assertRaises(plan.SafeError): plan.validate_manifest(manifest,context,sha,when)

    def test_exact_version_and_conditional_put(self):
        store=plan.Store('private-state','123456789012'); path=self.workspace/'binary'; path.write_bytes(b'x')
        with patch.object(store,'call',return_value={'VersionId':'v1','ServerSideEncryption':'AES256'}) as call:
            descriptor=store.put('ci-plans/test',path)
            self.assertEqual(descriptor['version'],'v1')
            self.assertIn('--if-none-match',call.call_args.args)
        with patch.object(store,'call',return_value={'VersionId':'null','ServerSideEncryption':'AES256'}):
            with self.assertRaises(plan.SafeError): store.put('ci-plans/test',path)

    def test_effective_auto_input_override_is_rejected(self):
        for key, wrong in [('state_bucket_name','wrong-bucket'),('region','wrong-region'),('expected_account_id','999999999999'),('environment','prod')]:
            with self.assertRaises(plan.SafeError):
                plan.validate_effective_inputs({'variables':{key:{'value':wrong}}}, self.context)

    def test_bucket_guards(self):
        store=plan.Store('private-state','123456789012')
        with patch.object(store,'call',return_value={'Status':'Suspended'}):
            with self.assertRaises(plan.SafeError): store.check()

    def test_state_access_error_is_not_absent_state(self):
        store=plan.Store('private-state','123456789012')
        with patch.object(store,'call',side_effect=plan.SafeError('Access denied')):
            with self.assertRaises(plan.SafeError): store.state('state/key')



class StatePipeTests(unittest.TestCase):
    def test_state_streams_through_memory_only_pipe(self):
        import subprocess
        import sys
        original=subprocess.Popen
        def fake_aws(args,**kwargs):
            pipe_path=next(arg for arg in args if arg.startswith('/proc/self/fd/'))
            body='{"lineage":"lineage-pipe","serial":9,"private_value":"DO_NOT_PUBLISH"}'
            program='import json; from pathlib import Path; Path('+repr(pipe_path)+').write_text('+repr(body)+'); print(json.dumps({"VersionId":"v9","ETag":"etag9","ContentLength":'+str(len(body))+',"ServerSideEncryption":"AES256"}))'
            return original([sys.executable,'-c',program],**kwargs)
        store=plan.Store('private-state','123456789012')
        output=io.StringIO()
        with patch.object(plan.subprocess,'Popen',side_effect=fake_aws), contextlib.redirect_stdout(output):
            state,fingerprint=plan.read_state_memory(store,'root/terraform.tfstate')
        self.assertEqual(state,{'version':'v9','etag':'etag9','lineage':'lineage-pipe','serial':9})
        self.assertEqual(fingerprint['version'],'v9')
        self.assertNotIn('DO_NOT_PUBLISH',output.getvalue())


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.workspace=Path(self.tmp.name)
        self.root='terraform/environments/dev/network/vpc'
        self.path=self.workspace/self.root; self.path.mkdir(parents=True)
        (self.workspace/'ci').mkdir(); (self.workspace/'ci/roots.json').write_text(json.dumps({'roots':[{'env':'dev','path':self.root}]}))
        (self.path/'.terraform.lock.hcl').write_text('reviewed lock')
        self.env={'GITHUB_WORKSPACE':str(self.workspace),'ROOT_PATH':self.root,'STATE_KEY':'network/vpc/terraform.tfstate','GITHUB_REF':'refs/heads/main','GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY_ID':'10','GITHUB_RUN_ID':'20','GITHUB_RUN_ATTEMPT':'1','GITHUB_REPOSITORY':'example/infra','EXPECTED_ACCOUNT_ID':'123456789012','AWS_REGION':'ap-northeast-2','STATE_BUCKET':'private-state','AWS_ROLE_ARN':'arn:aws:iam::123456789012:role/plan','EXPECTED_APPLY_ROLE_ARN':'arn:aws:iam::123456789012:role/apply','TF_VARS_JSON':'{"network/vpc":{}}'}
    def execute(self,args,**kwargs):
        if args[:3]==['git','rev-parse','HEAD']:return b'a'*40
        if args[:2]==['git','ls-files']:return b''
        if args[:2]==['terraform','version']:return b'{"terraform_version":"1.16.0"}'
        raise AssertionError(args)
    def prepare(self):
        with patch.dict(os.environ,self.env,clear=True),patch.object(plan,'execute',side_effect=self.execute),patch.object(plan,'check_identity',return_value='caller'),patch.object(plan.Store,'check'):
            return plan.prepare(self.workspace,self.workspace,'plan')
    def test_complete_protected_input_succeeds(self):
        result=self.prepare(); self.assertEqual(result[2]['backend']['bucket'],'private-state')
    def test_missing_root_input_rejected(self):
        self.env['TF_VARS_JSON']='{}'
        with self.assertRaises(plan.SafeError):self.prepare()
    def test_mismatched_protected_input_rejected_before_plan(self):
        self.env['TF_VARS_JSON']='{"network/vpc":{"environment":"prod"}}'
        with self.assertRaises(plan.SafeError):self.prepare()
    def test_undeclared_environment_input_rejected(self):
        self.env['TF_VAR_environment']='prod'
        with self.assertRaises(plan.SafeError):self.prepare()
    def test_untracked_auto_input_rejected(self):
        (self.path/'hidden.auto.tfvars').write_text('environment="prod"')
        def execute(args,**kwargs):
            if args[:2]==['git','ls-files'] and args[-1].endswith('hidden.auto.tfvars'):raise plan.SafeError('Untracked auto input')
            return self.execute(args,**kwargs)
        with patch.dict(os.environ,self.env,clear=True),patch.object(plan,'execute',side_effect=execute),patch.object(plan,'check_identity',return_value='caller'),patch.object(plan.Store,'check'):
            with self.assertRaises(plan.SafeError):plan.prepare(self.workspace,self.workspace,'plan')
    def test_wrong_assumed_role_rejected(self):
        with patch.object(plan,'aws',return_value={'Account':'123456789012','Arn':'arn:aws:sts::123456789012:assumed-role/other/session'}):
            with self.assertRaises(plan.SafeError):plan.check_identity('123456789012',self.env['AWS_ROLE_ARN'])

if __name__=='__main__': unittest.main()
