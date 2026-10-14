"""Offline unit/integration tests. All AWS/Terraform execution is mocked."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, (HERE / file if (HERE / file).exists() else HERE.parent / 'ci' / file))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

n = load('network_test_adapter', 'runtime-lifecycle.py')
old_tests = load('network_test_stores', 'test_vpc_lifecycle.py')
Store = old_tests.Store
VPC, PEER, TRANSIT = 'terraform/environments/dev/data', 'terraform/environments/dev/delivery', 'terraform/environments/dev/platform/queue'


class NetworkAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.path = Path(self.temp.name)
        self.store = Store(); self.target = dict(repository_id='17',account='123456789012',bucket='private-state',region='ap-northeast-2')
        self.env = dict(ROOT_PATH=VPC,LIFECYCLE_ENGINE='dev-later-runtime-v1',LIFECYCLE_CONFIG_SHA256='c'*64,LIFECYCLE_SELECTED_ROOTS=json.dumps([VPC]),
                        LIFECYCLE_SNAPSHOT_SHA='a'*40,LIFECYCLE_GENERATION='1-1', OPERATION='down', GITHUB_SHA='a'*40,
                        GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1', GITHUB_STEP_SUMMARY=str(self.path/'summary'),
                        LIFECYCLE_LATER_CONTRACT='{}', TF_VARS_JSON=json.dumps({'data': {'region':'ap-northeast-2'}}))
        self.stack = self.enterContext(ExitStack()); self.stack.enter_context(patch.dict(os.environ,self.env,clear=True))
        n.configure()
        self.record = dict(schema=1,root=VPC,phase='paused',**self.target,inputs={'region':'ap-northeast-2'},snapshot_sha='a'*40,generation='1-1',
                           lifecycle_contract={},lock_sha256='lock',operation='down',request_run='1',request_attempt='1',workflow_sha='a'*40,
                           original_resources=[{'address':'aws_vpc.this','type':'aws_vpc','id':'vpc-0123456789abcdef0'}],
                           original_state_identity={'lineage':'lineage','serial':1}, last_result='not-applied')
        self.control_key=n.marker_key('17'); n.c.update(self.store,self.control_key,self.record,{'exists':False})
        self.raw={'version':4,'lineage':'lineage','serial':1,'resources':[{'mode':'managed','type':'aws_vpc','name':'this','instances':[{'attributes':{'id':'vpc-0123456789abcdef0'}}]}]}
        self.store.objects[n.KEY]=(json.dumps(self.raw).encode(),'state1')
        self.upstream = {'terraform/environments/dev/retained/data': {'state':None, 'fingerprint':{'exists':False}}}
        self.guard = SimpleNamespace(validate_contract=Mock(),bind=Mock(),require_barriers=Mock(return_value={}),verify_present=Mock(return_value={}),allowed_types=Mock(return_value={'aws_vpc'}),read_upstreams=Mock(side_effect=lambda *a:self.upstream),
                                    upstream_fingerprints=Mock(side_effect=lambda *a:{k:v['fingerprint'] for k,v in self.upstream.items()}),
                                    guard_destroy=Mock(return_value={'deferred_runtime_consumer_check':False}),
                                    validate_state=Mock(),validate_plan_contracts=Mock(),verify_absent=Mock(return_value={}),managed_resources=load('up_completion_normalizer','vpc-lifecycle-guard.py').managed_resources)
        self.outputs={}; self.commands=[]; self.applied=False; self.fail_apply=False; self.fail_receipt=False
        for name,value in [('environment',Mock(return_value=(self.path,self.store,self.target))),('guard_module',Mock(return_value=self.guard)),('payload',self.payload)]:
            self.stack.enter_context(patch.object(n,name,value))
        for name,value in [('initialize',Mock()),('ensure_current_main',Mock()),('validate_effective_inputs',Mock()),('publish_summary',Mock()),('emit',self.outputs.update),('execute',self.execute)]:
            self.stack.enter_context(patch.object(n.h,name,value))
        real_put=self.store.put
        def put(key,path):
            if self.fail_receipt and key.endswith('/completion.json'): raise RuntimeError('receipt failed')
            return real_put(key,path)
        self.stack.enter_context(patch.object(self.store,'put',side_effect=put))
    def payload(self,workspace,temp,record,target):
        root=temp/'root';root.mkdir();backend=temp/'backend';backend.write_text('')
        context=dict(operation=os.environ['OPERATION'],root=n.ROOT,sha=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],
                     run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],source_sha=record['snapshot_sha'],generation=record['generation'],
                     lifecycle_registry_sha256=os.environ['LIFECYCLE_CONFIG_SHA256'],selected_roots=json.loads(os.environ['LIFECYCLE_SELECTED_ROOTS']))
        namespace='ci-up-plans' if context['operation']=='up' else 'ci-plans'
        context['prefix']=f"{namespace}/17/{context['run_id']}/{context['run_attempt']}/{context['sha']}/dev/network/vpc/lifecycle-{context['operation']}/"
        return root,backend,context
    def execute(self,args,**kwargs):
        self.commands.append(args)
        if kwargs.get('log'):Path(kwargs['log']).write_text('private diagnostic')
        if args[:2]==['terraform','plan']:
            Path(next(x[5:] for x in args if x.startswith('-out='))).write_bytes(('plan-'+os.environ['OPERATION']+'-'+os.environ['GITHUB_RUN_ID']).encode());return b''
        if args[:3]==['terraform','state','pull']: return json.dumps(self.raw).encode()
        if args[:3]==['terraform','show','-json']:
            return json.dumps({'format_version':'1.2','complete':True,'planned_values':{'root_module':{'resources':[{'mode':'managed','type':'aws_vpc','address':'aws_vpc.this'}]}},'resource_changes':[{'mode':'managed','type':'aws_vpc','change':{'actions':['delete' if os.environ['OPERATION']=='down' and not args[-1].endswith('source-scope.tfplan') else 'create']}}]}).encode()
        if args[:2]==['terraform','show']: return b'private review'
        if args[:2]==['terraform','apply']:
            if self.fail_apply: raise n.h.SafeError('Apply failed.')
            self.applied=True;self.raw['serial']+=1
            self.raw['resources']=[] if os.environ['OPERATION']=='down' else [{'mode':'managed','type':'aws_vpc','name':'this','instances':[{'attributes':{'id':'vpc-new'}}]}]
            self.store.objects[n.KEY]=(json.dumps(self.raw).encode(),'state2');return b''
        if args[:2]==['terraform','output']: return b'{}'
        if args[0]=='git': return b''
        raise AssertionError(args)
    def planned(self):
        n.run('plan');os.environ.update(MANIFEST_KEY=self.outputs['manifest_key'],MANIFEST_VERSION=self.outputs['manifest_version'],EXPECTED_MANIFEST_SHA=self.outputs['manifest_sha'],EXPECTED_PLAN_SHA=self.outputs['plan_sha'])
    def test_static_root_selection(self):
        for root in (VPC,PEER,TRANSIT):
            os.environ.update(ROOT_PATH=root,LIFECYCLE_SELECTED_ROOTS=json.dumps([root]));n.configure()
            self.assertEqual(n.KEY,'/'.join(root.split('/')[3:])+'/terraform.tfstate')
            self.assertEqual(n.marker_key('17'),'ci-lifecycle/17/dev/'+'-'.join(root.split('/')[3:])+'.json')
        os.environ.update(ROOT_PATH='terraform/environments/dev/bootstrap/state')
        with self.assertRaises(n.h.SafeError):n.configure()

    def test_exact_down_binary_plan_and_full_runtime_gate(self):
        self.guard.guard_destroy.return_value={'deferred_runtime_consumer_check':True}
        self.planned();n.run('apply')
        self.assertTrue(self.applied)
        self.assertEqual([c.kwargs['stage'] for c in self.guard.guard_destroy.call_args_list],['plan','apply'])
        record,_=n.c.read_json(self.store,self.control_key)
        self.assertEqual(record['phase'],'paused');self.assertEqual(record['last_result'],'down_complete')
        apply=next(c for c in self.commands if c[:2]==['terraform','apply'])
        self.assertTrue(apply[-1].endswith('change.tfplan'));self.assertNotIn('-destroy',apply)
        self.assertIn('deferred', (self.path/'summary').read_text())
        self.assertEqual(self.guard.verify_absent.call_count,1)
    def test_verify_reads_exact_plan_without_control_write_or_apply(self):
        self.planned();before=self.store.state(self.control_key);object_count=self.store.number;n.run('verify')
        self.assertEqual(self.store.state(self.control_key),before);self.assertFalse(self.applied);self.assertEqual(self.store.number,object_count)
        self.assertEqual(self.guard.guard_destroy.call_args.kwargs['stage'],'plan')
        self.assertFalse(any(c[:2]==['terraform','apply'] for c in self.commands))
    def test_verify_rejects_changed_consumed_descriptor_subset(self):
        self.guard.guard_destroy.return_value={'deferred_runtime_consumer_check':True,'deferred_consumers':{'eks':{'manifest_sha':'a'*64}}}
        self.planned();self.guard.guard_destroy.return_value={'deferred_runtime_consumer_check':True,'deferred_consumers':{'eks':{'manifest_sha':'b'*64}}}
        before=self.store.number
        with self.assertRaises(n.h.SafeError):n.run('verify')
        self.assertFalse(self.applied);self.assertEqual(self.store.number,before)
    def test_failed_verify_does_not_upload_private_diagnostics(self):
        self.planned();object_count=self.store.number
        self.guard.guard_destroy.side_effect=RuntimeError('untrusted private failure text')
        with self.assertRaises(RuntimeError):n.run('verify')
        self.assertEqual(self.store.number,object_count);self.assertFalse(self.applied)
    def test_up_diagnostics_use_apply_role_namespace_only(self):
        record,info=n.c.read_json(self.store,self.control_key);record['operation']='up';n.c.update(self.store,self.control_key,record,info)
        os.environ['OPERATION']='up';self.raw['resources']=[]
        self.planned();n.run('apply')
        self.assertTrue(self.outputs['manifest_key'].startswith('ci-up-plans/'))
        logs=[key for key in self.store.objects if key.endswith('.log')]
        self.assertTrue(logs);self.assertTrue(all(key.startswith('ci-logs/') and '/apply/up-' in key and '/plan/' not in key for key in logs))
    def test_runtime_guard_failure_never_applies(self):
        self.planned();self.guard.guard_destroy.side_effect=RuntimeError('unknown consumer')
        with self.assertRaises(RuntimeError):n.run('apply')
        self.assertFalse(self.applied)
    def test_upstream_or_root_state_change_blocks_saved_plan(self):
        self.planned();self.upstream['terraform/environments/dev/retained/data']['fingerprint']={'exists':True,'version':'changed'}
        with self.assertRaises(n.h.SafeError):n.run('apply')
        self.assertFalse(self.applied)
    def test_source_input_registry_session_tamper_block(self):
        self.planned()
        for field,value in [('LIFECYCLE_CONFIG_SHA256','d'*64),('LIFECYCLE_GENERATION','2-1'),('LIFECYCLE_SNAPSHOT_SHA','b'*40),('TF_VARS_JSON','{"data":{"region":"elsewhere"}}'),('LIFECYCLE_LATER_CONTRACT','{"changed":true}')]:
            with patch.dict(os.environ,{field:value}):
                with self.assertRaises(n.h.SafeError):n.run('apply')
        self.assertFalse(self.applied)
    def test_manifest_version_digest_plan_digest_and_expiry(self):
        self.planned()
        for field,value in [('MANIFEST_VERSION','no-such-version'),('EXPECTED_MANIFEST_SHA','b'*64),('EXPECTED_PLAN_SHA','b'*64)]:
            with patch.dict(os.environ,{field:value}):
                with self.assertRaises(Exception):n.run('apply')
        key=self.outputs['manifest_key'];raw,version=self.store.objects[key];manifest=json.loads(raw)
        manifest.update(created_at=1,expires_at=1+n.h.TTL_SECONDS)
        raw=n.h.canonical(manifest);self.store.objects[key]=(raw,version);os.environ['EXPECTED_MANIFEST_SHA']=n.h.digest(raw)
        with self.assertRaises(n.h.SafeError):n.run('apply')
        self.assertFalse(self.applied)
    def test_partial_failure_keeps_original_and_requires_fresh_run(self):
        self.planned();old=self.outputs.copy();self.fail_apply=True
        with self.assertRaises(n.h.SafeError):n.run('apply')
        retained,_=n.c.read_json(self.store,self.control_key)
        self.assertEqual(retained['original_resources'],self.record['original_resources']);self.assertEqual(retained['phase'],'paused')
        os.environ['GITHUB_RUN_ID']='2';n.start();self.fail_apply=False
        with self.assertRaises(n.h.SafeError):n.run('apply')
        self.planned();self.assertNotEqual(old['manifest_key'],self.outputs['manifest_key']);n.run('apply');self.assertTrue(self.applied)
    def test_receipt_failure_does_not_clear_pause(self):
        self.planned();self.fail_receipt=True
        with self.assertRaises(RuntimeError):n.run('apply')
        record,_=n.c.read_json(self.store,self.control_key)
        self.assertEqual(record['phase'],'paused');self.assertEqual(record['last_result'],'down_applying')
    def test_lineage_and_rollback_block(self):
        for value in ({**self.raw,'lineage':'other'}, {**self.raw,'serial':0}):
            with self.assertRaises(n.h.SafeError):n.validate_state_identity(value,self.record)
    def test_up_only_clears_pause_after_verified_apply(self):
        record,info=n.c.read_json(self.store,self.control_key);record['operation']='up';n.c.update(self.store,self.control_key,record,info)
        os.environ['OPERATION']='up';self.raw['resources']=[]
        self.planned();n.run('apply');record,_=n.c.read_json(self.store,self.control_key)
        self.assertTrue(self.applied);self.assertEqual(record['phase'],'active')
    def test_up_rejects_incomplete_deferred_or_forgetting_plan(self):
        valid={'format_version':'1.2','complete':True,'resource_changes':[{'mode':'managed','type':'aws_vpc','change':{'actions':['create']}}]}
        n.validate_up(valid,self.guard)
        for changed in ({'complete':False},{'errored':True},{'deferred_changes':[{}]},{'format_version':'2.0'}):
            with self.subTest(changed=changed),self.assertRaises(n.h.SafeError):n.validate_up(valid|changed,self.guard)
        for actions in (['delete'],['delete','create'],['forget'],['unknown'],[]):
            invalid=copy.deepcopy(valid);invalid['resource_changes'][0]['change']['actions']=actions
            with self.subTest(actions=actions),self.assertRaises(n.h.SafeError):n.validate_up(invalid,self.guard)
    def test_up_completion_requires_every_planned_managed_address(self):
        plan={'planned_values':{'root_module':{'resources':[{'mode':'managed','type':'aws_vpc','address':'aws_vpc.this'}]}}}
        n.validate_up_completion(plan,self.raw,self.guard)
        missing={**self.raw,'resources':[]}
        with self.assertRaises(n.h.SafeError):n.validate_up_completion(plan,missing,self.guard)
        plan['planned_values']['root_module']['child_modules']=[{'resources':[{'mode':'managed','type':'aws_subnet','address':'module.vpc.aws_subnet.private[0]'}]}]
        with self.assertRaises(n.h.SafeError):n.validate_up_completion(plan,self.raw,self.guard)
    def test_source_scope_blocked_before_destroy_plan(self):
        self.guard.allowed_types.return_value={'aws_subnet'}
        with self.assertRaises(n.h.SafeError):n.run('plan')
        self.assertEqual(len([c for c in self.commands if c[:2]==['terraform','plan']]),1)
        self.assertFalse(self.applied)


class NetworkPayloadTests(unittest.TestCase):
    def setUp(self):
        import subprocess
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)
        self.subprocess=subprocess
        subprocess.run(['git','init','-q',str(self.path)],check=True)
        for root in (VPC,PEER,TRANSIT):
            directory=self.path/root;directory.mkdir(parents=True);(directory/'.terraform.lock.hcl').write_text('lock');(directory/'main.tf').write_text('resource "terraform_data" "workspace_guard" {}')
        self.git('add','.');self.git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
        self.sha=self.git('rev-parse','HEAD').decode().strip()
        self.env=dict(ROOT_PATH=VPC,LIFECYCLE_ENGINE='dev-later-runtime-v1',LIFECYCLE_CONFIG_SHA256='c'*64,LIFECYCLE_SELECTED_ROOTS=json.dumps([VPC,PEER,TRANSIT]),
                      LIFECYCLE_SNAPSHOT_SHA=self.sha,LIFECYCLE_GENERATION='1-1',GITHUB_SHA=self.sha,OPERATION='up',
                      GITHUB_REPOSITORY='example/infra',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',AWS_ROLE_ARN='arn:aws:iam::123456789012:role/ci-dev-apply')
        self.record={'lifecycle_contract':{},'snapshot_sha':self.sha,'lock_sha256':n.h.digest(b'lock'),'inputs':{},'generation':'1-1'}
        self.target={'repository_id':'17','account':'123456789012','bucket':'private-state','region':'ap-northeast-2'}
    def git(self,*args):return self.subprocess.check_output(['git',*args],cwd=self.path,stderr=self.subprocess.PIPE)
    def test_root_backend_and_up_namespace_and_source_bindings(self):
        real=n.h.execute
        def execute(args,**kwargs):return b'{"terraform_version":"1.16.0"}' if args[:2]==['terraform','version'] else real(args,**kwargs)
        for root in (VPC,PEER,TRANSIT):
            with self.subTest(root=root),tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,self.env|{'ROOT_PATH':root},clear=True),patch.object(n.h,'execute',side_effect=execute):
                n.configure();directory,backend,context=n.payload(self.path,Path(tmp),self.record,self.target)
                self.assertEqual(context['root'],root);self.assertEqual(context['backend']['key'],root.removeprefix('terraform/environments/dev/')+'/terraform.tfstate')
                self.assertTrue(context['prefix'].startswith('ci-up-plans/17/1/1/'));self.assertEqual(context['source_sha'],self.sha)
                self.assertEqual(context['lifecycle_registry_sha256'],'c'*64);self.assertEqual(context['selected_roots'],[VPC,PEER,TRANSIT])
                self.assertFalse((Path(tmp)/'payload/ci').exists());self.assertTrue((directory/'terraform.tfvars.json').is_file())
    def test_destroy_namespace_is_separate(self):
        real=n.h.execute
        def execute(args,**kwargs):return b'{"terraform_version":"1.16.0"}' if args[:2]==['terraform','version'] else real(args,**kwargs)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,self.env|{'OPERATION':'down'},clear=True),patch.object(n.h,'execute',side_effect=execute):
            n.configure();_,_,context=n.payload(self.path,Path(tmp),self.record,self.target)
            self.assertTrue(context['prefix'].startswith('ci-plans/17/1/1/'))

if __name__=='__main__':unittest.main()
