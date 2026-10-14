import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch, Mock
from contextlib import ExitStack
from types import SimpleNamespace
import yaml

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj

v=load('tested_lifecycle','vpc-lifecycle.py')
c=v.c

class Store:
    def __init__(self): self.objects={};self.calls=[];self.number=0
    def state(self,key):
        if key not in self.objects:return {'exists':False}
        data,version=self.objects[key]
        return {'exists':True,'version':version,'etag':'etag-'+version,'size':len(data)}
    def call(self,operation,*args):
        self.calls.append((operation,args)); key=args[args.index('--key')+1]
        if operation=='get-object':
            data,version=self.objects[key]
            assert args[args.index('--version-id')+1]==version
            Path(args[-1]).write_bytes(data)
            return {'VersionId':version,'ServerSideEncryption':'AES256'}
        if operation=='put-object':
            previous=self.state(key)
            if '--if-none-match' in args:
                if previous['exists']:raise RuntimeError('412')
            elif '--if-match' in args:
                if not previous['exists'] or args[args.index('--if-match')+1]!=previous['etag']:raise RuntimeError('412')
            else:raise AssertionError('Unconditional control write')
            self.number+=1;version=str(self.number)
            data=Path(args[args.index('--body')+1]).read_bytes();self.objects[key]=(data,version)
            return {'VersionId':version,'ETag':'etag-'+version,'ServerSideEncryption':'AES256'}
        raise AssertionError(operation)
    def put(self,key,path):
        self.number+=1;version=str(self.number);data=Path(path).read_bytes();self.objects[key]=(data,version)
        return {'key':key,'version':version,'sha256':v.h.digest(data)}
    def get(self,descriptor,path):
        data,version=self.objects[descriptor['key']]
        v.h.require(version==descriptor['version'] and v.h.digest(data)==descriptor['sha256'],'Pinned object mismatch')
        Path(path).write_bytes(data)

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)
        self.store=Store();self.target=dict(repository_id='17',account='123456789012',bucket='private-state',region='ap-northeast-2')
        self.record=dict(schema=1,root=c.ROOT,phase='paused',**self.target,inputs={'region':'ap-northeast-2'},snapshot_sha='a'*40,generation='1-1',original_vpc_id='vpc-0123456789abcdef0',original_resources=[])
    def test_marker_is_outside_expiring_plan_log_prefixes(self):
        self.assertEqual(c.marker_key('17'),'ci-lifecycle/17/dev/network-vpc.json')
        with self.assertRaises(ValueError):c.marker_key('../17')
    def test_conditional_create_read_and_update(self):
        key=c.marker_key('17');first=c.update(self.store,key,self.record,{'exists':False})
        value,info=c.read_json(self.store,key);self.assertEqual(value,self.record);self.assertEqual(info,first)
        new={**value,'phase':'active'};c.update(self.store,key,new,info)
        self.assertEqual(c.read_json(self.store,key)[0]['phase'],'active')
        with self.assertRaises(RuntimeError):c.update(self.store,key,value,info)
    def test_absent_read_is_distinct_from_denial(self):
        self.assertEqual(c.read_json(self.store,'absent'),(None,{'exists':False}))
        with patch.object(self.store,'state',side_effect=RuntimeError('403')):
            with self.assertRaises(RuntimeError):c.read_json(self.store,'absent')
    def test_corrupt_control_rejected(self):
        for field,value in [('phase','unknown'),('root','terraform/environments/dev/bootstrap/state'),('account','999999999999'),('snapshot_sha','bad')]:
            with self.subTest(field=field):
                with self.assertRaises(Exception):c.validate({**self.record,field:value},**self.target)
        c.validate(self.record,**self.target)
    def test_transitive_consumers_block_and_unrelated_roots_do_not(self):
        (self.p/'ci').mkdir();graph={c.ROOT:[], 'terraform/environments/dev/eks':[c.ROOT], 'terraform/environments/dev/data':['terraform/environments/dev/eks'], 'terraform/environments/dev/independent':[]}
        (self.p/'ci/deploy-roots.json').write_text(json.dumps({'dependencies':graph}))
        self.assertTrue(c.affected(self.p,'terraform/environments/dev/data'));self.assertFalse(c.affected(self.p,'terraform/environments/dev/independent'))
        context={'root':'terraform/environments/dev/data','repository_id':'17','account':self.target['account'],'backend':{'bucket':self.target['bucket'],'region':self.target['region']}}
        c.update(self.store,c.marker_key('17'),self.record,{'exists':False})
        with self.assertRaises(Exception):c.assert_normal_allowed(self.store,context,self.p)
        record,info=c.read_json(self.store,c.marker_key('17'));record['phase']='active';c.update(self.store,c.marker_key('17'),record,info)
        c.assert_normal_allowed(self.store,context,self.p)
    def test_up_rejects_unsupported_resources_and_destructive_changes(self):
        guard=type('G',(),{'NETWORK_TYPES':{'aws_vpc'}})
        v.validate_up({'resource_changes':[{'type':'aws_vpc','mode':'managed','change':{'actions':['create']}}]},guard)
        for typ,actions in [('aws_iam_policy',['create']),('aws_vpc',['delete']),('aws_vpc',['delete','create'])]:
            with self.assertRaises(v.h.SafeError):v.validate_up({'resource_changes':[{'type':typ,'mode':'managed','change':{'actions':actions}}]},guard)
    def test_settings_requires_real_review_and_main_only(self):
        valid={'protection_rules':[{'type':'required_reviewers','reviewers':[{'type':'User'}]}],'can_admins_bypass':False,'deployment_branch_policy':{'custom_branch_policies':True}}
        branches={'total_count':1,'branch_policies':[{'name':'main','type':'branch'}]}
        env={'GITHUB_REF':'refs/heads/main','GITHUB_REPOSITORY':'example/infra'}
        for prevent in (False,True):
            value=copy.deepcopy(valid);value['protection_rules'][0]['prevent_self_review']=prevent
            with patch.dict(os.environ,env,clear=True),patch.object(v.h,'execute',side_effect=[json.dumps(value).encode(),json.dumps(branches).encode()]):v.settings()
        for bad in [{**valid,'protection_rules':[]},{**valid,'can_admins_bypass':True}]:
            with patch.dict(os.environ,env,clear=True),patch.object(v.h,'execute',return_value=json.dumps(bad).encode()):
                with self.assertRaises(v.h.SafeError):v.settings()
    def test_start_failure_leaves_pause_and_retry_preserves_snapshot(self):
        root=self.p/c.ROOT;root.mkdir(parents=True);(root/'.terraform.lock.hcl').write_text('lock')
        env={'OPERATION':'down','GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','TF_VARS_JSON':json.dumps({'network/vpc':self.record['inputs']})}
        with patch.dict(os.environ,env,clear=True),patch.object(v,'environment',return_value=(self.p,self.store,self.target)),patch.object(v,'initial_state',return_value=(None,{'exists':False})),patch.object(v.h,'execute',return_value=b''):
            with self.assertRaises(v.h.SafeError):v.start()
        retained,_=c.read_json(self.store,c.marker_key('17'));self.assertEqual(retained['phase'],'paused');self.assertEqual(retained['snapshot_sha'],'a'*40)
        env.update(OPERATION='up',GITHUB_SHA='b'*40,GITHUB_RUN_ID='2')
        # 원래 VPC 신원이 기록되지 않았으면 안전하게 중단합니다.
        with patch.dict(os.environ,env,clear=True),patch.object(v,'environment',return_value=(self.p,self.store,self.target)),patch.object(v,'initial_state',return_value=(None,{'exists':False})),patch.object(v.h,'execute',return_value=b''):
            with self.assertRaises(v.h.SafeError):v.start()
        retained,_=c.read_json(self.store,c.marker_key('17'));self.assertEqual(retained['snapshot_sha'],'a'*40)
    def test_workflow_contract(self):
        # Existing VPC helper now runs below the cumulative entrypoint.
        wf=yaml.safe_load((HERE.parent/'.github/workflows/terraform-lifecycle.yml').read_text())
        main=yaml.safe_load((HERE.parent/'.github/workflows/terraform-apply.yml').read_text())
        self.assertEqual(wf['concurrency'],main['concurrency'])
        self.assertFalse(wf['concurrency']['cancel-in-progress'])
        dispatch=wf['on']['workflow_dispatch']['inputs']
        self.assertEqual(set(dispatch),{'operation','environment','completed_chapter'})
        self.assertEqual(dispatch['operation']['options'],['down','up'])
        review=wf['jobs']['down-review']
        self.assertEqual(review['environment'],'${{ needs.settings.outputs.destroy_environment }}')
        self.assertEqual(review['permissions'],{})
        self.assertIn('down-review',wf['jobs']['down-apply']['needs'])
        self.assertEqual(wf['jobs']['down-plan']['environment'],'${{ needs.settings.outputs.plan_environment }}')
        self.assertEqual(wf['jobs']['down-apply']['environment'],'${{ needs.settings.outputs.apply_environment }}')
        for job in ('checkpoint','down-plan','down-apply','up'):
            self.assertEqual(wf['jobs'][job]['steps'][0]['with']['ref'],'${{ github.sha }}')
        self.assertEqual(wf['jobs']['down-apply']['if'],"inputs.operation == 'down' && needs.settings.outputs.privileged_destroy != 'true'")
    def test_ordinary_apply_checks_lifecycle_twice(self):
        source=(HERE/'saved-plan.py').read_text()
        self.assertEqual(source.count('lifecycle_gate(store, context, workspace)'),3) # 정의+plan/apply 진입+적용 직전

    def test_marker_retention_rejects_covering_expiration(self):
        store=Mock()
        for rule in [{'Status':'Enabled','Expiration':{'Days':1}}, {'Status':'Enabled','Filter':{'Prefix':'ci-lifecycle/'},'Expiration':{'Days':1}}, {'Status':'Enabled','Filter':{'And':{'Prefix':'ci-lifecycle/','Tags':[{}]}},'NoncurrentVersionExpiration':{'NoncurrentDays':1}}]:
            store.call.return_value={'Rules':[rule]}
            with self.assertRaises(v.h.SafeError):v.check_retention(store,c.marker_key('17'))
        store.call.return_value={'Rules':[{'Status':'Enabled','Filter':{'Prefix':'ci-plans/'},'Expiration':{'Days':1}}]}
        v.check_retention(store,c.marker_key('17'))
    def test_snapshot_accepts_helpers_but_rejects_terraform_diff_or_git_error(self):
        with patch.dict(os.environ,{'GITHUB_SHA':'b'*40},clear=True):
            with patch.object(v.h,'execute',return_value=b'') as execute:
                v.assert_snapshot_current(self.p,self.record)
                self.assertEqual(execute.call_args.args[0][-3:],['--','terraform','modules'])
            for code in (1,128):
                with self.subTest(code=code),patch.object(v.h,'execute',side_effect=[b'',v.h.SafeError('git failed')]):
                    with self.assertRaises(v.h.SafeError):v.assert_snapshot_current(self.p,self.record)
    def test_start_changed_payload_preserves_existing_control_version(self):
        key=c.marker_key('17');info=c.update(self.store,key,self.record,{'exists':False})
        env={'OPERATION':'up','GITHUB_SHA':'b'*40,'GITHUB_RUN_ID':'2','GITHUB_RUN_ATTEMPT':'1','TF_VARS_JSON':json.dumps({'network/vpc':self.record['inputs']})}
        with patch.dict(os.environ,env,clear=True),patch.object(v,'environment',return_value=(self.p,self.store,self.target)),patch.object(v.h,'execute',side_effect=v.h.SafeError('changed payload')):
            with self.assertRaises(v.h.SafeError):v.start()
        self.assertEqual(self.store.state(key),info)
    def test_source_scope_rejects_unapplied_extension(self):
        guard=SimpleNamespace(NETWORK_TYPES={'aws_vpc'})
        plan={'planned_values':{'root_module':{'child_modules':[{'resources':[{'mode':'managed','type':'aws_s3_bucket'}]}]}}}
        with self.assertRaises(v.h.SafeError):v.validate_supported_plan(plan,guard)


class LifecycleIntegrationTests(unittest.TestCase):
    def setUp(self):
        LifecycleTests.setUp(self)
        self.key=c.marker_key('17');self.applied=False;self.fail_apply=False;self.fail_receipt=False
        self.env={'OPERATION':'down','GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1',
                  'TF_VARS_JSON':json.dumps({'network/vpc':self.record['inputs']}),'GITHUB_STEP_SUMMARY':str(self.p/'summary')}
        self.record.update(operation='down',request_run='1',request_attempt='1',workflow_sha='a'*40,last_result='not-applied',lock_sha256='lock')
        c.update(self.store,self.key,self.record,{'exists':False})
        self.raw={'resources':[{'mode':'managed','type':'aws_vpc','instances':[{'attributes':{'id':self.record['original_vpc_id']}}]}]}
        self.store.objects[c.KEY]=(json.dumps(self.raw).encode(),'state1')
        self.guard=SimpleNamespace(NETWORK_TYPES={'aws_vpc'},guard_destroy=Mock(return_value={'verified':True}),
                                  validate_network_state=Mock(),verify_vpc_absent=Mock())
        self.outputs={};self.commands=[]
        stack=self.enterContext(ExitStack())
        stack.enter_context(patch.dict(os.environ,self.env,clear=True))
        stack.enter_context(patch.object(v,'environment',return_value=(self.p,self.store,self.target)))
        stack.enter_context(patch.object(v,'load',return_value=self.guard))
        stack.enter_context(patch.object(v,'payload',side_effect=self.payload))
        stack.enter_context(patch.object(v.h,'initialize'))
        stack.enter_context(patch.object(v.h,'ensure_current_main'))
        stack.enter_context(patch.object(v.h,'validate_effective_inputs'))
        stack.enter_context(patch.object(v.h,'publish_summary'))
        stack.enter_context(patch.object(v.h,'emit',side_effect=self.outputs.update))
        stack.enter_context(patch.object(v.h,'execute',side_effect=self.execute))
        self.real_put=self.store.put
        stack.enter_context(patch.object(self.store,'put',side_effect=self.put))
    def payload(self,workspace,temp,record,target):
        root=temp/'root';root.mkdir();backend=temp/'backend';backend.write_text('')
        context=dict(operation=os.environ['OPERATION'],root=c.ROOT,sha=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],
                     run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],source_sha=record['snapshot_sha'],generation=record['generation'])
        context['prefix']=f"ci-plans/17/{context['run_id']}/{context['run_attempt']}/{context['sha']}/dev/network/vpc/lifecycle-{context['operation']}/"
        return root,backend,context
    def put(self,key,path):
        if self.fail_receipt and key.endswith('/completion.json'):raise RuntimeError('receipt failure')
        return self.real_put(key,path)
    def execute(self,args,**kwargs):
        self.commands.append(args)
        if args[:2]==['terraform','plan']:
            Path(next(x[5:] for x in args if x.startswith('-out='))).write_bytes(('plan-'+os.environ['OPERATION']+'-'+os.environ['GITHUB_RUN_ID']).encode());return b''
        if args[:3]==['terraform','state','pull']:return json.dumps(self.raw).encode()
        if args[:3]==['terraform','show','-json']:
            actions=['delete'] if os.environ['OPERATION']=='down' and not args[-1].endswith('source-scope.tfplan') else ['create']
            return json.dumps({'resource_changes':[{'mode':'managed','type':'aws_vpc','change':{'actions':actions}}]}).encode()
        if args[:2]==['terraform','show']:return b'private plan text'
        if args[:2]==['terraform','apply']:
            if self.fail_apply:raise v.h.SafeError('apply failed')
            self.applied=True
            self.raw={'resources':[]} if os.environ['OPERATION']=='down' else {'resources':[{'mode':'managed','type':'aws_vpc','instances':[{'attributes':{'id':'vpc-new'}}]}]}
            self.store.objects[c.KEY]=(json.dumps(self.raw).encode(),'state2');return b''
        if args[:2]==['terraform','output']:return b'{}'
        if args[0]=='git':return b''
        raise AssertionError(args)
    def planned(self):
        v.run('plan')
        os.environ.update(MANIFEST_KEY=self.outputs['manifest_key'],MANIFEST_VERSION=self.outputs['manifest_version'],
                          EXPECTED_MANIFEST_SHA=self.outputs['manifest_sha'],EXPECTED_PLAN_SHA=self.outputs['plan_sha'])
    def test_down_applies_saved_binary_and_remains_paused(self):
        self.planned();v.run('apply')
        record,_=c.read_json(self.store,self.key)
        self.assertTrue(self.applied);self.assertEqual(record['phase'],'paused');self.assertEqual(record['last_result'],'down_complete')
        apply=[a for a in self.commands if a[:2]==['terraform','apply']]
        self.assertEqual(len(apply),1);self.assertTrue(apply[0][-1].endswith('change.tfplan'));self.assertNotIn('-destroy',apply[0])
        self.guard.verify_vpc_absent.assert_called_once()
        self.assertEqual(self.guard.guard_destroy.call_count,2)
    def test_up_success_only_then_activates(self):
        record,info=c.read_json(self.store,self.key);record['operation']='up';c.update(self.store,self.key,record,info);os.environ['OPERATION']='up'
        self.raw={'resources':[]};self.store.objects[c.KEY]=(b'{"resources":[]}','state1')
        self.planned();v.run('apply');record,_=c.read_json(self.store,self.key)
        self.assertEqual(record['phase'],'active');self.assertEqual(record['last_result'],'up_complete')
    def test_failed_apply_and_receipt_never_unpause(self):
        for failure in ('apply','receipt'):
            with self.subTest(failure=failure):
                self.fail_apply=failure=='apply';self.fail_receipt=failure=='receipt';self.planned()
                with self.assertRaises(Exception):v.run('apply')
                record,_=c.read_json(self.store,self.key)
                self.assertEqual(record['phase'],'paused');self.assertEqual(record['last_result'],'down_applying')
    def test_changed_inputs_or_control_refuses_apply(self):
        self.planned();os.environ['TF_VARS_JSON']=json.dumps({'network/vpc':{'region':'elsewhere'}})
        with self.assertRaises(v.h.SafeError):v.run('apply')
        self.assertFalse(self.applied)
        os.environ['TF_VARS_JSON']=self.env['TF_VARS_JSON'];record,info=c.read_json(self.store,self.key);c.update(self.store,self.key,record,info)
        with self.assertRaises(v.h.SafeError):v.run('apply')
        self.assertFalse(self.applied)
    def test_retry_requires_new_plan_and_retains_snapshot(self):
        self.planned();old=self.outputs.copy();self.fail_apply=True
        with self.assertRaises(v.h.SafeError):v.run('apply')
        self.fail_apply=False;os.environ['GITHUB_RUN_ID']='2';v.start()
        record,_=c.read_json(self.store,self.key);self.assertEqual(record['snapshot_sha'],'a'*40);self.assertEqual(record['generation'],'1-1')
        with self.assertRaises(v.h.SafeError):v.run('apply')
        self.assertFalse(self.applied)
        self.planned();self.assertNotEqual(old['manifest_key'],self.outputs['manifest_key']);v.run('apply');self.assertTrue(self.applied)
    def test_expired_plan_is_not_applied(self):
        self.planned();key=self.outputs['manifest_key'];data,version=self.store.objects[key];manifest=json.loads(data)
        manifest['created_at']=1;manifest['expires_at']=1+v.h.TTL_SECONDS
        data=v.h.canonical(manifest);self.store.objects[key]=(data,version);os.environ['EXPECTED_MANIFEST_SHA']=v.h.digest(data)
        with self.assertRaises(v.h.SafeError):v.run('apply')
        self.assertFalse(self.applied)


class PayloadRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)
        subprocess.run(['git','init','-q',str(self.p)],check=True)
        root=self.p/c.ROOT;root.mkdir(parents=True);(root/'.terraform.lock.hcl').write_text('lock')
        (root/'main.tf').write_text('resource "terraform_data" "workspace_guard" {}')
        self.commit();self.sha=self.git('rev-parse','HEAD').decode().strip()
        self.record={'snapshot_sha':self.sha,'lock_sha256':v.h.digest(b'lock'),'inputs':{},'generation':'1-1'}
        self.target={'repository_id':'17','account':'123456789012','bucket':'private-state','region':'ap-northeast-2'}
        self.env={'GITHUB_SHA':self.sha,'GITHUB_REPOSITORY':'test/infra','GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','AWS_ROLE_ARN':'arn:aws:iam::123456789012:role/ci-dev-apply','OPERATION':'up'}
    def git(self,*args):return subprocess.check_output(['git',*args],cwd=self.p,stderr=subprocess.PIPE)
    def commit(self):
        self.git('add','.');self.git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
    def test_top_level_modules_optional_and_helpers_stay_current(self):
        (self.p/'ci').mkdir();(self.p/'ci/new-helper.py').write_text('current helper')
        self.commit();self.env['GITHUB_SHA']=self.git('rev-parse','HEAD').decode().strip()
        real=v.h.execute
        def execute(args,**kwargs):
            return b'{"terraform_version":"1.16.0"}' if args[:2]==['terraform','version'] else real(args,**kwargs)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,self.env,clear=True),patch.object(v.h,'execute',side_effect=execute):
            root,backend,context=v.payload(self.p,Path(tmp),self.record,self.target)
            self.assertTrue((root/'terraform.tfvars.json').is_file());self.assertFalse((Path(tmp)/'payload/ci').exists())
            self.assertEqual(context['source_sha'],self.sha)
    def test_root_module_or_lock_change_blocks_snapshot_resume(self):
        for name in (c.ROOT+'/main.tf','terraform/modules/vpc/main.tf',c.ROOT+'/.terraform.lock.hcl'):
            with self.subTest(name=name):
                self.git('reset','--hard',self.sha)
                path=self.p/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('changed')
                self.commit();self.env['GITHUB_SHA']=self.git('rev-parse','HEAD').decode().strip()
                with patch.dict(os.environ,self.env,clear=True):
                    with self.assertRaises(v.h.SafeError):v.assert_snapshot_current(self.p,self.record)

if __name__=='__main__':unittest.main()
