"""Offline cross-root binary/identity proof tests; never contacts cloud services."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj

p=load('tested_consumer_proof','network-consumer-proof.py')
v=load('consumer_vpc_fixtures','test_vpc_lifecycle_guard.py')
Store=load('consumer_fake_store','test_vpc_lifecycle.py').Store
ROOT='terraform/environments/dev/eks';VPC='terraform/environments/dev/network/vpc'


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name);(self.path/'ci').mkdir()
        self.registry={'roots':{ROOT:{'mode':'adapter','engine':'dev-eks-v1'}}};self.registry_path=self.path/'ci/lifecycle-targets.json';self.registry_path.write_text(json.dumps(self.registry))
        self.deploy_path=self.path/'ci/deploy-roots.json';self.deploy_path.write_text(json.dumps({'dependencies':{ROOT:[]}}))
        self.context=dict(repository='example/infra',repository_id='17',run_id='10',run_attempt='1',sha='a'*40,source_sha='a'*40,generation='10-1',account=v.ACCOUNT,
                          root=VPC,environment='dev',workspace='default',operation='down',lifecycle_registry_sha256=p.h.digest(p.h.canonical(self.registry)),
                          selected_roots=[VPC,ROOT],apply_role_arn='arn:aws:iam::123456789012:role/ci-dev-apply',
                          backend={'bucket':'private-state','key':'network/vpc/terraform.tfstate','region':'ap-northeast-2','encrypt':True,'use_lockfile':True,'allowed_account_ids':[v.ACCOUNT]})
        self.store=Store();self.state=v.state_of([v.resource('aws_eks_cluster','this','course-cluster')]);self.plan=v.plan_of(self.state)
        self.key='eks/terraform.tfstate';self.marker='ci-lifecycle/17/dev/eks.json'
        self.store.objects[self.key]=(p.h.canonical(self.state),'state1');self.store.objects[self.marker]=(b'private-control','control1')
        self.fingerprint=self.store.state(self.key);self.inputs={'environment':'dev'}
        self.prefix='ci-plans/17/10/1/'+'a'*40+'/dev/eks/lifecycle-down/'
        saved={**self.context,'root':ROOT,'backend':{**self.context['backend'],'key':self.key},'prefix':self.prefix,'lifecycle_engine':'dev-eks-v1','terraform_version':'1.16.0',
               'input_sha256':p.h.digest(p.h.canonical(self.inputs)),'lock_sha256':p.h.digest(b'lock'),'tracked_auto_inputs':{}}
        binary=self.path/'plan';binary.write_bytes(b'fixed-saved-binary');binary_info=self.store.put(self.prefix+'change.tfplan',binary)
        self.manifest={'schema':1,'kind':'eks-lifecycle','context':saved,'state':self.fingerprint,'control':self.store.state(self.marker),'plan':binary_info,
                       'created_at':100,'expires_at':100+p.h.TTL_SECONDS,'upstream_states':{}}
        self.descriptor={};self.save_manifest()
        self.enterContext(patch.dict(os.environ,{'TF_VARS_JSON':json.dumps({'eks':self.inputs})},clear=True))
        self.reads=[]
    def save_manifest(self):
        target=self.path/'manifest';target.write_bytes(p.h.canonical(self.manifest));item=self.store.put(self.prefix+'manifest.json',target)
        self.descriptor.update(manifest_key=item['key'],manifest_version=item['version'],manifest_sha=item['sha256'],plan_sha=self.manifest['plan']['sha256'])
    def plan_reader(self,workspace,temp,manifest,binary,inputs):
        self.reads.append(str(binary));self.assertEqual(binary.read_bytes(),b'fixed-saved-binary');self.assertEqual(inputs,self.inputs);return self.plan
    def prove(self):
        return p.prove_consumers(self.path,self.context,{ROOT:{'state':self.state,'fingerprint':self.fingerprint}},{ROOT:self.descriptor},store=self.store,plan_reader=self.plan_reader,now=101)
    def test_exact_selected_eks_descriptor_identity_and_no_writes(self):
        before=self.store.number;result=self.prove()
        self.assertEqual(self.store.number,before);self.assertEqual(result[ROOT]['managed_count'],1);self.assertEqual(result[ROOT]['descriptor'],self.descriptor);self.assertEqual(len(self.reads),1)
    def test_registry_cannot_enable_unknown_engine_or_redirect_static_root(self):
        for engine in ('shell','dev-network-v2'):
            self.registry['roots'][ROOT]['engine']=engine;self.registry_path.write_text(json.dumps(self.registry));self.context['lifecycle_registry_sha256']=p.h.digest(p.h.canonical(self.registry))
            with self.subTest(engine=engine),self.assertRaises(p.h.SafeError):self.prove()
        self.registry['roots'][ROOT]={'mode':'retain','engine':'dev-eks-v1'};self.registry_path.write_text(json.dumps(self.registry));self.context['lifecycle_registry_sha256']=p.h.digest(p.h.canonical(self.registry))
        with self.assertRaises(p.h.SafeError):self.prove()
    def test_missing_descriptor_or_unselected_root_blocks(self):
        for selected,descriptors in (([],{ROOT:self.descriptor}),([ROOT],{})):
            self.context['selected_roots']=selected
            with self.assertRaises(p.h.SafeError):p.prove_consumers(self.path,self.context,{ROOT:{'state':self.state,'fingerprint':self.fingerprint}},descriptors,store=self.store,plan_reader=self.plan_reader,now=101)
    def test_manifest_source_run_region_input_and_kind_tamper_blocks(self):
        baseline=copy.deepcopy(self.manifest)
        mutations=[('kind','hook-lifecycle'),('root',VPC),('source_sha','b'*40),('run_id','11'),('generation','9-1'),('lifecycle_registry_sha256','c'*64),('input_sha256','d'*64),('operation','up')]
        for field,value in mutations:
            self.manifest=copy.deepcopy(baseline)
            if field=='kind':self.manifest[field]=value
            else:self.manifest['context'][field]=value
            self.save_manifest()
            with self.subTest(field=field),self.assertRaises(p.h.SafeError):self.prove()
    def test_descriptor_version_hash_and_expiry_block(self):
        baseline=self.descriptor.copy()
        for field,value in [('manifest_version','wrong'),('manifest_sha','b'*64),('plan_sha','c'*64),('manifest_key','ci-plans/other/manifest.json')]:
            self.descriptor={**baseline,field:value}
            with self.subTest(field=field),self.assertRaises(Exception):self.prove()
        self.descriptor=baseline;self.manifest['created_at']=101+self.manifest['expires_at'];self.save_manifest()
        with self.assertRaises(p.h.SafeError):self.prove()
    def test_current_consumer_state_or_control_change_blocks(self):
        for key in (self.key,self.marker):
            old=self.store.objects[key];self.store.objects[key]=(old[0],'changed-version')
            with self.subTest(key=key),self.assertRaises(p.h.SafeError):self.prove()
            self.store.objects[key]=old
    def test_missing_or_changed_upstream_state_binding_blocks(self):
        self.registry['roots'][VPC]={'mode':'adapter','engine':'dev-network-v2'}
        self.registry['roots'][ROOT]['dependencies']=[VPC]
        self.deploy_path.write_text(json.dumps({'dependencies':{ROOT:[VPC],VPC:[]}}))
        self.registry_path.write_text(json.dumps(self.registry));self.context['lifecycle_registry_sha256']=p.h.digest(p.h.canonical(self.registry))
        self.manifest['context']['lifecycle_registry_sha256']=self.context['lifecycle_registry_sha256'];self.save_manifest()
        with self.assertRaises(p.h.SafeError):self.prove()
        self.store.objects['network/vpc/terraform.tfstate']=(b'upstream-state','upstream1')
        self.manifest['upstream_states']={VPC:self.store.state('network/vpc/terraform.tfstate')};self.save_manifest();self.prove()
        self.store.objects['network/vpc/terraform.tfstate']=(b'upstream-state','upstream2')
        with self.assertRaises(p.h.SafeError):self.prove()
    def test_retained_ci_identity_prerequisite_is_never_read_as_state_dependency(self):
        protected='terraform/environments/dev/bootstrap/ci-identity';protected_key='bootstrap/ci-identity/terraform.tfstate'
        self.registry['roots'][protected]={'mode':'retain','engine':None};self.registry['roots'][ROOT]['dependencies']=[protected]
        self.registry_path.write_text(json.dumps(self.registry));self.context['lifecycle_registry_sha256']=p.h.digest(p.h.canonical(self.registry))
        self.manifest['context']['lifecycle_registry_sha256']=self.context['lifecycle_registry_sha256'];self.save_manifest()
        with patch.object(self.store,'state',wraps=self.store.state) as state_read:
            self.prove();self.assertNotIn(protected_key,[call.args[0] for call in state_read.call_args_list])
            self.manifest['upstream_states']={protected:{'exists':False}};self.save_manifest();state_read.reset_mock()
            with self.assertRaises(p.h.SafeError):self.prove()
            self.assertNotIn(protected_key,[call.args[0] for call in state_read.call_args_list])
    def test_complete_exact_delete_coverage_and_no_forgetting(self):
        baseline=copy.deepcopy(self.plan)
        mutations=[lambda plan:plan.update(complete=False),lambda plan:plan.update(deferred_changes=[{}]),
                   lambda plan:plan['resource_changes'][0]['change'].update(actions=['forget']),
                   lambda plan:plan['resource_changes'][0]['change']['before'].update(id='foreign'),
                   lambda plan:plan['resource_changes'].clear()]
        for change in mutations:
            self.plan=copy.deepcopy(baseline);change(self.plan)
            with self.assertRaises(Exception):self.prove()
    def test_s3_in_any_consumer_state_is_always_protected(self):
        state=v.state_of([v.resource('aws_s3_bucket','unexpected','bucket')])
        with self.assertRaises(p.h.SafeError):p.validate_delete_plan(state,v.plan_of(state))
    def test_state_change_during_binary_proof_is_detected(self):
        old=self.plan_reader
        def changing(*args):
            value=old(*args);raw,_=self.store.objects[self.key];self.store.objects[self.key]=(raw,'changed-during-proof');return value
        self.plan_reader=changing
        with self.assertRaises(p.h.SafeError):self.prove()


class PayloadTests(unittest.TestCase):
    def test_consumer_uses_own_pinned_provider_directory_and_backend_disabled(self):
        with tempfile.TemporaryDirectory() as work,tempfile.TemporaryDirectory() as tmp:
            workspace=Path(work);directory=Path(tmp);root=workspace/ROOT;root.mkdir(parents=True)
            (root/'.terraform.lock.hcl').write_text('lock');(root/'main.tf').write_text('resource "terraform_data" "test" {}')
            (workspace/'ci').mkdir();(workspace/'ci/never-run-old-helper.py').write_text('raise RuntimeError("old helper executed")')
            def git(*args):return subprocess.check_output(['git',*args],cwd=workspace,stderr=subprocess.PIPE)
            git('init','-q');git('add','.');git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','snapshot');sha=git('rev-parse','HEAD').decode().strip()
            binary=directory/'change.tfplan';binary.write_bytes(b'binary');commands=[];real=p.h.execute
            def execute(args,**kwargs):
                commands.append((args,kwargs))
                if args[:2]==['terraform','version']:return b'{"terraform_version":"1.16.0"}'
                if args[:2]==['terraform','init']:return b''
                if args[:2]==['terraform','show']:return b'{"format_version":"1.2"}'
                return real(args,**kwargs)
            manifest={'context':{'root':ROOT,'source_sha':sha,'sha':sha,'lock_sha256':p.h.digest(b'lock'),'tracked_auto_inputs':{},'terraform_version':'1.16.0'}}
            with patch.object(p.h,'execute',side_effect=execute):result=p.terraform_plan_json(workspace,directory,manifest,binary,{})
            self.assertEqual(result,{'format_version':'1.2'})
            init=next((args,kw) for args,kw in commands if args[:2]==['terraform','init'])
            self.assertIn('-backend=false',init[0]);self.assertIn('-lockfile=readonly',init[0]);self.assertEqual(init[1]['cwd'],directory/'source'/ROOT)
            self.assertFalse((directory/'source/ci').exists());self.assertFalse((root/'terraform.tfvars.json').exists())

if __name__=='__main__':unittest.main()
