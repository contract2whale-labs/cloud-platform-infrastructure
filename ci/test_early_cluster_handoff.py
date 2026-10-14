"""Offline BU06/BU07 bootstrap handoff and saved semantic barrier regressions."""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

w=load('early_staged',HERE/'eks-probe-lifecycle.py')
p=w.p
g=load('early_guard',HERE/'eks-lifecycle-guard.py')
fixtures=load('early_store',HERE/'test_vpc_lifecycle.py')
bootstrap=load('early_bootstrap_receipt',HERE/'operations-access.py')
ACCOUNT='111111111111'

def context(operation='down',chapter='BU07'):
    return {'step_id':w.PRIVATE_STEP,'snapshot_sha':'a'*40,'source_sha':'a'*40,'generation':'1-1','probe_inputs':{},'probe_policy_sha256':'b'*64,'source_capability':{'operations_access':True},'registration_sha256':'c'*64,'operation':operation,'completed_chapter':chapter,'environment':'dev','account':ACCOUNT,'backend':{'bucket':'private','region':'ap-northeast-2'},'root':'terraform/environments/dev/eks','run_id':'12','run_attempt':'1','private_api_contract':{'schema':1,'mode':'authenticated-private-readyz','bootstrap_required':chapter!='BU06','early_bootstrap_residuals':chapter=='BU07'},'prefix':('ci-plans' if operation=='down' else 'ci-up-plans')+'/1/12/1/sha/dev/hooks/cluster-private-api-check/lifecycle-'+operation+'/'}

def residual():
    return {'schema_version':1,'cluster_arn':'arn','cluster_created_at':'2026-10-13T00:00:00Z','source_sha':'a'*40,'generation':'1-1','approved_residuals':[]}

def row(obj):
    gv,resource,namespaced=p.BOOTSTRAP_RESOURCES[obj['kind']];md=obj['metadata']
    digest=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'gvr':gv+'/'+resource,'resource':resource,'base':'/api/v1' if gv=='v1' else '/apis/'+gv,'namespaced':namespaced,'kind':obj['kind'],'namespace':md.get('namespace',''),'name':md['name'],'uid':md['uid'],'spec_sha256':digest({k:v for k,v in obj.items() if k not in ('metadata','status')}),'metadata_policy_sha256':digest({k:md.get(k) for k in ('labels','annotations','finalizers','ownerReferences')})}

def effective(objects=()):
    return {'cluster':'owned','cluster_arn':'arn','cluster_created_at':'2026-10-13T00:00:00Z','relay':'i-abc','vpc_id':'vpc-abc','_bootstrap_receipt':{'bootstrap_residual_resources':[row(x) for x in objects]}}

@contextlib.contextmanager
def session(*args,**kwargs):
    yield {},{'arn':'arn','createdAt':'2026-10-13T00:00:00Z','resourcesVpcConfig':{'vpcId':'vpc-abc','endpointPrivateAccess':True,'endpointPublicAccess':False}}

class StagedPrivateTests(unittest.TestCase):
    def test_private_down_up_same_retained_checkpoint_and_no_diagnostics(self):
        store=fixtures.Store();ctx=context();binding={'eks':'version-1','operations_access':{'version':'bootstrap-1'}}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);out=path/'outputs';out.write_text('')
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(out)},clear=True),patch.object(w,'settings',side_effect=lambda stage:(path,{},store,'marker',ctx)),patch.object(w,'binding',side_effect=lambda *args:copy.deepcopy(binding)),patch.object(w.h,'ensure_current_main'),patch.object(w.p,'inspect_bootstrap_residuals',side_effect=lambda *args:(residual(),copy.deepcopy(binding))),patch.object(w.p,'run_private_api_completion',side_effect=lambda *args:{'state_binding':copy.deepcopy(binding)}),patch.object(w.p,'run_probe_completion') as diagnostics:
                def approve():
                    emitted=dict(line.split('=',1) for line in out.read_text().splitlines())
                    os.environ.update(MANIFEST_KEY=emitted['manifest_key'],MANIFEST_VERSION=emitted['manifest_version'],EXPECTED_MANIFEST_SHA=emitted['manifest_sha'],EXPECTED_PLAN_SHA=emitted['plan_sha'])
                w.run('start');w.run('plan');approve();w.run('verify');w.run('apply')
                record,_=w.c.read_json(store,'marker');original=copy.deepcopy(record['original'])
                result=json.loads(store.objects[record['receipt']['key']][0])['result']
                self.assertTrue(result['no_mutation']);self.assertEqual(result['residual_contract'],original['residual_contract'])
                self.assertEqual(result['bootstrap_binding'],original['bootstrap_binding'])
                with self.assertRaises(w.h.SafeError):w.run('apply')
                ctx.update(context('up'));binding.update(eks='new-version',operations_access={'version':'new-bootstrap'})
                w.run('start');w.run('plan');approve();w.run('verify');w.run('apply')
                record,_=w.c.read_json(store,'marker');self.assertEqual(record['phase'],'active');self.assertEqual(record['original'],original)
                diagnostics.assert_not_called()
                with self.assertRaises(w.h.SafeError):w.run('apply')

    def test_missing_bootstrap_pauses_up_without_inline_wait(self):
        store=fixtures.Store();ctx=context();contract=residual();bound={'proof':'old'}
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'outputs';out.write_text('')
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(out)},clear=True),patch.object(w,'settings',side_effect=lambda stage:(Path(directory),{},store,'marker',ctx)),patch.object(w.p,'inspect_bootstrap_residuals',return_value=(contract,bound)):
                w.run('start');ctx.update(context('up'));w.run('start')
                with patch.object(w.p,'probe_binding',side_effect=RuntimeError('Fresh-cluster protected GitOps bootstrap handoff required')),patch.object(w.p.time,'sleep') as sleep:
                    with self.assertRaises(RuntimeError):w.run('plan')
                    sleep.assert_not_called()
                record,_=w.c.read_json(store,'marker');self.assertEqual(record['phase'],'paused');self.assertEqual(record['generation'],'1-1');self.assertNotIn('receipt',record)

    def test_private_snapshot_has_no_image_inputs_and_detects_policy_change(self):
        ctx=context();original={**w.snapshot(ctx),'residual_contract':residual(),'bootstrap_binding':{'eks':'v'}}
        record={'schema':1,**{k:ctx[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')},'original':original}
        w.validate_record(record,ctx);self.assertEqual(original['probe_inputs'],{})
        for key,value in [('probe_policy_sha256','d'*64),('generation','2-1'),('source_capability',{'operations_access':False}),('private_api_contract',{})]:
            with self.subTest(key=key),self.assertRaises(w.h.SafeError):w.validate_record(record,{**ctx,key:value})

    def test_early_changed_residual_or_bootstrap_fails(self):
        ctx=context();original={'residual_contract':residual(),'bootstrap_binding':{'eks':'v'}}
        for contract,binding in [({**residual(),'cluster_created_at':'other'},{'eks':'v'}),(residual(),{'eks':'new'})]:
            with patch.object(w.p,'inspect_bootstrap_residuals',return_value=(contract,binding)),self.assertRaises(w.h.SafeError):w.verify_early_residuals(ctx,None,None,original)

class PrivateApiTests(unittest.TestCase):
    def test_bounded_private_readiness_no_nodes_images_or_logs(self):
        ctx=context('up');bound={'eks':'one','relay':'one','vpc':'one','operations_access':{'version':'one'}}
        cmds=[]
        def command(args,env,body=None):
            cmds.append(args)
            return json.dumps({'status':{'userInfo':{'username':'runner','groups':['cp:dev:lifecycle-apply']}}}).encode() if args[0]=='auth' else b'ok'
        with patch.dict(os.environ,{'AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-dev-apply'},clear=True),patch.object(p,'private_binding',return_value=(effective(),bound,{},None)),patch.object(p.p,'private_api',session),patch.object(p,'command',side_effect=command),patch.object(p,'run') as pods,patch.object(p,'wait_logs') as logs,patch.object(p,'validate_inputs') as images:
            proof=p.run_private_api_completion(ctx,None,{})
        self.assertEqual(proof['state_binding'],bound);self.assertEqual(proof['scope']['authenticated_group'],'cp:dev:lifecycle-apply')
        self.assertEqual(cmds,[['auth','whoami','-o','json'],['get','--raw=/readyz']]);pods.assert_not_called();logs.assert_not_called();images.assert_not_called()

    def test_wrong_role_or_anonymous_cannot_claim_readiness(self):
        ctx=context('up')
        with patch.dict(os.environ,{'AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-dev-plan'},clear=True),patch.object(p,'private_binding') as binding:
            with self.assertRaises(p.p.GuardError):p.run_private_api_completion(ctx,None,{})
            binding.assert_not_called()
        for groups,username in [(['system:unauthenticated'],'system:anonymous'),(['cp:dev:lifecycle-destroy'],'runner'),(['cp:dev:lifecycle-apply','system:unauthenticated'],'runner')]:
            with patch.object(p,'command',return_value=json.dumps({'status':{'userInfo':{'username':username,'groups':groups}}}).encode()),self.assertRaises(p.p.GuardError):p.private_identity({},ctx)

    def test_readyz_failure_or_binding_change_fails(self):
        with patch.object(p,'command',side_effect=[json.dumps({'status':{'userInfo':{'username':'runner','groups':['cp:dev:lifecycle-apply']}}}).encode(),b'not ok']),self.assertRaises(p.p.GuardError):p.private_identity({},context('up'))
        with patch.dict(os.environ,{'AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-dev-apply'},clear=True),patch.object(p,'private_binding',side_effect=[(effective(),{'eks':'one'},{},None),(effective(),{'eks':'two'},{},None)]),patch.object(p.p,'private_api',session),patch.object(p,'private_identity',return_value='cp:dev:lifecycle-apply'),self.assertRaises(p.p.GuardError):p.run_private_api_completion(context('up'),None,{})

    def test_residual_receipt_schema_and_scope_fail_closed(self):
        obj={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'argocd','uid':'uid'},'spec':{}}
        good=effective([obj]);p.bootstrap_resource_rows(good)
        for key,value in [('resource','secrets'),('namespaced',True),('base','/arbitrary'),('name','../../x'),('metadata_policy_sha256','wrong')]:
            bad=copy.deepcopy(good);bad['_bootstrap_receipt']['bootstrap_residual_resources'][0][key]=value
            with self.subTest(key=key),self.assertRaises(p.p.GuardError):p.bootstrap_resource_rows(bad)
        with self.assertRaises(p.p.GuardError):p.bootstrap_resource_rows(effective())

    def test_residual_reads_exact_objects_and_rejects_uid_spec_metadata_drift(self):
        obj={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'argocd','uid':'uid','labels':{'owner':'bootstrap'}},'spec':{}}
        bound={'eks':'one','operations_access':{'version':'one'}};ctx=context()
        for edit in (None,'uid','metadata','spec'):
            actual=copy.deepcopy(obj)
            if edit=='uid':actual['metadata']['uid']='other'
            if edit=='metadata':actual['metadata']['labels']['owner']='foreign'
            if edit=='spec':actual['spec']['finalizers']=['foreign']
            with patch.dict(os.environ,{'AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-dev-lifecycle-destroy'},clear=True),patch.object(p,'private_binding',return_value=(effective([obj]),bound,{},None)),patch.object(p.p,'private_api',session),patch.object(p,'private_identity'),patch.object(p,'command',return_value=json.dumps(actual).encode()) as command:
                if edit:
                    with self.assertRaises(p.p.GuardError):p.inspect_bootstrap_residuals(ctx,None,{})
                else:
                    contract,proof=p.inspect_bootstrap_residuals(ctx,None,{})
                    self.assertEqual(proof,bound);self.assertEqual(contract['approved_residuals'][0]['uid'],'uid')
                    self.assertTrue(all(call.args[0]==['get','--raw','/api/v1/namespaces/argocd'] for call in command.call_args_list))

class InstallerCollectorTests(unittest.TestCase):
    def data(self):
        deployment={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'argocd-redis','namespace':'argocd','uid':'deploy'},'spec':{'template':{'spec':{'containers':[{'name':'redis','env':[{'name':'password','valueFrom':{'secretKeyRef':{'name':'generated-auth','key':'auth'}}}]}]}}}}
        secret=lambda name,uid:{'apiVersion':'v1','kind':'Secret','metadata':{'namespace':'argocd','name':name,'uid':uid},'data':{'auth':'PRIVATE-BYTES'}}
        release=secret('sh.helm.release.v1.argocd.v1','helm');release.update(type='helm.sh/release.v1');release['metadata']['labels']={'owner':'helm','name':'argocd','status':'deployed','version':'1'}
        docs=[deployment];objects={('/apis/apps/v1/namespaces/argocd/deployments/argocd-redis'):deployment,'/api/v1/namespaces/argocd/secrets/argocd-repo-gitops':secret('argocd-repo-gitops','repo'),'/api/v1/namespaces/argocd/secrets/sh.helm.release.v1.argocd.v1':release,'/api/v1/namespaces/argocd/secrets/generated-auth':secret('generated-auth','generated')}
        return docs,objects
    def collect(self,docs,objects,status=None,before=()):
        import yaml
        status=status or {'name':'argocd','namespace':'argocd','version':1,'info':{'status':'deployed'}}
        return bootstrap.collect_bootstrap_residuals({'projects':[]},yaml.safe_dump_all(docs),[],lambda path,allow_missing=False:objects.get(path),status,lambda item:row(item['object']),before)
    def test_only_hashes_for_chart_bound_new_secret(self):
        docs,objects=self.data();rows=self.collect(docs,objects)
        self.assertEqual(len(rows),4);self.assertNotIn('PRIVATE-BYTES',json.dumps(rows));self.assertTrue(all('metadata_policy_sha256' in r for r in rows))
        self.assertEqual({r['name'] for r in rows},{'argocd-redis','argocd-repo-gitops','sh.helm.release.v1.argocd.v1','generated-auth'})
        with self.assertRaises(RuntimeError):self.collect(docs,objects,before=['generated'])
    def test_helm_revision_foreign_chart_object_and_missing_object_block(self):
        docs,objects=self.data()
        with self.assertRaises(RuntimeError):self.collect(docs,objects,{'name':'argocd','namespace':'argocd','version':2,'info':{'status':'deployed'}})
        bad=copy.deepcopy(docs);bad[0]['metadata']['namespace']='other'
        with self.assertRaises(RuntimeError):self.collect(bad,objects)
        del objects['/api/v1/namespaces/argocd/secrets/argocd-repo-gitops']
        with self.assertRaises(RuntimeError):self.collect(docs,objects)
    def test_successful_hook_job_exact_row_or_authenticated_absence(self):
        docs,objects=self.data();job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':'init','namespace':'argocd','uid':'hook','annotations':{'helm.sh/hook':'pre-install','helm.sh/hook-delete-policy':'hook-succeeded'}},'spec':{},'status':{'conditions':[{'type':'Complete','status':'True'}]}}
        docs.append(job);path='/apis/batch/v1/namespaces/argocd/jobs/init';objects[path]=job
        self.assertIn('init',{r['name'] for r in self.collect(docs,objects)})
        objects[path]['status']={'active':1}
        with self.assertRaises(RuntimeError):self.collect(docs,objects)
        del objects[path];self.assertNotIn('init',{r['name'] for r in self.collect(docs,objects)})
        docs[-1]['metadata']['annotations'].pop('helm.sh/hook-delete-policy')
        with self.assertRaises(RuntimeError):self.collect(docs,objects)


class PrivateSemanticsTests(unittest.TestCase):
    def material(self,operation='up',chapter='BU07'):
        ctx=context(operation,chapter);ctx['source_capability']['operations_source_sha256']=w.h.digest((HERE/'eks-operations-access.tf').read_bytes())
        roots=g.roots(ctx);bound={root:{'version':'1'} for root in roots[1:]}
        if chapter!='BU06':bound['operations_access']={'key':'operation-access/dev/'+'f'*64+'/complete.json','version':'1','sha256':'e'*64}
        scope={'account':ACCOUNT,'source_sha':ctx['snapshot_sha'],'run_id':ctx['run_id'],'run_attempt':ctx['run_attempt'],'cluster_arn':f'arn:aws:eks:ap-northeast-2:{ACCOUNT}:cluster/owned','cluster_created_at':'2026-10-13T00:00:00Z','relay_instance_id':'i-abc','vpc_id':'vpc-abc','readyz':'ok','authenticated':True,'private_endpoint':True,'authenticated_group':'cp:dev:lifecycle-'+('destroy' if operation=='down' else 'apply')}
        proof={'schema':1,'kind':'cluster-private-api-readiness','state_binding':bound,'checkpoint_generation':'1-1','snapshot_sha':ctx['snapshot_sha'],'scope':scope}
        original=w.snapshot(ctx);result={'checkpoint_generation':'1-1','private_api_readiness':proof}
        if chapter=='BU07':
            obj={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'argocd','uid':'owned'},'spec':{}}
            contract={**residual(),'cluster_arn':scope['cluster_arn'],'approved_residuals':[{k:v for k,v in row(obj).items() if k in ('resource','namespace','name','uid','spec_sha256','metadata_policy_sha256')}]}
            original.update(residual_contract=contract,bootstrap_binding=bound)
        if operation=='down':
            result.update(no_mutation=True,retained_probe_contract=original)
            if chapter=='BU07':result.update(residual_contract=original['residual_contract'],bootstrap_binding=bound)
        return original,result,ctx,bound
    def test_exact_private_semantics_all_chapter_boundaries(self):
        for chapter in ('BU06','BU07','BU08','BU16'):
            for operation in ('down','up'):
                original,result,ctx,bound=self.material(operation,chapter)
                w.validate_private_result(original,result,'1-1',ctx,bound)
    def test_tampered_authentication_run_state_and_source_fail(self):
        original,result,ctx,bound=self.material()
        for field,value in [('authenticated',False),('authenticated',1),('authenticated_group','cp:dev:lifecycle-plan'),('run_id','other'),('source_sha','b'*40),('account','222222222222'),('readyz','failed'),('private_endpoint',False),('cluster_arn','arn:foreign')]:
            changed=copy.deepcopy(result);changed['private_api_readiness']['scope'][field]=value
            with self.subTest(field=field),self.assertRaises(w.h.SafeError):w.validate_private_result(original,changed,'1-1',ctx,bound)
        for mutate in ('binding','generation','source','capability'):
            old=copy.deepcopy(original);changed=copy.deepcopy(result)
            if mutate=='binding':changed['private_api_readiness']['state_binding']['operations_access']['version']='other'
            if mutate=='generation':changed['checkpoint_generation']='2-1'
            if mutate=='source':changed['private_api_readiness']['snapshot_sha']='b'*40
            if mutate=='capability':old['source_capability']['operations_source_sha256']='b'*64
            with self.subTest(mutate=mutate),self.assertRaises(w.h.SafeError):w.validate_private_result(old,changed,'1-1',ctx,bound)
    def test_early_down_cannot_expand_or_change_residuals(self):
        original,result,ctx,bound=self.material('down')
        for mutate in ('uid','metadata','added','missing','binding'):
            changed=copy.deepcopy(result)
            # Retained semantic snapshot remains the original; only completion drifts.
            changed['residual_contract']=copy.deepcopy(result['residual_contract'])
            if mutate=='uid':changed['residual_contract']['approved_residuals'][0]['uid']='other'
            if mutate=='metadata':changed['residual_contract']['approved_residuals'][0]['metadata_policy_sha256']='a'*64
            if mutate=='added':changed['residual_contract']['approved_residuals'].append(copy.deepcopy(changed['residual_contract']['approved_residuals'][0]))
            if mutate=='missing':changed['residual_contract']['approved_residuals']=[]
            if mutate=='binding':changed['bootstrap_binding']={'foreign':'proof'}
            with self.subTest(mutate=mutate),self.assertRaises(w.h.SafeError):w.validate_private_result(original,changed,'1-1',ctx,bound)
    def test_bu06_uses_no_bootstrap_and_rejects_nodegroup(self):
        ctx=context('up','BU06');eks=g.roots(ctx)[1];state={'version':4,'resources':[]}
        with patch.object(p,'probe_binding',return_value=(effective(),{'eks':'one'},{eks:{'state':state}},None)) as bind:
            p.private_binding(ctx,None,{})
            self.assertEqual(bind.call_args.kwargs,{'require_bootstrap':False,'require_probe_namespace':False})
        guard=Mock();guard.roots.return_value=g.roots(ctx);guard.managed_resources.return_value=[{'type':'aws_eks_node_group'}]
        with patch.object(p,'probe_binding',return_value=(effective(),{'eks':'one'},{eks:{'state':state}},None)),patch.object(p,'load_shared',return_value=guard),self.assertRaises(p.p.GuardError):p.private_binding(ctx,None,{})
    def test_bu07_requires_bootstrap_and_early_guard_selects_authenticated_hook(self):
        with patch.object(p,'probe_binding',return_value=(effective(),{}, {},None)) as binding:p.private_binding(context('up'),None,{})
        self.assertTrue(binding.call_args.kwargs['require_bootstrap'])
        for chapter,step in [('BU07',w.PRIVATE_STEP),('BU08','hook:platform-core')]:
            barrier=Mock();barrier.for_consumer.return_value={'no_mutation':True,'checkpoint_generation':'1-1','bootstrap_binding':{'eks':'one'},'residual_contract':residual(),'load_balancers_absent':True}
            with patch.dict(os.environ,{'COMPLETED_CHAPTER':chapter,'LIFECYCLE_BARRIER_RECEIPTS':'{}'}),patch.object(g,'load',return_value=barrier):
                self.assertEqual(g.authenticated_residual_contract(context()),residual());self.assertEqual(barrier.for_consumer.call_args.kwargs['step'],step)
        with patch.dict(os.environ,{'COMPLETED_CHAPTER':'BU06'}),patch.object(g,'load') as barrier:
            self.assertIsNone(g.authenticated_residual_contract(context(chapter='BU06')));barrier.assert_not_called()

class PrivateSettingsTests(unittest.TestCase):
    def test_stage_roles_and_absent_image_configuration(self):
        for environment,chapter,operation,stage,suffix in [('dev','BU06','up','plan','apply'),('dev','BU07','up','verify','apply'),('prod','BU15','up','plan','plan'),('prod','BU15','up','verify','apply'),('prod','BU15','up','apply','apply'),('dev','BU07','down','plan','lifecycle-destroy')]:
            env={'LIFECYCLE_STEP_ID':w.PRIVATE_STEP,'LIFECYCLE_ENVIRONMENT':environment,'GITHUB_ACTIONS':'true','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','OPERATION':operation,'GITHUB_WORKSPACE':str(ROOT),'GITHUB_REPOSITORY_ID':'1','GITHUB_RUN_ID':'2','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'LIFECYCLE_SNAPSHOT_SHA':'a'*40,'LIFECYCLE_GENERATION':'1-1','LIFECYCLE_CONFIG_SHA256':'b'*64,'COMPLETED_CHAPTER':chapter,'EXPECTED_ACCOUNT_ID':ACCOUNT,'AWS_REGION':'ap-northeast-2','STATE_BUCKET':'private','AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-{environment}-{suffix}'}
            course={'phase':'paused','operation':operation,'generation':'1-1','snapshot_sha':'a'*40,'registry_sha256':'b'*64,'steps':[w.PRIVATE_STEP]}
            config={'account_id':ACCOUNT,'region':'ap-northeast-2'}
            with patch.dict(os.environ,env,clear=True),patch.object(w.h,'refresh_profile_guard'),patch.object(w.h,'check_identity') as identity,patch.object(w.h,'execute',return_value=b'a'*40),patch.object(w.h,'ensure_current_main'),patch.object(w.p,'registration',return_value=config),patch.object(w.p,'validate_inputs') as images,patch.object(w,'validate_source',return_value={'operations_access':True}),patch.object(w.h,'Store'),patch.object(w,'load'),patch.object(w.c,'assert_incident_clear'),patch.object(w.c,'read_json',return_value=(course,{})),patch.object(w.c,'validate_course'):
                _,_,_,key,ctx=w.settings(stage);self.assertEqual(ctx['probe_inputs'],{});self.assertEqual(ctx['private_api_contract']['bootstrap_required'],chapter!='BU06');self.assertTrue(key.endswith('/hook-cluster-private-api-check.json'));images.assert_not_called();identity.assert_called_once_with(ACCOUNT,env['AWS_ROLE_ARN'])

class ExactResidualGuardTests(unittest.TestCase):
    def contract(self,objects):
        ctx={'source_sha':'a'*40,'generation':'1-1'};live={'arn':'arn','createdAt':'now'}
        rows=[]
        for resource,obj in objects:
            metadata={k:obj['metadata'].get(k) for k in ('labels','annotations','finalizers','ownerReferences')}
            rows.append({'resource':resource,'namespace':obj['metadata'].get('namespace',''),'name':obj['metadata']['name'],'uid':obj['metadata']['uid'],'spec_sha256':g.residual_spec_hash(obj),'metadata_policy_sha256':hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
        return {'schema_version':1,'cluster_arn':'arn','cluster_created_at':'now',**ctx,'approved_residuals':rows},ctx,live
    def baseline(self):return load('early_strict_baseline',HERE/'test_eks_guard.py').baseline()
    def test_exact_networkpolicy_pdb_and_unicode_configmap(self):
        inv=self.baseline();objects=[]
        for resource,kind,api in [('networkpolicies','NetworkPolicy','networking.k8s.io/v1'),('poddisruptionbudgets','PodDisruptionBudget','policy/v1'),('configmaps','ConfigMap','v1')]:
            obj={'apiVersion':api,'kind':kind,'metadata':{'namespace':'argocd','name':'exact','uid':kind},'spec':{}}
            if kind=='ConfigMap':obj.update(data={'한국어':'값'})
            inv.setdefault(resource,[]).append(obj);objects.append((resource,obj))
        contract,ctx,live=self.contract(objects);g.validate_residual_inventory(inv,contract,ctx,live)
        inv['networkpolicies'][0]['metadata']['uid']='foreign'
        with self.assertRaises(g.SafeError):g.validate_residual_inventory(inv,contract,ctx,live)
    def test_exact_completed_hook_job_children_require_success_and_uid(self):
        inv=self.baseline();job={'apiVersion':'batch/v1','kind':'Job','metadata':{'namespace':'argocd','name':'init','uid':'job','annotations':{'helm.sh/hook':'pre-install'}},'spec':{},'status':{'conditions':[{'type':'Complete','status':'True'}]}}
        pod={'apiVersion':'v1','kind':'Pod','metadata':{'namespace':'argocd','name':'init-pod','uid':'pod','ownerReferences':[{'kind':'Job','uid':'job','controller':True}]},'spec':{},'status':{'phase':'Succeeded'}}
        inv['jobs']=[job];inv['pods']=[pod];contract,ctx,live=self.contract([('jobs',job)]);g.validate_residual_inventory(inv,contract,ctx,live)
        for mutate in ('active','failed','child-running','foreign-parent'):
            altered=copy.deepcopy(inv)
            if mutate in ('active','failed'):altered['jobs'][0]['status'][mutate]=1
            if mutate=='child-running':altered['pods'][0]['status']['phase']='Running'
            if mutate=='foreign-parent':altered['pods'][0]['metadata']['ownerReferences'][0]['uid']='other'
            with self.subTest(mutate=mutate),self.assertRaises(g.SafeError):g.validate_residual_inventory(altered,contract,ctx,live)
    def test_only_exact_five_velero_metadata_types(self):
        inv=self.baseline();objects=[]
        for index,resource in enumerate(g.VELERO_RESIDUAL_READS):
            obj={'apiVersion':'velero.io/v1','kind':resource,'metadata':{'namespace':'velero','name':'exact','uid':str(index)},'spec':{}}
            inv[resource]=[obj];objects.append((resource,obj))
        contract,ctx,live=self.contract(objects);g.validate_residual_inventory(inv,contract,ctx,live)
        bad=copy.deepcopy(contract);bad['approved_residuals'][0].pop('metadata_policy_sha256')
        with self.assertRaises(g.SafeError):g.validate_residual_inventory(inv,bad,ctx,live)
        for resource in ('volumesnapshots','volumesnapshotcontents','arbitrary'):
            obj={'apiVersion':'snapshot.storage.k8s.io/v1','kind':'VolumeSnapshot','metadata':{'namespace':'velero','name':'exact','uid':'other'},'spec':{}}
            rows,_,_=self.contract([(resource,obj)]);altered=self.baseline();altered[resource]=[obj]
            with self.assertRaises(g.SafeError):g.validate_residual_inventory(altered,rows,ctx,live)

if __name__=='__main__':unittest.main()
