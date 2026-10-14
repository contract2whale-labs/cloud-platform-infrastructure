import contextlib
import copy
import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import patch, Mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import application_hooks as hooks
spec=importlib.util.spec_from_file_location('asset_lifecycle',ROOT/'application-lifecycle.py')
adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)

class AssetHooks(unittest.TestCase):
    def config(self,hook):
        return {'_hook':hook,'account_id':'123456789012','applications':[]}
    def test_all_three_have_no_live_application_or_cluster_dependency(self):
        for hook in hooks.ASSET_HOOKS:
            with self.subTest(hook=hook),patch.object(hooks,'retained_assets',return_value={'immutable':'evidence'}),patch.object(hooks.core,'api_inventory',side_effect=AssertionError('inventory forbidden')),patch.object(hooks.core,'get_app',side_effect=AssertionError('Application read forbidden')),patch.object(hooks.core,'plan_authorities',side_effect=AssertionError('authority read forbidden')),patch.object(hooks.core,'verify_authorities',side_effect=AssertionError('authority read forbidden')),patch.object(hooks.core,'restore_authorities',side_effect=AssertionError('authority restore forbidden')),patch.object(hooks.ops,'run',side_effect=AssertionError('No unmocked access')):
                c=self.config(hook);snapshot=hooks.plan(c,'dev','1-1')
                self.assertEqual(snapshot['applications'],[])
                self.assertEqual(snapshot['authorities'],[])
                hooks.verify(c,'dev',snapshot,'1-1')
                down=hooks.down(c,'dev',snapshot,'1-1',Mock())
                self.assertEqual(down['retired'],[])
                self.assertEqual(down['restored'],[])
                up=hooks.up(c,'dev',snapshot,'1-1',pathlib.Path('/tmp'))
                self.assertEqual(up['restored'],[])
                self.assertEqual(up['retained_assets'],snapshot['retained_assets'])
    def test_asset_drift_rejects_both_directions(self):
        c=self.config('queue-credentials-provision')
        with patch.object(hooks,'retained_assets',return_value={'writer':{'version_id':'first'}}):snapshot=hooks.plan(c,'dev','1-1')
        with patch.object(hooks,'retained_assets',return_value={'writer':{'version_id':'changed'}}):
            with self.assertRaises(Exception):hooks.down(c,'dev',snapshot,'1-1',Mock())
            with self.assertRaises(Exception):hooks.up(c,'dev',snapshot,'1-1',pathlib.Path('/tmp'))
    def test_asset_snapshot_cannot_smuggle_authorities(self):
        c=self.config('operator-image-publish')
        with patch.object(hooks,'retained_assets',return_value={'operator_images':[{'image':'pinned'}]}):
            snapshot=hooks.plan(c,'dev','1-1');snapshot['authorities']=[{'name':'old-app'}]
            with self.assertRaises(Exception):hooks.verify(c,'dev',snapshot,'1-1')
    def test_image_asset_is_nonempty_mapping_for_central_barrier(self):
        with patch.object(hooks.retained_checks,'images',return_value=[{'image':'immutable'}]):
            self.assertEqual(hooks.retained_assets(self.config('operator-image-publish')),{'operator_images':[{'image':'immutable'}]})

class AssetAdapter(unittest.TestCase):
    def test_saved_plan_round_trip_never_opens_cluster_session(self):
        class Store:
            bucket='state-bucket'
            def __init__(self):self.files={}
            def put(self,key,path):
                data=path.read_bytes();descriptor={'key':key,'version':'1','sha256':adapter.h.digest(data)}
                self.files[key]=data;return descriptor
            def get(self,descriptor,path):path.write_bytes(self.files[descriptor['key']])
        for hook in hooks.ASSET_HOOKS:
            with self.subTest(hook=hook):
                store=Store();record=[None];revision=[0];emitted={}
                c={'_hook':hook,'account_id':'123456789012','applications':[]}
                context={'step_id':'hook:'+hook,'operation':'down','environment':'dev','generation':'1-1','snapshot_sha':'a'*40,'registration_sha256':'b'*64,'run_id':'1','run_attempt':'1','sha':'c'*40,'prefix':'ci-plans/1/dev/'+hook+'/'}
                def update(store,key,value,control):
                    record[0]=copy.deepcopy(value);revision[0]+=1;return {'version':str(revision[0])}
                def read(store,key):return copy.deepcopy(record[0]),{'version':str(revision[0])}
                def required(key):return {'MANIFEST_KEY':emitted['manifest_key'],'MANIFEST_VERSION':emitted['manifest_version'],'EXPECTED_MANIFEST_SHA':emitted['manifest_sha'],'EXPECTED_PLAN_SHA':emitted['plan_sha']}[key]
                with patch.object(adapter,'settings',side_effect=lambda stage:(copy.deepcopy(c),store,'checkpoint',copy.deepcopy(context))),patch.object(adapter,'live_binding',side_effect=AssertionError('cluster binding forbidden')),patch.object(adapter,'load',side_effect=AssertionError('cluster/access module forbidden')),patch.object(adapter.state,'read_json',side_effect=read),patch.object(adapter.state,'update',side_effect=update),patch.object(adapter.h,'emit',side_effect=lambda value:emitted.update(value)),patch.object(adapter.h,'required',side_effect=required),patch.object(adapter.h,'ensure_current_main'),patch.object(hooks,'retained_assets',return_value={'asset':'immutable'}),patch.object(hooks.core,'get_app',side_effect=AssertionError('Application read forbidden')),patch.object(hooks.core,'api_inventory',side_effect=AssertionError('inventory forbidden')):
                    for operation in ('down','up'):
                        context['operation']=operation;context['prefix']='ci-'+operation+'-plans/1/dev/'+hook+'/'
                        adapter.run('start');adapter.run('plan');adapter.run('verify');adapter.run('apply')
                        receipt=json.loads(store.files[record[0]['receipt']['key']])
                        self.assertEqual(receipt['result']['retained_assets'],{'asset':'immutable'})
                        self.assertEqual(receipt['result']['restored'],[])
                self.assertEqual(record[0]['phase'],'active')

class BootstrapHandoff(unittest.TestCase):
    def test_fixed_handler_resolves_installed_ci_gitops_layout(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory)/'ci/gitops';(base/'operations').mkdir(parents=True)
            (base/'operations/bootstrap_job_ops.py').write_text('INSTALLED = True\n')
            with patch.object(hooks,'BASE',base):self.assertTrue(hooks.bootstrap_module().INSTALLED)
    def test_fresh_plan_request_is_retained_for_exact_preapply_comparison(self):
        module=Mock();io=Mock();request={'source_sha':'a'*40,'db_resource_id':'fresh-incarnation'}
        target={'db':{'resource_id':'fresh-incarnation'},'source_sha':'a'*40}
        module.lifecycle_request.return_value=request;module.snapshot.return_value=target
        c={'_hook':'database-bootstrap'};ctx={'operation':'up','snapshot_sha':'a'*40}
        with patch.object(hooks,'bootstrap_module',return_value=module),patch.object(hooks,'bootstrap_io',return_value=io):
            action=hooks.prepare_bootstrap(c,ctx,'store')
            current=hooks.prepare_bootstrap(c,ctx,'store',request=action['request'])
            self.assertEqual(current,action)
            self.assertEqual(module.lifecycle_request.call_count,1)
            self.assertEqual(action['target']['db']['resource_id'],'fresh-incarnation')
    def test_old_request_source_rejected(self):
        module=Mock();module.lifecycle_request.return_value={'source_sha':'b'*40}
        with patch.object(hooks,'bootstrap_module',return_value=module),patch.object(hooks,'bootstrap_io',return_value=Mock()),self.assertRaises(Exception):
            hooks.prepare_bootstrap({'_hook':'database-bootstrap'},{'operation':'up','snapshot_sha':'a'*40},'store')
        module.snapshot.assert_not_called()
    def test_resume_observes_original_created_job_never_recreates(self):
        target={'source_sha':'a'*40,'bootstrap_run_id':'run','created_job':{'uid':'exact-original'}}
        module=Mock();module.observe_snapshot.return_value=target
        with patch.object(hooks,'bootstrap_module',return_value=module),patch.object(hooks,'bootstrap_io',return_value=Mock()):
            action=hooks.prepare_bootstrap({'_hook':'database-bootstrap'},{'operation':'up','snapshot_sha':'a'*40},'store',{'target':target})
        self.assertEqual(action,{'mode':'observe','target':target})
        module.verify_database.assert_called_once();module.snapshot.assert_not_called();module.lifecycle_request.assert_not_called()
    def test_up_executes_fixed_handler_instead_of_historical_job_read(self):
        app={'metadata':{'name':'platform-database-operations-dev'},'spec':{'source':{'targetRevision':'a'*40}}}
        c={'_hook':'database-bootstrap','account_id':'123','applications':[app],'state_bucket':'bucket','completion':{'namespace':'contract2whale-demo','disposable_lab':True,'seed_reset_approved':True,'cache_reset_approved':True,'application_image':'app@sha256:'+'d'*64,'fixture_sha256':'e'*64,'migration_sha256':'f'*64}}
        snapshot={'checkpoint_generation':'1-1','account_id':'123','applications':[{'desired':app}]}
        target={'db':{'resource_id':'new'}};action={'mode':'create','request':{'source_sha':'a'*40},'target':target}
        receipt={'created_job':{'uid':'fresh-job'},'created_configmap':{'uid':'fresh-configmap'},'database':target['db'],'complete':True}
        module=Mock();module.snapshot.return_value=target;module.apply.return_value=receipt
        guard=types.SimpleNamespace(BOUND={},verify_fixture_source=Mock(return_value={}))
        fake_spec=types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda m:None))
        live=dict(app,metadata={**app['metadata'],'uid':'app-uid'})
        with patch.object(hooks,'bootstrap_module',return_value=module),patch.object(hooks,'bootstrap_io',return_value=Mock()),patch.object(hooks.importlib.util,'spec_from_file_location',return_value=fake_spec),patch.object(hooks.importlib.util,'module_from_spec',return_value=guard),patch.dict(hooks.os.environ,{'LIFECYCLE_SNAPSHOT_SHA':'a'*40}),patch.object(hooks.core,'restore_authorities'),patch.object(hooks.core,'get_app',return_value=live),patch.object(hooks.ops,'argo_connection',return_value=contextlib.nullcontext(['argocd'])),patch.object(hooks.ops,'run',side_effect=[b'',b'',b'',json.dumps(live).encode()]),patch.object(hooks.ops,'validate_images'),patch.object(hooks.ops,'validate_ownership'),patch.object(hooks.ops,'validate_receipt'),patch.object(hooks,'get',side_effect=AssertionError('Historical Job read forbidden')):
            result=hooks.up(c,'dev',snapshot,'1-1',pathlib.Path('/tmp'),bootstrap_action=action,bootstrap_mark=Mock())
        module.apply.assert_called_once();self.assertEqual(result['database_bootstrap'],receipt)
        self.assertEqual(result['bootstrap_job_uid'],'fresh-job')
    def test_saved_plan_requires_preapply_revalidation_and_durable_mark(self):
        source=(ROOT/'application-lifecycle.py').read_text()
        self.assertLess(source.index('h.require(current==bootstrap_action'),source.index("record['apply_claim']="))
        self.assertIn("record['database_bootstrap' if operation=='up' else 'database_bootstrap_cleanup']",source)
        self.assertNotIn("completion']['bootstrap_job']",(ROOT/'application_hooks.py').read_text())


class BootstrapCleanupAdapter(unittest.TestCase):
    def test_next_down_start_plan_verify_apply_preserves_exact_prior_receipt(self):
        """Exercise the native planned/active/idle marker across saved-plan stages."""
        import hashlib
        module=hooks.bootstrap_module()
        run_id='a3d58c60-12ef-4cf1-8ed9-76f16b880001';name='database-bootstrap-'+run_id
        source='a'*40;objects={};delete_options=[]
        for kind,resource in [('Job','jobs.batch'),('ConfigMap','configmaps')]:
            objects[resource]={'apiVersion':'batch/v1' if kind=='Job' else 'v1','kind':kind,'metadata':{'uid':'uid-'+kind,'name':name,'namespace':module.NS,'resourceVersion':'3'},'spec':{}}
        objects['jobs.batch']['status']={'succeeded':1}
        def identity(obj):
            return {'uid':obj['metadata']['uid'],'name':obj['metadata']['name'],'namespace':obj['metadata']['namespace'],'body_sha256':hooks.digest({k:v for k,v in obj.items() if k not in ('metadata','status')}),'metadata_sha256':hooks.digest({k:obj['metadata'].get(k) for k in ('labels','annotations','ownerReferences')})}
        identities={'created_job':identity(objects['jobs.batch']),'created_configmap':identity(objects['configmaps'])}
        class Store:
            bucket='state-bucket'
            def __init__(self):self.files={}
            def put(self,key,path):
                data=path.read_bytes();self.files[key]=data
                return {'key':key,'version':'1','sha256':hashlib.sha256(data).hexdigest()}
            def get(self,desc,path):
                data=self.files[desc['key']]
                self.assert_digest(data,desc['sha256']);path.write_bytes(data)
            @staticmethod
            def assert_digest(data,wanted):
                if hashlib.sha256(data).hexdigest()!=wanted:raise ValueError('receipt digest')
        store=Store()
        old_key='ci-logs/1/9/1/'+source+'/dev/hooks/database-bootstrap/lifecycle-up/apply/receipt.json'
        old_receipt={'kind':'gitops-lifecycle-completion','context':{'operation':'up','step_id':'hook:database-bootstrap','account':'123456789012','environment':'dev','repository_id':'1','snapshot_sha':source},'result':{'database_bootstrap':dict(identities,bootstrap_run_id=run_id,complete=True,raw_job_logs_published=False,source_sha=source,target_sha256='d'*64)}}
        data=json.dumps(old_receipt).encode();store.files[old_key]=data
        old_desc={'key':old_key,'version':'1','sha256':hashlib.sha256(data).hexdigest()}
        record=[{'phase':'active','receipt':old_desc}];revision=[0];emitted={}
        c={'_hook':'database-bootstrap','account_id':'123456789012','environment':'dev','operations_access_config_sha256':'e'*64,'cluster':'cluster','relay':'relay','region':'ap-northeast-2'}
        context={'step_id':'hook:database-bootstrap','operation':'down','environment':'dev','repository_id':'1','generation':'10-1','snapshot_sha':source,'registration_sha256':'b'*64,'run_id':'10','run_attempt':'1','sha':'c'*40,'prefix':'ci-plans/1/10/1/'+source+'/dev/hooks/database-bootstrap/lifecycle-down/'}
        def read(*args):return copy.deepcopy(record[0]),{'version':str(revision[0])}
        def update(store,key,value,control):record[0]=copy.deepcopy(value);revision[0]+=1;return {'version':str(revision[0])}
        def required(key):
            if key=='GITHUB_REPOSITORY_ID':return '1'
            return {'MANIFEST_KEY':emitted['manifest_key'],'MANIFEST_VERSION':emitted['manifest_version'],'EXPECTED_MANIFEST_SHA':emitted['manifest_sha'],'EXPECTED_PLAN_SHA':emitted['plan_sha']}[key]
        def kube(kind,ns,wanted,optional=False):
            self.assertEqual(ns,module.NS);self.assertEqual(wanted,name)
            return copy.deepcopy(objects.get(kind))
        def run(args):
            self.assertIn('delete',args);options=json.loads(pathlib.Path(args[-1]).read_bytes());delete_options.append(options)
            kind='jobs.batch' if '/jobs/' in args[args.index('--raw')+1] else 'configmaps'
            self.assertEqual(options['preconditions'],{'uid':objects[kind]['metadata']['uid'],'resourceVersion':'3'})
            objects.pop(kind);return b''
        io=types.SimpleNamespace(require=hooks.check,kube=kube,identity=identity,ops=types.SimpleNamespace(run=run),h=types.SimpleNamespace(required=required,canonical=adapter.h.canonical))
        proof={'key':'proof','version':'1','sha256':'f'*64,'receipt':{'installer_residual_resources':[]}}
        access=types.SimpleNamespace(verify_bootstrap_receipt=Mock(return_value=proof))
        private=types.SimpleNamespace(private_api=lambda *args:contextlib.nullcontext(({'KUBECONFIG':'/tmp/no-live-cluster'},{})))
        snapshot={'applications':[],'retained_assets':{},'disposable_volumes':[]}
        with patch.object(adapter,'settings',side_effect=lambda stage:(copy.deepcopy(c),store,'checkpoint',copy.deepcopy(context))),patch.object(adapter,'live_binding',side_effect=lambda c,s:(copy.deepcopy(c),{})),patch.object(adapter,'load',side_effect=lambda name,path:access if name=='gitops_access' else private),patch.object(adapter.state,'read_json',side_effect=read),patch.object(adapter.state,'update',side_effect=update),patch.object(adapter.h,'emit',side_effect=lambda value:emitted.update(value)),patch.object(adapter.h,'required',side_effect=required),patch.object(adapter.h,'ensure_current_main'),patch.object(hooks,'plan',return_value=snapshot),patch.object(hooks,'verify'),patch.object(hooks,'bootstrap_module',return_value=module),patch.object(hooks,'bootstrap_io',return_value=io),patch.object(hooks.ops,'run',side_effect=AssertionError('No external commands')):
            adapter.run('start')
            self.assertEqual(record[0]['database_bootstrap_cleanup']['phase'],'planned')
            self.assertEqual(record[0]['database_bootstrap_cleanup']['target']['creation_receipt'],old_desc)
            adapter.run('plan');adapter.run('verify');adapter.run('apply')
        self.assertEqual(objects,{})
        self.assertEqual(len(delete_options),2)
        self.assertEqual(record[0]['database_bootstrap_cleanup']['phase'],'idle')
        receipt=json.loads(store.files[record[0]['receipt']['key']])
        self.assertEqual(receipt['result']['bootstrap_cleanup']['deleted_uids'],['uid-Job','uid-ConfigMap'])
        self.assertEqual(receipt['result']['bootstrap_cleanup']['creation_receipt'],old_desc)

if __name__=='__main__':unittest.main()
