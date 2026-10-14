import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import yaml

HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

d = load('course_dispatcher_test', 'terraform-lifecycle.py')
f = load('course_test_fixtures', 'test_vpc_lifecycle.py')
P = 'terraform/environments/dev/'


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.registry = d.read_registry()
        self.env = {'OPERATION': 'down', 'LIFECYCLE_ENVIRONMENT': 'dev', 'COMPLETED_CHAPTER': 'BU05',
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch'}

    def test_bu05_cumulative_deduplicated_forward_and_reverse_order(self):
        selected = d.resolve('down', 'dev', 'BU05', self.registry)
        self.assertEqual(selected['up_order'], [P+'network/vpc', P+'network/peer', P+'network/transit'])
        self.assertEqual(selected['down_order'], list(reversed(selected['up_order'])))
        for root in ('bootstrap/state', 'bootstrap/ci-identity', 'account-baseline', 'account-baseline-dns', 'network/log-storage'):
            self.assertIn(P+root, selected['retained'])
            self.assertNotIn(P+root, selected['down_order'])

    def test_reused_eks_and_vpc_roots_only_once(self):
        selected = d.resolve('up', 'dev', 'BU07', self.registry, executable=False)
        self.assertEqual(selected['up_order'].count(P+'network/vpc'), 1)
        self.assertEqual(selected['up_order'].count(P+'eks'), 1)
        self.assertLess(selected['up_order'].index(P+'platform/private-api'), selected['up_order'].index(P+'eks'))
        self.assertFalse(selected['blockers'])

    def test_supported_completed_chapters_have_no_registry_blockers(self):
        for chapter in self.registry['chapter_order']:
            with self.subTest(chapter=chapter):
                self.assertFalse(d.resolve('down', 'dev', chapter, self.registry)['blockers'])

    def test_unknown_and_pre_course_prod_stop_before_aws_or_adapter_import(self):
        cases = [('prod','BU02'), ('stage','BU15'), ('dev','BU99'), ('dev','../BU05'), ('dev','BU05\nroot=eks')]
        for environment, chapter in cases:
            with self.subTest(environment=environment, chapter=chapter), patch.dict(os.environ, {**self.env, 'LIFECYCLE_ENVIRONMENT':environment,'COMPLETED_CHAPTER':chapter}, clear=True), patch.object(d,'load_engine') as engine, patch('subprocess.run',side_effect=AssertionError('No subprocess allowed')):
                with self.assertRaises(d.SelectionError): d.run('settings')
                engine.assert_not_called()

    def test_unsupported_hooks_cannot_be_enabled_by_json(self):
        registry = copy.deepcopy(self.registry)
        registry['hooks']['platform-core']['status'] = 'ready'
        with self.assertRaises(d.SelectionError): d.resolve('down','dev','BU08',registry)

    def test_registry_cannot_redirect_adapter_to_iam_s3_or_unknown_code(self):
        for root, changes in [(P+'bootstrap/ci-identity', {'mode':'adapter','engine':'dev-network-v2'}),
                              (P+'network/log-storage', {'mode':'adapter','engine':'dev-network-v2'}),
                              (P+'network/vpc', {'engine':'../../arbitrary.sh'}),
                              (P+'network/vpc', {'command':'terraform destroy'})]:
            registry=copy.deepcopy(self.registry);registry['roots'][root].update(changes)
            with self.subTest(root=root,changes=changes):
                with self.assertRaises(d.SelectionError):d.resolve('down','dev','BU05',registry)

    def test_cycles_unknown_dependencies_duplicate_keys_and_schema_fail_closed(self):
        root=P+'network/vpc'; registry=copy.deepcopy(self.registry)
        registry['roots'][P+'network/log-storage']['dependencies']=[root]
        with self.assertRaises(d.SelectionError):d.resolve('down','dev','BU05',registry)
        for dependency in ('bad', 'terraform/environments/prod/network/vpc', root):
            registry=copy.deepcopy(self.registry);registry['roots'][root]['dependencies']=[dependency]
            with self.assertRaises(d.SelectionError):d.resolve('down','dev','BU02',registry)
        for version in (True,1,'2',None):
            registry=copy.deepcopy(self.registry);registry['schema']=version
            with self.assertRaises(d.SelectionError):d.resolve('down','dev','BU02',registry)
        with self.assertRaises(d.SelectionError):json.loads('{"schema":2,"schema":2}',object_pairs_hook=d.unique_object)

    def test_inspect_is_read_only_and_reports_registered_hook_scope(self):
        with patch.dict(os.environ, {**self.env,'COMPLETED_CHAPTER':'BU08B'}, clear=True),patch.object(d,'load_engine') as engine,patch('builtins.print') as printed:
            d.run('inspect');engine.assert_not_called()
            data=json.loads(printed.call_args.args[0]);self.assertIn('platform-mesh',data['hooks'])
            self.assertFalse(data['blockers'])
            self.assertIn('hook:platform-mesh',data['up_steps'])

    def test_chapter_cannot_change_paused_scope(self):
        selected=d.resolve('down','dev','BU05',self.registry)
        record={'operation':'down','completed':[selected['down_order'][1]]}
        with self.assertRaises(d.SelectionError):d.pending(record,selected)

    def test_selected_contract_map_is_explicit_and_source_bound(self):
        selected=d.resolve('down','dev','BU05',self.registry)
        contract={**d.ENGINES['dev-network-v2'],'contract_env':'LIFECYCLE_LATER_CONTRACT','derive_completion_sha256':True}
        source={root.removeprefix(P):{'mode':'reviewed-fixture'} for root in selected['up_order']}
        inputs={root:{'private':'DO_NOT_LOG'} for root in selected['up_order']};locks={root:'a'*64 for root in selected['up_order']}
        with patch.dict(d.ENGINES,{'dev-network-v2':contract}),patch.dict(os.environ,{'LIFECYCLE_ROOT_CONTRACTS':json.dumps(source)},clear=True):
            raw=d.checkpoint_contracts(self.registry,selected)
            result=d.normalize_contracts(self.registry,raw,'b'*40,inputs,locks)
            self.assertTrue(all(len(value['completion_sha256'])==64 for value in result.values()))
            self.assertEqual(result,d.normalize_contracts(self.registry,result,'b'*40,inputs,locks))
            with self.assertRaises(d.SelectionError):d.normalize_contracts(self.registry,result,'c'*40,inputs,locks)
            os.environ['LIFECYCLE_ROOT_CONTRACTS']=json.dumps({'unregistered':{}})
            with self.assertRaises(d.SelectionError):d.checkpoint_contracts(self.registry,selected)
            os.environ['LIFECYCLE_ROOT_CONTRACTS']='null'
            with self.assertRaises(d.SelectionError):d.checkpoint_contracts(self.registry,selected)

    def test_early_roots_do_not_require_later_contract_secret(self):
        selected=d.resolve('down','dev','BU03',self.registry)
        with patch.dict(os.environ,{},clear=True):self.assertEqual(d.checkpoint_contracts(self.registry,selected),{})

    def test_root_dag_is_valid_for_every_mapped_chapter(self):
        for chapter in self.registry['chapter_order']:
            with self.subTest(chapter=chapter):
                selected=d.resolve('up','dev',chapter,self.registry,executable=False)
                indexes={root:index for index,root in enumerate(selected['roots'])}
                for root in selected['roots']:
                    for dependency in self.registry['roots'][root]['dependencies']:
                        if dependency not in indexes:
                            self.assertIn(chapter,('BU01','BU02'));self.assertEqual(dependency,P+'network/log-storage')
                        else:self.assertLess(indexes[dependency], indexes[root])

    def test_hook_dag_retire_order_and_shared_root_dedup(self):
        registry=copy.deepcopy(self.registry)
        registry['chapters']['BU05']['hooks']=['platform-core','platform-mesh']
        registry['hooks']['platform-core']={'status':'adapter','reason':'reviewed fixture','engine':'fixture',
            'dependencies':[P+'network/vpc'],'required_by':[P+'network/peer','hook:platform-mesh']}
        registry['hooks']['platform-mesh']={'status':'adapter','reason':'reviewed fixture','engine':'fixture',
            'dependencies':['hook:platform-core'],'required_by':[P+'network/transit']}
        with patch.dict(d.HOOK_ENGINES,{'fixture':{'hooks':('platform-core','platform-mesh')}}):
            selected=d.resolve('down','dev','BU05',registry)
        up=selected['up_steps'];self.assertEqual(len(up),len(set(up)))
        self.assertLess(up.index(P+'network/vpc'),up.index('hook:platform-core'))
        self.assertLess(up.index('hook:platform-core'),up.index('hook:platform-mesh'))
        self.assertLess(up.index('hook:platform-mesh'),up.index(P+'network/transit'))
        self.assertEqual(selected['down_steps'],list(reversed(up)))


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name);self.store=f.Store();self.registry=d.read_registry()
        self.selection=d.resolve('down','dev','BU05',self.registry)
        self.target=dict(repository_id='17',account='123456789012',bucket='private-state',region='ap-northeast-2')
        self.env={'OPERATION':'down','COMPLETED_CHAPTER':'BU05','LIFECYCLE_ENVIRONMENT':'dev','GITHUB_REPOSITORY_ID':'17',
                  'GITHUB_RUN_ID':'10','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'GITHUB_OUTPUT':str(self.path/'outputs'),
                  'GITHUB_STEP_SUMMARY':str(self.path/'summary'),'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch'}
        self.record=dict(schema=2,kind='course-lifecycle',phase='paused',**self.target,completed_chapter='BU05',
                         roots=self.selection['roots'],retained_roots=self.selection['retained'],registry_sha256=self.selection['registry_sha256'],
                         generation='10-1',snapshot_sha='a'*40,inputs={root:{} for root in self.selection['up_order']},
                         locks={root:'b'*64 for root in self.selection['up_order']},operation='down',completed=[],events=[],last_result='not-applied',
                         request_run='10',request_attempt='1',workflow_sha='a'*40)
        self.key=d.c.course_marker_key('17');d.c.update(self.store,self.key,self.record,{'exists':False})
        self.env_patch=patch.dict(os.environ,self.env,clear=True);self.env_patch.start();self.addCleanup(self.env_patch.stop)
        self.target_patch=patch.object(d,'target_environment',return_value=(self.path,self.store,self.target));self.target_patch.start();self.addCleanup(self.target_patch.stop)
        self.calls=[]

    def invoke(self,registry,root,stage,descriptor=None, bundle_descriptors=None, barrier_receipts=None, root_contract=None):
        self.calls.append((stage,root,descriptor))
        if stage=='plan':return dict(manifest_key='private/'+root,manifest_version='1',manifest_sha='c'*64,plan_sha='d'*64)
        return {}

    def make_bundle(self):
        d.plan(self.registry,self.selection)
        values=dict(line.split('=',1) for line in (self.path/'outputs').read_text().splitlines())
        os.environ.update(BUNDLE_KEY=values['bundle_key'],BUNDLE_VERSION=values['bundle_version'],EXPECTED_BUNDLE_SHA=values['bundle_sha'])

    def test_down_all_plans_before_any_apply_reverse_dag_and_exact_descriptors(self):
        with patch.object(d,'invoke',side_effect=self.invoke):
            self.make_bundle();self.assertEqual([s for s,_,_ in self.calls],['plan']*3)
            d.apply(self.registry,self.selection)
        self.assertEqual([(s,r) for s,r,_ in self.calls], [('plan',root) for root in self.selection['down_order']]+[('verify',root) for root in self.selection['down_order']]+[('apply',root) for root in self.selection['down_order']])
        self.assertTrue(all(row['plan_sha']=='d'*64 for stage,_,row in self.calls if stage=='apply'))
        record,_=d.c.read_json(self.store,self.key)
        self.assertEqual(record['completed'],self.selection['down_order']);self.assertEqual(record['phase'],'paused')

    def test_dependent_plans_receive_only_prior_descriptors_and_verification_receives_full_bundle(self):
        observed=[]
        def invoke(registry,root,stage,descriptor=None,bundle_descriptors=None,barrier_receipts=None, root_contract=None):
            observed.append((stage,root,copy.deepcopy(bundle_descriptors)))
            return self.invoke(registry,root,stage,descriptor)
        with patch.object(d,'invoke',side_effect=invoke):
            self.make_bundle();d.apply(self.registry,self.selection)
        order=self.selection['down_order']
        for index,(stage,root,descriptors) in enumerate(observed[:len(order)]):
            self.assertEqual(list(descriptors),order[:index])
            self.assertTrue(all(set(value)=={'manifest_key','manifest_version','manifest_sha','plan_sha'} for value in descriptors.values()))
        self.assertTrue(all(list(descriptors)==order for stage,root,descriptors in observed[len(order):]))

    def test_private_descriptor_shape_fails_before_any_adapter(self):
        good={'root':P+'network/vpc','manifest_key':'private/key','manifest_version':'1','manifest_sha':'c'*64,'plan_sha':'d'*64}
        for rows in ([good,good],[{**good,'command':'unsafe'}],[{**good,'manifest_sha':None}],[None],{}):
            with self.subTest(rows=rows),self.assertRaises(d.SelectionError):d.bundle_descriptors(rows)

    def test_partial_failure_preserves_completed_prefix_and_replan_never_replays(self):
        count=0
        def partial(registry,root,stage,descriptor=None, bundle_descriptors=None, barrier_receipts=None, root_contract=None):
            nonlocal count
            result=self.invoke(registry,root,stage,descriptor)
            if stage=='apply':
                count+=1
                if count==2:raise RuntimeError('private partial failure')
            return result
        with patch.object(d,'invoke',side_effect=partial):
            self.make_bundle()
            with self.assertRaises(RuntimeError):d.apply(self.registry,self.selection)
        record,info=d.c.read_json(self.store,self.key)
        self.assertEqual(record['completed'],self.selection['down_order'][:1]);self.assertEqual(record['last_result'],'applying');self.assertEqual(record['phase'],'paused')
        with patch.object(d,'invoke') as invoke:
            with self.assertRaises(d.SelectionError):d.apply(self.registry,self.selection)
            invoke.assert_not_called()
        os.environ['GITHUB_RUN_ID']='11';record['request_run']='11'
        d.c.update(self.store,self.key,record,info);self.calls=[];(self.path/'outputs').write_text('')
        with patch.object(d,'invoke',side_effect=self.invoke):self.make_bundle()
        self.assertEqual([(stage,root) for stage,root,_ in self.calls],[('plan',root) for root in self.selection['down_order'][1:]])

    def test_invalid_later_root_blocks_before_any_destructive_apply(self):
        def failure(registry, root, stage, descriptor=None, bundle_descriptors=None, barrier_receipts=None, root_contract=None):
            result=self.invoke(registry,root,stage,descriptor)
            if stage=='verify' and root==self.selection['down_order'][1]:
                raise d.SelectionError('Later root state changed')
            return result
        with patch.object(d,'invoke',side_effect=failure):
            self.make_bundle()
            with self.assertRaises(d.SelectionError):d.apply(self.registry,self.selection)
        self.assertFalse(any(stage=='apply' for stage,_,_ in self.calls))
        record,_=d.c.read_json(self.store,self.key)
        self.assertEqual(record['completed'],[])

    def test_new_attempt_cannot_apply_previous_bundle(self):
        with patch.object(d,'invoke',side_effect=self.invoke):self.make_bundle()
        os.environ['GITHUB_RUN_ATTEMPT']='2'
        with patch.object(d,'invoke') as invoke:
            with self.assertRaises(d.SelectionError):d.apply(self.registry,self.selection)
            invoke.assert_not_called()

    def test_up_fresh_plan_exact_apply_interleaved_forward_dag(self):
        record,info=d.c.read_json(self.store,self.key);record['operation']='up'
        d.c.update(self.store,self.key,record,info);os.environ['OPERATION']='up'
        with patch.object(d,'invoke',side_effect=self.invoke):d.up(self.registry,self.selection)
        self.assertEqual([(stage,root) for stage,root,_ in self.calls],[(stage,root) for root in self.selection['up_order'] for stage in ('plan','apply')])
        record,_=d.c.read_json(self.store,self.key);self.assertEqual(record['phase'],'active')

    def test_up_partial_failure_cannot_clear_pause(self):
        record,info=d.c.read_json(self.store,self.key);record['operation']='up'
        d.c.update(self.store,self.key,record,info);os.environ['OPERATION']='up'
        with patch.object(d,'invoke',side_effect=RuntimeError('failed fresh plan')):
            with self.assertRaises(RuntimeError):d.up(self.registry,self.selection)
        record,_=d.c.read_json(self.store,self.key);self.assertEqual(record['phase'],'paused')

    def test_checkpoint_never_reads_private_ci_identity_state(self):
        record,info=d.c.read_json(self.store,self.key);record['phase']='active'
        d.c.update(self.store,self.key,record,info)
        for root in self.selection['up_order']:
            path=self.path/root;path.mkdir(parents=True)
            (path/'.terraform.lock.hcl').write_text('reviewed lock')
        os.environ['TF_VARS_JSON']=json.dumps({root.removeprefix(P):{} for root in self.selection['up_order']})
        with patch.object(d.h,'execute',return_value=b''),patch.object(d,'invoke',side_effect=self.invoke):
            d.start(self.registry,self.selection)
        keys=[args[args.index('--key')+1] for _,args in self.store.calls if '--key' in args]
        self.assertFalse(any('bootstrap/ci-identity' in key for key in keys))
        self.assertTrue(all(root in self.selection['up_order'] for _,root,_ in self.calls))
        record,_=d.c.read_json(self.store,self.key)
        self.assertNotIn(P+'bootstrap/ci-identity',record['inputs'])
        self.assertNotIn(P+'bootstrap/ci-identity',record['locks'])

    def test_course_pause_blocks_all_ordinary_dev_including_retained_foundation(self):
        context={'root':P+'bootstrap/ci-identity','repository_id':'17','account':self.target['account'],'backend':{'bucket':self.target['bucket'],'region':self.target['region']}}
        with self.assertRaises(Exception):d.c.assert_normal_allowed(self.store,context,self.path)

    def test_public_checkpoint_summary_has_exact_source_commands_and_no_input_secrets(self):
        record=copy.deepcopy(self.record);record['inputs'][P+'network/vpc']={'secret':'NEVER_PRINT_THIS_SECRET'}
        record['snapshot_sha']='b'*40;record['workflow_sha']='a'*40
        os.environ['GITHUB_REPOSITORY']='example/infra'
        with patch('builtins.print') as printed:
            d.publish_checkpoint_summary(self.selection,record,'down_complete')
        summary=(self.path/'summary').read_text()
        self.assertIn('b'*40,summary);self.assertIn('a'*40,summary)
        self.assertIn('gh workflow run terraform-lifecycle.yml --repo example/infra --ref main -f operation=up -f environment=dev -f completed_chapter=BU05',summary)
        self.assertIn('gh run view 10 --repo example/infra --log',summary)
        self.assertIn('LIFECYCLE_SNAPSHOT_SHA='+'b'*40,str(printed.call_args_list))
        self.assertNotIn('NEVER_PRINT_THIS_SECRET',summary+str(printed.call_args_list))
        self.assertNotIn('TF_VARS_JSON',summary)

    def test_tampered_private_bundle_is_not_applied(self):
        with patch.object(d,'invoke',side_effect=self.invoke):self.make_bundle()
        os.environ['EXPECTED_BUNDLE_SHA']='0'*64
        with patch.object(d,'invoke') as invoke:
            with self.assertRaises(Exception):d.apply(self.registry,self.selection)
            invoke.assert_not_called()


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow=yaml.safe_load((HERE.parent/'.github/workflows/terraform-lifecycle.yml').read_text())

    def test_one_common_workflow_simple_inputs_shared_concurrency(self):
        self.assertEqual(set(self.workflow['on']['workflow_dispatch']['inputs']),{'operation','environment','completed_chapter'})
        self.assertEqual(self.workflow['concurrency'],{'group':'terraform-infra-${{ github.repository_id }}','cancel-in-progress':False})
        self.assertNotIn('actions: write',yaml.safe_dump(self.workflow))
        self.assertNotIn('workflow_dispatch',str(self.workflow['jobs']))

    def test_real_destroy_environment_between_saved_bundle_and_exact_apply(self):
        jobs=self.workflow['jobs'];review=jobs['down-review']
        self.assertIn('down-plan',review['needs']);self.assertEqual(review['environment'],'${{ needs.settings.outputs.destroy_environment }}')
        self.assertEqual(review['permissions'],{});self.assertIn('down-review',jobs['down-apply']['needs'])
        self.assertNotIn('sleep',str(jobs));self.assertNotIn('matrix',str(jobs))
        self.assertEqual(jobs['down-apply']['steps'][-1]['run'],'python3 -I ci/run-lifecycle.py apply')

    def test_selection_before_every_oidc_job(self):
        jobs=self.workflow['jobs'];self.assertNotIn('id-token',jobs['settings']['permissions'])
        for name in ('checkpoint','down-plan','down-apply','up'):
            steps=jobs[name]['steps'];select=next(index for index,step in enumerate(steps) if step.get('run')=='python3 ci/terraform-lifecycle.py select')
            credentials=next(index for index,step in enumerate(steps) if step.get('run','').startswith('python3 -I ci/run-lifecycle.py '))
            self.assertFalse(any(step.get('uses','').startswith('aws-actions/configure-aws-credentials@') for step in steps))
            self.assertLess(select,credentials)
        self.assertEqual(jobs['up']['environment'],'${{ needs.settings.outputs.apply_environment }}')
        self.assertNotIn('down-review',jobs['up']['needs'])

if __name__=='__main__':unittest.main()
