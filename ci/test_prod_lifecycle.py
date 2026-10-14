"""Offline account isolation and genuine reviewed dependency-level sequencing."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import yaml
HERE=Path(__file__).resolve().parent

def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
d=load('prod_controller','terraform-lifecycle.py');f=load('prod_store_fixture','test_vpc_lifecycle.py')
P='terraform/environments/prod/'
A=P+'network/vpc';B=P+'platform/private-api';C=P+'platform/core';D=P+'eks'

class ProdLevels(unittest.TestCase):
 def setUp(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.path=Path(temp.name);self.store=f.Store()
  roots={name:dict(mode='adapter',engine='fixture-prod',dependencies=deps,reason='bounded test fixture') for name,deps in [(A,[]),(B,[A]),(C,[A]),(D,[B,C])]}
  self.registry=dict(schema=2,chapter_order=['BU01','BU15'],chapters={'BU01':dict(roots=[],hooks=[],blockers=[]),'BU15':dict(roots=list(roots),hooks=[],blockers=[])},roots=roots,hooks={})
  with patch.dict(d.ENGINES,{'fixture-prod':{'roots':tuple(roots),'module':'never-loaded.py'}}):self.selection=d.resolve('up','prod','BU15',self.registry)
  self.target=dict(environment='prod',repository_id='17',account='999999999999',bucket='prod-private-state',region='ap-northeast-2')
  self.env=dict(OPERATION='up',LIFECYCLE_ENVIRONMENT='prod',COMPLETED_CHAPTER='BU15',LIFECYCLE_LEVEL='1',GITHUB_RUN_ID='10',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40,GITHUB_REPOSITORY_ID='17',GITHUB_OUTPUT=str(self.path/'out'),GITHUB_STEP_SUMMARY=str(self.path/'summary'))
  self.record=dict(schema=2,kind='course-lifecycle',phase='paused',**self.target,completed_chapter='BU15',roots=self.selection['roots'],steps=self.selection['up_steps'],retained_roots=[],registry_sha256=self.selection['registry_sha256'],generation='1-1',snapshot_sha='b'*40,inputs={r:{'private':'SECRET_SENTINEL'} for r in roots},locks={r:'c'*64 for r in roots},operation='up',completed=[],events=[],last_result='not-applied',request_run='10',request_attempt='1',workflow_sha='a'*40)
  self.key=d.marker(self.target);d.c.update(self.store,self.key,self.record,{'exists':False})
  for obj in (patch.dict(os.environ,self.env,clear=True),patch.object(d,'target_environment',return_value=(self.path,self.store,self.target))):obj.start();self.addCleanup(obj.stop)
  self.calls=[]
 def invoke(self,registry,root,stage,descriptor=None,**kwargs):
  self.calls.append((stage,root,copy.deepcopy(descriptor)))
  if stage=='plan':return dict(manifest_key='private/'+root,manifest_version='1',manifest_sha='d'*64,plan_sha='e'*64)
  return {}
 def plan(self):
  (self.path/'out').write_text('');d.up_plan(self.registry,self.selection)
  values=dict(line.split('=',1) for line in (self.path/'out').read_text().splitlines())
  if values['has_work']=='true':os.environ.update(BUNDLE_KEY=values['bundle_key'],BUNDLE_VERSION=values['bundle_version'],EXPECTED_BUNDLE_SHA=values['bundle_sha'])
  return values
 def test_independent_roots_share_one_level_and_new_outputs_create_next_level(self):
  self.assertEqual(self.selection['up_levels'],[[A],[C,B],[D]])
  with patch.object(d,'invoke',side_effect=self.invoke):
   for level,roots in enumerate(self.selection['up_levels'],1):
    os.environ['LIFECYCLE_LEVEL']=str(level);before,_=d.c.read_json(self.store,self.key)
    self.plan();after,_=d.c.read_json(self.store,self.key);self.assertEqual(before,after)
    d.up_apply(self.registry,self.selection)
    self.assertEqual(self.calls[-len(roots):], [('apply',root,dict(manifest_key='private/'+root,manifest_version='1',manifest_sha='d'*64,plan_sha='e'*64,root=root)) for root in roots])
  saved,_=d.c.read_json(self.store,self.key);self.assertEqual(saved['phase'],'active');self.assertEqual(saved['completed'],[A,C,B,D])
  self.assertNotIn('SECRET_SENTINEL',(self.path/'summary').read_text())
 def test_future_level_cannot_plan_before_dependencies_complete(self):
  os.environ['LIFECYCLE_LEVEL']='2'
  with patch.object(d,'invoke') as invoke,self.assertRaises(d.SelectionError):self.plan()
  invoke.assert_not_called()
 def test_all_level_plans_verified_before_first_apply(self):
  self.record['completed']=[A];_,info=d.c.read_json(self.store,self.key);d.c.update(self.store,self.key,self.record,info);os.environ['LIFECYCLE_LEVEL']='2'
  def invoke(*args,**kwargs):
   result=self.invoke(*args,**kwargs)
   if args[2]=='verify' and args[1]==C:raise d.SelectionError('State changed')
   return result
  with patch.object(d,'invoke',side_effect=invoke):
   self.plan()
   with self.assertRaises(d.SelectionError):d.up_apply(self.registry,self.selection)
  self.assertFalse(any(stage=='apply' for stage,_,_ in self.calls))
 def test_partial_apply_requires_fresh_bundle_and_preserves_pause(self):
  self.record['completed']=[A];_,info=d.c.read_json(self.store,self.key);d.c.update(self.store,self.key,self.record,info);os.environ['LIFECYCLE_LEVEL']='2'
  def invoke(*args,**kwargs):
   result=self.invoke(*args,**kwargs)
   if args[2]=='apply' and args[1]==B:raise RuntimeError('partial')
   return result
  with patch.object(d,'invoke',side_effect=invoke):
   self.plan()
   with self.assertRaises(RuntimeError):d.up_apply(self.registry,self.selection)
  saved,_=d.c.read_json(self.store,self.key);self.assertEqual(saved['completed'],[A,C]);self.assertEqual(saved['phase'],'paused')
  with patch.object(d,'invoke') as invoke,self.assertRaises(d.SelectionError):d.up_apply(self.registry,self.selection)
  invoke.assert_not_called()
  with patch.object(d,'invoke',side_effect=self.invoke):
   self.calls=[];self.plan();self.assertEqual([(s,r) for s,r,_ in self.calls],[('plan',B)])
 def test_completed_level_is_no_write_skip_but_never_replays(self):
  self.record['completed']=[A];_,info=d.c.read_json(self.store,self.key);d.c.update(self.store,self.key,self.record,info)
  with patch.object(d,'invoke') as invoke:
   self.assertEqual(self.plan(),{'has_work':'false'})
   with self.assertRaises(d.SelectionError):d.up_apply(self.registry,self.selection)
   invoke.assert_not_called()
 def test_account_environment_and_marker_isolation(self):
  self.assertEqual(self.key,'ci-lifecycle/17/prod/course.json')
  self.assertNotEqual(self.key,d.c.course_marker_key('17','dev'))
  d.c.validate_course(self.record,**self.target)
  for target in ({**self.target,'environment':'dev'},{**self.target,'account':'123456789012'},{**self.target,'bucket':'dev-state'}):
   with self.assertRaises(Exception):d.c.validate_course(self.record,**target)
  context={'root':P+'bootstrap/state','repository_id':'17','account':self.target['account'],'backend':{'bucket':self.target['bucket'],'region':self.target['region']}}
  with self.assertRaises(Exception):d.c.assert_normal_allowed(self.store,context,self.path)
 def test_dev_automatic_up_is_forbidden_for_prod(self):
  with patch.object(d,'invoke') as invoke,self.assertRaises(d.SelectionError):d.up(self.registry,self.selection)
  invoke.assert_not_called()
 def test_read_only_preview_uses_actual_snapshot_not_main_and_no_secrets(self):
  before,_=d.c.read_json(self.store,self.key);d.preview(self.registry,self.selection);after,_=d.c.read_json(self.store,self.key)
  self.assertEqual(before,after);summary=(self.path/'summary').read_text();self.assertIn('b'*40,summary);self.assertNotIn('SECRET_SENTINEL',summary)

class ProdWorkflow(unittest.TestCase):
 def test_shared_reusable_gate_and_static_bound_no_chained_dispatch(self):
  workflow=yaml.safe_load((HERE.parent/'.github/workflows/terraform-lifecycle.yml').read_text())
  reusable=yaml.safe_load((HERE.parent/'.github/workflows/terraform-lifecycle-level.yml').read_text())
  jobs=workflow['jobs'];self.assertEqual(jobs['lifecycle-preview']['environment'],'${{ needs.settings.outputs.plan_environment }}')
  self.assertIn('source ${{ needs.lifecycle-preview.outputs.snapshot_sha',jobs['checkpoint']['name'])
  for level in range(1,d.MAX_UP_LEVELS+1):
   row=jobs[f'prod-up-{level:02d}'];self.assertEqual(row['uses'],'./.github/workflows/terraform-lifecycle-level.yml');self.assertEqual(row['with']['level'],level)
   self.assertIn('fromJSON(needs.settings.outputs.up_level_count)',row['if'])
   if level>1:self.assertIn(f'prod-up-{level-1:02d}',row['needs'])
  self.assertEqual(reusable['jobs']['plan']['environment'],'infra-prod-plan');self.assertEqual(reusable['jobs']['apply']['environment'],'infra-prod-apply')
  self.assertEqual(reusable['jobs']['apply']['if'],"needs.plan.outputs.has_work == 'true'")
  self.assertNotIn('concurrency',reusable);self.assertNotIn('actions: write',yaml.safe_dump(workflow)+yaml.safe_dump(reusable))
  self.assertEqual(reusable['jobs']['apply']['steps'][-1]['run'],'python3 -I ci/run-lifecycle.py up-apply')
 def test_privileged_down_has_two_real_destroy_gates_and_no_normal_role_fallback(self):
  w=yaml.safe_load((HERE.parent/'.github/workflows/terraform-lifecycle.yml').read_text());jobs=w['jobs']
  for name in ('privileged-prepare','privileged-apply'):
   self.assertEqual(jobs[name]['environment'],'${{ needs.settings.outputs.destroy_environment }}')
   self.assertIn("privileged_destroy == 'true'",jobs[name]['if'])
   self.assertFalse(any(step.get('uses','').startswith('aws-actions/configure-aws-credentials') for step in jobs[name]['steps']))
  self.assertIn('privileged-prepare',jobs['privileged-apply']['needs'])
  self.assertEqual(jobs['privileged-prepare']['steps'][-1]['run'],'python3 -I ci/run-lifecycle.py prepare')
  self.assertEqual(jobs['privileged-apply']['steps'][-1]['run'],'python3 -I ci/run-lifecycle.py destroy-apply')
  self.assertIn('needs.privileged-prepare.outputs.bundle_sha',jobs['privileged-apply']['env']['EXPECTED_BUNDLE_SHA'])

 def test_real_prod_map_is_separate_and_uses_reviewed_static_providers(self):
  with patch.dict(os.environ,{'LIFECYCLE_ENVIRONMENT':'prod'},clear=True):registry=d.read_registry()
  selection=d.resolve('up','prod','BU15',registry,executable=False)
  self.assertTrue(all('/prod/' in root for root in selection['roots']));self.assertFalse(selection['blockers'])
  self.assertTrue(d.resolve('up','prod','BU15',registry)['privileged_destroy'])
  self.assertIn('prod-edge-publication',selection['hooks'])

if __name__=='__main__':unittest.main()
