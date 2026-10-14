import copy,importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
B=Path(__file__).resolve().parent;C=B.parent
sp=importlib.util.spec_from_file_location('registered_guard_test',C/'ci/registered-root-guard.py');g=importlib.util.module_from_spec(sp);sp.loader.exec_module(g)
CORE='terraform/environments/dev/platform/core';EDGE='terraform/environments/dev/platform/edge';ACCESS='terraform/environments/dev/platform/dev-app-access'
def context(root=CORE,operation='down'):
 return dict(root=root,environment='dev',workspace='default',account='123456789012',operation=operation,
 backend=dict(key=g.key(root),bucket='private-state',region='ap-northeast-2'),repository_id='10',run_id='20',run_attempt='1',
 sha='a'*40,source_sha='b'*40,generation='20-1',lifecycle_registry_sha256='c'*64,selected_roots=[root])
def row(address='module.component.aws_iam_role.cert_manager',ty='aws_iam_role',identity='course-dev-cert-manager'):
 return dict(address=address,type=ty,mode='managed',name=address.rsplit('.',1)[-1],values={'id':identity,'name':identity})
def state(rows=()):return {'format_version':'1.0','values':{'root_module':{'resources':list(rows)}}}
def plan(rows=()):
 rows=list(rows)
 return {'format_version':'1.2','complete':True,'prior_state':state(rows),'planned_values':{'root_module':{}},
 'configuration':{'root_module':{}},'resource_changes':[dict(address=r['address'],type=r['type'],mode='managed',change={'actions':['delete'],'before':r['values'],'after':None}) for r in rows]}
class PureGuards(unittest.TestCase):
 def reject(self,fn,*a,**kw):
  with self.assertRaises(Exception):fn(*a,**kw)
 def test_all_first_seven_source_derived_and_edge(self):
  self.assertEqual(len(g.ROOTS),21)
  for root in g.ROOTS:
   self.assertTrue(g.spec(root)['source_variants'])
   for a,t in g.spec(root)['allowed_addresses'].items():
    self.assertEqual(g.check_address(root,a,t),a)
    if t!='aws_s3_bucket_notification':self.assertEqual(g.check_address(root,a+'["key\\\"safe"]',t),a)
    self.assertEqual(g.check_address(root,a+'[0]',t),a)
 def test_unknown_addresses_modules_indices_and_type_confusion(self):
  for address in ('module.other.aws_iam_role.cert_manager','module.component.aws_iam_role.other','module.component.aws_iam_role.cert_manager[0][0]',
   'module.component[0].aws_iam_role.cert_manager','module.component.aws_iam_role.cert_manager[-1]',
   'module.component.aws_iam_role.cert_manager[01]','module.component.aws_iam_role.cert_manager["x"]bad'):
   self.reject(g.check_address,CORE,address,'aws_iam_role')
  self.reject(g.check_address,CORE,'module.component.aws_iam_role.cert_manager','aws_iam_policy')
 def test_all_retained_types_and_whole_app_auth_refused(self):
  for t in ('aws_s3_bucket','aws_s3_bucket_notification','aws_kms_key','aws_secretsmanager_secret','aws_ecr_repository','aws_cognito_user_pool','aws_iam_openid_connect_provider'):
   self.reject(g.check_address,CORE,'module.component.'+t+'.cert_manager',t)
  for root in ('platform/app-auth','bootstrap/ci-identity','retained/operations','retained/observability-foundation'):
   self.reject(g.spec,'terraform/environments/dev/'+root)
  self.reject(g.spec,ACCESS.replace('/dev/','/prod/'))
 def test_ci_bootstrap_identity_disguised_under_allowed_address(self):
  for identity in ('github-actions-ci','cp-dev-bootstrap-role','terraform-state-access','arn:aws:iam::123456789012:role/ci-apply'):
   self.reject(g.validate_state,context(),state([row(identity=identity)]))
  with patch.dict(os.environ,{'AWS_ROLE_ARN':'arn:aws:iam::123456789012:role/innocent'}):
   self.reject(g.validate_state,context(),state([row(identity='innocent')]))
 def test_cross_account_rejected(self):
  r=row();r['values']['arn']='arn:aws:iam::999999999999:role/course'
  self.reject(g.validate_state,context(),state([r]))
 def test_expected_identity_cannot_expand_or_change(self):
  r=row();old=g.normalize_resources(state([r]));g.validate_state(context(),state([r]),old)
  self.reject(g.validate_state,context(),state([row(identity='changed')]),old)
 def test_replacement_forget_move_deposed_deferred_import_drift(self):
  for actions in (['delete','create'],['create','delete'],['forget'],['read']):
   p=plan([row()]);p['resource_changes'][0]['change']['actions']=actions
   self.reject(g.validate_supported_plan,p,CORE)
  for field in ('previous_address','deposed'):
   p=plan([row()]);p['resource_changes'][0][field]='anything';self.reject(g.validate_supported_plan,p,CORE)
  for field in ('deferred_changes','resource_drift'):
   p=plan();p[field]=[{}];self.reject(g.validate_supported_plan,p,CORE)
  p=plan([row()]);p['resource_changes'][0]['change']['importing']={'id':'old'};self.reject(g.validate_supported_plan,p,CORE)
 def test_source_configuration_unknown_even_count_zero(self):
  p=plan();p['configuration']['root_module']['resources']=[{'mode':'managed','type':'aws_s3_bucket','address':'aws_s3_bucket.zero'}]
  self.reject(g.validate_supported_plan,p,CORE)
  p=plan();p['configuration']['root_module']['module_calls']={'evil':{'source':'registry/unknown'}};self.reject(g.validate_supported_plan,p,CORE)
  for extra in ({'mode':'data','type':'external','address':'data.external.evil'}, {'mode':'managed','type':'terraform_data','address':'terraform_data.environment_boundary','provisioners':[{}]}):
   p=plan();p['configuration']['root_module']['resources']=[extra];self.reject(g.validate_supported_plan,p,CORE)
 def test_complete_destroy_prior_and_identity_coverage(self):
  proof=g.load('consumer_delete_test','network-consumer-proof.py');s=state([row()]);p=plan([row()])
  self.assertEqual(proof.validate_delete_plan(s,p)['managed_count'],1)
  for mutate in ('missing','identity','remaining'):
   bad=copy.deepcopy(p)
   if mutate=='missing':bad['resource_changes']=[]
   if mutate=='identity':bad['resource_changes'][0]['change']['before']['id']='other'
   if mutate=='remaining':bad['planned_values']={'root_module':{'resources':[row()]}}
   self.reject(proof.validate_delete_plan,s,bad)
 def test_empty_state_completion_no_cloud_absence_claim(self):
  result=g.validate_down_completion(context(),state())
  self.assertEqual(result,{'scope':'own-empty-managed-state-only','managed_count':0,'cloud_absence_proven':False})
  self.reject(g.validate_down_completion,context(),state([row()]))
 def test_up_exact_coverage_and_known_identity(self):
  r=row();p=plan();p['planned_values']={'root_module':{'resources':[r]}}
  p['resource_changes']=[dict(address=r['address'],mode='managed',type=r['type'],change={'actions':['create'],'before':None,'after':r['values']})]
  self.assertEqual(g.validate_up_completion(p,state([r]),context(operation='up'))['managed_count'],1)
  self.reject(g.validate_up_completion,p,state(),context(operation='up'))
  self.reject(g.validate_up_completion,p,state([row(identity='changed')]),context(operation='up'))
  self.reject(g.validate_up,plan([r]),context(operation='up'))
 def test_edge_requires_effective_false_and_no_aws_objects(self):
  p=plan();p['variables']={'enabled':{'value':False}};up={x:{'fingerprint':{'exists':True}} for x in g.spec(EDGE)['dependencies']}
  g.validate_plan_contracts(context(EDGE),p,up)
  for value in (True,None,0,'false'):
   p['variables']['enabled']['value']=value;self.reject(g.validate_plan_contracts,context(EDGE),p,up)
  self.reject(g.validate_state,context(EDGE),state([row('module.component.aws_cloudfront_distribution.app','aws_cloudfront_distribution')]))
 def test_raw_deposed_and_duplicate_states_refused(self):
  raw={'version':4,'resources':[{'mode':'managed','type':'terraform_data','name':'environment_boundary','instances':[{'deposed':'old','attributes':{'id':'id'}}]}]}
  self.reject(g.validate_state,context(),raw)
  self.reject(g.validate_state,context(),state([row(),row()]))

class IOContracts(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.path=Path(self.t.name);(self.path/'ci').mkdir()
  self.graph={CORE:g.spec(CORE)['dependencies']}
  self.registry={'roots':{CORE:{'mode':'adapter','engine':g.ENGINE}},'hooks':{'platform-core':{'status':'adapter','engine':'dev-gitops-v1'}}}
  self.ctx=context();self.save()
 def tearDown(self):self.t.cleanup()
 def save(self):
  (self.path/'ci/deploy-roots.json').write_text(json.dumps({'dependencies':self.graph}))
  (self.path/'ci/lifecycle-targets.json').write_text(json.dumps(self.registry))
  self.ctx['lifecycle_registry_sha256']=g.h.digest(g.h.canonical(self.registry))
 def test_protected_identity_key_never_read(self):
  calls=[];self.graph['terraform/environments/dev/bootstrap/ci-identity']=[CORE];self.save()
  with self.assertRaises(Exception):g.consumer_states(self.path,self.ctx,load_state=lambda k:calls.append(k))
  self.assertEqual(calls,[])
  self.reject_key='terraform/environments/dev/bootstrap/ci-identity'
  with self.assertRaises(Exception):g.key(self.reject_key)
 def test_live_transitive_consumer_is_not_ignored(self):
  self.graph['terraform/environments/dev/platform/gateway']=[CORE];self.graph[ACCESS]=['terraform/environments/dev/platform/gateway'];self.save()
  calls=[]
  def read(k):calls.append(k);return {'state':state([row()]),'fingerprint':{'exists':True,'version':'1'}}
  consumers=g.consumer_states(self.path,self.ctx,load_state=read)
  self.assertEqual(len(consumers),2);self.assertNotIn('bootstrap/ci-identity/terraform.tfstate',calls)
 def test_missing_hook_implementation_blocks_registration(self):
  self.registry['hooks']['platform-core']['status']='blocked';self.save()
  with self.assertRaises(Exception):g.assert_registration(self.path,self.ctx)
 def test_dev_session_closure_uses_integrated_proof_not_registry_claim(self):
  ctx=context(ACCESS);self.graph[ACCESS]=g.spec(ACCESS)['dependencies'];self.registry['roots'][ACCESS]={'mode':'adapter','engine':g.ENGINE}
  self.registry['hooks']['dev-app-sessions-closed']={'status':'adapter','engine':'dev-gitops-v1'};self.save();ctx['lifecycle_registry_sha256']=self.ctx['lifecycle_registry_sha256']
  self.assertTrue(g.spec(ACCESS)['dev_session_proof']);self.assertEqual(g.spec(ACCESS)['required_down_hooks'],[])
  g.assert_registration(self.path,ctx)
 def test_source_unknown_file_and_known_provisioner_injection_refused(self):
  # Materialize only source bytes already present in the locally supplied tooling.
  original=C/'ci/fixtures/registered-source'
  root=ACCESS
  for p in (original/root).glob('*.tf'):
   dest=self.path/root/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
  self.assertRegex(g.validate_source(self.path,root),'^[0-9a-f]{64}$')
  file=self.path/root/'main.tf';before=file.read_text();file.write_text(before+'\nresource "terraform_data" "evil" { provisioner "local-exec" { command="false" } }')
  with self.assertRaises(Exception):g.validate_source(self.path,root)
  file.write_text(before);(self.path/root/'unknown.tf').write_text('')
  with self.assertRaises(Exception):g.validate_source(self.path,root)
 def test_hook_receipt_calls_authenticated_consumer_helper(self):
  self.ctx['operation']='down'
  course={'steps':[CORE,'hook:platform-core'],'completed':['hook:platform-core'],'barriers':{'hook:platform-core':{'plan':{'manifest_key':'key'}}}}
  calls=[]
  class Barrier:
   PLAN_FIELDS=set()
   def descriptor(self,*a):pass
   def for_consumer(self,store,context,descriptors,*,step):calls.append((descriptors,step));raise RuntimeError('Unauthenticated receipt')
  with patch.object(g,'course_context',return_value=course),patch.object(g,'load',return_value=Barrier()),patch.dict(os.environ,{'LIFECYCLE_BARRIER_RECEIPTS':'{"hook:platform-core":true}','LIFECYCLE_BUNDLE_DESCRIPTORS':'{"hook:platform-core":{"manifest_key":"key"}}'}):
   with self.assertRaises(RuntimeError):g.hook_barriers(self.ctx,'apply',store=object())
  self.assertEqual(calls,[({'hook:platform-core':True},'hook:platform-core')])
 def test_completed_hook_must_match_the_same_saved_bundle_plan(self):
  course={'steps':[CORE,'hook:platform-core'],'completed':['hook:platform-core'],'barriers':{'hook:platform-core':{'plan':{'manifest_key':'original'}}}}
  calls=[]
  class Barrier:
   PLAN_FIELDS=set()
   def descriptor(self,*a):pass
   def for_consumer(self,*a,**kw):calls.append(True)
  with patch.object(g,'course_context',return_value=course),patch.object(g,'load',return_value=Barrier()),patch.dict(os.environ,{'LIFECYCLE_BARRIER_RECEIPTS':'{}','LIFECYCLE_BUNDLE_DESCRIPTORS':'{"hook:platform-core":{"manifest_key":"changed"}}'}):
   with self.assertRaisesRegex(Exception,'does not match'):g.hook_barriers(self.ctx,'apply',store=object())
  self.assertEqual(calls,[])
 def test_resume_uses_authenticated_completed_hook_from_previous_run(self):
  saved={'manifest_key':'old-approved-key'}
  course={'steps':[CORE,'hook:platform-core'],'completed':['hook:platform-core'],'barriers':{'hook:platform-core':{'plan':saved}}}
  calls=[]
  class Barrier:
   PLAN_FIELDS=set()
   def descriptor(self,*a):pass
   def for_consumer(self,*a,**kw):calls.append(kw['step']);return {'verified':True}
   def read(self,*a):raise AssertionError('Never re-plan or impose a new TTL on completed hook')
  with patch.object(g,'course_context',return_value=course),patch.object(g,'load',return_value=Barrier()),patch.dict(os.environ,{'LIFECYCLE_BARRIER_RECEIPTS':'{}','LIFECYCLE_BUNDLE_DESCRIPTORS':'{}'}):
   for stage in ('plan','apply'):self.assertEqual(g.hook_barriers(self.ctx,stage,store=object()),{'hook:platform-core':saved})
  self.assertEqual(calls,['hook:platform-core']*2)
 def test_hook_manifest_accepts_actual_fractional_timestamp(self):
  course={'steps':[CORE,'hook:platform-core'],'completed':[],'completed_chapter':'BU08'}
  wanted={k:self.ctx[k] for k in ('repository_id','account','run_id','run_attempt','sha','generation','environment','operation')}
  wanted.update(step_id='hook:platform-core',snapshot_sha=self.ctx['source_sha'],registry_sha256=self.ctx['lifecycle_registry_sha256'],completed_chapter='BU08')
  prefix=f"ci-plans/10/20/1/{self.ctx['sha']}/dev/hooks/platform-core/lifecycle-down/";wanted['prefix']=prefix
  descriptor={'manifest_key':prefix+'manifest.json','manifest_version':'1','manifest_sha':'d'*64,'plan_sha':'e'*64}
  manifest={'kind':'gitops-lifecycle','schema':1,'context':wanted,'plan':{'key':prefix+'actions.json','sha256':'e'*64},'created_at':100.125,'expires_at':100.125+g.h.TTL_SECONDS}
  class Barrier:
   PLAN_FIELDS=set()
   def descriptor(self,*a):pass
   def read(self,store,d):return manifest if d['key'].endswith('manifest.json') else {'step_id':'hook:platform-core','operation':'down'}
  with patch.object(g,'course_context',return_value=course),patch.object(g,'load',return_value=Barrier()),patch.object(g.time,'time',return_value=101),patch.dict(os.environ,{'LIFECYCLE_BARRIER_RECEIPTS':'{}','LIFECYCLE_BUNDLE_DESCRIPTORS':json.dumps({'hook:platform-core':descriptor})}):
   self.assertEqual(g.hook_barriers(self.ctx,'plan',store=object()),{'hook:platform-core':descriptor})
 def test_apply_refuses_live_consumers_even_with_saved_proof(self):
  proof=g.load('proof_apply_contract','network-consumer-proof.py')
  with patch.object(g,'assert_registration'),patch.object(g,'validate_plan_contracts'),patch.object(g,'hook_barriers',return_value={}),patch.object(g,'consumer_states',return_value={'consumer':{}}):
   with self.assertRaisesRegex(Exception,'Dependent Terraform State'):g.guard_destroy(self.path,self.ctx,state(),plan(),stage='apply')
 def test_planning_deferral_uses_authenticated_proof(self):
  calls=[];proof=g.load('proof_plan_contract','network-consumer-proof.py')
  proof.prove_consumers=lambda *a,**kw:calls.append((a,kw)) or {'consumer':{'authenticated':'descriptor'}}
  with patch.object(g,'assert_registration'),patch.object(g,'validate_plan_contracts'),patch.object(g,'hook_barriers',return_value={}),patch.object(g,'consumer_states',return_value={'consumer':{}}),patch.object(g,'load',return_value=proof),patch.dict(os.environ,{'LIFECYCLE_BUNDLE_DESCRIPTORS':'{"hook:platform-core":{}}'}):
   result=g.guard_destroy(self.path,self.ctx,state(),plan(),stage='plan')
  self.assertTrue(calls);self.assertTrue(result['deferred_runtime_consumer_check'])
 def test_patch_keeps_single_executor_and_defaults(self):
  shutil.copyfile(C/'ci/network-lifecycle.py',self.path/'ci/network-lifecycle.py')
  text=(self.path/'ci/network-lifecycle.py').read_text()
  if 'ADAPTER_API = 1' not in text:
   subprocess.run(['patch','-p1','--forward','--batch','--input',str(B/'network-executor-extension.patch')],cwd=self.path,check=True,stdout=subprocess.PIPE)
   text=(self.path/'ci/network-lifecycle.py').read_text()
  # Parent may have integrated the seam already. Never let patch auto-reverse it.
  self.assertIn("KIND = 'network-lifecycle'",text);self.assertIn("kind=KIND",text)
  self.assertIn("if stage == 'verify':",text);self.assertIn('completion_evidence',text)
  self.assertIn("current_evidence.get('hook_plan_descriptors') == manifest",text)
  self.assertIn('guard.verify_absent(context',text)
  wrapper=(C/'ci/registered-root-lifecycle.py').read_text()
  self.assertNotIn("['terraform','apply'",wrapper);self.assertIn("e.run(stage)",wrapper)
  self.assertNotIn('fakeapproval',wrapper)
if __name__=='__main__':unittest.main()
