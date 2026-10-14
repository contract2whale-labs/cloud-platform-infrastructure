"""Offline finite Prod ordinary-root catalog and account-isolation tests.
No provider RPC, AWS calls, GitHub mutation, or external audit tree is used.
"""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,file):
 sp=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
g=load('prod_registered_guard','registered-root-guard.py')
a=load('prod_registered_adapter','registered-root-lifecycle.py')
CORE='terraform/environments/prod/platform/core';EDGE='terraform/environments/prod/platform/edge'
ACCOUNT='123456789012'
def context(root=CORE,operation='down'):
 return dict(root=root,environment=g.environment(root),workspace='default',account=ACCOUNT,operation=operation,
 backend=dict(key=g.key(root),bucket='prod-private-state',region='ap-northeast-2'),repository_id='17',run_id='2',run_attempt='1',
 sha='a'*40,source_sha='b'*40,generation='2-1',lifecycle_registry_sha256='c'*64,selected_roots=[root])
def state(rows=()):return {'format_version':'1.0','values':{'root_module':{'resources':list(rows)}}}
def row(address,ty,values):return dict(mode='managed',address=address,type=ty,values=values)
def plan(rows=()):
 return {'format_version':'1.2','configuration':{'root_module':{}},'planned_values':{'root_module':{'resources':list(rows)}},'resource_changes':[]}
class ProdCatalog(unittest.TestCase):
 def test_all_exact_portable_source_variants(self):
  fixture=json.loads((HERE/'fixtures/registered-source/variants.json').read_text())['variants']
  self.assertEqual(set(fixture),set(g.ROOTS))
  for root,spec in g.CATALOG['roots'].items():
   self.assertEqual(len(fixture[root]),len(spec['source_variants']))
   for files,variant in zip(fixture[root],spec['source_variants']):
    self.assertEqual({p:g.h.digest(code.encode()) for p,code in files.items()},variant['files'])
    with tempfile.TemporaryDirectory() as temp:
     base=Path(temp)
     for name,code in files.items():
      target=base/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(code)
     with patch.object(g.h,'execute',side_effect=AssertionError('No source execution')):
      self.assertRegex(g.validate_source(base,root),'^[a-f0-9]{64}$')
 def test_prod_edge_actual_source_addresses_not_dev_mirror(self):
  spec=g.spec(EDGE);self.assertFalse(spec['disabled_edge']);self.assertTrue(spec['enabled_edge']);self.assertEqual(len(spec['allowed_addresses']),14)
  for name in ('aws_cloudfront_distribution.app','aws_cloudfront_vpc_origin.gateway','aws_wafv2_web_acl.edge','aws_acm_certificate.viewer','aws_route53_record.app_ipv4'):
   address='module.component.'+name;self.assertIn(address,spec['allowed_addresses'])
   with self.assertRaises(Exception):g.check_address(EDGE.replace('/prod/','/dev/'),address,spec['allowed_addresses'][address])
  paths={r['checkpoint'] for v in spec['source_variants'] for r in v['checkpoints']}
  self.assertIn('course/전체교안/쉬운버전/BU15/14-BU15-T11-public-service.md',paths)
  self.assertIn('course/파트3/BU15-파트3.md',paths)
 def test_prod_edge_requires_true_without_coercion(self):
  p=plan();up={root:{'fingerprint':{'exists':True}} for root in g.spec(EDGE)['dependencies']}
  for value in (False,None,0,1,'true'):
   p['variables']={'enabled':{'value':value}}
   with self.assertRaises(Exception):g.validate_plan_contracts(context(EDGE),p,up)
  p['variables']['enabled']['value']=True;g.validate_plan_contracts(context(EDGE),p,up)
 def test_context_environment_account_workspace_and_roles(self):
  good=context();g.validate_context(good)
  role='arn:aws:iam::'+ACCOUNT+':role/gha-infra-prod-lifecycle-destroy'
  g.validate_context({**good,'apply_role_arn':role})
  for fields in ({'environment':'dev'},{'workspace':'prod'},{'account':'123'}, {'apply_role_arn':role.replace('prod','dev')},{'apply_role_arn':role.replace('lifecycle-destroy','apply')}):
   with self.assertRaises(Exception):g.validate_context({**good,**fields})
 def test_finite_protected_exception(self):
  root='terraform/environments/dev/account-integrations';address='module.component.aws_s3_bucket_notification.network_logs'
  self.assertEqual(g.check_address(root,address+'[0]','aws_s3_bucket_notification'),address)
  for r,addr,ty in ((CORE,address+'[0]','aws_s3_bucket_notification'),(root,address+'[1]','aws_s3_bucket_notification'),(root,address+'["x"]','aws_s3_bucket_notification'),(root,'module.component.aws_s3_bucket.logs','aws_s3_bucket'),(root,'module.component.aws_kms_key.logs','aws_kms_key')):
   with self.assertRaises(Exception):g.check_address(r,addr,ty)
 def test_no_guessed_prod_account_integrations_activation(self):
  root='terraform/environments/prod/account-integrations'
  self.assertFalse(g.spec(root)['course_member'])
  self.assertEqual(g.spec(root)['status'],'source-supported-inactive')
 def test_no_temporary_audit_dependency(self):
  for path in (HERE/'registered-root-catalog.json',HERE/'registered-root-guard.py',HERE/'registered-root-lifecycle.py'):
   self.assertNotIn('/tmp/course-lifecycle-audit',path.read_text())
 def test_all_active_catalog_dependencies_match_actual_graph(self):
  graph=json.loads((HERE/'deploy-roots.json').read_text())['dependencies']
  for root,spec in g.CATALOG['roots'].items():
   if spec.get('course_member',True):self.assertEqual(spec['dependencies'],graph[root])

class ProdBoundaries(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);(self.base/'ci').mkdir()
  self.ctx=context();self.registry={'roots':{CORE:{'mode':'adapter','engine':'prod-registered-root-v1'}},'hooks':{'platform-core':{'status':'adapter','engine':'prod-gitops-v1'}}}
  self.graph={CORE:g.spec(CORE)['dependencies']};self.save()
 def save(self):
  (self.base/'ci/lifecycle-targets-prod.json').write_text(json.dumps(self.registry));(self.base/'ci/lifecycle-targets.json').write_text('{}')
  (self.base/'ci/deploy-roots.json').write_text(json.dumps({'dependencies':self.graph}))
  self.ctx['lifecycle_registry_sha256']=g.h.digest(g.h.canonical(self.registry))
 def test_application_hook_requires_its_static_engine_family(self):
  root='terraform/environments/prod/platform/operations';self.graph[root]=g.spec(root)['dependencies']
  self.registry['roots'][root]={'mode':'adapter','engine':'prod-registered-root-v1'}
  self.registry['hooks']['platform-operations']={'status':'adapter','engine':'prod-application-v1'};self.save()
  ctx={**self.ctx,'root':root};g.assert_registration(self.base,ctx)
  self.registry['hooks']['platform-operations']['engine']='prod-gitops-v1';self.save();ctx['lifecycle_registry_sha256']=self.ctx['lifecycle_registry_sha256']
  with self.assertRaises(Exception):g.assert_registration(self.base,ctx)
 def test_hook_manifest_prefix_must_be_prod(self):
  import time
  step='hook:platform-core';prefix=f"ci-plans/17/2/1/{self.ctx['sha']}/prod/hooks/platform-core/lifecycle-down/"
  descriptor={'manifest_key':prefix+'manifest.json','manifest_version':'1','manifest_sha':'d'*64,'plan_sha':'e'*64}
  course={'steps':[CORE,step],'completed':[],'completed_chapter':'BU15'}
  manifest={'schema':1,'kind':'gitops-lifecycle','created_at':time.time()-1,'expires_at':time.time()-1+g.h.TTL_SECONDS,
   'context':{k:self.ctx[k] for k in ('repository_id','account','run_id','run_attempt','sha','generation','environment','operation')},'plan':{'key':prefix+'actions.json','sha256':descriptor['plan_sha']}}
  manifest['expires_at']=manifest['created_at']+g.h.TTL_SECONDS
  manifest['context'].update(step_id=step,snapshot_sha=self.ctx['source_sha'],registry_sha256=self.ctx['lifecycle_registry_sha256'],completed_chapter='BU15',prefix=prefix)
  class Helper:
   PLAN_FIELDS=set()
   def descriptor(self,*args):pass
   def read(self,store,value):return manifest if value['key'].endswith('manifest.json') else {'step_id':step,'operation':'down'}
  with patch.object(g,'course_context',return_value=course),patch.object(g,'load',return_value=Helper()),patch.dict(os.environ,{'LIFECYCLE_BARRIER_RECEIPTS':'{}','LIFECYCLE_BUNDLE_DESCRIPTORS':json.dumps({step:descriptor})}):
   self.assertEqual(g.hook_barriers(self.ctx,'plan',store=object()),{step:descriptor})
   manifest['context']['prefix']=prefix.replace('/prod/','/dev/')
   with self.assertRaises(Exception):g.hook_barriers(self.ctx,'plan',store=object())
 def test_invalid_dependency_paths_never_become_state_keys(self):
  for path in ('terraform/environments/prod/','terraform/environments/prod/platform//core','terraform/environments/prod/platform/core/','terraform/environments/prod/platform/../core','terraform/environments/prod/bootstrap/ci-identity'):
   with self.assertRaises(Exception):g.key(path,'prod')
 def test_prod_registry_and_hook_engine_selected(self):
  g.assert_registration(self.base,self.ctx)
  for where in ('root','hook'):
   registry=copy.deepcopy(self.registry)
   if where=='root':self.registry['roots'][CORE]['engine']='dev-registered-root-v1'
   else:self.registry['hooks']['platform-core']['engine']='dev-gitops-v1'
   self.save()
   with self.assertRaises(Exception):g.assert_registration(self.base,self.ctx)
   self.registry=registry
 def test_cross_environment_consumers_block_before_state_read(self):
  self.graph['terraform/environments/dev/identity']=[CORE];self.save();calls=[]
  with self.assertRaises(Exception):g.consumer_states(self.base,self.ctx,load_state=lambda k:calls.append(k))
  self.assertEqual(calls,[])
 def test_upstream_state_keys_stay_inside_prod_bucket(self):
  calls=[]
  def read(k):calls.append(k);return {'state':None,'fingerprint':{'exists':False}}
  g.read_upstreams(self.base,self.ctx,load_state=read)
  self.assertEqual(set(calls),{'eks/terraform.tfstate','account-baseline-dns/terraform.tfstate'})
 def test_course_marker_uses_prod(self):
  class Control:
   course_marker_key=staticmethod(g.c.course_marker_key)
   def read_json(self,store,key):self.key=key;return None,{}
  control=Control()
  with patch.object(g,'c',control),self.assertRaises(Exception):g.course_context(object(),self.ctx)
  self.assertEqual(control.key,'ci-lifecycle/17/prod/course.json')
 def test_adapter_marker_and_selected_root_isolation(self):
  env=dict(ROOT_PATH=CORE,LIFECYCLE_ENGINE='prod-registered-root-v1',LIFECYCLE_ENVIRONMENT='prod',LIFECYCLE_CONFIG_SHA256='a'*64,LIFECYCLE_SELECTED_ROOTS=json.dumps([CORE]),LIFECYCLE_SNAPSHOT_SHA='b'*40,LIFECYCLE_GENERATION='2-1',GITHUB_WORKSPACE=str(self.base),TF_VARS_JSON=json.dumps({'platform/core':{}}))
  with patch.object(a.g,'assert_registration'),patch.dict(os.environ,env,clear=True):
   a.configure();self.assertEqual(a.marker_key('17'),'ci-lifecycle/17/prod/platform-core.json')
   os.environ['LIFECYCLE_SELECTED_ROOTS']=json.dumps([CORE,CORE.replace('/prod/','/dev/')])
   with self.assertRaises(Exception):a.configure()
 def test_stage_roles_cannot_cross_environment_account_or_plan_apply(self):
  base='arn:aws:iam::'+ACCOUNT+':role/gha-infra-prod-'
  env=dict(ROOT_PATH=CORE,EXPECTED_ACCOUNT_ID=ACCOUNT,OPERATION='down',EXPECTED_APPLY_ROLE_ARN=base+'lifecycle-destroy',AWS_ROLE_ARN=base+'lifecycle-destroy')
  with patch.dict(os.environ,env,clear=True):
   a.validate_role('apply')
   for role in (base+'plan',base+'apply',base.replace('prod','dev')+'lifecycle-destroy',base.replace(ACCOUNT,'999999999999')+'lifecycle-destroy'):
    os.environ['AWS_ROLE_ARN']=role
    with self.assertRaises(Exception):a.validate_role('apply')
   os.environ.update(OPERATION='up',EXPECTED_APPLY_ROLE_ARN=base+'apply',AWS_ROLE_ARN=base+'plan');a.validate_role('plan')
   with self.assertRaises(Exception):a.validate_role('apply')
   os.environ['AWS_ROLE_ARN']=base+'apply';a.validate_role('apply')

class CompletionProofs(unittest.TestCase):
 def test_prod_edge_completion_cannot_skip_publication(self):
  resource=row('terraform_data.environment_boundary','terraform_data',{'id':'root-marker'});p=plan([resource]);ctx=context(EDGE,'up')
  class Edge:
   def verify(self,*args):raise ValueError('Publication is not ready')
  with patch.object(g,'load',return_value=Edge()),self.assertRaisesRegex(ValueError,'Publication'):g.validate_up_completion(p,state([resource]),ctx)
 def test_dev_session_proof_runs_before_and_after_apply(self):
  root='terraform/environments/dev/platform/dev-app-access';ctx=context(root);ctx['environment']='dev'
  own=[row('aws_ssm_document.dev_app_https','aws_ssm_document',{'id':'CommerceDevelopmentAppHttps'}),row('aws_iam_role.dev_app_session','aws_iam_role',{'id':'CommerceDevelopmentAppSession'})]
  raw=state(own);p=plan();p['prior_state']=raw;p['resource_changes']=[{'address':r['address'],'type':r['type'],'mode':'managed','change':{'actions':['delete'],'before':r['values'],'after':None}} for r in own]
  relay=state([row('aws_instance.relay','aws_instance',{'id':'i-0123456789abcdef0'})]);up={name:{'fingerprint':{'exists':True},'state':relay} for name in g.spec(root)['dependencies']};calls=[]
  def aws(*args):calls.append(args);return {'Account':ACCOUNT} if args[0]=='sts' else {'Sessions':[]}
  with patch.object(g,'assert_registration'),patch.object(g,'hook_barriers',return_value={}),patch.object(g,'consumer_states',return_value={}),patch.object(g.h,'aws',side_effect=aws):
   evidence=g.guard_destroy(HERE.parent,ctx,raw,p,upstream_states=up,stage='apply')
   self.assertEqual(evidence['dev_app_sessions_closed']['active_owned_sessions'],0)
   self.assertEqual(g.validate_down_completion(ctx,state())['dev_app_sessions_closed']['active_owned_sessions'],0)
  self.assertEqual(len(calls),4)
 def test_notification_exception_requires_registered_source_binding(self):
  proof=load('registered_notification_delete_test','network-consumer-proof.py');notification=load('registered_notification_fixture','notification-lifecycle-guard.py')
  root='terraform/environments/dev/account-integrations';ctx=context(root);ctx.update(lifecycle_engine='dev-registered-root-v1',registered_catalog_sha256=g.h.digest((HERE/'registered-root-catalog.json').read_bytes()),registered_source_sha256='e'*64)
  values={'id':'cp-dev-network-logs-'+ACCOUNT+'-ap-northeast-2','bucket':'cp-dev-network-logs-'+ACCOUNT+'-ap-northeast-2','queue':[{'id':key,'queue_arn':'arn:aws:sqs:ap-northeast-2:'+ACCOUNT+':course-network-log-events','events':['s3:ObjectCreated:*'],'filter_prefix':prefix} for key,prefix in [('flow-logs','flow/'),('dns-logs','dns/')]]}
  resource=row(notification.ADDRESS,'aws_s3_bucket_notification',values);raw=state([resource]);p=plan();p.update(prior_state=raw,variables={'lifecycle_notification_backlog_mode':{'value':'discard-notifications-retain-source-objects'}},resource_changes=[{'address':resource['address'],'type':resource['type'],'mode':'managed','change':{'actions':['delete'],'before':values,'after':None}}])
  live=notification.owned(values,ACCOUNT,'ap-northeast-2')[1]
  with self.assertRaises(Exception):proof.validate_delete_plan(raw,p)
  with patch.object(proof.h,'aws',return_value=live):
   self.assertEqual(proof.validate_registered_delete_plan(raw,p,ctx)['managed_count'],1)
   for change in ({'registered_catalog_sha256':'x'*64},{'registered_source_sha256':None},{'lifecycle_engine':'prod-registered-root-v1'},{'root':root.replace('/dev/','/prod/'),'environment':'prod'}):
    with self.assertRaises(Exception):proof.validate_registered_delete_plan(raw,p,{**ctx,**change})
  with patch.object(proof.h,'aws',return_value={**live,'EventBridgeConfiguration':{}}),self.assertRaises(Exception):proof.validate_registered_delete_plan(raw,p,ctx)
 def test_alerting_application_barrier_only_after_actual_course_step(self):
  root='terraform/environments/dev/platform/alerting';ctx=context(root)
  self.assertEqual(g.spec(root)['required_down_hooks'],[]);self.assertEqual(g.spec(root)['conditional_down_hooks'],['hook:platform-alerting'])
  course={'steps':[root],'completed':[]}
  with patch.object(g,'course_context',return_value=course):self.assertEqual(g.hook_barriers(ctx,'apply',store=object()),{})
  course['steps']=[root,'hook:platform-alerting']
  with patch.object(g,'course_context',return_value=course),self.assertRaises(Exception):g.hook_barriers(ctx,'apply',store=object())
 def test_sns_reconfirmation_is_not_state_only_or_delivery_claim(self):
  ctx=context(operation='up');topic='arn:aws:sns:ap-northeast-2:'+ACCOUNT+':course-alerts';arn=topic+':12345678-1234-1234-1234-123456789012'
  values=dict(id=arn,arn=arn,topic_arn=topic,protocol='email',pending_confirmation=False,endpoint='operator@example.invalid')
  rows=[row('module.component.aws_sns_topic_subscription.email[0]','aws_sns_topic_subscription',values)]
  attrs={'SubscriptionArn':arn,'TopicArn':topic,'Owner':ACCOUNT,'PendingConfirmation':'false','ConfirmationWasAuthenticated':'false'}
  with patch.object(g.h,'aws',return_value={'Attributes':attrs}) as aws:
   self.assertTrue(g.verify_email_subscriptions(ctx,rows)[0]['confirmed']);aws.assert_called_once()
  for change in ({'PendingConfirmation':'true'},{'Owner':'999999999999'},{'TopicArn':topic+'-other'},{'PendingConfirmation':None}):
   with patch.object(g.h,'aws',return_value={'Attributes':{**attrs,**change}}),self.assertRaises(Exception):g.verify_email_subscriptions(ctx,rows)
  rows[0]['values']['pending_confirmation']=True
  with patch.object(g.h,'aws',side_effect=AssertionError('No AWS before confirmation')),self.assertRaises(Exception):g.verify_email_subscriptions(ctx,rows)
 def test_notification_preapply_and_postapply_use_same_context_plan(self):
  root='terraform/environments/dev/account-integrations';ctx=context(root);p=plan();proofs=[]
  class Notification:
   def completion(self,c,plan,rows,aws):proofs.append((c,plan,rows));return []
  with patch.object(g,'notification_guard',return_value=Notification()):
   with self.assertRaises(Exception):g.validate_down_completion(ctx,state())
   g.VERIFIED_DOWN_PLANS[g.h.digest(g.h.canonical(ctx))]=p
   result=g.validate_down_completion(ctx,state());self.assertFalse(result['cloud_absence_proven']);self.assertEqual(proofs,[(ctx,p,[])])
   with self.assertRaises(Exception):g.validate_down_completion(ctx,state())
if __name__=='__main__':unittest.main()
