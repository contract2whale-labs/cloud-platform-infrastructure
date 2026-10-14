import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('whole_course_controller',HERE/'terraform-lifecycle.py');d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
def registry(env):return json.loads((HERE/('lifecycle-targets'+('-prod' if env=='prod' else '')+'.json')).read_text())
class WholeCourse(unittest.TestCase):
 def select(self,env='dev',chapter='BU16'):return d.resolve('down',env,chapter,registry(env))
 def test_exact_environment_dedup_and_actual_prod_scope(self):
  for env in ('dev','prod'):
   s=self.select(env)
   self.assertFalse(s['blockers']);self.assertEqual(len(s['up_steps']),len(set(s['up_steps'])))
   self.assertTrue(all('/'+env+'/' in root for root in s['roots']))
   self.assertLessEqual(len(s['up_levels']),24)
   self.assertEqual(s['down_steps'],list(reversed(s['up_steps'])))
  self.assertNotIn('terraform/environments/prod/account-integrations',self.select('prod')['roots'])
 def test_storage_identity_and_app_auth_never_destroyed(self):
  for env in ('dev','prod'):
   s=self.select(env)
   for root in s['roots']:
    if any(x in root for x in ('/retained/','/bootstrap/','/network/log-storage','/account-baseline','/platform/app-auth')):
     self.assertIn(root,s['retained']);self.assertNotIn(root,s['down_steps'])
 def test_source_chapter_boundaries(self):
  self.assertNotIn('terraform/environments/dev/network/log-storage',self.select(chapter='BU02')['roots'])
  self.assertIn('terraform/environments/dev/network/log-storage',self.select(chapter='BU03')['roots'])
  six=self.select(chapter='BU06');seven=self.select(chapter='BU07')
  self.assertIn('hook:cluster-private-api-check',six['up_steps']);self.assertNotIn('hook:node-network-probes',six['up_steps'])
  self.assertIn('hook:node-network-probes',seven['up_steps'])
  self.assertNotIn('platform-alerting',self.select(chapter='BU10A')['hooks'])
  self.assertIn('platform-alerting',self.select(chapter='BU10B')['hooks'])
 def test_live_barriers_and_controller_retirement_order(self):
  for env in ('dev','prod'):
   steps=self.select(env)['down_steps'];i=steps.index;r='terraform/environments/'+env+'/'
   self.assertLess(i('hook:trace-drain-switch'),i('hook:platform-queue'))
   self.assertLess(i('hook:trace-drain-switch'),i('hook:platform-observability'))
   self.assertLess(i('hook:platform-observability'),i('hook:self-managed-queue-topics-acl'))
   self.assertLess(i('hook:velero-backup-restore'),i('hook:platform-operations'))
   self.assertLess(i('hook:platform-gateway'),i('hook:platform-core'))
   self.assertLess(i('hook:platform-core'),i(r+'eks'));self.assertLess(i(r+'eks'),i(r+'platform/private-api'))
   self.assertLess(i('hook:database-bootstrap'),i(r+'data'))
   self.assertEqual(steps[0],'hook:incident-quiescence-and-baseline')
   self.assertEqual(steps[-2:],['hook:reviewed-cleanup','hook:service-absence-audit'])
 def test_prod_publication_follows_actual_application_readiness(self):
  steps=self.select('prod')['up_steps'];edge='terraform/environments/prod/platform/edge'
  for hook in ('application-runtime','application-mesh'):self.assertLess(steps.index('hook:'+hook),steps.index(edge))
 def test_alias_cannot_forge_provider_or_discard_retention(self):
  for field,value in [('provider_hooks',['platform-mesh']),('retained_roots',[])]:
   r=registry('dev');r['hooks']['app-auth-provision-and-securitypolicy'][field]=value
   with self.assertRaises(d.SelectionError):d.resolve('down','dev','BU09',r)
 def test_actual_required_hook_edges_cover_registered_roots(self):
  catalog=json.loads((HERE/'registered-root-catalog.json').read_text())
  roots=catalog.get('roots',catalog)
  for env in ('dev','prod'):
   selected=self.select(env);steps=selected['down_steps']
   for root in selected['up_order']:
    row=roots.get(root,{})
    for hook in row.get('required_down_hooks',[]):
     self.assertIn(hook,steps);self.assertLess(steps.index(hook),steps.index(root))
    for hook in row.get('conditional_down_hooks',[]):
     if hook in steps:self.assertLess(steps.index(hook),steps.index(root))
 def test_partial_up_cannot_replace_original_down_identity_snapshot(self):
  for op in ('up','down'):
   d.validate_transition({'phase':'paused','operation':'down'},op)
   d.validate_transition({'phase':'active','operation':'up'},op)
  d.validate_transition({'phase':'paused','operation':'up'},'up')
  with self.assertRaises(d.h.SafeError):d.validate_transition({'phase':'paused','operation':'up'},'down')
 def test_handoff_summary_is_exact_and_secret_free(self):
  selection=self.select(chapter='BU07')
  record={'operation':'up','completed_chapter':'BU07','generation':'12-1','snapshot_sha':'a'*40,'workflow_sha':'b'*40,'completed':selection['up_steps'][:selection['up_steps'].index('hook:cluster-private-api-check')],'inputs':{'password':'NEVER-PUBLISH-THIS'},'phase':'paused'}
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);p=base/'ci/operations-access/bundles/dev/access-manifest.json';p.parent.mkdir(parents=True);p.write_text('{"schema":1}')
   env={'GITHUB_WORKSPACE':tmp,'GITHUB_STEP_SUMMARY':str(base/'summary'),'LIFECYCLE_ENVIRONMENT':'dev','COMPLETED_CHAPTER':'BU07'}
   with patch.dict(os.environ,env,clear=True),patch.object(d,'target_environment',return_value=(base,object(),{})),patch.object(d,'checked_record',return_value=(record,{'version':'exact-version'})),patch('builtins.print') as log:
    d.publish_bootstrap_handoff(registry('dev'))
   text=(base/'summary').read_text()+'\n'+str(log.call_args_list)
   self.assertNotIn('NEVER-PUBLISH-THIS',text);self.assertIn('checkpoint_version=exact-version',text)
   self.assertIn('checkpoint_sha256='+d.h.digest(d.h.canonical(record)),text);self.assertIn('generation=12-1',text)
   self.assertIn('gitops-access-bootstrap.yml',text);self.assertIn('operation=up',text)
if __name__=='__main__':unittest.main()
