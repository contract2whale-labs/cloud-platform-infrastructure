"""Offline saved-action pipeline integration; every external call mocked."""
import datetime as dt,importlib.util,json,os,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock,patch
from test_incident import m
s=importlib.util.spec_from_file_location('stores',m.CI/'test_vpc_lifecycle.py');stores=importlib.util.module_from_spec(s);s.loader.exec_module(stores)
class Store(stores.Store):
 bucket='private-state'
 def check(self):pass
 def call(self,op,*args):return {'Rules':[]} if op=='get-bucket-lifecycle-configuration' else super().call(op,*args)
class Pipeline(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name);self.original=Path.cwd();os.chdir(self.path);self.addCleanup(os.chdir,self.original)
  self.store=Store();self.outputs={};self.stack=self.enterContext(ExitStack())
  self.request={'schema':1,'operation':'scram-admin-schedule-delete','operation_authorization':'scram-admin-schedule-delete','environment':'dev','account':'123456789012','region':'ap-northeast-2','incident_run':'12345678-1234-4234-9234-123456789abc','expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat(),'approved_disposable_drill':True,'retain_all_s3_and_existing_backups':True,'secret_arn':'arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:temporary','secret_name':'temporary','secret_kms_key_id':'retained-key','cluster_arn':'arn:aws:kafka:ap-northeast-2:123456789012:cluster/test/id','secret_tags':[{'Key':'IncidentRun','Value':'12345678-1234-4234-9234-123456789abc'}],'temporary_admin_issuance_receipt':{'key':'fixture'},'recovery_window_days':7}
  req=Path('incidents/requests')/(self.request['incident_run']+'.json');req.parent.mkdir(parents=True);req.write_text(json.dumps(self.request))
  env={'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY_ID':'17','GITHUB_REPOSITORY':'test/infra','GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_STEP_SUMMARY':str(self.path/'summary'),'INCIDENT_REQUEST_PATH':str(req),'AWS_ROLE_ARN':'arn:aws:iam::123456789012:role/approved','STATE_BUCKET':'private-state'}
  self.stack.enter_context(patch.dict(os.environ,env,clear=True))
  for name,value in [('Store',Mock(return_value=self.store)),('check_identity',Mock(return_value='authenticated-session')),('ensure_current_main',Mock()),('emit',self.outputs.update),('execute',lambda args,**kw:('a'*40).encode() if args[:2]==['git','rev-parse'] else b'')]:self.stack.enter_context(patch.object(m.h,name,value))
  self.snapshot={'command':['secretsmanager','delete-secret','--secret-id',self.request['secret_arn'],'--recovery-window-in-days','7'],'identity':{'secret_arn':self.request['secret_arn']},'source_states':{'version':'immutable'}}
  self.stack.enter_context(patch.object(m,'inspect',return_value=self.snapshot));self.stack.enter_context(patch.object(m,'gate_settings'))
  self.aws=self.stack.enter_context(patch.object(m,'aws',return_value={'ARN':self.request['secret_arn'],'DeletionDate':'future'}))
  self.stack.enter_context(patch.object(m,'observe_result',return_value={'status':'scheduled-recoverable-deletion'}))
 def plan(self):
  m.run('plan');os.environ.update(PLAN_KEY=self.outputs['plan_key'],PLAN_VERSION=self.outputs['plan_version'],PLAN_SHA=self.outputs['plan_sha'])
 def test_reviewed_exact_action_and_observation_receipt(self):
  self.plan();m.run('apply');self.aws.assert_called_once_with('ap-northeast-2',*self.snapshot['command'])
  self.assertIn('receipt_sha',self.outputs)
  marker=[json.loads(data) for key,(data,_) in self.store.objects.items() if key.startswith('ci-lifecycle/')][0]
  self.assertEqual(marker['phase'],'idle')
 def test_verify_is_readonly(self):
  self.plan();count=self.store.number;m.run('verify');self.assertEqual(self.store.number,count);self.aws.assert_not_called()
 def test_tampered_plan_never_executes(self):
  self.plan();os.environ['PLAN_SHA']='b'*64
  with self.assertRaises(Exception):m.run('apply')
  self.aws.assert_not_called()
 def test_uncertain_request_blocks_replay(self):
  self.plan();self.aws.side_effect=RuntimeError('timeout')
  with self.assertRaises(RuntimeError):m.run('apply')
  self.aws.side_effect=None
  with self.assertRaises(m.h.SafeError):m.run('apply')
  self.assertEqual(self.aws.call_count,1)
if __name__=='__main__':unittest.main()
