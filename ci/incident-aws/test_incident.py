import datetime as dt,importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('incident',Path(__file__).with_name('incident_aws.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Incident(unittest.TestCase):
 def request(self):return {'schema':1,'operation':'scram-admin-schedule-delete','operation_authorization':'scram-admin-schedule-delete','environment':'dev','account':'123456789012','region':'ap-northeast-2','incident_run':'12345678-1234-4234-9234-123456789abc','expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat(),'approved_disposable_drill':True,'retain_all_s3_and_existing_backups':True,'secret_arn':'arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:temporary','secret_name':'temporary','secret_kms_key_id':'retained-key','cluster_arn':'arn:aws:kafka:ap-northeast-2:123456789012:cluster/test/id','secret_tags':[{'Key':'IncidentRun','Value':'12345678-1234-4234-9234-123456789abc'}],'temporary_admin_issuance_receipt':{'key':'test'},'recovery_window_days':7}
 def test_only_recoverable_secret_schedule(self):
  m.validate_request(self.request())
  for days in (0,6,31,True):
   with self.assertRaises(m.h.SafeError):m.validate_request(self.request()|{'recovery_window_days':days})
 def test_unknown_command_and_extra_secret_rejected(self):
  for extra in ({'operation':'delete-anything'},{'secret_value':'never'},{'environment':'prod'},{'approved_disposable_drill':False}):
   with self.assertRaises(m.h.SafeError):m.validate_request(self.request()|extra)
 def test_schedule_is_not_claimed_permanent_absence(self):
  r=self.request();result=m.observe_result(r,{},reader=lambda *a:{'ARN':r['secret_arn'],'DeletedDate':'future'},sleeper=lambda x:None)
  self.assertEqual(result['status'],'scheduled-recoverable-deletion')
 def test_disassociation_full_list_proof(self):
  r=self.request()|{'operation':'scram-admin-disassociate'}
  with self.assertRaises(m.h.SafeError):m.observe_result(r,{},reader=lambda *a:{'SecretArnList':[],'NextToken':'next'},sleeper=lambda x:None)
  self.assertEqual(m.observe_result(r,{},reader=lambda *a:{'SecretArnList':[]},sleeper=lambda x:None)['status'],'disassociated')
 def test_create_clone_identity_and_ready(self):
  r=self.request()|{'operation':'rds-pitr-create','target_db_identifier':'clone'}
  identity={'DBInstanceArn':'arn','DbiResourceId':'resource','DBInstanceStatus':'available','Endpoint':{'Address':'private-test'}}
  self.assertEqual(m.observe_result(r,{'DBInstance':identity},reader=lambda *a:{'DBInstances':[identity]},sleeper=lambda x:None)['status'],'available')
  with self.assertRaises(m.h.SafeError):m.observe_result(r,{'DBInstance':identity},reader=lambda *a:{'DBInstances':[identity|{'DbiResourceId':'replacement'}]},sleeper=lambda x:None)
if __name__=='__main__':unittest.main()
