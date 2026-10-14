import importlib.util,json,pathlib,types,unittest
from unittest.mock import patch
BASE=pathlib.Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location(name,BASE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
rds=load('rds_protection_ops');managed=load('managed_queue_ops')
class Tests(unittest.TestCase):
 def io(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  return types.SimpleNamespace(require=require,h=types.SimpleNamespace(SafeError=ValueError))
 def target(self):return {'identifier':'db','db_arn':'arn','resource_id':'id','from':True,'to':False,'region':'ap-northeast-2'}
 def test_exact_protection_command(self):
  api=self.io();calls=[];marks=[]
  def call(io,c,*args):
   calls.append(args)
   if args[0]=='modify-db-instance':return {}
   return {'DBInstances':[{'DBInstanceArn':'arn','DbiResourceId':'id','DeletionProtection':len(calls)==1}]}
  with patch.object(rds,'call',call):result=rds.apply(api,'database-protection-disable',self.target(),{},lambda phase,t:marks.append(phase))
  self.assertEqual(marks,['active','idle']);self.assertFalse(result['destroy_authorized']);self.assertIn('--no-deletion-protection',calls[1]);self.assertNotIn('delete-db-instance',str(calls))
 def test_replaced_db_no_mutation(self):
  api=self.io();marks=[]
  with patch.object(rds,'call',return_value={'DBInstances':[{'DBInstanceArn':'arn','DbiResourceId':'replacement','DeletionProtection':True}]}):
   with self.assertRaises(ValueError):rds.apply(api,'database-protection-disable',self.target(),{},lambda phase,t:marks.append(phase))
  self.assertEqual(marks,[])
 def test_unknown_managed_operation_no_source_execution(self):
  with self.assertRaises(ValueError):managed.apply(self.io(),'shell',{}, {},lambda *x:None)
 def test_source_helpers_recoverable_only(self):
  root=BASE/'fixtures/managed-queue'
  if not root.is_dir():root=BASE.parents[1]/'later-adapter-proposal/credential-ci/source'
  for env in ('dev','prod'):
   text=(root/env/'setup-managed-topics.sh').read_text();self.assertIn('--recovery-window-in-days 7',text);self.assertNotIn('--force-delete-without-recovery',text);self.assertIn('APPROVED_QUEUE_ADMIN_UID',text);self.assertIn('MANAGED_QUEUE_RUN_ID',text)
if __name__=='__main__':unittest.main()
