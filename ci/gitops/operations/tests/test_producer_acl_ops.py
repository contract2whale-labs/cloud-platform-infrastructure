import sys,pathlib,types,unittest,copy
from unittest.mock import patch
BASE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
import producer_acl_ops as m
class Tests(unittest.TestCase):
 def io(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  return types.SimpleNamespace(require=require,h=types.SimpleNamespace(SafeError=ValueError))
 def target(self):return {'topic':'platform-traces','baseline_acls':[['TOPIC','platform-traces','LITERAL','User:tempo-distributor','*','WRITE','ALLOW']]}
 def test_remove_only_owned_deny_tuple(self):
  io=self.io();t=self.target();base={tuple(x) for x in t['baseline_acls']};calls=[];marks=[]
  with patch.object(m,'acl_set',side_effect=[base|{m.deny(t)},base]),patch.object(m,'acl',side_effect=lambda *x:calls.append(x[2:])):
   m.restore(io,t,lambda *x:marks.append(x))
  self.assertEqual(len(calls),1);self.assertEqual(calls[0],('--remove','--deny-principal','User:tempo-distributor','--deny-host','*','--operation','Write','--topic','platform-traces','--resource-pattern-type','literal','--force'));self.assertTrue(t['acl_restored'])
 def test_unrelated_acl_change_stops_recovery(self):
  t=self.target();calls=[]
  with patch.object(m,'acl_set',return_value={('OTHER',)}),patch.object(m,'acl',side_effect=lambda *x:calls.append(x)):
   with self.assertRaises(ValueError):m.restore(self.io(),t,lambda *x:None)
  self.assertEqual(calls,[])
 def test_clean_baseline_never_removes_any_acl(self):
  t=self.target();base={tuple(x) for x in t['baseline_acls']}
  with patch.object(m,'acl_set',return_value=base),patch.object(m,'acl') as call:
   m.restore(self.io(),t,lambda *x:None);call.assert_not_called()
 def test_unknown_issuance_cannot_be_fabricated(self):
  with self.assertRaises(ValueError):m.recover_credentials(self.io(),{},lambda *x:None)
 def test_unknown_operation_has_no_effect(self):
  with self.assertRaises(ValueError):m.apply(self.io(),'delete-everything',{}, {},lambda *x:None)
 def test_fault_exception_restores_then_cleans(self):
  t={'credential_run_id':'run','topic':'platform-traces','hold_seconds':30,'probe_pods':[],'observations':{}};events=[]
  baseline=m.expected_acls(t['topic'],'tempo-distributor','tempo-consumer','platform-tempo-e2')
  with patch.object(m,'issue'),patch.object(m,'acl_set',return_value=baseline),patch.object(m,'probe',side_effect=ValueError('probe failed')),patch.object(m,'restore',side_effect=lambda *x:events.append('restore')),patch.object(m,'cleanup',side_effect=lambda *x:events.append('cleanup')),patch.object(m,'cleanup_probes',side_effect=lambda *x:events.append('pods')):
   with self.assertRaises(ValueError):m.apply(self.io(),'producer-acl-cycle',t,{},lambda *x:None)
  self.assertEqual(events,['restore','cleanup','pods'])
 def test_complete_cycle_keeps_trace_outcomes_separate(self):
  io=self.io();io.kube=lambda *x:{'metadata':{'uid':'producer'}};io.identity=lambda x:{'uid':'producer'};io.ops=types.SimpleNamespace(run=lambda *x:b'TOPIC_AUTHORIZATION_FAILED')
  t={'credential_run_id':'run','topic':'platform-traces','hold_seconds':30,'probe_pods':[],'observations':{},'distributor':{'uid':'producer'}}
  baseline=m.expected_acls(t['topic'],'tempo-distributor','tempo-consumer','platform-tempo-e2');actual=set(baseline);marks=[];probes=[]
  def acl(io,t,*args):
   if args[0]=='--add':actual.add(m.deny(t))
   else:actual.remove(m.deny(t))
  def probe(io,t,phase,action,mark):
   probes.append((phase,action));return {'accepted':True,'found':phase!='fault' or action=='requery'}
  with patch.object(m,'issue'),patch.object(m,'acl_set',side_effect=lambda *x:set(actual)),patch.object(m,'acl',side_effect=acl),patch.object(m,'probe',side_effect=probe),patch.object(m,'cleanup'),patch.object(m,'cleanup_probes'),patch.object(m.time,'sleep'):
   result=m.apply(io,'producer-acl-cycle',t,{},lambda phase,target:marks.append(phase))
  self.assertEqual(actual,baseline);self.assertEqual(marks[-1],'idle');self.assertTrue(result['acl_restored']);self.assertTrue(result['deny_verified']);self.assertIn(('fault','requery'),probes)
 def test_cleanup_has_recovery_window_and_full_association_check(self):
  io=self.io();t={'issued':{'arn':'secret-arn','version_id':'run'},'cluster_arn':'cluster','original_associations':['existing'],'config_written':True,'config':'/tmp/queue-admin-run.properties'};calls=[]
  def aws(io,t,*args,**kwargs):
   calls.append(args)
   if args[1]=='batch-disassociate-scram-secret':return {'UnprocessedScramSecrets':[]}
   if args[1]=='list-scram-secrets':return {'SecretArnList':['existing']}
   if args[1]=='delete-secret':return {'ARN':'secret-arn','DeletionDate':1}
   return {'ARN':'secret-arn','DeletedDate':1}
  with patch.object(m,'aws',side_effect=aws),patch.object(m,'kube_exec'):
   m.cleanup(io,t,lambda *x:None)
  delete=next(x for x in calls if x[1]=='delete-secret');self.assertIn('--recovery-window-in-days',delete);self.assertIn('7',delete);self.assertNotIn('--force-delete-without-recovery',delete);self.assertFalse(t['recoverable_cleanup']['permanent_absence_claimed'])
if __name__=='__main__':unittest.main()
