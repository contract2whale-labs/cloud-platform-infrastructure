import pathlib,sys,types,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import builder_trace as m
class Tests(unittest.TestCase):
 def io(self):
  def check(value,msg):
   if not value:raise ValueError(msg)
  return types.SimpleNamespace(require=check,identity=lambda x:x,kube=Mock(),ops=types.SimpleNamespace(DIGEST=__import__('re').compile(r'.+@sha256:[0-9a-f]{64}')))
 def test_prepare_fixed_identity(self):
  io=self.io();io.kube.side_effect=[{'uid':'ns'},None,None,None]
  t=m.prepare(io,{'experiment_id':'00000000-0000-4000-8000-000000000001','data_decision':'pause-builder-send-one-synthetic-trace-restore-and-uid-cleanup'},{'trace_probe_image':'example@sha256:'+'a'*64})
  self.assertEqual(len(t['trace_ids']['fault']),32);self.assertEqual(t['namespace'],{'uid':'ns'})
 def test_unknown_create_does_not_clean(self):
  io=self.io()
  with self.assertRaises(ValueError):m.cleanup_probes(io,{'pending_probe':'x'},Mock())
  io.kube.assert_not_called()
 def test_missing_without_delete_intent_blocks(self):
  io=self.io();io.kube.side_effect=[{'uid':'ns'},None]
  with self.assertRaises(ValueError):m.cleanup_probes(io,{'namespace':{'uid':'ns'},'probe_pods':[{'uid':'p','name':'p'}]},Mock())
 def test_absence_after_delete_intent_resumes(self):
  io=self.io();io.kube.side_effect=[{'uid':'ns'},None]
  t={'namespace':{'uid':'ns'},'probe_pods':[{'uid':'p','name':'p'}],'delete_attempted_uids':['p']}
  m.cleanup_probes(io,t,Mock());self.assertEqual(t['deleted_probe_uids'],['p'])
 def test_block_query_and_digest_source(self):
  source=pathlib.Path(m.__file__).read_text();self.assertIn('/querier/api/traces/',source);self.assertIn('?mode=blocks',source);self.assertIn("'automountServiceAccountToken':False",source)
if __name__=='__main__':unittest.main()

class BuilderCycleTests(unittest.TestCase):
 def test_probe_failure_restores_before_cleanup(self):
  import incident_ops as ops
  events=[];target={'normal_replicas':1,'trace':{'observations':{}}}
  with patch.object(ops,'selfheal_policy'),patch.object(ops,'patch_replicas'),patch.object(ops,'wait_replicas'),patch.object(ops,'restore',side_effect=lambda t:events.append('restore')),patch.object(m,'probe',side_effect=ValueError('send failed')),patch.object(m,'cleanup_probes',side_effect=lambda *a:events.append('cleanup')):
   with self.assertRaises(ValueError):ops.run_replica('builder-cycle',target,{'hold_seconds':1},Mock())
  self.assertEqual(events,['restore','cleanup'])
 def test_unknown_creation_keeps_recovery_marker(self):
  import incident_ops as ops
  target={'normal_replicas':1,'trace':{'pending_probe':'p','observations':{}}};marks=[]
  with patch.object(ops,'selfheal_policy'),patch.object(ops,'patch_replicas'),patch.object(ops,'wait_replicas'),patch.object(ops,'restore'),patch.object(m,'probe',side_effect=ValueError('timeout')),patch.object(m,'cleanup_probes',side_effect=ValueError('unknown UID')):
   with self.assertRaises(ValueError):ops.run_replica('builder-cycle',target,{'hold_seconds':1},lambda phase,t:marks.append(phase))
  self.assertEqual(marks[-1],'recovery-required');self.assertNotIn('idle',marks)
