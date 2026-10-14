import importlib.util,pathlib,types,unittest
from unittest.mock import Mock,patch
P=pathlib.Path(__file__).with_name('trace-fault-probe.py');spec=importlib.util.spec_from_file_location('trace_test',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def io(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  return types.SimpleNamespace(require=require)
 def test_during_keeps_live_and_blocks_evidence_separate(self):
  t={};calls=[]
  fake=types.SimpleNamespace(probe=lambda io,t,p,a,mark:calls.append((p,a,t.get('query_mode','live'))))
  with patch.object(m,'producer',return_value=fake):m.during(self.io(),t,lambda *x:None)
  self.assertEqual(calls,[('fault','send','live'),('fault','query','live'),('fault','requery','blocks')])
 def test_recovered_requires_exact_blocks_trace(self):
  t={};calls=[]
  def probe(io,t,p,a,mark):calls.append((p,a,t.get('query_mode','live')));return {'accepted':True,'found':False}
  with patch.object(m,'producer',return_value=types.SimpleNamespace(probe=probe)):
   with self.assertRaises(ValueError):m.after(self.io(),t,lambda *x:None)
  self.assertEqual(calls[-1],('recovered','query','blocks'))
 def test_unknown_created_probe_blocks_cleanup_completion(self):
  with patch.object(m,'producer') as handler:
   with self.assertRaises(ValueError):m.cleanup(self.io(),{'pending_probe':'unacknowledged'},lambda *x:None)
   handler.assert_not_called()
if __name__=='__main__':unittest.main()
