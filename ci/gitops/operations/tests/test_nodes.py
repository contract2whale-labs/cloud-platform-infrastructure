import copy,pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import incident_ops as m,node_ops as n
class Nodes(unittest.TestCase):
 def obj(self):return {'metadata':{'name':'node-a','uid':'a','resourceVersion':'4','labels':{'workload':'app','eks.amazonaws.com/nodegroup':'contract2whale-dev-eks-app'},'annotations':{n.KEY:'true'}},'spec':{'providerID':'aws:///zone/i-a'}}
 def row(self):return {'name':'node-a','uid':'a','before':None,'provider_id':'aws:///zone/i-a'}
 def test_replaced_uid_blocks(self):
  o=self.obj();o['metadata']['uid']='replacement'
  with patch.object(m,'kube',return_value=o):
   with self.assertRaises(m.h.SafeError):n.current(m.fixture_io(),self.row())
 def test_unknown_annotation_blocks(self):
  o=self.obj();o['metadata']['annotations'][n.KEY]='false'
  with patch.object(m,'kube',return_value=o):
   with self.assertRaises(m.h.SafeError):n.current(m.fixture_io(),self.row())
 def test_absent_baseline_removes_with_preconditions(self):
  o=self.obj();after=copy.deepcopy(o);after['metadata']['annotations']={}
  with patch.object(m,'kube',side_effect=[o,after]),patch.object(m.ops,'run') as call:n.patch(m.fixture_io(),self.row(),None)
  import json
  actions=json.loads(call.call_args.args[0][-1]);self.assertEqual(actions[0]['path'],'/metadata/uid');self.assertEqual(actions[1]['path'],'/metadata/resourceVersion');self.assertEqual(actions[-1]['op'],'remove')
 def test_cycle_finally_restores_after_failure(self):
  target={'nodes':[self.row()],'hold_seconds':2};marks=[]
  with patch.object(n,'patch',side_effect=[m.h.SafeError('injection failed'),None]) as mutate:
   with self.assertRaises(m.h.SafeError):n.apply(m.fixture_io(),'node-protection-cycle',target,{},lambda phase,t:marks.append(phase))
   self.assertEqual(mutate.call_args.args[-1],None);self.assertEqual(marks,['active','idle'])
if __name__=='__main__':unittest.main()
