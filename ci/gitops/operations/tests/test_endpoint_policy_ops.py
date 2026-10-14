import sys,pathlib,json,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import endpoint_policy_ops as m
class Tests(unittest.TestCase):
 def setup(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  t={'region':'ap-northeast-2','endpoint_id':'vpce-exact','account':'111111111111','vpc_id':'vpc-exact','old_policy':{'Statement':[]},'desired_policy':{'Statement':[{'Effect':'Allow'}]},'route_table_ids':['rtb-1'],'policy_source':{'sha256':'a'},'reconcile_source_change':'approved-pr'}
  io=types.SimpleNamespace(require=require,h=types.SimpleNamespace(canonical=lambda x:json.dumps(x).encode(),digest=lambda x:'sha',SafeError=ValueError),ops=types.SimpleNamespace(run=lambda args:b'{"Return":true}'))
  live={'OwnerId':t['account'],'VpcId':t['vpc_id'],'RouteTableIds':['rtb-1'],'PolicyDocument':json.dumps(t['old_policy'])}
  return io,t,live
 def test_exact_ack_and_readback(self):
  io,t,live=self.setup();after=dict(live,PolicyDocument=json.dumps(t['desired_policy']));marks=[]
  with patch.object(m,'describe',side_effect=[live,after]):result=m.apply(io,'s3-endpoint-policy-recover',t,{},lambda phase,target:marks.append(phase))
  self.assertEqual(marks,['active','idle']);self.assertTrue(result['verified'])
 def test_drift_prevents_write(self):
  io,t,live=self.setup();live['RouteTableIds']=['rtb-other'];calls=[];io.ops.run=lambda args:calls.append(args)
  with patch.object(m,'describe',return_value=live):
   with self.assertRaises(ValueError):m.apply(io,'s3-endpoint-policy-recover',t,{},lambda *x:None)
  self.assertEqual(calls,[])
 def test_unknown_operation_no_read_or_write(self):
  io,t,live=self.setup()
  with patch.object(m,'describe') as read:
   with self.assertRaises(ValueError):m.apply(io,'network-reset',t,{},lambda *x:None)
   read.assert_not_called()
if __name__=='__main__':unittest.main()
