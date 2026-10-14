import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
n=load('parameterized_network','network-lifecycle.py')
g=load('parameterized_guard','network-lifecycle-guard.py')
class EnvironmentTests(unittest.TestCase):
 def env(self,root='terraform/environments/prod/network/vpc'):
  return dict(ROOT_PATH=root,LIFECYCLE_ENGINE='prod-network-v2',LIFECYCLE_ENVIRONMENT='prod',LIFECYCLE_CONFIG_SHA256='a'*64,LIFECYCLE_SELECTED_ROOTS=json.dumps([root]),LIFECYCLE_SNAPSHOT_SHA='b'*40,LIFECYCLE_GENERATION='1-1')
 def test_prod_vpc_exact_namespace_and_guard(self):
  with patch.dict(os.environ,self.env(),clear=True):
   n.configure();self.assertEqual(n.marker_key('17'),'ci-lifecycle/17/prod/network-vpc.json')
   guard=n.guard_module();self.assertEqual(guard.VPC,'terraform/environments/prod/network/vpc');self.assertEqual(guard.v.ROOT,guard.VPC)
   ctx=dict(root=guard.VPC,environment='prod',workspace='default',account='123456789012',backend={'key':'network/vpc/terraform.tfstate','bucket':'prod-private','region':'ap-northeast-2'})
   guard.v.validate_context(ctx)
   with self.assertRaises(guard.SafeError):guard.v.validate_context({**ctx,'environment':'dev'})
 def test_unmapped_prod_peer_or_transit_block(self):
  for name in ('peer','transit'):
   with patch.dict(os.environ,self.env('terraform/environments/prod/network/'+name),clear=True),self.assertRaises(n.h.SafeError):n.configure()
 def test_cross_account_selected_roots_block(self):
  env=self.env();env['LIFECYCLE_SELECTED_ROOTS']=json.dumps([env['ROOT_PATH'],'terraform/environments/dev/eks'])
  with patch.dict(os.environ,env,clear=True),self.assertRaises(n.h.SafeError):n.configure()
 def test_prod_does_not_infer_dev_optional_log_state(self):
  with tempfile.TemporaryDirectory() as directory:
   base=Path(directory);(base/'ci').mkdir();root='terraform/environments/prod/network/vpc'
   (base/'ci/deploy-roots.json').write_text(json.dumps({'dependencies':{root:[]}}));g.configure('prod');calls=[]
   self.assertEqual(g.read_upstreams(base,{'root':root},load_state=lambda key:calls.append(key)),{});self.assertEqual(calls,[])
 def test_cross_account_upstream_state_blocked_before_read(self):
  with tempfile.TemporaryDirectory() as directory:
   base=Path(directory);(base/'ci').mkdir();root='terraform/environments/prod/network/vpc'
   (base/'ci/deploy-roots.json').write_text(json.dumps({'dependencies':{root:['terraform/environments/dev/network/log-storage']}}));g.configure('prod');calls=[]
   with self.assertRaises(g.SafeError):g.read_upstreams(base,{'root':root},load_state=lambda key:calls.append(key))
   self.assertEqual(calls,[])
if __name__=='__main__':unittest.main()
