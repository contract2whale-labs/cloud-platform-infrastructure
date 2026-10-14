import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import gitops_ops as ops
class Tests(unittest.TestCase):
 def test_packaged_access_helper_resolves(self):
  self.assertTrue(ops.shared_file('operations-access.py').is_file())
 def test_unregistered_module_rejected(self):
  with self.assertRaises(ops.Blocked):ops.shared_file('../../arbitrary.py')
 def test_both_wrappers_pin_proof_and_skip_up_start_network(self):
  base=pathlib.Path(__file__).resolve().parents[2]
  paths=(base/'gitops/gitops-lifecycle.py',base/'gitops/application-lifecycle.py') if (base/'gitops').is_dir() else (base/'gitops-ci-proposal/gitops-lifecycle.py',base/'application-hooks-proposal/application-lifecycle.py')
  for p in paths:
   s=p.read_text();self.assertIn("fingerprints['operations_access']",s);self.assertIn('generation=generation',s)
   self.assertLess(s.index("if stage=='start' and operation=='up'"),s.index('effective,fingerprints=live_binding'))
   self.assertIn("c['lifecycle_destroy_role_arn']",s)
if __name__=='__main__':unittest.main()

class ResidualTests(unittest.TestCase):
 def test_exact_installer_role_and_metadata_binding(self):
  import copy,os
  from unittest.mock import patch
  import lifecycle_hooks as hooks
  item={'gvr':'rbac.authorization.k8s.io/v1/roles','resource':'roles','base':'/apis/rbac.authorization.k8s.io/v1','namespaced':True,'object':{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'namespace':'incident-fixture-t3','name':'fixed','uid':'uid','labels':{'owner':'ci'}},'rules':[]}}
  c={'environment':'dev','applications':[],'cluster_arn':'arn','cluster_created_at':'date','_installer_residual_resources':[hooks.resource_row(item)]}
  with patch.dict(os.environ,{'LIFECYCLE_SNAPSHOT_SHA':'a'*40}):
   result=hooks.residual_contract(c,[item],'1-1');self.assertEqual(result['approved_residuals'][0]['uid'],'uid')
   changed=copy.deepcopy(item);changed['object']['metadata']['labels']['owner']='other'
   with self.assertRaises(hooks.HookBlocked):hooks.residual_contract(c,[changed],'1-1')
 def test_missing_installer_object_blocks(self):
  import os
  from unittest.mock import patch
  import lifecycle_hooks as hooks
  c={'applications':[],'_installer_residual_resources':[{'kind':'Role','resource':'roles','namespace':'n','name':'r'}]}
  with patch.dict(os.environ,{'LIFECYCLE_SNAPSHOT_SHA':'a'*40}):
   with self.assertRaises(hooks.HookBlocked):hooks.residual_contract(c,[],'1-1')
