import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'automation'))
spec=importlib.util.spec_from_file_location('input_pr',ROOT/'automation/create_inputs_pr.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class PublisherPRScopeTests(unittest.TestCase):
 def test_application_field_is_allowed_without_other_environment_or_shared_base(self):
  with tempfile.TemporaryDirectory() as directory:
   repo=Path(directory);(repo/'automation').mkdir()
   (repo/'automation/platform-input-mappings.json').write_text(json.dumps([{'root':'data','field':'runtime_secret_arn','targets':[{'file':'gitops/apps/commerce-api/overlays/{environment}/externalsecret.patch.yaml'}]}]))
   allowed=module.allowed_changed_paths({'root':'data','environment':'dev'},repo)
   self.assertIn('gitops/apps/commerce-api/overlays/dev/externalsecret.patch.yaml',allowed)
   self.assertIn('gitops/inputs/dev/data.receipt.json',allowed)
   self.assertNotIn('gitops/apps/commerce-api/base/externalsecret.yaml',allowed)
   self.assertNotIn('gitops/apps/commerce-api/overlays/prod/externalsecret.patch.yaml',allowed)
   self.assertNotIn('.github/workflows/platform-validate.yml',allowed)
 def test_only_registered_root_changes_are_publishable(self):
  with tempfile.TemporaryDirectory() as directory:
   repo=Path(directory);(repo/'automation').mkdir()
   (repo/'automation/platform-input-mappings.json').write_text(json.dumps([{'root':'data','field':'bucket','targets':[{'file':'gitops/apps/commerce-api/overlays/{environment}/runtime-config.patch.yaml'}]},{'root':'delivery','field':'client_id','targets':[{'file':'gitops/platform/values/argo-cd-{environment}.yaml'}]}]))
   allowed=module.allowed_changed_paths({'root':'data','environment':'dev'},repo)
   self.assertNotIn('gitops/platform/values/argo-cd-dev.yaml',allowed)
 def test_inactive_future_prod_target_is_not_publishable(self):
  with tempfile.TemporaryDirectory() as directory:
   repo=Path(directory);(repo/'automation').mkdir()
   target='gitops/platform/monitoring-resources/overlays/{environment}/dashboard-route.yaml'
   (repo/'automation/platform-input-mappings.json').write_text(json.dumps([{'root':'gateway','field':'dashboard_hostname','targets':[{'file':target,'environments':['dev']}]}]))
   self.assertIn(target.replace('{environment}','dev'),module.allowed_changed_paths({'root':'gateway','environment':'dev'},repo))
   self.assertNotIn(target.replace('{environment}','prod'),module.allowed_changed_paths({'root':'gateway','environment':'prod'},repo))
if __name__=='__main__':unittest.main()
