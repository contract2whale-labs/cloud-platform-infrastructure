import hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'automation'))
spec=importlib.util.spec_from_file_location('apply_receipt',ROOT/'automation/apply_and_collect.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class ApplyReceiptTests(unittest.TestCase):
 def fixture(self,directory):
  repo=Path(directory);plan=repo/'reviewed.tfplan';plan.write_bytes(b'reviewed fixture only')
  backend=repo/'terraform/environments/dev/platform/observability/.terraform';backend.mkdir(parents=True)
  (backend/'terraform.tfstate').write_text(json.dumps({'backend':{'type':'s3','config':{'bucket':'fixture-state','key':'platform/observability/terraform.tfstate'}}}))
  argv=['apply_and_collect.py','--repo',str(repo),'--root','observability','--environment','dev','--profile','fixture','--expect-account','111111111111','--expect-revision','a'*40,'--state-bucket','fixture-state','--plan',str(plan),'--reviewed-plan-sha256',hashlib.sha256(plan.read_bytes()).hexdigest(),'--receipt',str(repo/'receipt.json')]
  return repo,plan,argv
 def test_modified_saved_plan_never_reaches_apply(self):
  with tempfile.TemporaryDirectory() as d:
   repo,plan,argv=self.fixture(d);plan.write_bytes(b'changed bytes')
   with patch.object(sys,'argv',argv),patch.object(module,'run') as run, self.assertRaises(ValueError):module.main()
   run.assert_not_called();self.assertFalse((repo/'receipt.json').exists())
 def test_wrong_backend_never_reaches_apply(self):
  with tempfile.TemporaryDirectory() as d:
   repo,plan,argv=self.fixture(d);backend=repo/'terraform/environments/dev/platform/observability/.terraform/terraform.tfstate';backend.write_text(json.dumps({'backend':{'type':'s3','config':{'bucket':'other-state','key':'platform/observability/terraform.tfstate'}}}))
   with patch.object(sys,'argv',argv),patch.object(module,'run') as run,self.assertRaises(ValueError):module.main()
   run.assert_not_called()
 def test_failed_apply_cannot_produce_receipt(self):
  with tempfile.TemporaryDirectory() as d:
   repo,plan,argv=self.fixture(d)
   def fake_run(command,**kwargs):
    if command[0]=='terraform':raise subprocess.CalledProcessError(1,command)
    value='a'*40 if 'rev-parse' in command else '111111111111' if 'sts' in command else ''
    return subprocess.CompletedProcess(command,0,value,'')
   with patch.object(sys,'argv',argv),patch.object(module,'run',side_effect=fake_run),patch.object(module,'collect') as collect,self.assertRaises(subprocess.CalledProcessError):module.main()
   collect.assert_not_called();self.assertFalse((repo/'receipt.json').exists())
if __name__=='__main__':unittest.main()
