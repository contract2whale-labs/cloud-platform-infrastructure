"""Fake-only receipt preservation tests. No real subprocess or SDK calls."""
import hashlib, importlib.util, json, os
from pathlib import Path
import subprocess, sys, tempfile, types, unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[2]/'automation/apply_and_collect.py'
fake_collector=types.ModuleType('collect_platform_inputs')
fake_collector.collect=lambda *args: {'fake': True}
with patch.dict(sys.modules, {'collect_platform_inputs':fake_collector}):
    spec=importlib.util.spec_from_file_location('receipt_apply_test_target',SOURCE)
    target=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)

class ReceiptPreservation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.repo=Path(self.tmp.name);self.receipt=self.repo/'protected/request.json'
        self.tfroot=self.repo/'terraform/environments/dev/platform/observability'
        (self.tfroot/'.terraform').mkdir(parents=True)
        (self.tfroot/'.terraform/terraform.tfstate').write_text(json.dumps({'backend':{'type':'s3','config':{'bucket':'example-state','key':'platform/observability/terraform.tfstate'}}}))
        self.plan=self.repo/'reviewed.tfplan';self.plan.write_bytes(b'fake-reviewed-plan')
        self.argv=['apply_and_collect.py','--repo',str(self.repo),'--root','observability','--environment','dev','--profile','fake','--expect-account','111111111111','--expect-revision','a'*40,'--state-bucket','example-state','--plan',str(self.plan),'--reviewed-plan-sha256',hashlib.sha256(self.plan.read_bytes()).hexdigest(),'--receipt',str(self.receipt)]
    def fake_run(self,command,**kwargs):
        if command[:1]==['git']:
            body='a'*40 if command[3:]==['rev-parse','HEAD'] else ''
        elif command[0]=='aws' and 'get-caller-identity' in command:body='111111111111'
        elif command[0]=='aws' and 'cp' in command:body=json.dumps({'lineage':'11111111-2222-4333-8444-555555555555','serial':1})
        elif command[0]=='terraform' and 'apply' in command:body='fake applied'
        else:raise AssertionError(f'unexpected fake command {command}')
        return subprocess.CompletedProcess(command,0,body,'')
    def invoke(self,collector=None,runner=None):
        with patch.object(sys,'argv',self.argv),patch.object(target,'run',side_effect=runner or self.fake_run),patch.object(target,'collect',side_effect=collector or (lambda *a:{'fake':True})):
            target.main()
    def test_existing_receipt_stops_before_any_command(self):
        self.receipt.parent.mkdir();self.receipt.write_text('previous-success')
        with patch.object(sys,'argv',self.argv),patch.object(target,'run') as run:
            with self.assertRaises(FileExistsError):target.main()
            run.assert_not_called()
        self.assertEqual(self.receipt.read_text(),'previous-success')
    def test_broken_symlink_stops_before_any_command(self):
        self.receipt.parent.mkdir();self.receipt.symlink_to(self.repo/'missing-target')
        with patch.object(sys,'argv',self.argv),patch.object(target,'run') as run:
            with self.assertRaises(FileExistsError):target.main()
            run.assert_not_called()
        self.assertTrue(self.receipt.is_symlink())
    def test_new_receipt_is_exclusive_and_private(self):
        self.invoke()
        self.assertEqual(json.loads(self.receipt.read_text()),{'fake':True})
        self.assertEqual(self.receipt.stat().st_mode & 0o777,0o600)
    def test_receipt_created_during_collection_is_preserved(self):
        def racing_collector(*args):
            self.receipt.parent.mkdir();self.receipt.write_text('other-attempt')
            return {'fake':True}
        with self.assertRaises(FileExistsError):self.invoke(collector=racing_collector)
        self.assertEqual(self.receipt.read_text(),'other-attempt')
    def test_apply_failure_does_not_create_success_receipt(self):
        def failed_run(command,**kwargs):
            if command[0]=='terraform':raise subprocess.CalledProcessError(1,command)
            return self.fake_run(command,**kwargs)
        with self.assertRaises(subprocess.CalledProcessError):self.invoke(runner=failed_run)
        self.assertFalse(self.receipt.exists())

if __name__=='__main__':unittest.main()
