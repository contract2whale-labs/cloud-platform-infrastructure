"""Standalone collector CLI receipt preservation; every collection call is fake."""
import importlib.util, json, subprocess, sys, tempfile, types, unittest
from pathlib import Path
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[2]/'automation/collect_platform_inputs.py'
fake_registry=types.ModuleType('platform_input_registry')
fake_registry.active_entries=lambda *args: []
with patch.dict(sys.modules,{'platform_input_registry':fake_registry}):
    spec=importlib.util.spec_from_file_location('standalone_collect_test_target',SOURCE)
    target=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)

class CollectReceiptPreservation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.repo=Path(self.tmp.name);self.output=self.repo/'protected/receipt.json'
        self.metadata=self.repo/'metadata.json';self.metadata.write_text(json.dumps({'fixture':True}))
        self.argv=['collect_platform_inputs.py','--repo',str(self.repo),'--terraform-root',str(self.repo/'terraform'),'--metadata',str(self.metadata),'--output',str(self.output)]
    def invoke(self,collector):
        # Fail immediately if this fake-only suite ever reaches a real subprocess.
        with patch.object(sys,'argv',self.argv),patch.object(target,'collect',side_effect=collector) as collect,patch.object(subprocess,'run',side_effect=AssertionError('real subprocess forbidden')):
            target.main()
        return collect
    def test_existing_file_stops_before_collection(self):
        self.output.parent.mkdir();self.output.write_text('previous-receipt')
        with patch.object(sys,'argv',self.argv),patch.object(target,'collect') as collect,patch.object(subprocess,'run',side_effect=AssertionError('real subprocess forbidden')):
            with self.assertRaises(SystemExit) as error:target.main()
            self.assertEqual(error.exception.code,2);collect.assert_not_called()
        self.assertEqual(self.output.read_text(),'previous-receipt')
    def test_broken_symlink_stops_before_collection(self):
        self.output.parent.mkdir();self.output.symlink_to(self.repo/'missing-target')
        with patch.object(sys,'argv',self.argv),patch.object(target,'collect') as collect,patch.object(subprocess,'run',side_effect=AssertionError('real subprocess forbidden')):
            with self.assertRaises(SystemExit) as error:target.main()
            self.assertEqual(error.exception.code,2);collect.assert_not_called()
        self.assertTrue(self.output.is_symlink());self.assertFalse((self.repo/'missing-target').exists())
    def test_fresh_receipt_is_private(self):
        self.invoke(lambda *args:{'fixture':True})
        self.assertEqual(json.loads(self.output.read_text()),{'fixture':True})
        self.assertEqual(self.output.stat().st_mode & 0o777,0o600)
    def test_late_collision_preserves_other_attempt(self):
        def collision(*args):
            self.output.parent.mkdir();self.output.write_text('other-attempt')
            return {'fixture':True}
        with self.assertRaises(SystemExit) as error:self.invoke(collision)
        self.assertEqual(error.exception.code,2);self.assertEqual(self.output.read_text(),'other-attempt')
    def test_collection_failure_has_no_success_receipt(self):
        def failure(*args):raise subprocess.CalledProcessError(1,['fake-terraform'])
        with self.assertRaises(SystemExit) as error:self.invoke(failure)
        self.assertEqual(error.exception.code,2);self.assertFalse(self.output.exists())

if __name__=='__main__':unittest.main()
