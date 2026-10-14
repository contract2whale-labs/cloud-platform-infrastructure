import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('log_storage_inputs',Path(__file__).with_name('saved-plan.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class InputTests(unittest.TestCase):
    def normalize(self,source,root='network/log-storage'):
        return h.normalized_root_inputs(source,root,'dev','123456789012','ap-northeast-2')
    def test_storage_defaults_use_only_existing_protected_target(self):
        self.assertEqual(self.normalize({'network/vpc':{'secret':'not-copied'}}),{'expected_account_id':'123456789012','region':'ap-northeast-2','environment':'dev'})
    def test_explicit_values_and_default_plan_apply_hashes_are_identical(self):
        plan=self.normalize({'network/vpc':{}})
        apply=self.normalize({'network/log-storage':{'region':'ap-northeast-2','expected_account_id':'123456789012','environment':'dev'}})
        self.assertEqual(h.canonical(plan),h.canonical(apply));self.assertEqual(h.digest(h.canonical(plan)),h.digest(h.canonical(apply)))
    def test_target_overrides_fail_closed(self):
        for key,value in [('expected_account_id','999999999999'),('region','us-east-1'),('environment','prod')]:
            with self.subTest(key=key),self.assertRaises(h.SafeError):self.normalize({'network/log-storage':{key:value}})
    def test_malformed_or_secret_like_storage_input_never_silently_defaults(self):
        for value in (None,[],42,'secret',{'network/log-storage':None},{'network/log-storage':[]},{'network/log-storage':{'password':'secret'}}):
            with self.subTest(value=type(value)),self.assertRaises(h.SafeError):self.normalize(value)
    def test_no_other_root_gets_implicit_input_or_backend_values(self):
        with self.assertRaises(h.SafeError):self.normalize({},'network/vpc')
        original={'state_bucket_name':'approved','state_region':'ap-northeast-2'}
        self.assertEqual(self.normalize({'network/vpc':original},'network/vpc'),original)
if __name__=='__main__':unittest.main()
