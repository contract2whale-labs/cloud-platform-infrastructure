import copy, importlib.util, pathlib, unittest
from unittest.mock import patch
p=pathlib.Path(__file__).resolve().parents[1]/'gitops-lifecycle.py'
spec=importlib.util.spec_from_file_location('gitops_adapter_test',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def manifest(self):return {'schema':1,'kind':'gitops-lifecycle','context':{'step_id':'hook:platform-core'},'control':{'version':'1'},'binding':{'eks':'1','relay':'2'},'created_at':0,'expires_at':m.h.TTL_SECONDS}
    def test_good_manifest(self):
        x=self.manifest();m.validate_manifest(x,x['context'],x['control'],x['binding'],1)
    def test_hook_swap(self):
        x=self.manifest()
        with self.assertRaises(m.h.SafeError):m.validate_manifest(x,{'step_id':'hook:platform-mesh'},x['control'],x['binding'],1)
    def test_stale_marker(self):
        x=self.manifest()
        with self.assertRaises(m.h.SafeError):m.validate_manifest(x,x['context'],{'version':'2'},x['binding'],1)
    def test_state_replacement(self):
        x=self.manifest()
        with self.assertRaises(m.h.SafeError):m.validate_manifest(x,x['context'],x['control'],{'eks':'new','relay':'2'},1)
    def test_expired(self):
        x=self.manifest()
        with self.assertRaises(m.h.SafeError):m.validate_manifest(x,x['context'],x['control'],x['binding'],m.h.TTL_SECONDS)
    def test_no_up_without_checkpoint_reset(self):
        self.assertFalse(m.operation_context_is_new({'phase':'active'},{'operation':'up'}))
    def test_new_down_after_completed_up(self):
        self.assertTrue(m.operation_context_is_new({'phase':'active'},{'operation':'down'}))
    def test_paused_down_preserves_snapshot(self):
        self.assertFalse(m.operation_context_is_new({'phase':'paused'},{'operation':'down'}))
if __name__=='__main__':unittest.main()
