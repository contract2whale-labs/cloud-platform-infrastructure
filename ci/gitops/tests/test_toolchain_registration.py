import hashlib,importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('pinned_toolchain_register',ROOT/'register-toolchain.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class ToolchainRegistration(unittest.TestCase):
 def fixture(self):return dict(source_sha='a'*40,operator_image='ghcr.io/example/platform-toolchain@sha256:'+'b'*64,binary_sha256={tool:'c'*64 for tool in r.TOOLS})
 def test_retained_signature_tool_is_in_same_verified_publication(self):
  self.assertIn('cosign',r.TOOLS)
  published=self.fixture()
  with patch.object(r.subprocess,'run') as run,patch.object(r.subprocess,'check_output',return_value=json.dumps(published['binary_sha256']).encode()):
   self.assertEqual(r.verify(published)['binary_sha256'],published['binary_sha256'])
  self.assertIn('--network=none',r.verify.__code__.co_consts)
 def test_missing_signature_binary_is_not_valid_toolchain(self):
  published=self.fixture();del published['binary_sha256']['cosign']
  with patch.object(r.subprocess,'run') as run,self.assertRaises(ValueError):r.verify(published)
  run.assert_not_called()
 def test_changed_signature_binary_fails(self):
  published=self.fixture();actual=dict(published['binary_sha256'],cosign='d'*64)
  with patch.object(r.subprocess,'run'),patch.object(r.subprocess,'check_output',return_value=json.dumps(actual).encode()),self.assertRaises(ValueError):r.verify(published)
 def test_publisher_and_lock_include_signature_binary(self):
  text=(ROOT/'workflows/gitops-toolchain-publish.yml').read_text()
  self.assertIn('"cosign"',text)
  lock=json.loads((ROOT/'tooling/toolchain.lock.json').read_text())
  self.assertEqual(len([v for v in lock['tools'] if v['name']=='cosign' and v['binary']=='cosign']),1)
if __name__=='__main__':unittest.main()
