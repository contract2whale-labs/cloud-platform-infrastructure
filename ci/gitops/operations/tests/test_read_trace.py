import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]));import read_trace
class ReadOnlyTrace(unittest.TestCase):
 def test_allowed_fixed_get(self):self.assertEqual(read_trace.coordinates('http://platform-tempo-e2-querier.monitoring:3200/querier/api/traces/'+'a'*32+'?mode=blocks')[0],'platform-tempo-e2-querier')
 def test_arbitrary_host_rejected(self):
  with self.assertRaises(ValueError):read_trace.coordinates('http://evil.example:3200/api/traces/'+'a'*32)
 def test_write_path_rejected(self):
  with self.assertRaises(ValueError):read_trace.coordinates('http://platform-tempo-e2-querier.monitoring:3200/v1/traces')
 def test_source_never_creates_pod(self):
  source=pathlib.Path(read_trace.__file__).read_text();self.assertNotIn("'run'",source);self.assertNotIn("'create'",source);self.assertIn("method='GET'",source)

class RedirectBoundary(unittest.TestCase):
 def test_redirect_not_followed(self):
  self.assertIsNone(read_trace.NoRedirect().redirect_request(None,None,302,"redirect",{},"http://external/"))
