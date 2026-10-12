import importlib.util,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('diagnostics',ROOT/'automation/export_diagnostic_context.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class DiagnosticContextTests(unittest.TestCase):
 def test_quotes_are_literal_and_file_is_private(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'context.env';value="value'$(touch should-not-exist)`echo danger`"
   module.write_context(path,{'SAFE_FIELD':value})
   result=subprocess.check_output(['bash','-c','source "$1"; printf %s "$SAFE_FIELD"','fixture',str(path)],text=True,cwd=d)
   self.assertEqual(value,result);self.assertFalse((Path(d)/'should-not-exist').exists());self.assertEqual(path.stat().st_mode&0o777,0o600)
 def test_sensitive_output_cannot_be_exported(self):
  with self.assertRaises(ValueError):module.select({'contract':{'sensitive':True,'value':{'name':'fixture'}}},{'variables':{'SAFE_FIELD':{'output':'contract','field':'name'}}},{})
 def test_only_registered_fields_selected(self):
  result=module.select({'contract':{'sensitive':False,'value':{'name':'approved','password':'fixture'}}},{'variables':{'SAFE_FIELD':{'output':'contract','field':'name'}}},{})
  self.assertEqual(result,{'SAFE_FIELD':'approved'})
 def test_complex_objects_rejected(self):
  with self.assertRaises(ValueError):module.select({'contract':{'sensitive':False,'value':{'name':{'unknown':'value'}}}},{'variables':{'SAFE_FIELD':{'output':'contract','field':'name'}}},{})
 def test_ecr_repository_leaf_exports_url_without_serializing_object(self):
  outputs={'delivery_contract':{'sensitive':False,'value':{'ecr_repositories':{'commerce-web':{'url':'111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/commerce-web','arn':'fixture-arn'}}}}}
  mapping={'variables':{'DELIVERY_WEB_IMAGE_REPOSITORY':{'output':'delivery_contract','field':'ecr_repositories.commerce-web.url'}}}
  self.assertEqual(module.select(outputs,mapping,{}),{'DELIVERY_WEB_IMAGE_REPOSITORY':'111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/commerce-web'})
 def test_optional_redis_reports_presence_without_exporting_object(self):
  mapping={'variables':{'DATA_REDIS_ENABLED':{'output':'data_contract','field':'redis','transform':'present'}}}
  for redis,expected in [(None,'false'),({'address':'cache.internal','port':6379,'tls_enabled':True},'true')]:
   result=module.select({'data_contract':{'sensitive':False,'value':{'redis':redis}}},mapping,{})
   self.assertEqual(result,{'DATA_REDIS_ENABLED':expected})
if __name__=='__main__':unittest.main()
