import importlib.util
from pathlib import Path
import unittest
p=Path(__file__).parents[2]/'automation/inspect_config.py'
s=importlib.util.spec_from_file_location('inspect_config',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class RuntimeInspectionTests(unittest.TestCase):
    def test_read_live_configmap_among_runtime_maps(self):
        response={'kind':'ConfigMapList','items':[{'kind':'ConfigMap','data':{'runtime.yaml':'x: 1'}},{'kind':'ConfigMap','data':{'tempo.yaml':'storage:\n  trace:\n    s3:\n      prefix: dev/traces-epoch-3\n'}}]}
        self.assertEqual(m.inspect(response,'tempo.yaml',['storage.trace.s3.prefix']),['dev/traces-epoch-3'])
    def test_reject_failed_empty_ambiguous_or_secret_requests(self):
        for response in ({'kind':'Status','status':'Failure'},{'kind':'ConfigMapList','items':[]},{'kind':'ConfigMapList','items':[{'kind':'ConfigMap','data':{'tempo.yaml':'a: 1'}},{'kind':'ConfigMap','data':{'tempo.yaml':'a: 2'}}]}):
            with self.assertRaises(ValueError):m.inspect(response,'tempo.yaml',['storage.trace.s3.prefix'])
        with self.assertRaises(ValueError):m.inspect({'kind':'ConfigMap','data':{'tempo.yaml':'password: bad'}},'tempo.yaml',['password'])
if __name__=='__main__':unittest.main()
