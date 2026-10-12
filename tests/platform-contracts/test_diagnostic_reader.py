import importlib.util
import json
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FILE=ROOT/'automation/read_platform_contract.py'
if FILE.exists():
    spec=importlib.util.spec_from_file_location('diagnostic_reader',FILE)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

@unittest.skipUnless(FILE.exists(),'diagnostic reader not introduced yet')
class DiagnosticReaderTests(unittest.TestCase):
    def outputs(self):
        return {'queue_managed_contract':{'sensitive':False,'value':{key:3 if key=='partitions' else 'fixture-value' for key in reader.COMPONENTS['queue'][2]}},'actual_credential':{'sensitive':True,'value':'PRIVATE_VALUE'}}
    def test_selected_contract_only(self):
        result=reader.select(self.outputs(),'queue')
        self.assertEqual(result['partitions'],3)
        self.assertNotIn('PRIVATE_VALUE',json.dumps(result))
        self.assertNotIn('actual_credential',result)
    def test_sensitive_selected_output_is_rejected(self):
        outputs=self.outputs();outputs['queue_managed_contract']['sensitive']=True
        with self.assertRaises(ValueError):reader.select(outputs,'queue')
    def test_missing_output_field_is_not_defaulted(self):
        outputs=self.outputs();del outputs['queue_managed_contract']['value']['cluster_arn']
        with self.assertRaises(ValueError):reader.select(outputs,'queue')
