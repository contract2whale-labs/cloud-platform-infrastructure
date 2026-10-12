# -*- coding: utf-8 -*-
"""Offline contract checks; not a PromQL engine or Rollouts controller test."""
import math, re, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class CanaryEvidenceContracts(unittest.TestCase):
 def conditions(self):
  base=(ROOT/'gitops/apps/commerce-web/base/analysis-template.yaml').read_text()
  prod=(ROOT/'gitops/apps/commerce-web/overlays/prod/kustomization.yaml').read_text()
  return re.findall(r'^\s*successCondition: (.*?)\s+#',base,re.M)+re.findall(r'^\s*value: (len\(result\)[^\n]+)',prod,re.M)
 def evaluate(self,condition,result):
  # Deliberately restricted to the authored len/comparison contract.
  match=re.fullmatch(r'len\(result\) > 0 && result\[0\] (<=|<) ([0-9.]+)',condition.strip())
  self.assertIsNotNone(match,condition)
  if not result:return False
  value=result[0];threshold=float(match[2])
  return value<=threshold if match[1]=='<=' else value<threshold
 def test_thresholds_are_preserved_for_both_environments(self):
  self.assertEqual(self.conditions(),['len(result) > 0 && result[0] <= 0.01','len(result) > 0 && result[0] < 800','len(result) > 0 && result[0] <= 0.005','len(result) > 0 && result[0] < 600'])
 def test_no_data_or_zero_traffic_is_not_a_success_result(self):
  for c in self.conditions():
   for state in ['missing-series','zero-traffic']:
    with self.subTest(condition=c,state=state):self.assertFalse(self.evaluate(c,[]))
 def test_observed_zero_normal_and_error_values(self):
  for c in self.conditions():
   limit=float(c.split()[-1]);normal=limit/2
   with self.subTest(condition=c):
    self.assertTrue(self.evaluate(c,[0]));self.assertTrue(self.evaluate(c,[normal]));self.assertFalse(self.evaluate(c,[limit+1]));self.assertFalse(self.evaluate(c,[math.nan]))
 def test_queries_filter_zero_denominators_without_outer_zero_fallback(self):
  source=(ROOT/'gitops/apps/commerce-web/base/analysis-template.yaml').read_text()
  self.assertNotRegex(source,r'^\s{12}or vector\(0\)',)
  queries=re.findall(r'query: \|\n(.*?)(?=^---|\Z)',source,re.S|re.M)
  self.assertEqual(sum(q.count(' > 0)') for q in queries),2)
  self.assertIn('consecutiveErrorLimit: 2',source)
if __name__=='__main__':unittest.main()
