import os, pathlib, sys, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import incident_ops as m, fixture_ops as f
class Fixtures(unittest.TestCase):
 def manifests(self,case='t3'):
  image='ghcr.io/example/platform-toolchain@sha256:'+'a'*64
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'1'}):return f.manifests(m.fixture_io(),{'operator_image':image,'fixture_image':image},{},case)
 def test_all_cases_are_fixed(self):self.assertEqual(len(f.IDS),12)
 def test_dedicated_namespace(self):
  for case in ('t3','t4','t5','t6'):
   docs=self.manifests(case);self.assertEqual(docs[0]['metadata']['name'],'incident-fixture-'+case)
   self.assertTrue(all(x['metadata'].get('namespace','incident-fixture-'+case)=='incident-fixture-'+case for x in docs))
 def test_no_credentials_or_privilege(self):
  spec=self.manifests()[-1]['spec']['template']['spec'];self.assertFalse(spec['automountServiceAccountToken']);self.assertTrue(spec['securityContext']['runAsNonRoot'])
  c=spec['containers'][0];self.assertFalse(c['securityContext']['allowPrivilegeEscalation']);self.assertEqual(c['resources']['limits']['memory'],'64Mi');self.assertNotIn('env',c)
 def test_dns_fault_not_global(self):
  docs=self.manifests('t6');self.assertEqual(docs[-1]['spec']['template']['spec']['containers'][0]['args'],['dns']);self.assertFalse(any(x['metadata']['name']=='coredns' for x in docs))
 def test_image_digest_binding(self):
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'1'}):
   with self.assertRaises(m.h.SafeError):f.manifests(m.fixture_io(),{'operator_image':'x@sha256:'+'a'*64,'fixture_image':'x@sha256:'+'b'*64},{},'t3')
 def test_cross_case_recovery_rejected(self):
  marker={'owner':'kubernetes-fixed-operations','phase':'active','operation':'fixture-t3-cycle'}
  self.assertTrue(m.recovery_authorized('fixture-t3-restore',{},marker));self.assertFalse(m.recovery_authorized('fixture-t4-cleanup',{},marker))
 def test_cluster_resource_no_empty_namespace_flag(self):
  with patch.object(m.ops,'run',return_value=b'{}') as run:m.kube('namespaces','','fixture')
  self.assertNotIn('-n',run.call_args.args[0])
if __name__=='__main__':unittest.main()

class NamespaceBoundary(unittest.TestCase):
 def test_cycle_reuses_registered_namespace_without_cluster_create(self):
  image='ghcr.io/example/tool@sha256:'+'a'*64;c={'fixture_image':image,'operator_image':image,'fixture_namespace_uids':{'t4':'ns1'}}
  ns={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'incident-fixture-t4','uid':'ns1','labels':{'platform.course/fixture-namespace':'t4'}},'spec':{}}
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'1'}),patch.object(m,'kube',side_effect=[ns]+[None]*5):
   target=f.snapshot(m.fixture_io(),'fixture-t4-cycle',{'hold_seconds':30},c,None,None)
  self.assertEqual(len(target['manifests']),5);self.assertTrue(target['created'][0]['preprovisioned']);self.assertFalse(any(x['kind']=='Namespace' for x in target['manifests']))
 def test_foreign_namespace_uid_rejected(self):
  c={'fixture_namespace_uids':{'t4':'expected'}};ns={'metadata':{'uid':'foreign','labels':{'platform.course/fixture-namespace':'t4'}}}
  with patch.object(m,'kube',return_value=ns):
   with self.assertRaises(m.h.SafeError):f.snapshot(m.fixture_io(),'fixture-t4-cycle',{'hold_seconds':30},c,None,None)
