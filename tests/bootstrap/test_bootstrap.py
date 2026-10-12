import importlib.util,os,subprocess,tempfile,unittest
from pathlib import Path
import yaml
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'bootstrap/argocd/bootstrap.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
IMAGE='ghcr.io/fixture/platform-toolchain@sha256:'+'a'*64
class BootstrapContracts(unittest.TestCase):
 def preflight_fixture(self):
  return SimpleNamespace(toolchain_image=IMAGE,repo_url='git@github.com:fixture/cloud-platform-infrastructure.git',revision='b'*40,repo=ROOT,environment='prod')
 def test_unreviewed_bootstrap_source_stops_before_account_query(self):
  calls=[]
  def fake_output(command):
   calls.append(command)
   if 'rev-parse' in command:return 'b'*40+'\n'
   if 'status' in command:return '?? gitops/clusters/prod/platform-applications/unreviewed.yaml\n'
   self.fail('unexpected command: '+str(command))
  with patch.object(module,'output',side_effect=fake_output),patch.object(module,'execute'):
   with self.assertRaisesRegex(ValueError,'unreviewed'):module.preflight(self.preflight_fixture())
  self.assertFalse(any(command[0]=='aws' for command in calls))
 def test_uncommitted_application_directory_stops_before_account_query(self):
  calls=[]
  def fake_output(command):
   calls.append(command)
   if 'rev-parse' in command:return 'b'*40+'\n'
   if 'status' in command or 'ls-tree' in command:return ''
   self.fail('unexpected command: '+str(command))
  with patch.object(module,'output',side_effect=fake_output),patch.object(module,'execute'):
   with self.assertRaisesRegex(ValueError,'approved commit'):module.preflight(self.preflight_fixture())
  self.assertFalse(any(command[0]=='aws' for command in calls))
 def test_bootstrap_preserves_tracking_tools_and_known_hosts(self):
  values=module.configured_values(IMAGE)
  self.assertTrue(values['crds']['keep']);self.assertEqual(values['configs']['cm']['application.resourceTrackingMethod'],'annotation')
  repo=values['repoServer'];self.assertEqual(repo['initContainers'][0]['image'],IMAGE)
  self.assertEqual({m['subPath'] for m in repo['volumeMounts']},{'helm','kustomize'})
  self.assertIn('ssh-ed25519',values['configs']['ssh']['knownHosts']);self.assertIn('--enable-helm',values['configs']['cm']['kustomize.buildOptions'])
 def test_formal_takeover_preserves_bootstrap_invariants(self):
  initial=module.configured_values(IMAGE)
  formal=yaml.safe_load((ROOT/'gitops/platform/values/argo-cd.yaml').read_text())
  formal['repoServer']['initContainers'][0]['image']=IMAGE
  self.assertTrue(formal['crds']['keep'])
  self.assertEqual(formal['configs']['cm']['application.resourceTrackingMethod'],initial['configs']['cm']['application.resourceTrackingMethod'])
  self.assertEqual(formal['configs']['cm']['kustomize.buildOptions'],initial['configs']['cm']['kustomize.buildOptions'])
  self.assertEqual(formal['configs']['ssh']['knownHosts'],initial['configs']['ssh']['knownHosts'])
  self.assertEqual(formal['configs']['repositories'],initial['configs']['repositories'])
  for key in ['initContainers','volumes','volumeMounts']:
   self.assertEqual(formal['repoServer'][key],initial['repoServer'][key])
  self.assertFalse(formal['configs']['cm']['admin.enabled'])
  self.assertTrue(initial['configs']['cm']['admin.enabled'])
 @unittest.skipUnless(os.environ.get('ARGO_BOOTSTRAP_CHART'),'native chart path provided by release verification')
 def test_actual_pinned_chart_repo_server_has_both_renderer_mounts(self):
  with tempfile.TemporaryDirectory() as d:
   file=Path(d)/'values.yaml';file.write_text(yaml.safe_dump(module.configured_values(IMAGE)))
   result=subprocess.check_output(['helm','template','argocd',os.environ['ARGO_BOOTSTRAP_CHART'],'--namespace','argocd','--values',str(file),'--include-crds'],text=True)
   objects=[x for x in yaml.safe_load_all(result) if x]
   repo=next(x for x in objects if x['kind']=='Deployment' and x['metadata']['name']=='argocd-repo-server')['spec']['template']['spec']
   self.assertEqual(next(x for x in repo['initContainers'] if x['name']=='pinned-renderers')['image'],IMAGE)
   mounts=repo['containers'][0]['volumeMounts'];self.assertTrue({'/usr/local/bin/helm','/usr/local/bin/kustomize'}.issubset({m['mountPath'] for m in mounts}))
   self.assertTrue(any(x['kind']=='CustomResourceDefinition' for x in objects))
if __name__=='__main__':unittest.main()
