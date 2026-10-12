"""Read the shipped publisher; prevent PR credentials and source-copy drift."""
import re, unittest
from pathlib import Path
from ruamel.yaml import YAML
ROOT=Path(__file__).resolve().parents[2]
class DeliveryWorkflowContracts(unittest.TestCase):
 def setUp(self):
  self.source=(ROOT/'modules/delivery/examples/github-actions-ci.yml').read_text()
  self.workflow=YAML(typ='safe').load(self.source)
 def test_only_approved_main_release_can_request_oidc(self):
  self.assertEqual(self.workflow['permissions'],{'contents':'read'})
  test=self.workflow['jobs']['ci-test'];release=self.workflow['jobs']['release']
  self.assertFalse(any(v=='write' for v in test.get('permissions',{}).values()))
  self.assertNotRegex(str(test),r'\$\{\{\s*secrets\.')
  self.assertEqual(release['needs'],'ci-test')
  self.assertEqual(release['if'],"github.event_name == 'push' && github.ref == 'refs/heads/main'")
  self.assertEqual(release['permissions'],{'contents':'read','id-token':'write'})
  self.assertNotIn('pull_request_target',self.workflow['on'])
  self.assertEqual(self.workflow['on']['push']['branches'],['main'])
  self.assertNotIn('tags',self.workflow['on']['push'])
 def test_checkout_and_application_token_scope_are_explicit(self):
  tokens=[]
  for job in self.workflow['jobs'].values():
   for step in job['steps']:
    if 'uses' not in step:continue
    self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
    if step['uses'].startswith('actions/checkout@'):self.assertIs(step['with']['persist-credentials'],False)
    if step['uses'].startswith('actions/create-github-app-token@'):tokens.append(step['with'])
  self.assertEqual(len(tokens),1)
  self.assertEqual(tokens[0]['repositories'],'cloud-platform-infrastructure')
  self.assertEqual(tokens[0]['permission-contents'],'write');self.assertEqual(tokens[0]['permission-pull-requests'],'write')
 def test_edit_and_promotion_check_stay_in_same_pinned_ci_toolchain(self):
  step=next(s for s in self.workflow['jobs']['release']['steps'] if s.get('name')=='Open the gitops digest PR (one line, kustomize edit)')
  run=step['run']
  self.assertLess(run.index('gh auth setup-git'),run.index('gh repo clone'))
  self.assertLess(run.index('TOOLCHAIN_IMAGE:?'),run.index('kustomize edit'))
  self.assertEqual(run.count('"$TOOLCHAIN_IMAGE"'),2)
  self.assertIn('-v "$PWD:/workspace:ro"',run)
  self.assertIn('--expected-digest "$DIGEST"',run)
  self.assertIn('--expected-repository "$IMAGE_REPOSITORY"',run)
  self.assertIn('check_image_promotion.py',run)
  self.assertNotIn('curl',run)
if __name__=='__main__':unittest.main()
