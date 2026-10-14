import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
spec=importlib.util.spec_from_file_location('publisher',Path(__file__).with_name('publish.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_copy_transfers_all_blobs_preserves_digest(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'config.json').write_text('{}')
   source='public.ecr.aws/abc/course-bu07-pause@sha256:'+'a'*64
   with patch.dict(os.environ,{'DOCKER_CONFIG':d}),patch.object(m,'cmd') as cmd,patch.object(m,'immutable',return_value='repo@sha256:'+'a'*64):
    m.copy_image(source,'repo:tag');args=cmd.call_args.args
    self.assertIn('--all',args);self.assertIn('--preserve-digests',args);self.assertIn('docker://'+source,args)
    self.assertNotIn('imagetools',args);self.assertIn(m.SKOPEO_IMAGE,args)
 def test_copy_digest_mismatch_stops(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'config.json').write_text('{}')
   with patch.dict(os.environ,{'DOCKER_CONFIG':d}),patch.object(m,'cmd'),patch.object(m,'immutable',return_value='repo@sha256:'+'b'*64):
    with self.assertRaisesRegex(RuntimeError,'changed'):m.copy_image('repo@sha256:'+'a'*64,'repo:tag')
 def test_instructor_copies_only_linux_then_joins_same_registry(self):
  source='registry.k8s.io/pause@sha256:'+'c'*64;target='public.ecr.aws/abc/course-bu07-pause:tag'
  doc={'manifests':[{'digest':'sha256:'+letter*64,'platform':{'os':osname,'architecture':arch}} for osname,arch,letter in [('linux','amd64','a'),('linux','arm64','b'),('windows','amd64','d')]]}
  with patch.object(m,'cmd',return_value=json.dumps(doc)) as cmd,patch.object(m,'copy_image') as cp,patch.object(m,'immutable',return_value='index'):
   self.assertEqual(m.publish_linux_pair(source,target),'index');self.assertEqual(cp.call_count,2)
   self.assertEqual(cmd.call_args.args[0:4],('docker','buildx','imagetools','create'))
   self.assertTrue(all(x.startswith('public.ecr.aws/') for x in cmd.call_args.args[6:]))
 def test_both_cpu_manifests_required(self):
  for platforms,passes in [(['amd64'],False),(['amd64','arm64'],True)]:
   doc={'manifests':[{'platform':{'os':'linux','architecture':a}} for a in platforms]}
   with patch.object(m,'cmd',return_value=json.dumps(doc)):
    if passes:m.require_platforms('image')
    else:
     with self.assertRaises(RuntimeError):m.require_platforms('image')
 def test_receipt_has_exact_version_and_sha(self):
  h=Mock();store=Mock();store.bucket='bucket';store.call.return_value={'VersionId':'version-123','ServerSideEncryption':'AES256'}
  with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'GITHUB_REPOSITORY_ID':'123','GITHUB_RUN_ID':'456','GITHUB_RUN_ATTEMPT':'2'}):
   p=Path(d)/'receipt';p.write_text('{}');result=m.retain_receipt(h,store,p)
   self.assertEqual(result['version'],'version-123');self.assertEqual(len(result['sha256']),64)
   self.assertIn('--if-none-match',store.call.call_args.args);self.assertEqual(result['key'],'ci-probe-images/123/456/2/receipt.json')
 def test_missing_version_refused(self):
  with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'GITHUB_REPOSITORY_ID':'123','GITHUB_RUN_ID':'456','GITHUB_RUN_ATTEMPT':'2'}):
   p=Path(d)/'receipt';p.write_text('{}');store=Mock();store.call.return_value={'ServerSideEncryption':'AES256'}
   with self.assertRaises(RuntimeError):m.retain_receipt(Mock(),store,p)
 def test_exact_role_and_pause_guard_before_publication(self):
  env={'EXPECTED_ACCOUNT_ID':'111111111111','GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY_ID':'123','AWS_ROLE_ARN':'arn:aws:iam::111111111111:role/apply','STATE_BUCKET':'bucket','AWS_REGION':'ap-northeast-2','GITHUB_WORKSPACE':'/repo'}
  h=Mock();guard=Mock(spec=['assert_normal_allowed'])
  with patch.dict(os.environ,env),patch.object(m,'load_ci',side_effect=lambda name:h if name=='saved-plan' else guard),patch.object(m,'cmd',return_value='a'*40):
   m.publication_context('learner');h.check_identity.assert_called_once_with(env['EXPECTED_ACCOUNT_ID'],env['AWS_ROLE_ARN']);guard.assert_normal_allowed.assert_called_once()
 def test_paused_course_stops(self):
  env={'EXPECTED_ACCOUNT_ID':'111111111111','GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY_ID':'123','AWS_ROLE_ARN':'role','STATE_BUCKET':'bucket','AWS_REGION':'ap-northeast-2','GITHUB_WORKSPACE':'/repo'}
  h=Mock();guard=Mock(spec=['assert_normal_allowed']);guard.assert_normal_allowed.side_effect=RuntimeError('paused')
  with patch.dict(os.environ,env),patch.object(m,'load_ci',side_effect=lambda name:h if name=='saved-plan' else guard),patch.object(m,'cmd',return_value='a'*40):
   with self.assertRaisesRegex(RuntimeError,'paused'):m.publication_context('learner')
 def test_private_auth_removed_after_failure(self):
  with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'RUNNER_TEMP':d,'PUBLICATION_MODE':'learner','DOCKER_CONFIG':'previous'}),patch.object(m,'publish',side_effect=RuntimeError('failed')):
   with self.assertRaises(RuntimeError):m.main()
   self.assertEqual(list(Path(d).iterdir()),[]);self.assertEqual(os.environ['DOCKER_CONFIG'],'previous')
 def test_workflow_uses_existing_environment_and_mutex(self):
  s=Path(__file__).with_name('publish.yml').read_text()
  self.assertIn("'infra-dev-apply'",s);self.assertNotIn('probe-images-${{',s)
  self.assertIn('terraform-infra-${{ github.repository_id }}',s);self.assertNotIn('secrets.AWS_ROLE_ARN',s)
if __name__=='__main__':unittest.main()
