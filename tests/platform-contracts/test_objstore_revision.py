import importlib.util
import tempfile
import unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/'automation/update_objstore_revision.py'
if SCRIPT.exists():
    spec=importlib.util.spec_from_file_location('objstore_revision',SCRIPT)
    revision=importlib.util.module_from_spec(spec);spec.loader.exec_module(revision)

@unittest.skipUnless(SCRIPT.exists(),'objectstore consumer source is not introduced yet')
class ObjstoreRevisionTests(unittest.TestCase):
    def prepare(self, root):
        config=root/'gitops/platform/monitoring/overlays/dev/objstore.yml'
        config.parent.mkdir(parents=True);config.write_text('type: S3\nconfig:\n  bucket: fixture-bucket\n  aws_sdk_auth: true\n')
        target=root/'gitops/platform/monitoring/values/dev.yaml';target.parent.mkdir(parents=True);target.write_text('prometheus:\n  prometheusSpec:\n    replicas: 1 # keep the reviewed comment\n')
        return config,target
    def test_only_pod_revision_field_changes_and_comment_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);_,target=self.prepare(root)
            digest,files=revision.revision(root,'dev',['sidecar'])
            obj=yaml.safe_load(target.read_text());self.assertEqual(obj['prometheus']['prometheusSpec']['replicas'],1)
            self.assertIn('keep the reviewed comment',target.read_text())
            self.assertEqual(obj['prometheus']['prometheusSpec']['podMetadata']['annotations'][revision.KEY],digest)
            self.assertEqual(len(files),1)
    def test_unintroduced_consumer_fails_before_any_source_is_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);_,target=self.prepare(root);before=target.read_text()
            with self.assertRaises(FileNotFoundError):revision.revision(root,'dev',['sidecar','store'])
            self.assertEqual(target.read_text(),before)
    def test_credentials_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config,target=self.prepare(root);before=target.read_text()
            config.write_text(config.read_text()+'  secret_key: rejected\n')
            with self.assertRaises(ValueError):revision.revision(root,'dev',['sidecar'])
            self.assertEqual(target.read_text(),before)
