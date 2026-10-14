"""Real local Git history tests. No AWS, GitHub or Terraform calls."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('deploy_activation_integration', HERE / 'deploy-select.py')
select = importlib.util.module_from_spec(spec)
spec.loader.exec_module(select)


class ActivationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / 'ci').mkdir()
        for name in ('roots.json', 'deploy-roots.json', 'lifecycle-targets.json', 'lifecycle-targets-prod.json'):
            shutil.copy2(HERE / name, self.repo / 'ci' / name)
        registry = json.loads((HERE / 'roots.json').read_text())
        graph = json.loads((HERE / 'deploy-roots.json').read_text())['dependencies']
        self.document = select.activation.initial_activation('BU02', select.activation.read_catalogs(HERE.parent), registry, graph)
        self.write_activation(self.document)
        self.vpc = 'terraform/environments/dev/network/vpc'
        root = self.repo / self.vpc
        root.mkdir(parents=True)
        (root / 'main.tf').write_text('module "vpc" { source = "../../../../modules/vpc" }')
        (root / 'backend.tf').write_text('terraform { backend "s3" {} }')
        (root / '.terraform.lock.hcl').write_text('provider "registry.terraform.io/hashicorp/aws" { version = "6.0.0" hashes = ["h1:abc"] }')
        # Both future example-only directories and future partial .tf scaffolds
        # are valid inventory, but neither is an activation signal.
        future = self.repo / 'terraform/environments/dev/eks'
        future.mkdir()
        (future / 'versions.tf').write_text('terraform { required_version = ">= 1.0" }')
        (future / 'main.tf.example').write_text('module "eks" {}')
        future = self.repo / 'terraform/environments/prod/network/vpc'
        future.mkdir(parents=True)
        (future / 'main.tf.example').write_text('module "vpc" {}')
        self.git('init', '-q', '-b', 'main')
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Test Fixture', '-c', 'user.email=fixture@example.invalid', *args], cwd=self.repo, text=True).strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'Local fixture')
        sha = self.git('rev-parse', 'HEAD')
        self.git('update-ref', 'refs/remotes/origin/main', sha)
        return sha

    def write_activation(self, document):
        (self.repo / 'ci/course-activation.json').write_text(json.dumps(document))

    def run_select(self, *, preview=False, baseline=None, requested=''):
        sha = self.git('rev-parse', 'HEAD')
        output = self.repo / 'test-output'
        summary = self.repo / 'test-summary'
        environment = {'GITHUB_WORKSPACE': str(self.repo), 'GITHUB_SHA': sha, 'GITHUB_REF': 'refs/pull/1/merge' if preview else 'refs/heads/main', 'GITHUB_REPOSITORY': 'fixture/local', 'GITHUB_RUN_ID': '123', 'GITHUB_OUTPUT': str(output), 'GITHUB_STEP_SUMMARY': str(summary), 'INPUT_ROOT': requested, 'BASE_SHA': self.base}
        cwd = Path.cwd()
        try:
            with patch.dict(os.environ, environment), patch.object(select, 'last_successful_push', return_value=baseline), patch('sys.argv', ['deploy-select.py', 'preview'] if preview else ['deploy-select.py']):
                select.main()
        finally:
            os.chdir(cwd)
        return json.loads(next(line.removeprefix('matrix=') for line in output.read_text().splitlines() if line.startswith('matrix=')))

    def test_first_deploy_ignores_all_future_partial_directories(self):
        self.assertEqual([row['path'] for row in self.run_select()], [self.vpc])

    def test_pr_ci_only_change_selects_active_ready_roots(self):
        (self.repo / 'ci/test-change.txt').write_text('Shared CI edit')
        self.commit()
        self.assertEqual([row['path'] for row in self.run_select(preview=True)], [self.vpc])

    def test_pr_activation_removal_is_rejected_against_base(self):
        self.write_activation(select.activation.empty_activation())
        self.commit()
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.run_select(preview=True)

    def test_main_deactivation_rejected_even_without_successful_baseline(self):
        self.write_activation(select.activation.empty_activation())
        self.commit()
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.run_select()

    def test_first_deployment_cannot_hide_deactivation_behind_another_commit(self):
        self.write_activation(select.activation.empty_activation())
        self.commit()
        (self.repo / 'ci/second-change.txt').write_text('second subsequent commit')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.run_select()

    def test_manual_retry_checks_successful_baseline_for_deactivation(self):
        self.write_activation(select.activation.empty_activation())
        self.commit()
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.run_select(baseline=self.base, requested=self.vpc)

    def test_main_successful_baseline_catches_older_activation_retirement(self):
        self.write_activation(select.activation.empty_activation())
        self.commit()
        (self.repo / 'ci/second-change.txt').write_text('second subsequent commit')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.run_select(baseline=self.base)

    def test_requested_future_root_is_rejected_without_job_output(self):
        with self.assertRaisesRegex(ValueError, 'not explicitly activated'):
            self.run_select(requested='terraform/environments/dev/eks')
        self.assertFalse((self.repo / 'test-output').exists())

    def test_missing_activation_has_explicit_install_guidance(self):
        (self.repo / 'ci/course-activation.json').unlink()
        self.commit()
        with self.assertRaisesRegex(ValueError, 'explicit --prepared-chapter'):
            self.run_select(preview=True)

    def test_active_readiness_failure_prevents_all_job_outputs(self):
        (self.repo / self.vpc / '.terraform.lock.hcl').unlink()
        self.commit()
        with self.assertRaisesRegex(ValueError, 'provider lock'):
            self.run_select(preview=True)
        self.assertFalse((self.repo / 'test-output').exists())

    def test_removed_active_root_is_not_silent_docs_only_success(self):
        shutil.rmtree(self.repo / self.vpc)
        (self.repo / 'README.md').write_text('Docs also changed')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'missing or redirected'):
            self.run_select(baseline=self.base)

    def test_unregistered_source_is_rejected_before_jobs(self):
        root = self.repo / 'terraform/environments/dev/not-registered'
        root.mkdir()
        (root / 'main.tf').write_text('module "unexpected" {}')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'outside registered'):
            self.run_select(preview=True)


if __name__ == '__main__':
    unittest.main()
