import copy
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('course_activation_tested', HERE / 'course_activation.py')
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.registry = json.loads((HERE / 'roots.json').read_text())
        self.graph = json.loads((HERE / 'deploy-roots.json').read_text())['dependencies']
        self.catalogs = activation.read_catalogs(HERE.parent)
        self.vpc = 'terraform/environments/dev/network/vpc'
        self.storage = 'terraform/environments/dev/network/log-storage'
        self.eks = 'terraform/environments/dev/eks'
        self.doc = self.initial('BU02')

    def initial(self, chapter, **kwargs):
        return activation.initial_activation(chapter, self.catalogs, self.registry, self.graph, **kwargs)

    def validate(self, document, **kwargs):
        return activation.validate_activation(document, self.registry, self.graph, self.catalogs, **kwargs)

    def test_bu02_is_only_vpc_and_prod_is_not_inferred(self):
        self.assertEqual(self.validate(self.doc), {self.vpc})
        self.assertEqual(self.doc['environments']['prod'], {'prepared_chapter': None, 'roots': []})
        active, graph = activation.deployment_graph(self.doc, self.registry, self.graph, self.catalogs)
        self.assertEqual(graph[self.vpc], [])
        self.assertEqual(active, {self.vpc})

    def test_bu03_explicitly_adds_retained_log_storage(self):
        self.assertEqual(self.validate(self.initial('BU03')), {self.vpc, self.storage})
        bad = copy.deepcopy(self.doc)
        bad['environments']['dev']['prepared_chapter'] = 'BU03'
        with self.assertRaisesRegex(ValueError, 'inactive dependency'):
            self.validate(bad)

    def test_future_root_cannot_hide_beneath_earlier_chapter(self):
        self.doc['environments']['dev']['roots'].append(self.eks)
        with self.assertRaisesRegex(ValueError, 'Future chapter'):
            self.validate(self.doc)

    def test_no_implicit_missing_dependency_activation(self):
        with self.assertRaisesRegex(ValueError, 'inactive dependency'):
            activation.merge_activation(self.doc, 'BU06', [self.eks], self.catalogs, self.registry, self.graph)
        self.assertEqual(self.doc['environments']['dev']['roots'], [self.vpc])

    def test_append_known_selected_roots_preserves_previous(self):
        result = activation.merge_activation(self.doc, 'BU03', [self.storage, self.vpc], self.catalogs, self.registry, self.graph)
        self.assertEqual(self.validate(result, previous=self.doc), {self.vpc, self.storage})
        self.assertEqual(self.doc['environments']['dev']['prepared_chapter'], 'BU02')

    def test_upgrade_preserves_activation_without_source_selection(self):
        result = activation.merge_activation(self.doc, 'BU16', [], self.catalogs, self.registry, self.graph)
        self.assertEqual(result, self.doc)
        self.assertIsNot(result, self.doc)

    def test_deactivation_and_chapter_regression_rejected(self):
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.validate(activation.empty_activation(), previous=self.doc)
        old = self.initial('BU03')
        with self.assertRaisesRegex(ValueError, 'deactivation'):
            self.validate(self.doc, previous=old)
        old['environments']['dev']['prepared_chapter'] = 'BU04'
        with self.assertRaisesRegex(ValueError, 'backward'):
            self.validate(self.initial('BU03'), previous=old)

    def test_external_bootstrap_and_unknown_roots_rejected(self):
        for path in ('terraform/environments/dev/bootstrap/state', 'terraform/environments/dev/bootstrap/ci-identity', 'terraform/environments/dev/unknown'):
            bad = copy.deepcopy(self.doc)
            bad['environments']['dev']['roots'].append(path)
            with self.assertRaises(ValueError):
                self.validate(bad)

    def test_cross_environment_dependencies_rejected(self):
        self.graph[self.vpc] = ['terraform/environments/prod/network/log-storage']
        with self.assertRaisesRegex(ValueError, 'cross-environment'):
            self.validate(self.doc)

    def test_lifecycle_executability_does_not_block_normal_activation(self):
        self.catalogs['dev']['chapters']['BU03']['blockers'] = ['lifecycle registration disabled']
        self.catalogs['dev']['roots'][self.storage]['mode'] = 'blocked'
        self.assertIn(self.storage, self.validate(self.initial('BU03')))

    def test_retained_roots_follow_actual_chapter_catalog(self):
        early = self.initial('BU09')
        later = self.initial('BU10A')
        retained = 'terraform/environments/dev/retained/operations'
        self.assertNotIn(retained, self.validate(early))
        self.assertIn(retained, self.validate(later))

    def test_explicit_learner_custom_root_is_preserved_never_inferred(self):
        path = 'terraform/environments/dev/custom-worker'
        self.registry['roots'].append({'env': 'dev', 'path': path})
        self.graph[path] = [self.vpc]
        self.assertNotIn(path, self.validate(self.initial('BU03')))
        result = activation.merge_activation(self.doc, 'BU02', [path], self.catalogs, self.registry, self.graph)
        self.assertEqual(self.validate(result, previous=self.doc), {self.vpc, path})
        self.assertEqual(activation.merge_activation(result, 'BU16', [], self.catalogs, self.registry, self.graph), result)

    def test_schema_unknown_fields_duplicates_and_mismatched_env_rejected(self):
        for update in (
            {'prepared_chapter': 'BU02', 'roots': [self.vpc, self.vpc]},
            {'prepared_chapter': None, 'roots': [self.vpc]},
            {'prepared_chapter': 'BU02', 'roots': ['terraform/environments/prod/network/vpc']},
            {'prepared_chapter': 'BU02', 'roots': [self.vpc], 'auto_activate': True},
        ):
            bad = copy.deepcopy(self.doc)
            bad['environments']['dev'] = update
            with self.assertRaises(ValueError):
                self.validate(bad)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.path = 'terraform/environments/dev/network/vpc'
        self.root = self.workspace / self.path
        self.root.mkdir(parents=True)

    def check(self):
        activation.validate_root_readiness(self.workspace, {self.path})

    def prepare(self):
        (self.root / 'main.tf').write_text('module "network" { source = "../../../../modules/network" }')
        (self.root / 'backend.tf').write_text('terraform { backend "s3" {} }')
        (self.root / '.terraform.lock.hcl').write_text('provider "registry.terraform.io/hashicorp/aws" {\n version = "6.0.0"\n hashes = ["h1:abc"]\n}')

    def test_example_only_future_directory_cannot_be_readied(self):
        (self.root / 'main.tf.example').write_text('resource "aws_vpc" "example" {}')
        with self.assertRaisesRegex(ValueError, 'actual top-level'):
            self.check()

    def test_scaffolding_is_insufficient_even_with_backend_and_lock(self):
        self.prepare()
        (self.root / 'main.tf').write_text('terraform { required_version = ">= 1.0" }')
        with self.assertRaisesRegex(ValueError, 'scaffolding'):
            self.check()

    def test_real_source_backend_and_lock_required(self):
        self.prepare()
        self.check()
        (self.root / '.terraform.lock.hcl').unlink()
        with self.assertRaisesRegex(ValueError, 'provider lock'):
            self.check()

    def test_commented_blocks_cannot_satisfy_readiness(self):
        self.prepare()
        (self.root / 'backend.tf').write_text('# backend "s3" {}\n/* backend "s3" {} */')
        with self.assertRaisesRegex(ValueError, 'actual S3 backend'):
            self.check()
        self.prepare()
        (self.root / 'main.tf').write_text('// module "example" {}')
        with self.assertRaisesRegex(ValueError, 'scaffolding'):
            self.check()

    def test_empty_or_example_lock_is_rejected(self):
        self.prepare()
        for text in ('', '# provider "registry.terraform.io/hashicorp/aws" { version = "6.0.0" hashes = ["h1:abc"] }'):
            (self.root / '.terraform.lock.hcl').write_text(text)
            with self.assertRaisesRegex(ValueError, 'empty or incomplete'):
                self.check()

    def test_missing_root_is_error(self):
        self.root.rmdir()
        with self.assertRaisesRegex(ValueError, 'missing or redirected'):
            self.check()

    def test_inactive_future_partial_roots_are_not_checked(self):
        self.prepare()
        (self.workspace / 'terraform/environments/dev/eks').mkdir()
        self.check()


class ActivationCommandTests(unittest.TestCase):
    def setUp(self):
        ReadinessTests.setUp(self)
        ReadinessTests.prepare(self)
        directory = self.workspace / 'ci'
        directory.mkdir()
        for name in ('roots.json', 'deploy-roots.json', 'lifecycle-targets.json', 'lifecycle-targets-prod.json'):
            (directory / name).write_bytes((HERE / name).read_bytes())
        registry = json.loads((directory / 'roots.json').read_text())
        graph = json.loads((directory / 'deploy-roots.json').read_text())['dependencies']
        document = activation.initial_activation('BU02', activation.read_catalogs(self.workspace), registry, graph)
        self.activation_path = directory / 'course-activation.json'
        self.activation_path.write_text(json.dumps(document))

    def command(self, *extra):
        args = ['course_activation.py', '--repo', str(self.workspace), '--prepare', 'BU02', '--environment', 'dev', '--roots', self.path, *extra]
        with patch('sys.argv', args), contextlib.redirect_stdout(io.StringIO()):
            activation.main()

    def test_command_preview_does_not_write(self):
        before = self.activation_path.read_bytes()
        self.command()
        self.assertEqual(self.activation_path.read_bytes(), before)

    def test_command_writes_only_explicit_activation(self):
        before = json.loads(self.activation_path.read_text())
        self.command('--write')
        self.assertEqual(json.loads(self.activation_path.read_text()), before)

    def test_command_requires_actual_authored_source_before_write(self):
        before = self.activation_path.read_bytes()
        (self.root / 'main.tf').unlink()
        with self.assertRaisesRegex(ValueError, 'scaffolding'):
            self.command('--write')
        self.assertEqual(self.activation_path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
