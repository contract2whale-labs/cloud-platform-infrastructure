import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock
import unittest
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('deploy_select', HERE / 'deploy-select.py')
select = importlib.util.module_from_spec(spec)
spec.loader.exec_module(select)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.vpc='terraform/environments/dev/network/vpc'
        self.eks='terraform/environments/dev/eks'
        self.ops='terraform/environments/dev/platform/operations'
        self.prod='terraform/environments/prod/network/vpc'
        self.registry={'roots':[{'path':p,'env':p.split('/')[2]} for p in (self.vpc,self.eks,self.ops,self.prod)]}
        self.graph={self.vpc:[],self.eks:[self.vpc],self.ops:[self.eks],self.prod:[]}
        self.existing=set(self.graph)

    def run_selection(self, changes, **kwargs):
        return select.waves(self.registry, kwargs.get('graph',self.graph), kwargs.get('existing',self.existing), changes, kwargs.get('requested'), active=kwargs.get('active',self.existing))

    def test_upstream_change_selects_consumers_in_order(self):
        result=self.run_selection([self.vpc+'/main.tf'])
        self.assertEqual([[r['path'] for r in w] for w in result],[[self.vpc],[self.eks],[self.ops]])

    def test_common_module_selects_dev_and_prod(self):
        result=self.run_selection(['modules/eks/main.tf'])
        self.assertEqual(set(r['path'] for r in result[0]),{self.vpc,self.prod})
        self.assertEqual(result[2][0]['path'],self.ops)

    def test_legacy_module_and_ci_change(self):
        for path in ['terraform/modules/eks/main.tf','ci/deploy-roots.json','.github/workflows/terraform-apply.yml']:
            self.assertEqual(sum(map(len,self.run_selection([path]))),4)

    def test_docs_only_and_prefix_collision(self):
        self.assertEqual(self.run_selection(['README.md','modules-extra/file']),[])

    def test_missing_dependency_is_not_silent(self):
        with self.assertRaises(ValueError): self.run_selection([self.eks+'/main.tf'],existing={self.eks,self.ops,self.prod})

    def test_cycles_and_unknown_dependencies(self):
        for graph in [dict(self.graph,**{self.vpc:[self.ops]}),dict(self.graph,**{self.eks:['missing']})]:
            with self.assertRaises(ValueError): self.run_selection(['README.md'],graph=graph)

    def test_root_removal_is_not_destroy(self):
        with self.assertRaises(ValueError): self.run_selection([self.ops+'/main.tf'],existing=self.existing-{self.ops})

    def test_manual_retry_also_selects_consumers(self):
        self.assertEqual(len(self.run_selection([],requested=self.vpc)),3)

    def test_superseded_push_and_revert_paths_are_all_selected(self):
        git=Mock(return_value=self.vpc+'/main.tf\n'+self.eks+'/main.tf\n'+self.vpc+'/main.tf')
        touched=select.changed_since_success(git,'a'*40,'b'*40)
        self.assertEqual(touched,sorted([self.vpc+'/main.tf',self.eks+'/main.tf']))
        self.assertEqual(len(self.run_selection(touched)),3)
        self.assertIn('log',git.call_args.args)
        self.assertIn('a'*40+'..'+'b'*40,git.call_args.args)

    def test_first_push_reconciles_explicit_active_roots(self):
        touched=select.changed_since_success(Mock(),None,'b'*40)
        self.assertEqual(sum(map(len,self.run_selection(touched))),4)

    def test_registry_removal_and_unregistered_sources_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace=Path(directory)
            with self.assertRaises(ValueError):
                select.validate_root_inventory(workspace,{'roots':[]},self.registry)
            file=workspace/'terraform/environments/dev/unregistered/main.tf'
            file.parent.mkdir(parents=True); file.write_text('resource "example" "x" {}')
            with self.assertRaises(ValueError): select.validate_root_inventory(workspace,self.registry)

    def test_packaged_full_graph(self):
        registry=json.loads((HERE/'roots.json').read_text())
        graph=json.loads((HERE/'deploy-roots.json').read_text())['dependencies']
        catalogs=select.activation.read_catalogs(HERE.parent)
        document=select.activation.initial_activation('BU16',catalogs,registry,graph,environments=('dev','prod'))
        active,effective=select.activation.deployment_graph(document,registry,graph,catalogs)
        result=select.waves(registry,effective,set(graph),['modules/eks/main.tf'],active=active)
        self.assertLessEqual(len(result),select.MAX_WAVES)
        prior=set()
        for wave in result:
            for root in wave:
                self.assertTrue(set(effective[root['path']]) <= prior)
            prior.update(r['path'] for r in wave)
        self.assertEqual(prior,active)


    def test_first_baseline_does_not_activate_future_partial_directories(self):
        touched=select.changed_since_success(Mock(),None,'b'*40)
        result=self.run_selection(touched,active={self.vpc})
        self.assertEqual([[r['path'] for r in wave] for wave in result],[[self.vpc]])

    def test_ci_change_reconciles_active_roots_only(self):
        result=self.run_selection(['ci/lifecycle-targets.json'],active={self.vpc,self.eks})
        self.assertEqual([[r['path'] for r in wave] for wave in result],[[self.vpc],[self.eks]])

    def test_future_changed_source_is_not_implicit_activation(self):
        self.assertEqual(self.run_selection([self.eks+'/main.tf'],active={self.vpc}),[])

    def test_requested_future_root_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'not explicitly activated'):
            self.run_selection([],requested=self.eks,active={self.vpc})

    def test_missing_activation_never_falls_back_to_directories(self):
        with self.assertRaisesRegex(ValueError,'Explicit course activation'):
            select.waves(self.registry,self.graph,self.existing,['ci/example.json'])

    def test_removed_active_root_blocks_docs_and_manual_retry(self):
        for requested in (None,self.vpc):
            with self.assertRaisesRegex(ValueError,'Root removal'):
                self.run_selection(['README.md'],existing=self.existing-{self.ops},requested=requested)

    def test_dependency_closure_does_not_implicitly_activate_root(self):
        with self.assertRaisesRegex(ValueError,'inactive dependency'):
            self.run_selection(['ci/test.py'],active={self.eks})


if __name__=='__main__': unittest.main()
