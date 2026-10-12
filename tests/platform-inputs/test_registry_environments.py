import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('registry', ROOT / 'automation/platform_input_registry.py')
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)


class EnvironmentRegistrationTests(unittest.TestCase):
    def entry(self):
        return {'root': 'gateway', 'field': 'dashboard_hostname', 'targets': [
            {'file': 'existing-namespace', 'pointer': '/hostname'},
            {'file': 'later-dashboard-route', 'pointer': '/hostname', 'environments': ['dev']}]}

    def test_prod_early_stage_does_not_consume_future_route_but_dev_keeps_it(self):
        source = [self.entry()]
        self.assertEqual(2, len(registry.active_entries(source, 'gateway', 'dev')[0]['targets']))
        self.assertEqual(['existing-namespace'], [x['file'] for x in registry.active_entries(source, 'gateway', 'prod')[0]['targets']])
        self.assertEqual(['dev'], source[0]['targets'][1]['environments'])

    def test_whole_field_can_remain_dev_only_until_prod_consumer_is_authored(self):
        entry = self.entry(); entry['environments'] = ['dev']
        self.assertEqual([], registry.active_entries([entry], 'gateway', 'prod'))
        self.assertEqual(1, len(registry.active_entries([entry], 'gateway', 'dev')))

    def test_completed_registry_default_keeps_both_environments(self):
        entry = self.entry(); del entry['targets'][1]['environments']
        for environment in ('dev', 'prod'):
            self.assertEqual(2, len(registry.active_entries([entry], 'gateway', environment)[0]['targets']))

    def test_invalid_scope_in_any_root_stops_selection(self):
        for invalid in ([], ['production'], ['dev', 'dev'], 'dev', None):
            with self.subTest(invalid=invalid):
                entry = self.entry(); entry['root'] = 'other'; entry['environments'] = invalid
                with self.assertRaises(ValueError):registry.active_entries([entry], 'gateway', 'prod')
                entry = self.entry(); entry['targets'][1]['environments'] = invalid
                with self.assertRaises(ValueError):registry.active_entries([entry], 'gateway', 'prod')


if __name__ == '__main__':
    unittest.main()
