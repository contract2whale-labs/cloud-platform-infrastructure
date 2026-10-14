import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('recovery', Path(__file__).with_name('vpc-lifecycle-recover.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.target = dict(repository_id='17', account='123456789012', bucket='private-state', region='ap-northeast-2')
        self.state = dict(exists=True, version='state-v1', etag='state-etag', size=100)
        self.info = dict(exists=True, version='marker-v1', etag='marker-etag', size=300)
        self.record = dict(schema=1, root=r.c.ROOT, phase='paused', **self.target,
                           generation='1-1', snapshot_sha='a'*40, inputs={'secret': 'do-not-print'},
                           last_result='not-applied', original_state_fingerprint=self.state)
        self.store = Mock(); self.store.state.return_value = self.state
        self.read = patch.object(r.c, 'read_json', return_value=(self.record, self.info)).start()
        self.write = patch.object(r.c, 'update').start()
        self.quiet = patch.object(r, 'github_quiet').start()
        self.addCleanup(patch.stopall)

    def run_recovery(self, **changes):
        args = dict(store=self.store, target=self.target, repo='owner/repo', generation='1-1',
                    stage='resume', confirmation='1-1', actor='admin-actor')
        args.update(changes)
        return r.recover(**args)

    def test_inspect_never_writes_or_exposes_inputs(self):
        result = self.run_recovery(stage='inspect', confirmation=None)
        self.assertEqual(result['phase'], 'paused'); self.write.assert_not_called()
        self.assertNotIn('secret', json.dumps(result))

    def test_resume_retains_snapshot_and_records_actor(self):
        self.assertEqual(self.run_recovery()['phase'], 'active')
        args = self.write.call_args.args
        self.assertEqual(args[1], 'ci-lifecycle/17/dev/network-vpc.json')
        self.assertEqual(args[2]['inputs'], self.record['inputs'])
        self.assertEqual(args[2]['admin_recovery_actor'], 'admin-actor')
        self.assertIn('admin_recovery_at', args[2]); self.assertEqual(args[3], self.info)

    def test_started_apply_and_down_complete_rejected(self):
        for status in ('down_applying', 'up_applying', 'down_complete', None):
            with self.subTest(status=status):
                self.record['last_result'] = status
                with self.assertRaises(Exception): self.run_recovery()
        self.write.assert_not_called()

    def test_wrong_generation_and_missing_confirmation_rejected(self):
        for values in ({'generation': '2-1'}, {'confirmation': None}, {'confirmation': '2-1'}):
            with self.assertRaises(Exception): self.run_recovery(**values)
        self.write.assert_not_called()

    def test_missing_or_changed_state_rejected(self):
        self.store.state.return_value = {**self.state, 'version': 'state-v2'}
        with self.assertRaises(Exception): self.run_recovery()
        self.record.pop('original_state_fingerprint')
        with self.assertRaises(Exception): self.run_recovery()
        self.write.assert_not_called()

    def test_state_change_before_cas_rejected(self):
        self.store.state.side_effect = [self.state, {**self.state, 'version': 'state-v2'}]
        with self.assertRaises(Exception): self.run_recovery()
        self.write.assert_not_called()

    def test_marker_change_before_cas_rejected(self):
        changed = dict(self.record, last_result='down_applying')
        self.read.side_effect = [(self.record, self.info), (changed, {**self.info, 'version': 'marker-v2'})]
        with self.assertRaises(Exception): self.run_recovery()
        self.write.assert_not_called()

    def test_stale_cas_fails_without_success_or_retry(self):
        self.write.side_effect = RuntimeError('412')
        with self.assertRaises(RuntimeError): self.run_recovery()
        self.assertEqual(self.write.call_count, 1)
        self.assertEqual(self.record['phase'], 'paused')

    def test_active_workflows_block_before_write(self):
        self.quiet.side_effect = RuntimeError('workflow active')
        with self.assertRaises(RuntimeError): self.run_recovery()
        self.write.assert_not_called()

    def test_admin_session_requires_explicit_sso_role_and_rejects_ci(self):
        from types import SimpleNamespace
        args = SimpleNamespace(profile='securityadmin', account=self.target['account'],
                               region=self.target['region'], sso_role_name='ApprovedSecurityAdmin')
        arn = 'arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ApprovedSecurityAdmin_0123456789abcdef/person'
        with patch.dict(r.os.environ, {}, clear=True), patch.object(r.h, 'execute', side_effect=[b'123456789012', b'ApprovedSecurityAdmin']), patch.object(r.h, 'aws', return_value={'Account': args.account, 'Arn': arn}):
            self.assertEqual(r.admin_session(args), arn)
        with patch.dict(r.os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True):
            with self.assertRaises(Exception): r.admin_session(args)
        with patch.dict(r.os.environ, {}, clear=True), patch.object(r.h, 'execute', side_effect=[b'123456789012', b'ApprovedSecurityAdmin']), patch.object(r.h, 'aws', return_value={'Account': args.account, 'Arn': 'arn:aws:sts::123456789012:assumed-role/ci-apply/run'}):
            with self.assertRaises(Exception): r.admin_session(args)

class GithubQuietTests(unittest.TestCase):
    def setUp(self):
        self.legacy = dict(id=44, path=r.LEGACY_PATH, state='disabled_manually')
        self.pages = [{'total_count': 0, 'workflows': []}]
        self.runs = []
        self.run_status = None
        self.current_runs = []
        self.states = {name: 'disabled_manually' for name in r.WORKFLOWS}
        self.error = None

    def response(self, command):
        endpoint = command[-1]
        if endpoint == 'repos/owner/repo':
            result = {'id': 17, 'permissions': {'admin': True}}
        elif endpoint.endswith('/actions/workflows?per_page=100'):
            if self.error: raise self.error
            self.assertIn('--paginate', command); self.assertIn('--slurp', command)
            result = self.pages
        elif '/actions/runs?' in endpoint:
            self.assertIn('--paginate', command)
            runs = self.runs if self.run_status is None or endpoint.endswith('status=' + self.run_status) else []
            result = [{'total_count': len(runs), 'workflow_runs': runs}]
        elif '/runs?' in endpoint:
            result = {'total_count': len(self.current_runs), 'workflow_runs': self.current_runs}
        else:
            result = {'state': self.states[endpoint.rsplit('/', 1)[1]]}
        return json.dumps(result).encode()

    def check(self):
        with patch.object(r.h, 'execute', side_effect=self.response) as execute:
            r.github_quiet('owner/repo', '17')
        return execute

    def test_current_names_and_verified_legacy_absence(self):
        self.assertEqual(r.WORKFLOWS, ('terraform-apply.yml', 'terraform-lifecycle.yml'))
        self.assertEqual(self.check().call_count, 19)

    def test_current_workflows_must_be_manually_disabled(self):
        for name in r.WORKFLOWS:
            for state in ('active', 'disabled_inactivity', 'deleted'):
                with self.subTest(name=name, state=state):
                    self.states = {workflow: 'disabled_manually' for workflow in r.WORKFLOWS}
                    self.states[name] = state
                    with self.assertRaises(Exception): self.check()

    def test_paginated_legacy_disabled_or_deleted_is_allowed(self):
        for state in ('disabled_manually', 'deleted'):
            self.pages = [{'total_count': 2, 'workflows': [{'id': 3, 'path': 'unrelated'}]},
                          {'total_count': 2, 'workflows': [dict(self.legacy, state=state)]}]
            self.check()

    def test_enabled_legacy_on_later_page_is_rejected(self):
        self.pages = [{'total_count': 2, 'workflows': [{'id': 3, 'path': 'unrelated'}]},
                      {'total_count': 2, 'workflows': [dict(self.legacy, state='active')]}]
        with self.assertRaises(Exception): self.check()

    def test_legacy_active_run_rejected_by_id_or_deleted_path(self):
        self.pages = [{'total_count': 1, 'workflows': [self.legacy]}]
        self.runs = [{'workflow_id': 44, 'path': '.github/workflows/renamed.yml'}]
        with self.assertRaises(Exception): self.check()
        self.pages = [{'total_count': 0, 'workflows': []}]
        for status in r.ACTIVE:
            for suffix in ('', '@main'):
                self.run_status = status
                self.runs = [{'workflow_id': 44, 'path': r.LEGACY_PATH + suffix}]
                with self.assertRaises(Exception): self.check()

    def test_listing_denial_and_incomplete_listing_are_fatal(self):
        self.error = RuntimeError('403')
        with self.assertRaises(RuntimeError): self.check()
        self.error = None
        self.pages = [{'total_count': 1, 'workflows': []}]
        with self.assertRaises(Exception): self.check()

    def test_missing_or_invalid_workflow_identity_is_rejected(self):
        for row in ({'id': 44}, {'path': r.LEGACY_PATH}, {'id': '44', 'path': r.LEGACY_PATH},
                    {'id': True, 'path': r.LEGACY_PATH}, {'id': 44, 'path': ''}):
            with self.subTest(row=row):
                self.pages = [{'total_count': 1, 'workflows': [row]}]
                with self.assertRaises(Exception): self.check()

    def test_duplicate_workflow_ids_across_pages_are_rejected(self):
        row = {'id': 3, 'path': '.github/workflows/unrelated.yml'}
        self.pages = [{'total_count': 2, 'workflows': [row]},
                      {'total_count': 2, 'workflows': [dict(row)]}]
        with self.assertRaises(Exception): self.check()

    def test_current_active_runs_still_block(self):
        self.current_runs = [{'id': 88}]
        with self.assertRaises(Exception): self.check()

    def test_incomplete_active_run_identity_is_rejected(self):
        self.runs = [{'workflow_id': 99}]
        with self.assertRaises(Exception): self.check()

    def test_unrelated_active_run_is_not_a_legacy_run(self):
        self.runs = [{'workflow_id': 99, 'path': '.github/workflows/unrelated.yml'}]
        self.check()


if __name__ == '__main__':
    unittest.main()
