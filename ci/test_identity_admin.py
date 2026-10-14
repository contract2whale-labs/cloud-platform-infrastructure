import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ENGINE = HERE/'saved-plan.py' if (HERE/'saved-plan.py').exists() else BASE.parent/'ci/saved-plan.py'
IDENTITY_TF = HERE/'fixtures/identity-admin.tf' if (HERE/'fixtures/identity-admin.tf').exists() else BASE/'terraform/identity-admin.tf'


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        (self.workspace / 'ci').mkdir()
        for source in (ENGINE, HERE / 'identity-admin.py'):
            shutil.copy(source, self.workspace / 'ci' / source.name)
        spec = importlib.util.spec_from_file_location('identity_under_test', self.workspace / 'ci/identity-admin.py')
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.root = 'terraform/environments/dev/bootstrap/ci-identity'
        (self.workspace / self.root).mkdir(parents=True)
        self.env = {
            'GITHUB_WORKSPACE': str(self.workspace), 'ROOT_PATH': self.root,
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'EXPECTED_ACCOUNT_ID': '123456789012',
            'AWS_ROLE_ARN': 'arn:aws:iam::123456789012:role/gha-identity-dev-plan',
            'EXPECTED_APPLY_ROLE_ARN': 'arn:aws:iam::123456789012:role/gha-identity-dev-apply',
        }

    def test_plan_guard(self):
        with patch.dict(os.environ, self.env, clear=True):
            self.m.guard('plan')

    def test_apply_guard(self):
        self.env['AWS_ROLE_ARN'] = self.env['EXPECTED_APPLY_ROLE_ARN']
        with patch.dict(os.environ, self.env, clear=True):
            self.m.guard('apply')

    def test_reject_wrong_event_branch_role_root(self):
        for name, value in [('GITHUB_REF', 'refs/heads/feature'),
                            ('GITHUB_REF', 'refs/tags/main'),
                            ('GITHUB_EVENT_NAME', 'pull_request'),
                            ('ROOT_PATH', 'terraform/environments/dev/network/vpc'),
                            ('AWS_ROLE_ARN', 'arn:aws:iam::123456789012:role/gha-infra-dev-apply'),
                            ('EXPECTED_APPLY_ROLE_ARN', 'arn:aws:iam::123456789012:role/gha-identity-prod-apply')]:
            with self.subTest(name=name, value=value), patch.dict(os.environ, {**self.env, name: value}, clear=True):
                with self.assertRaises(self.m.h.SafeError):
                    self.m.guard('plan')

    def test_reject_preview_and_missing_root(self):
        with patch.dict(os.environ, self.env, clear=True):
            with self.assertRaises(self.m.h.SafeError):
                self.m.guard('preview')
        with self.assertRaises(self.m.h.SafeError):
            self.m.select_root(self.workspace, 'terraform/environments/prod/bootstrap/ci-identity')

    def test_identity_adapter_does_not_add_normal_registry(self):
        self.m.configure()
        self.assertEqual(self.m.h.select_root(self.workspace, self.root), ('dev', 'bootstrap/ci-identity/terraform.tfstate'))
        self.assertEqual(self.m.h.upstream_states(None, None, None), {})
        self.assertFalse((self.workspace / 'ci/roots.json').exists())

    def test_missing_identity_state_fails_closed(self):
        with patch.dict(os.environ, {**self.env, 'STATE_BUCKET': 'private-bucket'}, clear=True), \
             patch.object(self.m.h, 'check_identity'), patch.object(self.m.h, 'Store') as store:
            store.return_value.state.return_value = {'exists': False}
            with self.assertRaises(self.m.h.SafeError):
                self.m.check_existing_state()
            store.return_value.state.return_value = {'exists': True}
            self.m.check_existing_state()

    def test_summary_private_exact_version_and_correct_approval(self):
        summary = self.workspace / 'summary'
        item = {'key': 'ci-plans/run/review.txt', 'version': 'v123', 'sha256': 'a' * 64}
        with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}):
            self.m.identity_summary({'root': self.root, 'sha': 'b' * 40, 'environment': 'dev'},
                                    {'plan': item, 'review': item, 'expires_at': 1234}, item)
        text = summary.read_text()
        self.assertIn('--version-id v123', text)
        self.assertIn('identity-dev-apply', text)
        self.assertNotIn('자동 적용', text)
        self.assertNotIn('apply job은 없습니다', text)

    def test_workflow_contract(self):
        w = yaml.safe_load((BASE / '.github/workflows/identity-admin.yml').read_text())
        self.assertEqual(set(w['on']), {'workflow_dispatch'})
        self.assertEqual(w['on']['workflow_dispatch']['inputs']['environment']['options'], ['dev', 'prod'])
        plan, apply = w['jobs']['tf-saved-plan'], w['jobs']['tf-apply']
        self.assertEqual(apply['needs'], 'tf-saved-plan')
        self.assertFalse(w['concurrency']['cancel-in-progress'])
        for mode, job in [('plan', plan), ('apply', apply)]:
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
            self.assertEqual(job['environment'], 'identity-${{ inputs.environment }}-' + mode)
            self.assertIn('guard', job['steps'][1]['run'])
            self.assertEqual(job['steps'][-1]['run'], 'python3 ci/identity-admin.py ' + mode)
            self.assertEqual(job['permissions']['id-token'], 'write')
            self.assertFalse(job['steps'][0]['with']['persist-credentials'])
            self.assertTrue(all(len(step['uses'].split('@')[-1]) == 40 for step in job['steps'] if 'uses' in step))
        for name, output in [('MANIFEST_KEY', 'manifest_key'), ('MANIFEST_VERSION', 'manifest_version'),
                             ('EXPECTED_MANIFEST_SHA', 'manifest_sha'), ('EXPECTED_PLAN_SHA', 'plan_sha')]:
            self.assertEqual(apply['env'][name], '${{ needs.tf-saved-plan.outputs.' + output + ' }}')
        text = (BASE / '.github/workflows/identity-admin.yml').read_text()
        self.assertNotIn('upload-artifact', text)
        self.assertNotIn('aws-secret-access-key', text)

    def test_reused_engine_applies_binary_without_replanning(self):
        source = ENGINE.read_text()
        self.assertIn('store.get(manifest["plan"], plan_path)', source)
        self.assertIn('str(plan_path)], cwd=root, log=temp / "apply.log")', source)
        self.assertIn('validate_manifest(manifest, context', source)
        self.assertIn('ensure_current_main(context)', source)
        self.assertIn('"State changed during plan; create a new run."', source)
        # Adapter must not replace the engine's integrity or apply functions.
        adapter = (HERE / 'identity-admin.py').read_text()
        for protected in ('validate_manifest', 'ensure_current_main', 'execute', 'prepare', 'initialize', 'Store'):
            self.assertNotIn('h.' + protected + ' =', adapter)

    def test_normal_roles_explicitly_isolated(self):
        source = IDENTITY_TF.read_text()
        for value in ('DenyIdentityAndAttachedPolicyMutation', 'DenyIdentityRoleChaining', 'DenyIdentityStorageMutation',
                      '"iam:Create*"', '"iam:Set*"', '"iam:PassRole"', '"sts:AssumeRole"',
                      'local.identity_plan_objects', 'var.apply_additional_policy_arns'):
            self.assertIn(value, source)
        # Chaining denial must target only the administrative identities, never
        # wildcard all STS destinations (the course uses cross-account DNS).
        chaining = source.split('Sid      = "DenyIdentityRoleChaining"', 1)[1].split('},', 1)[0]
        self.assertIn('Resource = concat([for role in aws_iam_role.identity : role.arn], local.operational_role_arns)', chaining)
        self.assertNotIn('Resource = ["*"]', chaining)
        self.assertNotIn('aws_iam_role.ci', chaining)
        for prefix in ('gha-infra-${var.environment}-vpc-',
                       'gha-infra-${var.environment}-course-lifecycle-',
                       'course-${var.environment}-ci-bu0912-', 'cp-${var.environment}-ci-'):
            self.assertIn(prefix, source)
        self.assertNotIn('variable "github_repository_id"', source)
        self.assertNotIn('AdministratorAccess', source)
        self.assertIn('for_each   = local.roles', source)
        self.assertIn('resource "aws_iam_policy" "normal_identity_isolation"', source)
        self.assertIn('policy_arn = aws_iam_policy.normal_identity_isolation.arn', source)

    def test_identity_private_diagnostics_are_phase_isolated(self):
        source = IDENTITY_TF.read_text()
        self.assertIn('Resource = local.identity_log_write_objects[each.key]', source)
        self.assertIn('"${local.identity_log_prefix}/plan/*.log"', source)
        self.assertIn('"${local.identity_log_prefix}/apply/completion.json"', source)
        self.assertIn('"PreventOtherPhaseWrites"', source)
        self.assertIn('each.key == "plan" ? ["${local.identity_log_prefix}/apply/*"]', source)
        self.assertIn('"NeverDeletePrivatePlanVersions"', source)

    def test_validation_workflow_without_cloud_credentials(self):
        w = yaml.safe_load((BASE / '.github/workflows/identity-validate.yml').read_text())
        self.assertEqual(set(w['on']), {'pull_request'})
        self.assertEqual(w['permissions'], {'contents': 'read'})
        job = w['jobs']['validate']
        self.assertEqual(job['strategy']['matrix']['environment'], ['dev', 'prod'])
        commands = job['steps'][-1]['run']
        self.assertIn('fmt -check -diff', commands)
        self.assertIn('init -backend=false -input=false -lockfile=readonly', commands)
        self.assertIn('validate', commands)
        self.assertNotIn('configure-aws-credentials', str(w))


    def test_fixed_operational_plan_allowlist(self):
        context = {'environment': 'dev', 'account': '123456789012'}
        def item(kind, values, actions=None):
            return {'address': kind + '.test', 'mode': 'managed', 'type': kind,
                    'change': {'before': None, 'after': values, 'actions': actions or ['create']}}
        valid = [item('aws_iam_role', {'name': 'cp-dev-gitops-apply', 'path': '/'}),
                 item('aws_iam_policy', {'name': 'cp-dev-ci-gitops', 'path': '/'}),
                 item('aws_iam_role_policy', {'role': 'gha-aws-ops-dev-apply'}),
                 item('aws_iam_role_policy_attachment', {'role': 'cp-dev-incident-plan',
                       'policy_arn': 'arn:aws:iam::123456789012:policy/cp-dev-ci-incident'})]
        self.m.validate_identity_plan({'resource_changes': valid}, context)
        self.assertNotIn('gha-aws-ops-dev-plan', self.m.operational_names('prod'))
        invalid = [item('aws_iam_role', {'name': name}) for name in (
            'other-admin', 'gha-infra-dev-plan', 'gha-course-probe-instructor', 'cp-prod-gitops-apply',
            'gha-infra-dev-lifecycle-destroy-extra', 'gha-infra-prod-lifecycle-destroy')]
        invalid += [item('aws_iam_role', {'name': 'cp-dev-gitops-apply', 'path': '/admin/'}),
                    item('aws_iam_role', {'name': 'cp-dev-gitops-apply'}, ['delete', 'create']),
                    item('aws_iam_policy', {'name': 'other-policy'}),
                    item('aws_iam_openid_connect_provider', {'url': 'https://attacker.invalid'}),
                    item('aws_s3_bucket', {'bucket': 'unexpected'}),
                    item('aws_iam_role_policy', {'role': 'other-admin'}),
                    item('aws_iam_role_policy_attachment', {'role': 'cp-dev-gitops-apply',
                         'policy_arn': 'arn:aws:iam::aws:policy/AdministratorAccess'}),
                    item('aws_iam_role_policy_attachment', {'role': 'cp-dev-gitops-apply', 'policy_arn': None})]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(self.m.h.SafeError):
                self.m.validate_identity_plan({'resource_changes': [change]}, context)

    def test_new_resource_references_resolve_without_wildcard_targets(self):
        context = {'environment': 'dev', 'account': '123456789012'}
        changes = [
            {'address': 'aws_iam_role.aws_ops["apply"]', 'type': 'aws_iam_role', 'change': {
                'actions': ['create'], 'after': {'name': 'gha-aws-ops-dev-apply'}}},
            {'address': 'aws_iam_policy.ops', 'type': 'aws_iam_policy', 'change': {
                'actions': ['create'], 'after': {'name': 'cp-dev-ci-ops'}}},
            {'address': 'aws_iam_role_policy_attachment.ops', 'type': 'aws_iam_role_policy_attachment', 'change': {
                'actions': ['create'], 'after': {'role': None, 'policy_arn': None}}},
            {'address': 'aws_iam_role_policy.inline["apply"]', 'type': 'aws_iam_role_policy', 'change': {
                'actions': ['create'], 'after': {'role': None}}},
        ]
        config = {'root_module': {'resources': [
            {'address': 'aws_iam_role_policy_attachment.ops', 'expressions': {
                'role': {'references': ['aws_iam_role.aws_ops["apply"].id', 'aws_iam_role.aws_ops']},
                'policy_arn': {'references': ['aws_iam_policy.ops.arn', 'aws_iam_policy.ops']}}},
            {'address': 'aws_iam_role_policy.inline', 'expressions': {'role': {'references': ['each.value.id', 'each.value']}},
             'for_each_expression': {'references': ['aws_iam_role.aws_ops']}}
        ]}}
        plan = {'resource_changes': changes, 'configuration': config}
        self.m.validate_identity_plan(plan, context)
        config['root_module']['resources'][0]['expressions']['role']['references'] = ['aws_iam_role.other.id']
        with self.assertRaises(self.m.h.SafeError):
            self.m.validate_identity_plan(plan, context)

    def test_allowlist_hook_preserves_input_validation(self):
        self.m.configure()
        with patch.object(self.m, '_original_input_validation') as original, patch.object(self.m, 'validate_identity_plan') as scope:
            context = {'environment': 'dev', 'account': '123456789012'}
            self.m.h.validate_effective_inputs({'variables': {}}, context)
            original.assert_called_once()
            scope.assert_not_called()
            self.m.h.validate_effective_inputs({'resource_changes': []}, context)
            scope.assert_called_once()


    def test_existing_packing_module_is_scoped_and_supported(self):
        module = 'module.course_service_policy_packing[0]'
        policy = module + '.aws_iam_policy.packed["read-001"]'
        attachment = module + '.aws_iam_role_policy_attachment.packed["plan-read-001"]'
        context = {'environment': 'dev', 'account': '123456789012'}
        plan = {'resource_changes': [
            {'address': policy, 'type': 'aws_iam_policy', 'change': {'actions': ['create'], 'after': {
                'name': 'cp-dev-ci-packed-read-001', 'path': '/course-packed/'}}},
            {'address': attachment, 'type': 'aws_iam_role_policy_attachment', 'change': {'actions': ['create'], 'after': {
                'role': 'gha-infra-dev-plan', 'policy_arn': None}}},
            {'address': module + '.terraform_data.packing_guard', 'type': 'terraform_data',
             'change': {'actions': ['create'], 'after': {'input': 'guard'}}}],
            'configuration': {'root_module': {'module_calls': {'course_service_policy_packing': {'module': {'resources': [
                {'address': 'aws_iam_role_policy_attachment.packed', 'expressions': {
                    'policy_arn': {'references': ['aws_iam_policy.packed', 'each.value.policy']}}}
            ]}}}}}}
        self.m.validate_identity_plan(plan, context)
        plan['resource_changes'][1]['change']['after']['policy_arn'] = 'arn:aws:iam::123456789012:policy/course-packed/cp-dev-ci-packed-read-001'
        self.m.validate_identity_plan(plan, context)
        for name in ('cp-prod-ci-packed-read-001', 'cp-dev-ci-other'):
            plan['resource_changes'][0]['change']['after']['name'] = name
            with self.assertRaises(self.m.h.SafeError):
                self.m.validate_identity_plan(plan, context)
        plan['resource_changes'][0]['change']['after']['name'] = 'cp-dev-ci-packed-read-001'
        plan['resource_changes'][0]['address'] = 'module.other.aws_iam_policy.packed'
        with self.assertRaises(self.m.h.SafeError):
            self.m.validate_identity_plan(plan, context)


    def test_lifecycle_destroy_requires_exact_destroy_trust(self):
        context = {'environment': 'dev', 'account': '123456789012'}
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
            'Principal': {'Federated': 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com'},
            'Condition': {'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                'token.actions.githubusercontent.com:sub': 'repo:team/course:environment:infra-dev-destroy'}}}]}
        after = {'name': 'gha-infra-dev-lifecycle-destroy', 'assume_role_policy': json.dumps(trust)}
        plan = {'variables': {'github_org': {'value': 'team'}, 'github_repo': {'value': 'course'}},
                'resource_changes': [{'address': 'aws_iam_role.inspector', 'type': 'aws_iam_role',
                                      'change': {'actions': ['create'], 'after': after}}]}
        self.m.validate_identity_plan(plan, context)
        sub = trust['Statement'][0]['Condition']['StringEquals']
        for value in ('repo:team/course:environment:infra-dev-apply', 'repo:other/course:environment:infra-dev-destroy',
                      'repo:team/course:environment:infra-prod-destroy', 'repo:team/course:environment:*'):
            sub['token.actions.githubusercontent.com:sub'] = value
            after['assume_role_policy'] = json.dumps(trust)
            with self.subTest(subject=value), self.assertRaises(self.m.h.SafeError):
                self.m.validate_identity_plan(plan, context)


if __name__ == '__main__':
    unittest.main()
