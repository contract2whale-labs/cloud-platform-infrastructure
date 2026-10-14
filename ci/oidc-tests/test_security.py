import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

from support import FakeTransport, claims, environment, jwt, oidc, wrapper, xml


class ProcessSecurity(unittest.TestCase):
    def setUp(self):
        self.env = environment()
        self.binding = oidc.make_binding(self.env, 'plan')

    def test_fresh_oidc_and_exact_direct_sts_per_invocation(self):
        transport = FakeTransport(self.binding)
        for _ in range(2):
            result = oidc.credentials(self.binding, self.env, transport)
            self.assertEqual(set(result), {'Version', 'AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration'})
            self.assertEqual(result['Version'], 1)
        self.assertEqual([row[1] for row in transport.requests], ['GET', 'POST', 'GET', 'POST'])

    def test_stage_role_operation_and_region_binding(self):
        for stage in oidc.STAGE_MODE:
            env = environment(stage)
            binding = oidc.make_binding(env, stage)
            self.assertTrue(binding['role'].endswith(oidc.STAGE_MODE[stage]))
        for key, value in [('AWS_ROLE_ARN', 'arn:aws:iam::123456789012:role/Administrator'),
                           ('EXPECTED_ACCOUNT_ID', '111111111111'), ('AWS_REGION', 'us-east-1'),
                           ('LIFECYCLE_ENVIRONMENT', 'prod'), ('GITHUB_ACTIONS', 'false'), ('GITHUB_REF', 'refs/heads/evil'),
                           ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_RUN_ID', 'a;evil'),
                           ('GITHUB_WORKFLOW_REF', 'example/course/.github/workflows/evil.yml@refs/heads/main'),
                           ('EXPECTED_APPLY_ROLE_ARN', 'arn:aws:iam::123456789012:role/admin')]:
            with self.subTest(key=key), self.assertRaises(oidc.CredentialError):
                oidc.make_binding(dict(self.env, **{key: value}), 'plan')
        with self.assertRaises(oidc.CredentialError):
            oidc.make_binding(self.env, 'up')
        with self.assertRaises(oidc.CredentialError):
            oidc.make_binding(self.env, 'shell')

    def test_prod_reusable_identity_is_separate_and_fixed(self):
        for stage in ('up-plan','up-apply'):
            env=environment(stage); binding=oidc.make_binding(env,stage)
            transport=FakeTransport(binding)
            self.assertEqual(oidc.credentials(binding,env,transport)['Version'],1)
            for key,value in [('job_workflow_ref','example/course/.github/workflows/evil.yml@refs/heads/main'),('job_workflow_sha','b'*40),('environment','infra-dev-'+binding['mode'])]:
                with self.subTest(stage=stage,key=key),self.assertRaises(oidc.CredentialError):
                    oidc.validate_jwt(jwt(claims(binding,**{key:value})),binding,time.time())
            with self.assertRaises(oidc.CredentialError):
                oidc.make_binding(dict(env,AWS_ROLE_ARN=env['AWS_ROLE_ARN'].replace('-prod-','-dev-')),stage)

    def test_destroy_role_requires_destroy_environment_for_both_gates(self):
        for stage in ('prepare','destroy-apply'):
            env=environment(stage);binding=oidc.make_binding(env,stage)
            self.assertEqual(binding['role'],'arn:aws:iam::123456789012:role/gha-infra-dev-lifecycle-destroy')
            self.assertEqual(binding['environment_name'],'infra-dev-destroy')
            self.assertEqual(oidc.credentials(binding,env,FakeTransport(binding))['Version'],1)
            with self.assertRaises(oidc.CredentialError):
                oidc.validate_jwt(jwt(claims(binding,sub='repo:example/course:environment:infra-dev-apply',environment='infra-dev-apply')),binding,time.time())
            with self.assertRaises(oidc.CredentialError):
                oidc.make_binding(dict(env,AWS_ROLE_ARN='arn:aws:iam::123456789012:role/gha-infra-dev-apply'),stage)

    def test_no_runtime_binding_changes(self):
        for key in self.binding:
            altered = dict(self.binding, **{key: 'tampered'})
            with self.subTest(key=key), self.assertRaises(oidc.CredentialError):
                oidc.validate_binding(altered, self.env)
        for key in ['ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'GITHUB_RUN_ID']:
            with self.assertRaises(oidc.CredentialError):
                oidc.validate_binding(self.binding, dict(self.env, **{key: '777'}))

    def test_url_restrictions(self):
        invalid = ['http://run-actions-1.actions.githubusercontent.com/x/idtoken',
                   'https://evil.example/x/idtoken', 'https://actions.githubusercontent.com.evil.test/x/idtoken',
                   'https://evilactions.githubusercontent.com/x/idtoken', 'https://actions.githubusercontent.com/x/idtoken',
                   'https://u:p@run-actions-1.actions.githubusercontent.com/x/idtoken',
                   'https://run-actions-1.actions.githubusercontent.com:444/x/idtoken',
                   'https://run-actions-1.actions.githubusercontent.com/x/idtoken#fragment',
                   'https://run-actions-1.actions.githubusercontent.com/x/idtoken?audience=evil',
                   'https://run-actions-1.actions.githubusercontent.com/x/idtoken?audience=sts.amazonaws.com&audience=sts.amazonaws.com',
                   'https://run-actions-1.actions.githubusercontent.com/x/../idtoken',
                   'https://run-actions-1.actions.githubusercontent.com/%2F/idtoken',
                   'https://run-actions-1.actions.githubusercontent.com/x/idtoken\n']
        for value in invalid:
            with self.subTest(url=value), self.assertRaises((oidc.CredentialError, ValueError)):
                oidc.request_url(value)
        url = oidc.request_url(self.env['ACTIONS_ID_TOKEN_REQUEST_URL'])
        self.assertEqual(url.count('audience='), 1)
        self.assertEqual(url, oidc.request_url(url))

    def test_identity_and_token_lifetime(self):
        now = time.time()
        for key, value in [('aud', 'evil'), ('iss', 'https://evil'), ('sub', 'repo:example/course:environment:infra-dev-apply'),
                           ('repository_id', '999'), ('run_id', '999'), ('run_attempt', '2'), ('sha', 'b' * 40),
                           ('environment', 'infra-dev-apply'), ('exp', int(now) - 1), ('exp', int(now) + 59),
                           ('iat', int(now) + 31), ('nbf', int(now) + 31), ('exp', True), ('iat', int(now) - 301)]:
            with self.subTest(key=key, value=value), self.assertRaises(oidc.CredentialError):
                oidc.validate_jwt(jwt(claims(self.binding, **{key: value})), self.binding, now)
        immutable = claims(self.binding, sub='repo:example@123/course@234:environment:infra-dev-plan')
        oidc.validate_jwt(jwt(immutable), self.binding, now)
        with self.assertRaises(oidc.CredentialError):
            oidc.validate_jwt(jwt(claims(self.binding), alg='none'), self.binding, now)

    def test_sts_credentials_fail_closed(self):
        identity = claims(self.binding)
        for values in [dict(lifetime=-10), dict(lifetime=1799), dict(lifetime=4000), dict(AccessKeyId='AKIA' + 'X' * 16),
                       dict(SecretAccessKey=''), dict(SessionToken=''), dict(Expiration='2999-01-01'),
                       dict(Arn='arn:aws:sts::111111111111:assumed-role/admin/evil'), dict(Audience='evil')]:
            with self.subTest(values=values), self.assertRaises(oidc.CredentialError):
                oidc.sts_credentials(xml(self.binding, identity, **values), self.binding, identity, time.time())
        raw = xml(self.binding, identity)
        for bad in [raw.replace(b'<Credentials>', b'<Credentials><AccessKeyId>duplicate</AccessKeyId>'),
                    b'<!DOCTYPE x [<!ENTITY e "secret">]>' + raw]:
            with self.assertRaises(oidc.CredentialError):
                oidc.sts_credentials(bad, self.binding, identity, time.time())

    def test_no_redirect_or_error_body_read(self):
        for status in (301, 302, 307, 308, 400, 403, 500):
            with self.subTest(status=status), patch.object(oidc.http.client, 'HTTPSConnection') as connect:
                response = connect.return_value.getresponse.return_value
                response.status = status
                response.read.side_effect = AssertionError('Must not read secret error body')
                with self.assertRaises(oidc.CredentialError):
                    oidc.https_request(self.binding['oidc_url'], 'GET', {})
                response.read.assert_not_called()
                connect.return_value.close.assert_called_once()

    def test_bounded_response(self):
        with patch.object(oidc.http.client, 'HTTPSConnection') as connect:
            response = connect.return_value.getresponse.return_value
            response.status = 200
            response.getheader.side_effect = lambda key, default=None: '99999999' if key == 'Content-Length' else default
            with self.assertRaises(oidc.CredentialError):
                oidc.https_request(self.binding['oidc_url'], 'GET', {})
            response.read.assert_not_called()

    def test_private_config_permissions_cleanup_and_binding_hash(self):
        with wrapper.private_profile(self.binding, self.env) as child:
            config = Path(child['AWS_CONFIG_FILE'])
            root = config.parent
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            for filename in ['config', 'credentials', 'binding.json', 'oidc_process.py']:
                self.assertEqual(stat.S_IMODE((root / filename).stat().st_mode), 0o400)
            raw = (root / 'binding.json').read_bytes()
            self.assertNotIn(self.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'].encode(), raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(oidc.read_binding(root / 'binding.json', digest), self.binding)
            with self.assertRaises(oidc.CredentialError):
                oidc.read_binding(root / 'binding.json', 'f' * 64)
            self.assertEqual((root / 'credentials').read_bytes(), b'')
            self.assertNotIn('source_profile', config.read_text())
            self.assertIn(' -I ', config.read_text())
        self.assertFalse(root.exists())

    def test_remove_all_credential_endpoint_profile_and_debug_overrides(self):
        poison = dict(self.env, AWS_ACCESS_KEY_ID='fake', AWS_SECRET_ACCESS_KEY='fake', AWS_SESSION_TOKEN='fake',
                      AWS_SECURITY_TOKEN='fake', AWS_PROFILE='evil', AWS_CONFIG_FILE='/evil', AWS_SHARED_CREDENTIALS_FILE='/evil',
                      AWS_WEB_IDENTITY_TOKEN_FILE='/evil', AWS_ROLE_SESSION_NAME='evil', AWS_CONTAINER_CREDENTIALS_FULL_URI='http://evil',
                      AWS_CONTAINER_AUTHORIZATION_TOKEN='evil', AWS_ENDPOINT_URL='http://evil', AWS_ENDPOINT_URL_STS='http://evil',
                      AWS_CA_BUNDLE='/evil', AWS_FUTURE_CREDENTIAL_SOURCE='evil', BOTO_CONFIG='/evil', PYTHONPATH='/evil',
                      TF_LOG='TRACE', TF_LOG_PROVIDER='TRACE', SSLKEYLOGFILE='/evil', SSL_CERT_FILE='/evil', LD_PRELOAD='/evil')
        clean = wrapper.clean_environment(poison, self.binding)
        for key, value in poison.items():
            if value in ('fake', 'evil', '/evil', 'http://evil', 'TRACE'):
                self.assertNotEqual(clean.get(key), value, key)
        self.assertEqual(clean['AWS_ROLE_ARN'], self.binding['role'])
        self.assertEqual(clean['ACTIONS_ID_TOKEN_REQUEST_TOKEN'], self.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'])

    def test_stdout_empty_stderr_redacted_on_any_failure(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(oidc.sys, 'argv', ['helper', '/path', 'a' * 64]), patch.object(oidc, 'read_binding', side_effect=RuntimeError('SECRET_TOKEN')):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(oidc.main(), 1)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('SECRET_TOKEN', err.getvalue())

    def test_no_network_after_oidc_rejection(self):
        transport = FakeTransport(self.binding, claims(self.binding, exp=0))
        with self.assertRaises(oidc.CredentialError):
            oidc.credentials(self.binding, self.env, transport)
        self.assertEqual(len(transport.requests), 1)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(oidc.CredentialError):
            oidc.parse_json('{"value":"a","value":"b"}')


if __name__ == '__main__':
    unittest.main()
