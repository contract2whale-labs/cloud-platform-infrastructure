"""LOCAL fixtures only. Production code has no endpoint/clock/test-mode switch."""
import base64
import datetime as dt
import importlib.util
import json
from pathlib import Path
import time
from urllib.parse import parse_qs

TESTS = Path(__file__).resolve().parent
# Source: <proposal>/tests; installed: <repository>/ci/oidc-tests.
# ROOT remains the repository/proposal root for existing wrapper tests.
ROOT = TESTS.parent.parent if TESTS.name == 'oidc-tests' and TESTS.parent.name == 'ci' else TESTS.parent
CI = ROOT / 'ci'
PROCESS_FIXTURE = TESTS / 'process_fixture.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oidc = load('test_oidc', CI / 'oidc_process.py')
wrapper = load('test_wrapper', CI / 'run-lifecycle.py')


def environment(stage='plan'):
    mode = oidc.STAGE_MODE[stage]
    apply_mode = 'lifecycle-destroy' if mode == 'lifecycle-destroy' else 'apply'
    target = 'prod' if stage in ('preview','up-plan','up-apply') else 'dev'
    return dict(GITHUB_ACTIONS='true', GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_REPOSITORY='example/course', GITHUB_REPOSITORY_ID='234', GITHUB_REPOSITORY_OWNER_ID='123',
                GITHUB_RUN_ID='456', GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='a' * 40,
                GITHUB_WORKFLOW_REF='example/course/.github/workflows/terraform-lifecycle.yml@refs/heads/main',
                LIFECYCLE_ENVIRONMENT=target, OPERATION='up' if stage in ('up','up-plan','up-apply') else 'down',
                EXPECTED_ACCOUNT_ID='123456789012', AWS_REGION='ap-northeast-2',
                AWS_ROLE_ARN='arn:aws:iam::123456789012:role/gha-infra-' + target + '-' + mode,
                EXPECTED_APPLY_ROLE_ARN='arn:aws:iam::123456789012:role/gha-infra-' + target + '-' + apply_mode,
                ACTIONS_ID_TOKEN_REQUEST_URL='https://run-actions-1.actions.githubusercontent.com/abc/idtoken?api-version=2.0',
                ACTIONS_ID_TOKEN_REQUEST_TOKEN='LOCAL-FAKE-OIDC-REQUEST-CREDENTIAL')


def claims(binding, **updates):
    now = int(time.time())
    value = dict(iss=oidc.ISSUER, aud=oidc.AUDIENCE, sub='repo:example/course:environment:' + binding['environment_name'],
                 repository=binding['repository'], repository_id=binding['repository_id'], repository_owner_id=binding['repository_owner_id'],
                 run_id=binding['run_id'], run_attempt=binding['run_attempt'], sha=binding['sha'], ref='refs/heads/main',
                 workflow_ref=binding['workflow_ref'], event_name='workflow_dispatch', environment=binding['environment_name'],
                 iat=now, nbf=now - 1, exp=now + 300)
    if binding['stage'] in ('up-plan','up-apply'):
        value.update(job_workflow_ref=binding['repository']+'/.github/workflows/terraform-lifecycle-level.yml@refs/heads/main', job_workflow_sha=binding['sha'])
    return dict(value, **updates)


def jwt(value, alg='RS256'):
    encode = lambda item: base64.urlsafe_b64encode(json.dumps(item).encode()).decode().rstrip('=')
    return encode({'alg': alg, 'typ': 'JWT'}) + '.' + encode(value) + '.LOCALFAKESIGNATURE'


def xml(binding, identity, count=1, lifetime=3600, **updates):
    values = dict(AccessKeyId='ASIA' + f'{count:016}', SecretAccessKey='s' * 40, SessionToken='LOCALFAKESESSION' + 'A' * 64,
                  Expiration=dt.datetime.fromtimestamp(time.time() + lifetime, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  Arn=f"arn:aws:sts::{binding['account']}:assumed-role/gha-infra-{binding['environment']}-{binding['mode']}/{binding['session']}",
                  Audience=oidc.AUDIENCE, SubjectFromWebIdentityToken=identity['sub'])
    values.update(updates)
    creds = ''.join(f'<{key}>{values[key]}</{key}>' for key in ('AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration'))
    return (f'<AssumeRoleWithWebIdentityResponse xmlns="{oidc.NS[1:-1]}"><AssumeRoleWithWebIdentityResult>'
            f'<Credentials>{creds}</Credentials><AssumedRoleUser><Arn>{values["Arn"]}</Arn></AssumedRoleUser>'
            f'<Audience>{values["Audience"]}</Audience><SubjectFromWebIdentityToken>{values["SubjectFromWebIdentityToken"]}</SubjectFromWebIdentityToken>'
            '</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>').encode()


class FakeTransport:
    def __init__(self, binding, identity=None, count=1, **updates):
        self.binding = binding
        self.identity = identity or claims(binding)
        self.count = count
        self.updates = updates
        self.requests = []

    def __call__(self, url, method, headers, body=None):
        self.requests.append((url, method, headers, body))
        if method == 'GET':
            assert url == self.binding['oidc_url']
            return json.dumps({'value': jwt(self.identity)}).encode()
        assert url == 'https://sts.ap-northeast-2.amazonaws.com/'
        params = parse_qs(body.decode())
        assert params['Action'] == ['AssumeRoleWithWebIdentity']
        assert params['RoleArn'] == [self.binding['role']]
        assert params['RoleSessionName'] == [self.binding['session']]
        assert params['DurationSeconds'] == ['3600']
        assert set(params) == {'Action', 'Version', 'RoleArn', 'RoleSessionName', 'WebIdentityToken', 'DurationSeconds'}
        assert 'Authorization' not in headers
        return xml(self.binding, self.identity, count=self.count, **self.updates)
