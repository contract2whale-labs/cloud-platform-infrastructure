#!/usr/bin/env python3
"""Private same-job GitHub OIDC -> STS credential_process. Python 3.10+, stdlib only."""
import base64
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

REGION = 'ap-northeast-2'
AUDIENCE = 'sts.amazonaws.com'
ISSUER = 'https://token.actions.githubusercontent.com'
DURATION = 3600
MIN_AWS_LIFETIME = 1800
MIN_OIDC_LIFETIME = 60
MAX_RESPONSE = 131072
PROFILE = 'course-lifecycle'
STAGE_MODE = {'preview': 'plan', 'start': 'apply', 'plan': 'plan', 'apply': 'apply', 'up': 'apply', 'up-plan': 'plan', 'up-apply': 'apply', 'prepare': 'lifecycle-destroy', 'destroy-apply': 'lifecycle-destroy'}
NS = '{https://sts.amazonaws.com/doc/2011-06-15/}'


class CredentialError(Exception):
    """Messages must be constants, never remote data or exception strings."""


def require(condition, message='Credential validation failed.'):
    if not condition:
        raise CredentialError(message)


def canonical(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode('utf-8')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key.')
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def required(env, key):
    value = env.get(key)
    require(isinstance(value, str) and value and '\n' not in value and '\r' not in value,
            'Required job context missing or invalid.')
    return value


def request_url(value):
    """Only GitHub.com's documented OIDC service domain, never redirects/proxies."""
    require(isinstance(value, str) and len(value) <= 8192 and not re.search(r'[\x00-\x20\x7f\\]', value),
            'Invalid GitHub OIDC endpoint.')
    u = urlsplit(value)
    require(u.scheme == 'https' and u.port in (None, 443) and not u.username and not u.password
            and not u.fragment and u.hostname is not None
            and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+actions\.githubusercontent\.com', u.hostname)
            and u.path.startswith('/') and u.path.endswith('/idtoken')
            and '%' not in u.path and '..' not in u.path.split('/'), 'Unapproved GitHub OIDC endpoint.')
    pairs = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
    require(len(pairs) == len({k for k, _ in pairs}) and all(k != 'audience' or v == AUDIENCE for k, v in pairs),
            'Invalid OIDC audience query.')
    pairs = [(k, v) for k, v in pairs if k != 'audience'] + [('audience', AUDIENCE)]
    return urlunsplit(('https', u.netloc, u.path, urlencode(pairs), ''))


def make_binding(env, stage):
    require(stage in STAGE_MODE, 'Unsupported lifecycle stage.')
    environment = required(env, 'LIFECYCLE_ENVIRONMENT')
    require(environment in ('dev', 'prod') and (stage not in ('up-plan','up-apply') or environment == 'prod')
            and (stage != 'up' or environment == 'dev'), 'Unsupported environment/stage boundary.')
    require(required(env, 'GITHUB_ACTIONS') == 'true' and required(env, 'GITHUB_REF') == 'refs/heads/main'
            and required(env, 'GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and environment in ('dev','prod'), 'Only the protected main lifecycle job is supported.')
    operation = required(env, 'OPERATION')
    require(operation in ('up', 'down') and (stage not in ('up','up-plan','up-apply') or operation == 'up')
            and (stage not in ('plan', 'apply', 'prepare', 'destroy-apply') or operation == 'down'), 'Lifecycle stage/operation mismatch.')
    account = required(env, 'EXPECTED_ACCOUNT_ID')
    require(re.fullmatch(r'[0-9]{12}', account) and required(env, 'AWS_REGION') == REGION,
            'Incorrect registered account or Region.')
    mode = STAGE_MODE[stage]
    role = f'arn:aws:iam::{account}:role/gha-infra-{environment}-{mode}'
    require(required(env, 'AWS_ROLE_ARN') == role, 'The job role is not the exact registered environment role.')
    apply_mode = 'lifecycle-destroy' if mode == 'lifecycle-destroy' else 'apply'
    environment_name = 'infra-' + environment + '-' + ('destroy' if mode == 'lifecycle-destroy' else mode)
    if mode == 'plan' or env.get('EXPECTED_APPLY_ROLE_ARN'):
        require(required(env, 'EXPECTED_APPLY_ROLE_ARN') == f'arn:aws:iam::{account}:role/gha-infra-{environment}-{apply_mode}',
                'Incorrect expected apply role.')
    repository = required(env, 'GITHUB_REPOSITORY')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'Invalid repository.')
    ids = {key: required(env, key) for key in ('GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')}
    require(all(re.fullmatch(r'[1-9][0-9]{0,19}', value) for value in ids.values()), 'Invalid immutable job identity.')
    sha = required(env, 'GITHUB_SHA')
    workflow_ref = required(env, 'GITHUB_WORKFLOW_REF')
    require(re.fullmatch(r'[0-9a-f]{40}', sha)
            and workflow_ref == repository + '/.github/workflows/terraform-lifecycle.yml@refs/heads/main',
            'Unexpected lifecycle workflow identity.')
    token = required(env, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    require(len(token) <= 32768 and re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', token), 'Invalid OIDC request credential.')
    endpoint = request_url(required(env, 'ACTIONS_ID_TOKEN_REQUEST_URL'))
    session = f"gha-{ids['GITHUB_RUN_ID']}-{ids['GITHUB_RUN_ATTEMPT']}-{stage}"
    require(len(session) <= 64, 'Job session identity too long.')
    return dict(schema=1, environment=environment, environment_name=environment_name, account=account, region=REGION, role=role, mode=mode, stage=stage,
                operation=operation, session=session, repository=repository,
                repository_id=ids['GITHUB_REPOSITORY_ID'], repository_owner_id=ids['GITHUB_REPOSITORY_OWNER_ID'],
                run_id=ids['GITHUB_RUN_ID'], run_attempt=ids['GITHUB_RUN_ATTEMPT'], sha=sha,
                workflow_ref=workflow_ref, oidc_url=endpoint,
                request_token_sha256=hashlib.sha256(token.encode()).hexdigest())


def validate_binding(binding, env):
    # Reconstruct from the current same-job context; callers cannot switch role,
    # audience, Region, run, workflow, URL, session name or bearer after setup.
    require(isinstance(binding, dict) and binding == make_binding(env, binding.get('stage')),
            'Credential process job binding changed.')


def read_binding(path, digest):
    path = Path(path)
    require(path.is_absolute() and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid private binding reference.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o400,
                'Binding permissions changed.')
        parent = path.parent.stat()
        require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
                'Private credential directory permissions changed.')
        raw = os.read(fd, MAX_RESPONSE + 1)
    finally:
        os.close(fd)
    require(len(raw) <= MAX_RESPONSE and hashlib.sha256(raw).hexdigest() == digest, 'Binding integrity failed.')
    return parse_json(raw)



TERRAFORM_CONFIG = b'disable_checkpoint = true\nprovider_installation { direct {} }\n'
AWS_PROVIDER_VERSION = '6.62.0'


def profile_file(directory, name):
    """Read only fixed-name private, owned, non-symlink profile components."""
    path = directory / name
    require(path.parent == directory and not path.is_symlink(), 'Redirected credential profile component.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o400, 'Credential profile permissions changed.')
        raw = os.read(fd, MAX_RESPONSE + 1)
    finally:
        os.close(fd)
    require(len(raw) <= MAX_RESPONSE, 'Credential profile component too large.')
    return raw


def validate_private_profile(env):
    """Permit only the wrapper's exact configuration, never an arbitrary rc path.

    This is a same-job integrity contract, not a sandbox against trusted same-UID
    code. Fixed source and Environment/main protection remain required.
    """
    config = Path(required(env, 'AWS_CONFIG_FILE'))
    require(config.is_absolute() and config.resolve() == config and config.name == 'config',
            'Invalid private AWS configuration path.')
    directory = config.parent
    info = directory.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Private credential directory permissions changed.')
    raw = profile_file(directory, 'binding.json')
    binding = parse_json(raw)
    validate_binding(binding, env)
    require(profile_file(directory, 'oidc_process.py') == Path(__file__).read_bytes(),
            'Private credential process differs from the reviewed helper.')
    python = str(Path(sys.executable).resolve())
    require(all(re.fullmatch(r'[A-Za-z0-9_/ .-]+', value) for value in (python, str(directory))),
            'Unsafe credential process path.')
    quote = lambda value: '"' + str(value) + '"'
    command = (quote(python) + ' -I ' + quote(directory / 'oidc_process.py') + ' '
               + quote(directory / 'binding.json') + ' ' + hashlib.sha256(raw).hexdigest())
    expected = f'[profile {PROFILE}]\nregion = {REGION}\ncredential_process = {command}\n'.encode()
    require(profile_file(directory, 'config') == expected and
            profile_file(directory, 'credentials') == b'' and
            profile_file(directory, 'terraform.rc') == TERRAFORM_CONFIG,
            'Private credential or Terraform configuration changed.')
    fixed = dict(AWS_PROFILE=PROFILE, AWS_DEFAULT_PROFILE=PROFILE, AWS_SDK_LOAD_CONFIG='1',
                 AWS_EC2_METADATA_DISABLED='true', AWS_IGNORE_CONFIGURED_ENDPOINT_URLS='true',
                 AWS_STS_REGIONAL_ENDPOINTS='regional', AWS_CONFIG_FILE=str(config),
                 AWS_SHARED_CREDENTIALS_FILE=str(directory / 'credentials'),
                 AWS_REGION=binding['region'], AWS_DEFAULT_REGION=binding['region'],
                 AWS_ROLE_ARN=binding['role'], TF_CLI_CONFIG_FILE=str(directory / 'terraform.rc'))
    require(all(env.get(key) == value for key, value in fixed.items()), 'Private execution profile changed.')
    require(not any(key.startswith(('AWS_', 'AMAZON_')) and key not in fixed for key in env),
            'Inherited AWS credential or endpoint override is forbidden.')
    require(env.get('BOTO_CONFIG') == os.devnull, 'Inherited boto configuration is forbidden.')
    return binding


def provider_lock(raw):
    """Exact AWS version/checksum boundary, also applied to restored snapshots."""
    text = raw.decode('utf-8')
    blocks = re.findall(r'^provider "registry\.terraform\.io/hashicorp/aws" \{\s*\n([^{}]*)^\}', text, re.M)
    require(len(blocks) == 1, 'Selected root needs one reviewed AWS provider lock.')
    block = blocks[0]
    versions = re.findall(r'^\s*version\s*=\s*"([^"]+)"\s*$', block, re.M)
    require(versions == [AWS_PROVIDER_VERSION], 'Selected root AWS provider differs from the smoke pin.')
    require(bool(re.search(r'"h1:[A-Za-z0-9+/]{43}="', block)) and
            bool(re.search(r'"zh:[0-9a-f]{64}"', block)), 'Reviewed provider checksums are required.')
    return ('provider "registry.terraform.io/hashicorp/aws" {\n' + block + '}\n').encode()

def https_request(url, method, headers, body=None):
    u = urlsplit(url)
    require(u.scheme == 'https' and not u.username and not u.password and not u.fragment
            and u.port in (None, 443), 'Invalid TLS destination.')
    require(url == f'https://sts.{REGION}.amazonaws.com/' or request_url(url) == url,
            'Unapproved credential destination.')
    # No urllib environment proxies, custom CA overrides, HTTP redirects, debug
    # logging or AWS credential chain. System CA store + hostname verification.
    context = ssl.create_default_context()
    context.keylog_filename = None
    conn = http.client.HTTPSConnection(u.hostname, port=443, timeout=15, context=context)
    try:
        conn.request(method, u.path + ('?' + u.query if u.query else ''), body=body, headers=headers)
        response = conn.getresponse()
        require(response.status == 200, 'Credential endpoint rejected the request.')
        require(response.getheader('Content-Encoding', 'identity') == 'identity', 'Unexpected response encoding.')
        size = response.getheader('Content-Length')
        require(size is None or (size.isdigit() and int(size) <= MAX_RESPONSE), 'Credential response too large.')
        raw = response.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE, 'Credential response too large.')
        return raw
    finally:
        conn.close()


def jwt_payload(token):
    require(isinstance(token, str) and len(token) <= 32768 and re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token),
            'Malformed OIDC token.')
    header, payload, _ = token.split('.')
    decode = lambda value: parse_json(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
    require(decode(header).get('alg') == 'RS256', 'Unexpected OIDC signature algorithm.')
    return decode(payload)


def validate_jwt(token, binding, now):
    # These are consistency checks only. STS performs signature/JWKS/trust-policy
    # validation; never use this unverified payload as authentication by itself.
    claims = jwt_payload(token)
    require(isinstance(claims, dict), 'Malformed OIDC claims.')
    expected = dict(iss=ISSUER, aud=AUDIENCE, repository=binding['repository'], repository_id=binding['repository_id'],
                    repository_owner_id=binding['repository_owner_id'], run_id=binding['run_id'],
                    run_attempt=binding['run_attempt'], sha=binding['sha'], ref='refs/heads/main',
                    workflow_ref=binding['workflow_ref'], event_name='workflow_dispatch', environment=binding['environment_name'])
    require(all(claims.get(key) == value for key, value in expected.items()), 'OIDC job identity mismatch.')
    owner, repo = binding['repository'].split('/')
    prefixes = (f'repo:{owner}/{repo}', f"repo:{owner}@{binding['repository_owner_id']}/{repo}@{binding['repository_id']}")
    require(claims.get('sub') in {p + ':environment:' + binding['environment_name'] for p in prefixes},
            'OIDC subject is not the registered environment.')
    if binding['stage'] in ('up-plan','up-apply'):
        prefix = binding['repository'] + '/.github/workflows/terraform-lifecycle-level.yml@'
        require(claims.get('job_workflow_ref') in (prefix + 'refs/heads/main', prefix + binding['sha']) and
                claims.get('job_workflow_sha') == binding['sha'], 'Unexpected reusable lifecycle workflow identity.')
    for key in ('exp', 'iat', 'nbf'):
        require(type(claims.get(key)) is int, 'OIDC token timestamp missing.')
    require(now + MIN_OIDC_LIFETIME < claims['exp'] <= now + 3600 and claims['iat'] <= now + 30
            and claims['nbf'] <= now + 30 and claims['exp'] > claims['iat'] >= now - 300,
            'OIDC token expired, not active or insufficiently fresh.')
    return claims


def sts_credentials(raw, binding, claims, now):
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe STS XML.')
    root = ET.fromstring(raw)
    require(root.tag == NS + 'AssumeRoleWithWebIdentityResponse', 'Unexpected STS response.')
    def one(path):
        values = root.findall(path)
        require(len(values) == 1 and values[0].text, 'Malformed STS response.')
        return values[0].text
    prefix = './' + NS + 'AssumeRoleWithWebIdentityResult/'
    assumed = one(prefix + NS + 'AssumedRoleUser/' + NS + 'Arn')
    require(assumed == f"arn:aws:sts::{binding['account']}:assumed-role/gha-infra-{binding['environment']}-{binding['mode']}/{binding['session']}",
            'STS returned an unexpected account, role or session.')
    require(one(prefix + NS + 'Audience') == AUDIENCE and one(prefix + NS + 'SubjectFromWebIdentityToken') == claims['sub'],
            'STS web identity binding mismatch.')
    credpath = prefix + NS + 'Credentials/'
    values = {key: one(credpath + NS + key) for key in ('AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration')}
    require(re.fullmatch(r'ASIA[A-Z0-9]{16}', values['AccessKeyId']) and re.fullmatch(r'[A-Za-z0-9/+=]{40}', values['SecretAccessKey'])
            and re.fullmatch(r'[A-Za-z0-9/+=]{16,16384}', values['SessionToken']), 'Malformed STS credentials.')
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', values['Expiration']), 'Invalid STS expiration format.')
    expires = dt.datetime.fromisoformat(values['Expiration'].replace('Z', '+00:00')).timestamp()
    require(now + MIN_AWS_LIFETIME < expires <= now + DURATION + 120, 'STS credentials have an unsafe lifetime.')
    return dict(Version=1, **values)


def credentials(binding, env, transport=https_request):
    validate_binding(binding, env)
    response = parse_json(transport(binding['oidc_url'], 'GET',
                                  {'Authorization': 'Bearer ' + required(env, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'),
                                   'Accept': 'application/json', 'User-Agent': 'course-lifecycle-oidc/1'}))
    require(isinstance(response, dict) and isinstance(response.get('value'), str), 'Malformed OIDC response.')
    token = response['value']
    claims = validate_jwt(token, binding, time.time())
    body = urlencode(dict(Action='AssumeRoleWithWebIdentity', Version='2011-06-15', RoleArn=binding['role'],
                          RoleSessionName=binding['session'], WebIdentityToken=token, DurationSeconds=str(DURATION))).encode()
    response = transport(f'https://sts.{REGION}.amazonaws.com/', 'POST',
                         {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/xml',
                          'User-Agent': 'course-lifecycle-oidc/1'}, body)
    return sts_credentials(response, binding, claims, time.time())


def main():
    try:
        require(len(sys.argv) == 3 and not sys.stdout.isatty(), 'Credential process is private SDK input only.')
        result = credentials(read_binding(sys.argv[1], sys.argv[2]), os.environ)
        sys.stdout.write(json.dumps(result, separators=(',', ':')) + '\n')
        return 0
    except BaseException:
        # Never print exception strings, request URLs, headers, tokens or remote
        # response bodies: AWS SDKs can include this stderr in their own logs.
        sys.stderr.write('Course credentials unavailable; the lifecycle must stop.\n')
        return 1


if __name__ == '__main__':
    sys.exit(main())
