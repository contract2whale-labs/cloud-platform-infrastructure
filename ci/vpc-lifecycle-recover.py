#!/usr/bin/env python3
"""Local securityadmin-only recovery of a never-applied pause; never runs Terraform.
Disable current and any legacy workflows; finish/cancel all their runs first. Use an existing
approved AWS IAM Identity Center administrator profile; this script grants no permissions.
"""
import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


h = load('recovery_saved_plan', 'saved-plan.py')
c = load('recovery_lifecycle', 'lifecycle-state.py')
WORKFLOWS = ('terraform-apply.yml', 'terraform-lifecycle.yml')
LEGACY_PATH = '.github/workflows/vpc-lifecycle.yml'
ACTIVE = ('queued', 'waiting', 'in_progress', 'pending', 'requested')


def github_quiet(repo, repository_id):
    def get(endpoint, paginate=False):
        options = ['--paginate', '--slurp'] if paginate else []
        return json.loads(h.execute(['gh', 'api', '--hostname', 'github.com', *options, endpoint]))
    def listing(endpoint, field):
        pages = get(endpoint, paginate=True)
        h.require(isinstance(pages, list) and bool(pages), 'Complete workflow/run listing required.')
        rows = []
        for page in pages:
            h.require(isinstance(page.get(field), list) and type(page.get('total_count')) is int and
                      page['total_count'] == pages[0]['total_count'], 'Inconsistent workflow/run listing.')
            rows.extend(page[field])
        h.require(len(rows) == pages[0]['total_count'], 'Incomplete workflow/run listing; retain the pause.')
        return rows
    value = get('repos/' + repo)
    h.require(str(value.get('id')) == repository_id and value.get('permissions', {}).get('admin') is True,
              'Repository ID or administrator access mismatch.')
    for workflow in WORKFLOWS:
        endpoint = f'repos/{repo}/actions/workflows/{workflow}'
        value = get(endpoint)
        h.require(value.get('state') == 'disabled_manually', 'Both workflows must be administratively disabled.')
        for status in ACTIVE:
            runs = get(endpoint + '/runs?per_page=1&status=' + status)
            h.require(runs.get('total_count') == 0 and runs.get('workflow_runs') == [],
                      'Old workflow runs remain active; finish or cancel them first.')
    rows = listing(f'repos/{repo}/actions/workflows?per_page=100', 'workflows')
    h.require(all(isinstance(row, dict) and type(row.get('id')) is int and
                  isinstance(row.get('path'), str) and bool(row['path'].strip()) for row in rows),
              'Incomplete workflow identity; retain the pause.')
    h.require(len({row['id'] for row in rows}) == len(rows), 'Duplicate workflow listing; retain the pause.')
    legacy = [row for row in rows if row.get('path') == LEGACY_PATH]
    h.require(all(row.get('state') in ('disabled_manually', 'disabled_inactivity', 'disabled_fork', 'deleted')
                  and type(row.get('id')) is int for row in legacy), 'Legacy workflow must also be disabled/deleted.')
    legacy_ids = {row['id'] for row in legacy}
    # Deleted workflows may disappear from the listing while old runs remain.
    for status in ACTIVE:
        runs = listing(f'repos/{repo}/actions/runs?per_page=100&status={status}', 'workflow_runs')
        h.require(all(type(run.get('workflow_id')) is int and isinstance(run.get('path'), str)
                      and bool(run['path']) for run in runs), 'Incomplete active run identity; retain the pause.')
        h.require(not any(run.get('workflow_id') in legacy_ids or
                          str(run.get('path', '')).split('@', 1)[0] == LEGACY_PATH for run in runs),
                  'Legacy workflow runs remain active; finish or cancel them first.')


def admin_session(args):
    h.require(not any(os.environ.get(k) for k in ('GITHUB_ACTIONS', 'CI', 'AWS_ACCESS_KEY_ID',
              'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN',
              'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', 'AWS_CONTAINER_CREDENTIALS_FULL_URI')),
              'Use a local securityadmin SSO session, never CI or inherited role credentials.')
    def setting(name):
        return h.execute(['aws', 'configure', 'get', name, '--profile', args.profile]).decode().strip()
    h.require(setting('sso_account_id') == args.account and setting('sso_role_name') == args.sso_role_name,
              'The profile must match the approved account and SSO permission set.')
    original = h.aws
    h.aws = lambda service, operation, *values: original(service, operation, *values,
                                                          '--profile', args.profile, '--region', args.region)
    caller = h.aws('sts', 'get-caller-identity')
    expected = rf'arn:aws:sts::{args.account}:assumed-role/AWSReservedSSO_{re.escape(args.sso_role_name)}_[0-9a-f]{{16}}/[^/]+'
    h.require(caller.get('Account') == args.account and
              re.fullmatch(expected, caller.get('Arn', '')) is not None,
              'Caller does not match the explicitly approved administrator SSO role.')
    return caller['Arn']


def recover(store, target, repo, generation, stage, confirmation, actor):
    key = c.marker_key(target['repository_id'])
    record, previous = c.read_json(store, key)
    c.validate(record, **target)
    h.require(record['phase'] == 'paused' and record.get('last_result') == 'not-applied',
              'Only a paused, never-applied generation can be recovered.')
    h.require(record['generation'] == generation, 'Generation mismatch.')
    original = record.get('original_state_fingerprint')
    h.require(isinstance(original, dict) and original.get('exists') is True and
              isinstance(original.get('version'), str) and original['version'] not in ('', 'null') and
              isinstance(original.get('etag'), str) and bool(original['etag']) and
              type(original.get('size')) is int and original['size'] > 0,
              'Original versioned State fingerprint is missing or invalid; retain the pause.')
    h.require(store.state(c.KEY) == original, 'State changed; retain the pause for administrator review.')
    github_quiet(repo, target['repository_id'])
    if stage == 'resume':
        h.require(confirmation == generation, 'Resume requires exact --confirm-generation.')
        github_quiet(repo, target['repository_id'])
        h.require(store.state(c.KEY) == original, 'State changed before recovery; retain the pause.')
        latest, info = c.read_json(store, key)
        h.require(latest == record and info == previous, 'Control record changed; retain the pause.')
        recovered = dict(record, phase='active', admin_recovery_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                         admin_recovery_actor=actor)
        c.update(store, key, recovered, previous)  # If-Match only; never delete or recreate.
        record = recovered
    return {'repository_id': target['repository_id'], 'generation': generation,
            'marker': key, 'phase': record['phase']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=('inspect', 'resume'), default='inspect')
    for name in ('profile', 'sso-role-name', 'account', 'bucket', 'region', 'repo', 'repository-id', 'generation'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--confirm-generation')
    args = parser.parse_args()
    h.require(re.fullmatch(r'\d{12}', args.account) is not None and args.repository_id.isdigit() and
              re.fullmatch(r'\d+-\d+', args.generation) is not None and args.region == 'ap-northeast-2' and
              re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo) is not None and
              bool(re.fullmatch(r'[A-Za-z0-9_.-]+', args.profile)), 'Invalid explicit recovery target.')
    os.umask(0o077)
    actor = admin_session(args)
    store = h.Store(args.bucket, args.account); store.check()
    target = {name: getattr(args, name) for name in ('repository_id', 'account', 'bucket', 'region')}
    print(json.dumps(recover(store, target, args.repo, args.generation, args.stage, args.confirm_generation, actor)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Recovery not verified. Retain disabled workflows and inspect the marker before retrying.', file=sys.stderr)
        sys.exit(1)
