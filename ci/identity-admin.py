#!/usr/bin/env python3
"""Narrow adapter to the course's versioned private saved-plan engine."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location('private_saved_plan', Path(__file__).with_name('saved-plan.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def select_root(workspace, value):
    match = re.fullmatch(r'terraform/environments/(dev|prod)/bootstrap/ci-identity', value)
    h.require(match is not None, 'Only the identity root is permitted.')
    root = workspace / value
    h.require(root.is_dir() and root.resolve().is_relative_to(workspace.resolve()), 'Invalid identity root.')
    return match[1], 'bootstrap/ci-identity/terraform.tfstate'


def guard(mode):
    h.require(mode in ('plan', 'apply'), 'Only identity plan or apply is supported.')
    h.require(h.required('GITHUB_REF') == 'refs/heads/main', 'Only main may administer identity.')
    h.require(h.required('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Only the dedicated dispatch is permitted.')
    env, _ = select_root(Path(h.required('GITHUB_WORKSPACE')), h.required('ROOT_PATH'))
    account = h.required('EXPECTED_ACCOUNT_ID')
    base = f'arn:aws:iam::{account}:role/gha-identity-{env}-'
    h.require(h.required('AWS_ROLE_ARN') == base + mode, 'Incorrect identity role.')
    if mode == 'plan':
        h.require(h.required('EXPECTED_APPLY_ROLE_ARN') == base + 'apply', 'Incorrect identity apply role.')


def check_existing_state():
    account = h.required('EXPECTED_ACCOUNT_ID')
    h.check_identity(account, h.required('AWS_ROLE_ARN'))
    store = h.Store(h.required('STATE_BUCKET'), account)
    store.check()
    h.require(store.state('bootstrap/ci-identity/terraform.tfstate')['exists'],
              'Existing BU01 identity State is required; do not recreate or migrate it in CI.')


def identity_summary(context, manifest, descriptor):
    import shlex
    with open(h.required('GITHUB_STEP_SUMMARY'), 'a', encoding='utf-8') as out:
        out.write('## Identity change awaiting review\n\n')
        out.write(f'Root: `{context["root"]}`; commit: `{context["sha"]}`\n\n')
        out.write(f'Plan SHA-256: `{manifest["plan"]["sha256"]}`\n\n')
        out.write(f'Expires (Unix seconds): `{manifest["expires_at"]}`\n\n')
        out.write('Use your authorized read-only SSO session to download and inspect these private objects. '
                  'Do not paste their contents into Actions or a PR.\n\n```bash\n')
        for label, item in (('manifest.json', descriptor), ('review.txt', manifest['review'])):
            out.write('aws s3api get-object --bucket "$STATE_BUCKET" --expected-bucket-owner "$ACCOUNT_ID" '
                      '--key ' + shlex.quote(item['key']) + ' --version-id ' + shlex.quote(item['version']) +
                      ' ' + label + ' >/dev/null\nsha256sum ' + label + '\n# expected: ' + item['sha256'] + '\n')
        out.write('less review.txt\n```\n\n')
        out.write(f'Approve `identity-{context["environment"]}-apply` in THIS run only after review. '
                  'Apply uses the exact version-pinned binary; it does not create another plan.\n')


def operational_names(environment):
    return {f'cp-{environment}-{suffix}' for suffix in (
        'gitops-bootstrap', 'gitops-apply', 'incident-plan', 'incident-apply'
    )} | {f'gha-infra-{environment}-lifecycle-destroy'} | ({'gha-aws-ops-dev-plan', 'gha-aws-ops-dev-apply'} if environment == 'dev' else set())


def validate_identity_plan(plan, context):
    """Reject drift outside the BU01 capability before publishing an approvable plan.

    This is a scope check, not a policy-content sandbox: reviewers still audit
    every document/trust/provisioner and the privileged identity-admin source.
    """
    env, account = context['environment'], context['account']
    operational = operational_names(env)
    roles = operational | {f'gha-{kind}-{env}-{mode}' for kind in ('infra', 'identity') for mode in ('plan', 'apply')}
    prefixes = (f'gha-course-{env}-', f'gha-infra-{env}-vpc-',
                f'gha-infra-{env}-course-lifecycle-', f'course-{env}-ci-bu0912-', f'cp-{env}-ci-')
    policy_prefix = f'arn:aws:iam::{account}:policy/'
    additional = set()
    for name in ('plan_additional_policy_arns', 'apply_additional_policy_arns'):
        additional.update(plan.get('variables', {}).get(name, {}).get('value', []))
    def allowed_policy(arn):
        return isinstance(arn, str) and (arn in additional or (
            arn.startswith(policy_prefix) and (arn[len(policy_prefix):].startswith(prefixes) or
             arn[len(policy_prefix):].startswith(f'course-packed/cp-{env}-ci-packed-'))))
    changes = plan.get('resource_changes', [])
    configs = {r['address']: r for r in plan.get('configuration', {}).get('root_module', {}).get('resources', [])}
    packing_module = 'module.course_service_policy_packing'
    packing_config = plan.get('configuration', {}).get('root_module', {}).get('module_calls', {}).get(
        'course_service_policy_packing', {}).get('module', {})
    configs.update({packing_module + '.' + r['address']: r for r in packing_config.get('resources', [])})
    approved = {'aws_iam_role': set(), 'aws_iam_policy': set()}
    def base(address):
        return re.sub(r'\[[^\]]*\]', '', address)
    def allowed_policy_values(values):
        name, path = values.get('name'), values.get('path', '/')
        return isinstance(name, str) and ((path == '/' and name.startswith(prefixes)) or
               (path == '/course-packed/' and name.startswith(f'cp-{env}-ci-packed-')))
    for item in changes:
        if item.get('mode') == 'data':
            continue
        kind = item.get('type')
        for values in (item.get('change', {}).get('before'), item.get('change', {}).get('after')):
            if not values:
                continue
            if kind == 'aws_iam_role' and values.get('name') in roles and values.get('path', '/') == '/':
                approved[kind].add(base(item['address']))
            if kind == 'aws_iam_policy' and allowed_policy_values(values):
                approved[kind].add(base(item['address']))
    def reference_allowed(item, field, kind):
        config = configs.get(base(item['address']), {})
        expr = config.get('expressions', {}).get(field, {})
        references = expr.get('references', [])
        if not any(r.startswith(kind + '.') for r in references) and any(r.startswith('each.value') for r in references):
            references = config.get('for_each_expression', {}).get('references', [])
        refs = [r for r in references if r.startswith(kind + '.')]
        # Direct Terraform references only; no opaque locals/inputs for unknown targets.
        prefix = packing_module + '.' if base(item['address']).startswith(packing_module + '.') else ''
        return bool(refs) and all(prefix + '.'.join(base(r).split('.')[:2]) in approved[kind] for r in refs)
    for item in changes:
        change = item.get('change', {})
        actions = change.get('actions', ['no-op'])
        if item.get('mode') == 'data' or actions == ['no-op']:
            continue
        address = base(item['address'])
        kind = item.get('type')
        packing_targets = {packing_module + '.' + target for target in (
            'aws_iam_policy.packed', 'aws_iam_role_policy_attachment.packed',
            'terraform_data.packing_guard', 'terraform_data.restriction_generation',
            'terraform_data.restriction_attachment_latch')}
        h.require(not address.startswith('module.') or address in packing_targets,
                  'Only the existing fixed policy-packing module is permitted.')
        if kind == 'terraform_data':
            h.require(address == 'terraform_data.course_vpc_policy_parity' or address in packing_targets,
                      'Unrecognized local packing guard.')
            h.require(not configs.get(address, {}).get('provisioners'), 'Packing guards must not execute provisioners.')
            continue
        h.require(kind in ('aws_iam_role', 'aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_role_policy_attachment'),
                  'Identity plan contains a resource outside the fixed IAM allowlist.')
        if kind == 'aws_iam_role' and (change.get('after') or {}).get('name') == f'gha-infra-{env}-lifecycle-destroy':
            variables = {key: value.get('value') for key, value in plan.get('variables', {}).items()}
            prefix = variables.get('github_subject_prefix') or f"repo:{variables.get('github_org')}/{variables.get('github_repo')}"
            try:
                trust = json.loads(change['after']['assume_role_policy'])
            except (TypeError, ValueError, KeyError):
                raise h.SafeError('Lifecycle destruction role trust must be fully known in the plan.')
            expected = {'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
                        'Principal': {'Federated': f'arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com'},
                        'Condition': {'StringEquals': {
                            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                            'token.actions.githubusercontent.com:sub': f'{prefix}:environment:infra-{env}-destroy'}}}
            statements = trust.get('Statement', [])
            h.require(len(statements) == 1 and {k: v for k, v in statements[0].items() if k != 'Sid'} == expected,
                      'Lifecycle destruction role must trust only the exact infra destroy Environment and repository.')
        for values in (change.get('before'), change.get('after')):
            if not values:
                continue
            if kind == 'aws_iam_role':
                h.require(values.get('name') in roles and values.get('path', '/') == '/', 'Role identity is not allowlisted.')
                h.require('delete' not in actions, 'CI role deletion/replacement requires separate recovery review.')
                if 'create' in actions:
                    h.require(values['name'] in operational, 'Only fixed operational roles may be created after BU01.')
            elif kind == 'aws_iam_policy':
                h.require(allowed_policy_values(values),
                          'Managed policy name/path is outside the course namespace.')
            else:
                role = values.get('role')
                h.require(role in roles or (role is None and reference_allowed(item, 'role', 'aws_iam_role')),
                          'Attachment/inline policy role is not allowlisted or cannot be resolved.')
                if kind == 'aws_iam_role_policy_attachment':
                    arn = values.get('policy_arn')
                    h.require(allowed_policy(arn) or (arn is None and reference_allowed(item, 'policy_arn', 'aws_iam_policy')),
                              'Attached policy is not allowlisted or cannot be resolved.')


_original_input_validation = h.validate_effective_inputs


def validate_inputs_and_identity_plan(plan, context):
    _original_input_validation(plan, context)
    if 'resource_changes' in plan:
        validate_identity_plan(plan, context)


def configure():
    h.validate_effective_inputs = validate_inputs_and_identity_plan
    h.select_root = select_root
    # Identity has its own State and no remote-State dependencies. It deliberately
    # stays outside normal deploy registries and remains usable during course Down.
    h.upstream_states = lambda store, context, workspace: {}
    h.lifecycle_gate = lambda store, context, workspace: None
    h.publish_summary = identity_summary


if __name__ == '__main__':
    try:
        h.require(len(sys.argv) == 2, 'Expected plan or apply.')
        guard(sys.argv[1])
        configure()
        check_existing_state()
        h.run(sys.argv[1])
    except h.SafeError as error:
        print('::error::' + str(error))
        sys.exit(1)
    except Exception:
        print('::error::Identity operation failed; inspect authorized private diagnostics.')
        sys.exit(1)
