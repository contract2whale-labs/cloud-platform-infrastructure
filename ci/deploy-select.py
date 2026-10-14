#!/usr/bin/env python3
"""Select changed roots and downstream consumers, then emit true dependency waves."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

MAX_WAVES = 12
_spec = importlib.util.spec_from_file_location('course_activation', Path(__file__).with_name('course_activation.py'))
activation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(activation)


def waves(registry, graph, existing, changed, requested=None, *, active=None):
    roots = activation.validate_registries(registry, graph)
    if active is None:
        raise ValueError('Explicit course activation is required; directories never authorize deployment.')
    active = set(active)
    if not active <= roots.keys() or any(activation.external_root(p) for p in active):
        raise ValueError('Unknown or bootstrap root in ordinary CI activation.')
    if not set(existing) <= roots.keys():
        raise ValueError('Unknown existing deployment root.')
    # A deleted active root is an error even on docs-only changes or manual retry.
    removed = active - set(existing)
    if removed:
        raise ValueError('Root removal is not an automatic destroy operation: ' + ', '.join(sorted(removed)))
    if requested:
        if requested not in active:
            raise ValueError('Requested root is not explicitly activated.')
        selected = {requested}
    else:
        common = any(f.startswith(('modules/', 'terraform/modules/', 'ci/', '.github/workflows/terraform-')) for f in changed)
        selected = set(active) if common else {p for p in active if any(f.startswith(p + '/') for f in changed)}
    # Changing an upstream output may affect only already-active consumer roots.
    while True:
        expanded = selected | {p for p in active if set(graph[p]) & selected}
        if expanded == selected:
            break
        selected = expanded
    for path in active:
        if any(dep not in active for dep in graph[path]):
            raise ValueError('Active root has an inactive dependency: ' + path)
    result, remaining = [], set(selected)
    while remaining:
        ready = sorted(p for p in remaining if not (set(graph[p]) & remaining))
        result.append([dict(roots[p], key='/'.join(p.split('/')[3:]) + '/terraform.tfstate') for p in ready])
        remaining -= set(ready)
    if len(result) > MAX_WAVES:
        raise ValueError('Dependency depth exceeds supported workflow waves; expand and test the orchestrator first.')
    return result


def last_successful_push(repo, current_run):
    raw = subprocess.check_output([
        'gh', 'api', '--method', 'GET',
        f'repos/{repo}/actions/workflows/terraform-apply.yml/runs',
        '-f', 'branch=main', '-f', 'event=push', '-f', 'status=success', '-f', 'per_page=100'
    ], text=True)
    runs = json.loads(raw)['workflow_runs']
    for run in runs:
        if str(run['id']) != str(current_run) and run.get('conclusion') == 'success' and run.get('event') == 'push' and run.get('head_branch') == 'main':
            return run['head_sha']
    return None


def changed_since_success(git, baseline, sha):
    if baseline is None:
        # First deployment reconciles explicitly activated roots only.
        return ['ci/deploy-roots.json']
    if not re.fullmatch(r'[0-9a-f]{40}', baseline):
        raise ValueError('Invalid successful deployment baseline.')
    git('merge-base', '--is-ancestor', baseline, sha)
    # Union all touched paths, including changes subsequently reverted after a failed run.
    return sorted(set(git('log', '--format=', '--name-only', '--diff-merges=first-parent', baseline + '..' + sha).splitlines()) - {''})


def validate_root_inventory(workspace, registry, previous=None):
    registered = {r['path'] for r in registry['roots']}
    if previous:
        removed = {r['path'] for r in previous['roots']} - registered
        if removed:
            raise ValueError('Registry root retirement requires a separate reviewed procedure: ' + ', '.join(sorted(removed)))
    source_root = workspace / 'terraform/environments'
    for file in [*source_root.rglob('*.tf'), *source_root.rglob('*.tf.json')]:
        relative = file.relative_to(workspace).as_posix()
        if '.terraform' in file.parts or any(relative.startswith('terraform/environments/' + env + '/bootstrap/ci-identity/') for env in ('dev', 'prod')):
            continue
        if not any(relative.startswith(root + '/') for root in registered):
            raise ValueError('Terraform source is outside registered deployment roots: ' + relative)


def main():
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    os.chdir(workspace)
    def git(*args):
        return subprocess.check_output(['git', *args], text=True).strip()
    preview = len(sys.argv) == 2 and sys.argv[1] == 'preview'
    if git('rev-parse', 'HEAD') != os.environ['GITHUB_SHA']:
        raise ValueError('Checkout SHA mismatch.')
    if preview:
        if not re.fullmatch(r'refs/pull/\d+/merge', os.environ['GITHUB_REF']):
            raise ValueError('Preview requires a PR merge ref.')
    elif os.environ['GITHUB_REF'] != 'refs/heads/main' or git('rev-parse', 'origin/main') != os.environ['GITHUB_SHA']:
        raise ValueError('Deployment must start from the current main SHA.')
    registry = json.loads(Path('ci/roots.json').read_text())
    graph = json.loads(Path('ci/deploy-roots.json').read_text())['dependencies']
    if not Path(activation.ACTIVATION_PATH).is_file():
        raise ValueError('Missing ci/course-activation.json. First support installation requires an explicit --prepared-chapter (for example BU02). Normal CI never infers activation from directories.')
    document = json.loads(Path(activation.ACTIVATION_PATH).read_text())
    catalogs = activation.read_catalogs(workspace)
    existing = {r['path'] for r in registry['roots'] if Path(r['path']).is_dir()}
    requested = None if preview else (os.environ.get('INPUT_ROOT') or None)
    changed = []
    comparison_refs = []
    if preview:
        before = os.environ.get('BASE_SHA', '')
        if not re.fullmatch(r'[0-9a-f]{40}', before):
            raise ValueError('Invalid pull request base SHA.')
        changed = git('diff', '--name-only', before + '...' + os.environ['GITHUB_SHA']).splitlines()
        comparison_refs.append(before)
    else:
        # Manual retries must obey the same activation-retirement guards as push.
        baseline = last_successful_push(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_RUN_ID'])
        changed = changed_since_success(git, baseline, os.environ['GITHUB_SHA'])
        if baseline:
            comparison_refs.append(baseline)
        # Also retain roots prepared after the last successful deployment. A failed
        # first deployment cannot make a later deactivation/removal look harmless.
        parents = git('rev-list', '--parents', '-n', '1', os.environ['GITHUB_SHA']).split()
        if len(parents) > 1:
            comparison_refs.append(parents[1])
        # Successful deployment can lag several pushes, or not exist yet. Retain
        # every activation that reached the main first-parent history in that
        # interval, even when a later failed push removed it again.
        interval = baseline + '..' + os.environ['GITHUB_SHA'] if baseline else os.environ['GITHUB_SHA']
        comparison_refs.extend(git('log', '--first-parent', '--format=%H', interval, '--', activation.ACTIVATION_PATH).splitlines())
    validate_root_inventory(workspace, registry)
    active, effective_graph = activation.deployment_graph(document, registry, graph, catalogs)
    for before in dict.fromkeys(comparison_refs):
        # Installation can legitimately precede both registry and activation files.
        for name in ('ci/roots.json', activation.ACTIVATION_PATH):
            available = subprocess.run(['git', 'cat-file', '-e', before + ':' + name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if not available:
                continue
            previous = json.loads(git('show', before + ':' + name))
            if name == 'ci/roots.json':
                validate_root_inventory(workspace, registry, previous)
            else:
                activation.validate_activation(document, registry, graph, catalogs, previous)
    # Do not obtain cloud credentials or emit even preview jobs for partial roots.
    activation.validate_root_readiness(workspace, active)
    result = waves(registry, effective_graph, existing, changed, requested, active=active)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
        out.write('matrix=' + json.dumps([root for stage in result for root in stage], separators=(',', ':')) + '\n')
        out.write('has_roots=' + str(bool(result)).lower() + '\n')
        for n in range(MAX_WAVES):
            stage = result[n] if n < len(result) else []
            for env in ('dev', 'prod'):
                out.write(env + '_wave_' + str(n) + '=' + json.dumps([r for r in stage if r['env'] == env], separators=(',', ':')) + '\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as out:
        out.write('## 의존 순서 배포 대상\n\n')
        for n, stage in enumerate(result):
            out.write(str(n + 1) + '. ' + ', '.join('`' + r['path'] + '`' for r in stage) + '\n')
        if not result:
            out.write('Terraform 영향 범위 없음. 인프라 배포 job은 실행하지 않습니다.\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print('::error::' + str(error))
        sys.exit(1)
