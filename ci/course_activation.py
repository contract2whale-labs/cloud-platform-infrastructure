#!/usr/bin/env python3
"""Explicit, monotonic source preparation for normal Terraform CI.

This contract is independent of lifecycle Down/Up registration and hook readiness.
The full registries describe possible roots; only this document authorizes normal
CI selection. Helpers are pure and never infer activation from checkout files.
"""
from copy import deepcopy
import json
from pathlib import Path
import re

ENVIRONMENTS = ('dev', 'prod')
ACTIVATION_PATH = 'ci/course-activation.json'
ROOT_PATTERN = r'terraform/environments/(dev|prod)/[a-z0-9][a-z0-9/_-]*'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def external_root(path):
    return path.endswith('/bootstrap/state') or path.endswith('/bootstrap/ci-identity')


def validate_registries(registry, graph):
    need(isinstance(registry, dict) and set(registry) == {'roots'} and isinstance(registry['roots'], list), 'Invalid root registry.')
    roots = {}
    for row in registry['roots']:
        need(isinstance(row, dict) and set(row) == {'env', 'path'}, 'Invalid registered root row.')
        path = row['path']
        need(isinstance(path, str) and re.fullmatch(ROOT_PATTERN, path) is not None and '..' not in path.split('/'), 'Invalid registered root path.')
        need(row['env'] == path.split('/')[2], 'Registered environment mismatch.')
        need(path not in roots, 'Duplicate registered root.')
        roots[path] = row
    need(isinstance(graph, dict) and set(graph) == set(roots), 'Root and dependency registries must contain the same unique paths.')
    for path, deps in graph.items():
        need(isinstance(deps, list) and all(isinstance(d, str) for d in deps) and len(set(deps)) == len(deps), 'Invalid dependency list.')
        need(all(d in roots and d != path and roots[d]['env'] == roots[path]['env'] for d in deps), 'Invalid, missing or cross-environment dependency.')
    remaining = set(roots)
    while remaining:
        ready = {p for p in remaining if not (set(graph[p]) & remaining)}
        need(bool(ready), 'Dependency cycle detected.')
        remaining -= ready
    return roots


def chapter_assignments(catalogs):
    """Read chapter ownership, ignoring lifecycle modes, blockers and enabled flags."""
    need(isinstance(catalogs, dict) and set(catalogs) == set(ENVIRONMENTS), 'Both environment chapter catalogs are required.')
    result, orders = {}, {}
    for env in ENVIRONMENTS:
        catalog = catalogs[env]
        order = catalog.get('chapter_order')
        need(isinstance(order, list) and bool(order) and all(isinstance(c, str) for c in order) and len(set(order)) == len(order), 'Invalid chapter order.')
        need(isinstance(catalog.get('chapters'), dict) and set(catalog['chapters']) == set(order), 'Chapter catalog and order differ.')
        orders[env] = order
        result[env] = {}
        for chapter in order:
            rows = catalog['chapters'][chapter].get('roots')
            need(isinstance(rows, list), 'Invalid chapter root list.')
            for path in rows:
                need(isinstance(path, str) and re.fullmatch(ROOT_PATTERN, path) is not None and path.split('/')[2] == env, 'Chapter root environment mismatch.')
                result[env].setdefault(path, chapter)
    need(orders['dev'] == orders['prod'], 'Environment chapter orders differ.')
    return result, orders


def empty_activation():
    return {'schema': 1, 'environments': {env: {'prepared_chapter': None, 'roots': []} for env in ENVIRONMENTS}}


def _shape(document, orders):
    need(isinstance(document, dict) and set(document) == {'schema', 'environments'} and type(document['schema']) is int and document['schema'] == 1, 'Invalid course activation schema.')
    need(isinstance(document['environments'], dict) and set(document['environments']) == set(ENVIRONMENTS), 'Activation must name exactly dev and prod.')
    active = set()
    for env, row in document['environments'].items():
        need(isinstance(row, dict) and set(row) == {'prepared_chapter', 'roots'}, 'Invalid environment activation row.')
        chapter, paths = row['prepared_chapter'], row['roots']
        need(chapter is None or chapter in orders[env], 'Unknown prepared chapter.')
        need(isinstance(paths, list) and all(isinstance(p, str) for p in paths) and len(set(paths)) == len(paths), 'Activation roots must be a unique list.')
        need(chapter is not None or not paths, 'Unprepared environment cannot activate roots.')
        for path in paths:
            need(re.fullmatch(ROOT_PATTERN, path) is not None and path.split('/')[2] == env, 'Activated root environment mismatch.')
            need(not external_root(path), 'Bootstrap State and CI identity are external prerequisites, never ordinary CI roots: ' + path)
        active.update(paths)
    return active


def _deferred_dependency(path, dependency, document):
    # BU02 predates the retained log-storage split introduced in BU03. This is
    # the only chapter-gated edge; it never activates/creates storage implicitly.
    env = path.split('/')[2]
    return (env == 'dev' and document['environments'][env]['prepared_chapter'] == 'BU02'
            and path == 'terraform/environments/dev/network/vpc'
            and dependency == 'terraform/environments/dev/network/log-storage')


def validate_activation(document, registry, graph, catalogs, previous=None):
    """Return active paths after schema, chapter, graph and monotonicity checks."""
    roots = validate_registries(registry, graph)
    assignments, orders = chapter_assignments(catalogs)
    active = _shape(document, orders)
    need(active <= roots.keys(), 'Activated root is outside the full root registry.')
    for env, row in document['environments'].items():
        if row['prepared_chapter'] is None:
            continue
        limit = orders[env].index(row['prepared_chapter'])
        for path in row['roots']:
            introduction = assignments[env].get(path)
            # Custom learner roots remain explicitly registered/activated. They
            # have no implicit course chapter and are never generated below.
            need(introduction is None or orders[env].index(introduction) <= limit, 'Future chapter root cannot be activated: ' + path)
    for path in active:
        missing = [d for d in graph[path] if d not in active and not external_root(d) and not _deferred_dependency(path, d, document)]
        need(not missing, 'Active root has an inactive dependency: ' + path + (' -> ' + ', '.join(missing) if missing else ''))
    if previous is not None:
        before = _shape(previous, orders)
        removed = before - active
        need(not removed, 'Active root deactivation requires a separate reviewed retirement procedure: ' + ', '.join(sorted(removed)))
        for env in ENVIRONMENTS:
            old = previous['environments'][env]['prepared_chapter']
            new = document['environments'][env]['prepared_chapter']
            need(old is None or (new is not None and orders[env].index(new) >= orders[env].index(old)), 'Prepared chapter cannot move backward: ' + env)
    return active


def deployment_graph(document, registry, graph, catalogs, previous=None):
    active = validate_activation(document, registry, graph, catalogs, previous)
    effective = {path: [d for d in deps if not external_root(d) and not _deferred_dependency(path, d, document)] for path, deps in graph.items()}
    return active, effective


def initial_activation(chapter, catalogs, registry, graph, environments=('dev',)):
    """Explicit first install: activate the chosen environments through chapter.

    BU02 dev selects VPC only; BU03 dev selects VPC and retained log-storage.
    The caller must explicitly supply chapter. No directories are examined.
    """
    assignments, orders = chapter_assignments(catalogs)
    need(isinstance(environments, (tuple, list)) and bool(environments) and len(set(environments)) == len(environments) and all(env in ENVIRONMENTS for env in environments), 'Invalid activation environments.')
    result = empty_activation()
    for env in environments:
        need(chapter in orders[env], 'Unknown prepared chapter.')
        limit = orders[env].index(chapter)
        result['environments'][env] = {'prepared_chapter': chapter, 'roots': sorted(path for path, first in assignments[env].items() if orders[env].index(first) <= limit and not external_root(path))}
    validate_activation(result, registry, graph, catalogs)
    return result


def merge_activation(existing, chapter, selected_roots, catalogs, registry, graph):
    """Add only explicitly selected roots and advance their environment frontier.

    An empty selected list preserves activation exactly. Callers can pass roots
    already active when chapter edits only extend their existing source. Missing
    dependencies are rejected, never auto-added. Upgrade without source changes
    should retain the existing document, not call initial_activation again.
    """
    _, orders = chapter_assignments(catalogs)
    _shape(existing, orders)
    need(isinstance(selected_roots, (list, tuple, set)) and all(isinstance(p, str) for p in selected_roots), 'Explicit selected root paths are required.')
    need(chapter in orders['dev'], 'Unknown prepared chapter.')
    result = deepcopy(existing)
    for path in sorted(set(selected_roots)):
        need(re.fullmatch(ROOT_PATTERN, path) is not None, 'Invalid selected root path.')
        env = path.split('/')[2]
        row = result['environments'][env]
        if row['prepared_chapter'] is None or orders[env].index(chapter) > orders[env].index(row['prepared_chapter']):
            row['prepared_chapter'] = chapter
        row['roots'] = sorted(set(row['roots']) | {path})
    validate_activation(result, registry, graph, catalogs, previous=existing)
    return result


def read_catalogs(workspace):
    workspace = Path(workspace)
    return {env: json.loads((workspace / 'ci' / name).read_text()) for env, name in (('dev', 'lifecycle-targets.json'), ('prod', 'lifecycle-targets-prod.json'))}


def _without_comments(text):
    # Preserve strings while removing HCL comments, so commented example blocks
    # cannot satisfy source/backend/lock readiness.
    pattern = r'"(?:\\.|[^"\\])*"|/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*'
    return re.sub(pattern, lambda match: match[0] if match[0].startswith('"') else '', text)


def validate_root_readiness(workspace, active):
    """Local preflight only; Terraform validate and plan remain authoritative."""
    workspace = Path(workspace).resolve()
    for path in sorted(active):
        root = workspace / path
        need(root.is_dir() and not root.is_symlink() and root.resolve().is_relative_to(workspace), 'Activated root checkout is missing or redirected: ' + path)
        sources = sorted(set(root.glob('*.tf')) | set(root.glob('*.tf.json')))
        need(bool(sources) and all(p.is_file() and not p.is_symlink() for p in sources), 'Activated root needs actual top-level Terraform source: ' + path)
        hcl = '\n'.join(_without_comments(p.read_text()) for p in sources if p.suffix == '.tf')
        structured = [json.loads(p.read_text()) for p in sources if p.name.endswith('.tf.json')]
        has_body = re.search(r'\b(?:resource|module|data)\s+"', hcl) is not None or any(any(key in value for key in ('resource', 'module', 'data')) for value in structured)
        has_backend = re.search(r'\bbackend\s+"s3"\s*\{', hcl) is not None or any('s3' in value.get('terraform', {}).get('backend', {}) for value in structured)
        need(has_body, 'Activated root has only examples or Terraform scaffolding: ' + path)
        need(has_backend, 'Activated root requires an actual S3 backend: ' + path)
        lock = root / '.terraform.lock.hcl'
        need(lock.is_file() and not lock.is_symlink(), 'Activated root requires a committed provider lock: ' + path)
        lock_text = _without_comments(lock.read_text())
        need(re.search(r'\bprovider\s+"[^"\n]+"\s*\{', lock_text) is not None and re.search(r'\bversion\s*=\s*"[0-9][^"\n]*"', lock_text) is not None and re.search(r'\bhashes\s*=\s*\[\s*"(?:h1:|zh:)[^"\n]+"', lock_text) is not None, 'Activated root provider lock is empty or incomplete: ' + path)


def main():
    import argparse
    import os
    import tempfile

    parser = argparse.ArgumentParser(description='Explicitly prepare authored chapter roots for normal CI. No cloud calls.')
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--prepare', required=True, help='Chapter whose selected source is prepared, such as BU04 or BU15.')
    parser.add_argument('--environment', required=True, choices=ENVIRONMENTS)
    parser.add_argument('--roots', required=True, nargs='+', help='Explicit full registered root paths; dependencies are never added automatically.')
    parser.add_argument('--write', action='store_true', help='Write the reviewed local activation change after source/backend/lock readiness checks.')
    args = parser.parse_args()
    workspace = args.repo.expanduser().resolve()
    path = workspace / ACTIVATION_PATH
    need(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(workspace), 'Install common CI with an explicit --prepared-chapter first; course activation must already exist.')
    need(all(root.startswith('terraform/environments/' + args.environment + '/') for root in args.roots), 'Every selected root must match --environment.')
    registry = json.loads((workspace / 'ci/roots.json').read_text())
    graph = json.loads((workspace / 'ci/deploy-roots.json').read_text())['dependencies']
    existing = json.loads(path.read_text())
    result = merge_activation(existing, args.prepare, args.roots, read_catalogs(workspace), registry, graph)
    # Author real source and pin locks first. This command never manufactures
    # root source merely to make an activation pass.
    validate_root_readiness(workspace, set(args.roots))
    data = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    print(data, end='')
    if not args.write:
        print('Read-only activation preview. Add --write to save this local change, then review the ordinary PR.')
        return
    fd, name = tempfile.mkstemp(prefix='.course-activation-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(data)
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print('Saved explicit local activation. Review source and activation together in the ordinary PR; no cloud action occurred.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit('Activation stopped: ' + str(error))
