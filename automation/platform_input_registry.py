"""Select reviewed field/target registrations for the current build stage.

Missing environments means dev and prod, preserving the completed registry.
Explicit environments is a source-reviewed construction boundary, not runtime
permission to ignore an absent registered consumer.
"""
import copy


def scope_enabled(item, environment):
    scope = item.get('environments', ['dev', 'prod'])
    if (not isinstance(scope, list) or not scope
            or any(value not in ('dev', 'prod') for value in scope)
            or len(set(scope)) != len(scope)):
        raise ValueError('registry environments must be a nonempty unique dev/prod list')
    return environment in scope


def active_entries(registry, root, environment):
    if environment not in ('dev', 'prod'):
        raise ValueError('unsupported registry environment')
    selected = []
    # Validate every declared scope even if another root is selected.
    for entry in registry:
        enabled = scope_enabled(entry, environment)
        targets = [target for target in entry['targets']
                   if scope_enabled(target, environment)]
        if enabled and entry['root'] == root and targets:
            current = copy.deepcopy(entry)
            current['targets'] = copy.deepcopy(targets)
            selected.append(current)
    return selected
