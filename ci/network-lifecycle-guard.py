#!/usr/bin/env python3
"""Read-only cumulative network guard; retained S3 ownership is never destroyed.

The BU02 guard remains unchanged. A private module instance extends its type set
for BU03 log subscriptions and reservations only; S3, IAM, KMS stay forbidden.
AWS denial, missing fields, unknown ownership and incomplete pages always block.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
VPC = 'terraform/environments/dev/network/vpc'
PEER = 'terraform/environments/dev/network/peer'
TRANSIT = 'terraform/environments/dev/network/transit'
LOG = 'terraform/environments/dev/network/log-storage'
LOG_TYPES = frozenset({'aws_flow_log', 'aws_route53_resolver_query_log_config',
                       'aws_route53_resolver_query_log_config_association'})
EXTRA_TYPES = LOG_TYPES | {'aws_ec2_subnet_cidr_reservation'}
STORAGE_TYPES = frozenset({'aws_s3_bucket', 'aws_s3_bucket_ownership_controls',
    'aws_s3_bucket_server_side_encryption_configuration', 'aws_s3_bucket_public_access_block',
    'aws_s3_bucket_lifecycle_configuration', 'aws_s3_bucket_policy', 'aws_s3_bucket_versioning'})


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


v = load('network_base_vpc_guard', 'vpc-lifecycle-guard.py')
v.NETWORK_TYPES = v.NETWORK_TYPES | EXTRA_TYPES
v.READ_OPERATIONS = v.READ_OPERATIONS | {
    ('ec2', 'describe-flow-logs'), ('ec2', 'get-subnet-cidr-reservations'),
    ('route53resolver', 'list-resolver-query-log-config-associations'),
    ('route53resolver', 'list-resolver-query-log-configs'),
}
SafeError, require = v.SafeError, v.require
normalize_resources, managed_resources = v.normalize_resources, v.managed_resources
VersionedStateReader = v.VersionedStateReader


def configure(environment):
    """One account per adapter instance; Prod supports only the mapped VPC root."""
    global VPC,PEER,TRANSIT,LOG
    require(environment in ('dev','prod'),'Unknown network environment.')
    VPC='terraform/environments/'+environment+'/network/vpc'
    PEER='terraform/environments/'+environment+'/network/peer'
    TRANSIT='terraform/environments/'+environment+'/network/transit'
    LOG='terraform/environments/'+environment+'/network/log-storage'
    v.ROOT=VPC


def topology():
    return load('network_topology_guard', 'network-topology-guard.py')


def allowed_types(root):
    if root == VPC:
        return v.NETWORK_TYPES
    require(root in (PEER, TRANSIT) and '/dev/' in root, 'Unregistered network root.')
    return topology().ALLOWED_TYPES[root]


def key(root):
    require(re.fullmatch(r'terraform/environments/(dev|prod)/[a-z0-9][a-z0-9/_-]*', root) is not None,
            'Invalid Dev dependency root.')
    return '/'.join(root.split('/')[3:]) + '/terraform.tfstate'


def read_upstreams(workspace, context, *, load_state=None):
    graph = json.loads((Path(workspace) / 'ci/deploy-roots.json').read_text())['dependencies']
    root = context['root']; require(root in graph, 'Network root missing from dependency graph.')
    names = set(graph[root])
    require(all(name.split('/')[2]==root.split('/')[2] for name in names),'Cross-account upstream is forbidden.')
    # BU03 retained storage is a potential optional dependency at BU02. It is
    # always pinned, including absence, so a mid-run storage introduction blocks.
    if root == VPC and '/dev/' in root:
        names.add(LOG)
    if root == TRANSIT:
        names |= {VPC, PEER}
        require(set(graph[root]) <= {VPC, PEER, LOG}, 'Unreviewed transit State dependency.')
    reader = load_state or VersionedStateReader(context['backend']['bucket'], context['account'], context['backend']['region'])
    return {name: reader(key(name)) for name in sorted(names)}


def upstream_fingerprints(workspace, context, *, load_state=None):
    return {name: row['fingerprint'] for name, row in read_upstreams(workspace, context, load_state=load_state).items()}


def state_value(value):
    return value.get('state') if isinstance(value, dict) and 'fingerprint' in value else value


def storage_contract(context, upstream):
    state = state_value(upstream.get(LOG))
    require(isinstance(state, dict), 'Retained network log-storage State is required for log subscriptions.')
    rows = managed_resources(state)
    require({row['type'] for row in rows} == STORAGE_TYPES and len(rows) == len(STORAGE_TYPES),
            'Retained network log-storage ownership/configuration is incomplete or unsupported.')
    name = f"cp-{context['environment']}-network-logs-{context['account']}-{context['backend']['region']}"
    arn = 'arn:aws:s3:::' + name
    for row in rows:
        require(row['address'] == row['type'] + '.network_logs', 'Unknown retained log-storage resource identity.')
        values = row['values']
        require(values.get('id') == name and values.get('bucket') == name,
                'Retained storage resource refers to another bucket.')
        if row['type'] == 'aws_s3_bucket':
            require(values.get('arn') == arn and values.get('force_destroy') is False,
                    'Retained bucket identity/protection is not established.')
    attributes = {row['type']: row['values'] for row in rows}
    ownership = attributes['aws_s3_bucket_ownership_controls'].get('rule')
    require(isinstance(ownership, list) and len(ownership) == 1 and ownership[0].get('object_ownership') == 'BucketOwnerEnforced',
            'Retained bucket ownership enforcement is missing.')
    encryption = attributes['aws_s3_bucket_server_side_encryption_configuration'].get('rule')
    require(isinstance(encryption, list) and len(encryption) == 1 and
            isinstance(encryption[0].get('apply_server_side_encryption_by_default'), list) and
            len(encryption[0]['apply_server_side_encryption_by_default']) == 1 and
            encryption[0]['apply_server_side_encryption_by_default'][0].get('sse_algorithm') == 'AES256' and
            not encryption[0]['apply_server_side_encryption_by_default'][0].get('kms_master_key_id'),
            'Retained bucket must use the reviewed AES256 encryption contract.')
    public = attributes['aws_s3_bucket_public_access_block']
    require(all(public.get(field) is True for field in ('block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets')),
            'Retained bucket public-access protection is incomplete.')
    versioning = attributes['aws_s3_bucket_versioning'].get('versioning_configuration')
    require(isinstance(versioning, list) and len(versioning) == 1 and versioning[0].get('status') == 'Enabled',
            'Retained bucket versioning must be enabled.')
    rules = attributes['aws_s3_bucket_lifecycle_configuration'].get('rule')
    require(isinstance(rules, list), 'Retained bucket lifecycle configuration is missing.')
    require(all(isinstance(rule, dict) and rule.get('status') in ('Enabled', 'Disabled') and
                not (rule['status'] == 'Enabled' and any(rule.get(field) for field in ('expiration', 'noncurrent_version_expiration')))
                for rule in rules), 'Retained objects or previous versions have an enabled expiration policy.')
    try:
        policy = json.loads(attributes['aws_s3_bucket_policy']['policy'])
    except (ValueError, TypeError, KeyError):
        raise SafeError('Retained bucket deletion-protection policy is missing or invalid.') from None
    def as_set(value):
        return {value} if isinstance(value, str) else set(value) if isinstance(value, list) and all(isinstance(x, str) for x in value) else set()
    require(any(isinstance(statement, dict) and statement.get('Effect') == 'Deny' and statement.get('Principal') == '*' and
                not statement.get('Condition') and {'s3:DeleteBucket','s3:DeleteObject','s3:DeleteObjectVersion'} <= as_set(statement.get('Action')) and
                {arn, arn + '/*'} <= as_set(statement.get('Resource')) for statement in policy.get('Statement', [])),
            'Retained bucket policy must explicitly deny bucket/object/version deletion.')
    outputs = state.get('outputs', {})
    require(outputs.get('network_logs_bucket_name', {}).get('value') == name and
            outputs.get('network_logs_bucket_arn', {}).get('value') == arn,
            'Retained storage outputs differ from its owned bucket.')
    return name, arn


def validate_log_rows(context, rows, upstream, *, planned=False, original=None):
    logging = [row for row in rows if row['type'] in LOG_TYPES]
    if not logging:
        return
    _, arn = storage_contract(context, upstream)
    vpcs = {r['values'].get('id') for r in rows if r['type'] == 'aws_vpc'}
    configs = {r['values'].get('id') for r in rows if r['type'] == 'aws_route53_resolver_query_log_config'}
    vpcs |= {r['id'] for r in (original or []) if r['type'] == 'aws_vpc'}
    configs |= {r['id'] for r in (original or []) if r['type'] == 'aws_route53_resolver_query_log_config'}
    for row in logging:
        kind, values = row['type'], row['values']
        require(row['address'] == kind + '.vpc', 'Unknown network logging subscription address.')
        if kind == 'aws_flow_log':
            require(values.get('log_destination') == arn + '/flow/' and values.get('log_destination_type') == 's3' and
                    not values.get('iam_role_arn') and not values.get('log_group_name'),
                    'Flow log destination must be the retained S3 flow prefix.')
            if not planned or values.get('vpc_id'):
                require(values.get('vpc_id') in vpcs, 'Flow log belongs to another VPC.')
        elif kind == 'aws_route53_resolver_query_log_config':
            require(values.get('destination_arn') == arn + '/dns/', 'Resolver log destination must be the retained S3 DNS prefix.')
        else:
            if not planned or values.get('resource_id'):
                require(values.get('resource_id') in vpcs, 'Resolver logging association belongs to another VPC.')
            if not planned or values.get('resolver_query_log_config_id'):
                require(values.get('resolver_query_log_config_id') in configs,
                        'Resolver association uses a configuration outside this State.')


def validate_state(context, state, *, expected_resources=None, upstream_states=None):
    upstream = upstream_states or {}
    if context['root'] != VPC:
        return topology().validate_state(context, state, expected_resources=expected_resources, upstream_states={k: val for k, val in upstream.items() if k in (VPC, PEER)})
    rows = v.validate_network_state(context, state, expected_resources=expected_resources)
    if state_value(upstream.get(LOG)) is not None:
        storage_contract(context, upstream)
    validate_log_rows(context, rows, upstream, original=expected_resources)
    return rows


def planned_rows(plan):
    result = []
    def visit(module):
        for row in module.get('resources', []):
            if row.get('mode') == 'managed':
                result.append({'address': row.get('address'), 'type': row.get('type'), 'values': row.get('values', {})})
        for child in module.get('child_modules', []): visit(child)
    visit(plan.get('planned_values', {}).get('root_module', {}))
    return result


def validate_plan_contracts(context, plan, upstream):
    rows = planned_rows(plan)
    if context['root'] == VPC:
        validate_log_rows(context, rows, upstream, planned=True)
    else:
        # Source/State type validation remains independent: retained buckets,
        # account identity and unreviewed extensions cannot enter an Up plan.
        topology().validate_plan_contracts(context, plan, {k: val for k, val in upstream.items() if k in (VPC, PEER)})


def inventory_logging(context, rows, vpc_id, upstream, aws_call=None):
    call = aws_call or v.aws_read
    region, account = context['backend']['region'], context['account']
    by_type = {}
    for row in rows: by_type.setdefault(row['type'], {})[row['values']['id']] = row['values']
    def read(service, operation, field, *args):
        result = v.complete_list(call(service, operation, *args, '--region', region), field)
        require(all(isinstance(row, dict) for row in result), 'Malformed network logging inventory.')
        return result
    logged_resources = {vpc_id} | set(by_type.get('aws_subnet', {})) | set(by_type.get('aws_network_interface', {}))
    logged_resources |= {value['network_interface_id'] for value in by_type.get('aws_nat_gateway', {}).values() if value.get('network_interface_id')}
    for value in by_type.get('aws_vpc_endpoint', {}).values():
        logged_resources |= set(v.array(value.get('network_interface_ids', [])))
    require(all(isinstance(identity, str) and re.fullmatch(r'(?:vpc|subnet|eni)-(?:[0-9a-f]{8}|[0-9a-f]{17})', identity) for identity in logged_resources),
            'Logging inventory resource identities are incomplete.')
    logs = read('ec2', 'describe-flow-logs', 'FlowLogs', '--filter', 'Name=resource-id,Values=' + ','.join(sorted(logged_resources)))
    owned = by_type.get('aws_flow_log', {})
    require({row.get('FlowLogId') for row in logs} == set(owned) and len(logs) == len(owned), 'Unknown or missing VPC flow log.')
    for row in logs:
        value = owned[row['FlowLogId']]
        require(row.get('ResourceId') == vpc_id and row.get('LogDestinationType') == 's3' and
                row.get('LogDestination') == value.get('log_destination') and row.get('FlowLogStatus') == 'ACTIVE',
                'Live flow log does not match the retained S3 subscription.')
    associations = read('route53resolver', 'list-resolver-query-log-config-associations', 'ResolverQueryLogConfigAssociations',
                        '--filters', 'Name=ResourceId,Values=' + vpc_id)
    owned_assoc = by_type.get('aws_route53_resolver_query_log_config_association', {})
    require({row.get('Id') for row in associations} == set(owned_assoc) and len(associations) == len(owned_assoc),
            'Unknown or missing Resolver logging association.')
    for row in associations:
        value = owned_assoc[row['Id']]
        require(row.get('ResourceId') == vpc_id and row.get('ResolverQueryLogConfigId') == value.get('resolver_query_log_config_id') and
                row.get('Status') == 'CREATED', 'Live Resolver association differs from managed State.')
    for identity, value in by_type.get('aws_route53_resolver_query_log_config', {}).items():
        configs = read('route53resolver', 'list-resolver-query-log-configs', 'ResolverQueryLogConfigs', '--filters', 'Name=Id,Values=' + identity)
        require(len(configs) == 1 and configs[0].get('Id') == identity and configs[0].get('OwnerId') == account and
                configs[0].get('DestinationArn') == value.get('destination_arn') and configs[0].get('Status') == 'CREATED' and
                configs[0].get('ShareStatus') == 'NOT_SHARED',
                'Resolver configuration owner/destination changed.')
        consumers = read('route53resolver', 'list-resolver-query-log-config-associations', 'ResolverQueryLogConfigAssociations',
                         '--filters', 'Name=ResolverQueryLogConfigId,Values=' + identity)
        require({row.get('Id') for row in consumers} == {i for i, val in owned_assoc.items() if val.get('resolver_query_log_config_id') == identity} and
                all(row.get('ResourceId') == vpc_id for row in consumers), 'Another VPC consumes the managed Resolver log configuration.')
    reservations = by_type.get('aws_ec2_subnet_cidr_reservation', {})
    found = set()
    for subnet in by_type.get('aws_subnet', {}):
        response = call('ec2', 'get-subnet-cidr-reservations', '--subnet-id', subnet, '--region', region)
        ipv4 = v.complete_list(response, 'SubnetIpv4CidrReservations')
        ipv6 = v.complete_list(response, 'SubnetIpv6CidrReservations')
        for row in ipv4 + ipv6:
            identity = row.get('SubnetCidrReservationId'); value = reservations.get(identity)
            require(identity not in found and value is not None and row.get('SubnetId') == subnet and row.get('OwnerId') == account and
                    row.get('Cidr') == value.get('cidr_block') and row.get('ReservationType') == value.get('reservation_type'),
                    'Unknown or changed subnet CIDR reservation.')
            found.add(identity)
    require(found == set(reservations), 'Managed subnet reservations are missing.')
    return {'flow_logs': len(logs), 'resolver_associations': len(associations), 'subnet_reservations': len(found)}


def dependent_states(workspace, context, *, load_state=None):
    graph = json.loads((Path(workspace) / 'ci/deploy-roots.json').read_text())['dependencies']
    reached = {context['root']}
    require(context['root'] in graph, 'Network root missing from dependency graph.')
    while True:
        expanded = reached | {name for name, deps in graph.items() if set(deps) & reached}
        if expanded == reached: break
        reached = expanded
    require(all(name.split('/')[2]==context['root'].split('/')[2] for name in reached),'Cross-account dependent State is forbidden.')
    reader = load_state or VersionedStateReader(context['backend']['bucket'], context['account'], context['backend']['region'])
    return {name: reader(key(name)) for name in sorted(reached - {context['root']})}


def guard_destroy(workspace, context, state, plan, *, expected_resources, upstream_states, stage, aws_call=None, load_state=None):
    require(stage in ('plan', 'apply'), 'Unknown network guard phase.')
    rows = validate_state(context, state, expected_resources=expected_resources, upstream_states=upstream_states)
    dependents = dependent_states(workspace, context, load_state=load_state)
    live = {name: item for name, item in dependents.items() if item['state'] is not None and managed_resources(item['state'])}
    selected = set(context.get('selected_roots', []))
    # Only complete saved-plan proofs can defer additional selected consumers.
    # Apply never accepts deferral, regardless of supplied descriptors.
    require(not live or stage == 'plan' and set(live) <= selected,
            'A non-retired or unselected dependent root still has managed State.')
    consumer_evidence = None
    deferred = None
    if live:
        consumer = load('network_consumer_proof', 'network-consumer-proof.py')
        descriptors = consumer.selected_descriptors()
        if descriptors:
            consumer_evidence = consumer.prove_consumers(workspace, context, live, descriptors)
            deferred = {'saved_plan_consumer_proof': True}
        else:
            require(set(live) == {TRANSIT}, 'A live consumer lacks a registered exact saved-plan proof.')
    if TRANSIT in live:
        transit = live[TRANSIT]['state']
        # Controller starts every selected root before it creates the bundle.
        control = load('network_lifecycle_state', 'lifecycle-state.py')
        helper = load('network_saved_plan', 'saved-plan.py')
        store = helper.Store(context['backend']['bucket'], context['account'])
        record, _ = control.read_json(store, f"ci-lifecycle/{context['repository_id']}/dev/network-transit.json")
        require(record is not None and record.get('root') == TRANSIT and record.get('phase') == 'paused' and
                record.get('operation') == 'down' and record.get('request_run') == context['run_id'] and
                record.get('request_attempt') == context['run_attempt'] and record.get('workflow_sha') == context['sha'] and
                record.get('repository_id') == context['repository_id'] and record.get('account') == context['account'] and
                record.get('bucket') == context['backend']['bucket'] and record.get('region') == context['backend']['region'] and
                record.get('snapshot_sha') == context['source_sha'] and record.get('generation') == context['generation'],
                'Selected transit consumer lacks this exact paused request identity.')
        original = record.get('original_state_identity', {})
        require(transit.get('lineage') == original.get('lineage') and type(transit.get('serial')) is int and
                transit['serial'] >= original.get('serial', -1), 'Selected consumer State lineage changed or serial rolled back.')
        states = dict(upstream_states)
        states[context['root']] = state
        # For VPC preplan load the peer upstream explicitly; it is never an
        # unvalidated output-only contract.
        reader = load_state or VersionedStateReader(context['backend']['bucket'], context['account'], context['backend']['region'])
        for root in (VPC, PEER):
            if root not in states: states[root] = reader(key(root))
        transit_context = {**context, 'root': TRANSIT, 'backend': {**context['backend'], 'key': key(TRANSIT)}}
        deferred = topology().prove_selected_transit(transit_context, transit, record.get('original_resources'), {k: val for k, val in states.items() if k in (VPC, PEER)}, aws_call=aws_call)
    if context['root'] != VPC:
        if context['root'] == PEER:
            peers = [r['id'] for r in expected_resources if r['type'] == 'aws_vpc']
            require(len(peers) == 1, 'Exactly one original peer VPC is required.')
            inventory_logging(context, rows, peers[0], upstream_states, aws_call)
        if deferred is not None:
            topology().validate_destroy(state, plan, expected_resources=expected_resources)
            return {'dependent_states': {k: val['fingerprint'] for k, val in dependents.items()},
                    'deferred_runtime_consumer_check': True, 'selected_transit': deferred if TRANSIT in live else None, 'deferred_consumers': consumer_evidence}
        return topology().guard_destroy(workspace, context, state, plan, expected_resources=expected_resources,
                                        upstream_states={k: val for k, val in upstream_states.items() if k in (VPC, PEER)}, aws_call=aws_call, load_state=load_state)
    original_vpcs = [r['id'] for r in expected_resources if r['type'] == 'aws_vpc']
    require(len(original_vpcs) == 1, 'Exactly one original VPC identity is required.')
    rows, vpc_id = v.validate_destroy(state, plan, expected_resources=expected_resources, expected_vpc_id=original_vpcs[0])
    call = aws_call or v.aws_read
    require(v.object_value(call('sts', 'get-caller-identity', '--region', context['backend']['region'])).get('Account') == context['account'],
            'AWS caller differs from the approved account.')
    log_evidence = inventory_logging(context, rows, vpc_id, upstream_states, call)
    if deferred is not None:
        # Never claim TGW ENI ownership from descriptions, tags, or subnet alone.
        # The private bundle explicitly exposes the deferred live VPC gate.
        return {'vpc_id': vpc_id, 'dependent_states': {k: val['fingerprint'] for k, val in dependents.items()},
                'logging': log_evidence, 'deferred_runtime_consumer_check': True, 'selected_transit': deferred if TRANSIT in live else None, 'deferred_consumers': consumer_evidence}
    inventory = v.inventory_consumers(rows, vpc_id, context['account'], context['backend']['region'], call, expected_resources=expected_resources)
    return {'vpc_id': vpc_id, 'dependent_states': {k: val['fingerprint'] for k, val in dependents.items()},
            'inventory_counts': inventory, 'logging': log_evidence, 'deferred_runtime_consumer_check': False}


def verify_absent(context, expected_resources, *, aws_call=None):
    if context['root'] != VPC:
        return topology().verify_absent(context, expected_resources, aws_call=aws_call)
    vpcs = [row['id'] for row in expected_resources if row['type'] == 'aws_vpc']
    require(len(vpcs) == 1, 'Missing original VPC identity.')
    call = aws_call or v.aws_read
    evidence = v.verify_vpc_absent(context, vpcs[0], aws_call=call)
    scope = v.original_resources(expected_resources)
    region = context['backend']['region']
    checks = (
        ('aws_eip', 'describe-addresses', 'Addresses', 'allocation-id', 'AllocationId', 'eipalloc'),
        ('aws_internet_gateway', 'describe-internet-gateways', 'InternetGateways', 'internet-gateway-id', 'InternetGatewayId', 'igw'),
        ('aws_nat_gateway', 'describe-nat-gateways', 'NatGateways', 'nat-gateway-id', 'NatGatewayId', 'nat'),
        ('aws_vpc_endpoint', 'describe-vpc-endpoints', 'VpcEndpoints', 'vpc-endpoint-id', 'VpcEndpointId', 'vpce'),
        ('aws_subnet', 'describe-subnets', 'Subnets', 'subnet-id', 'SubnetId', 'subnet'),
        ('aws_network_interface', 'describe-network-interfaces', 'NetworkInterfaces', 'network-interface-id', 'NetworkInterfaceId', 'eni'),
        ('aws_route_table', 'describe-route-tables', 'RouteTables', 'route-table-id', 'RouteTableId', 'rtb'),
        ('aws_default_route_table', 'describe-route-tables', 'RouteTables', 'route-table-id', 'RouteTableId', 'rtb'),
        ('aws_security_group', 'describe-security-groups', 'SecurityGroups', 'group-id', 'GroupId', 'sg'),
        ('aws_default_security_group', 'describe-security-groups', 'SecurityGroups', 'group-id', 'GroupId', 'sg'),
        ('aws_network_acl', 'describe-network-acls', 'NetworkAcls', 'network-acl-id', 'NetworkAclId', 'acl'),
        ('aws_default_network_acl', 'describe-network-acls', 'NetworkAcls', 'network-acl-id', 'NetworkAclId', 'acl'),
        ('aws_flow_log', 'describe-flow-logs', 'FlowLogs', 'flow-log-id', 'FlowLogId', 'fl'),
    )
    counts = {}
    for kind, operation, field, filter_name, identity_field, prefix in checks:
        ids = {row['id'] for row in scope if row['type'] == kind}
        if not ids: continue
        require(all(re.fullmatch(prefix + r'-(?:[0-9a-f]{8}|[0-9a-f]{17})', identity) for identity in ids),
                'An original network identity is invalid for absence verification.')
        option = '--filter' if operation == 'describe-flow-logs' else '--filters'
        rows = v.complete_list(call('ec2', operation, option, 'Name=' + filter_name + ',Values=' + ','.join(sorted(ids)), '--region', region), field)
        require(all(isinstance(row, dict) and row.get(identity_field) in ids for row in rows), 'An exact absence query returned ambiguous network identities.')
        if kind in ('aws_nat_gateway', 'aws_vpc_endpoint'):
            require(all(str(row.get('State', '')).lower() == 'deleted' for row in rows), 'An original network gateway/endpoint remains live after Down.')
        else:
            require(not rows, 'An original network resource remains after Down; keep pause and investigate.')
        counts[kind] = len(ids)
    for kind, operation, field in (
        ('aws_route53_resolver_query_log_config', 'list-resolver-query-log-configs', 'ResolverQueryLogConfigs'),
        ('aws_route53_resolver_query_log_config_association', 'list-resolver-query-log-config-associations', 'ResolverQueryLogConfigAssociations'),
    ):
        ids = {row['id'] for row in scope if row['type'] == kind}
        for identity in sorted(ids):
            require(re.fullmatch(r'[a-z][a-z0-9-]+', identity) is not None, 'Invalid original Resolver log identity.')
            rows = v.complete_list(call('route53resolver', operation, '--filters', 'Name=Id,Values=' + identity, '--region', region), field)
            require(not rows, 'An original Resolver log subscription remains after Down.')
        if ids: counts[kind] = len(ids)
    return {**evidence, 'original_identity_absence': counts}
