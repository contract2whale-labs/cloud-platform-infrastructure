#!/usr/bin/env python3
"""Fixed BU16 AWS operations. No arbitrary command, role, or API dispatch."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


h = module('fixed_ops_saved_plan', 'saved-plan.py')
lc = module('fixed_ops_lifecycle', 'lifecycle-state.py')
OPERATIONS = {
    'metrics-deny-remove': ('metrics', 'remove'),
    'metrics-deny-rollback': ('metrics', 'rollback'),
    'trace-deny-remove': ('trace', 'remove'),
    'trace-deny-rollback': ('trace', 'rollback'),
    'nodegroup-limit': ('nodegroup', 'limit'),
    'nodegroup-restore': ('nodegroup', 'restore'),
}
OWNER = 'aws-fixed-operations'


def now():
    return int(time.time())


def fingerprint(value):
    return h.digest(h.canonical(value))


def context(mode):
    h.require(mode in ('plan', 'apply'), 'Invalid mode.')
    h.require(h.required('GITHUB_REF') == 'refs/heads/main' and h.required('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Use protected main dispatch only.')
    operation = h.required('OPERATION')
    h.require(operation in OPERATIONS, 'Unregistered operation.')
    account = h.required('EXPECTED_ACCOUNT_ID')
    role = f'arn:aws:iam::{account}:role/gha-aws-ops-dev-{mode}'
    h.require(h.required('AWS_ROLE_ARN') == role, 'Unexpected operation role.')
    h.check_identity(account, role)
    result = {'source_sha': h.required('GITHUB_SHA'), 'run_id': h.required('GITHUB_RUN_ID'),
              'run_attempt': h.required('GITHUB_RUN_ATTEMPT'), 'repository_id': h.required('GITHUB_REPOSITORY_ID'),
              'repository': h.required('GITHUB_REPOSITORY'), 'environment': 'dev', 'account': account,
              'bucket': h.required('STATE_BUCKET'), 'region': h.required('AWS_REGION'), 'operation': operation}
    h.require(re.fullmatch('[0-9a-f]{40}', result['source_sha']) and all(result[k].isdigit() for k in ('run_id','run_attempt','repository_id')), 'Invalid run context.')
    h.require(result['region'] == 'ap-northeast-2', 'This fixed operation supports the reviewed Dev region only.')
    h.ensure_current_main({'sha': result['source_sha']})
    return result


def request(ctx):
    data = json.loads(h.required('AWS_OPERATIONS_JSON'))
    h.require(data.get('schema') == 1 and data.get('enabled') is True, 'Fixed operations are not configured.')
    target_type, action = OPERATIONS[ctx['operation']]
    item = data['targets'][target_type]
    h.require(item.get('account') == ctx['account'] and item.get('region') == ctx['region'], 'Approved target context mismatch.')
    h.require(isinstance(item.get('approval_reference'), str) and item['approval_reference'] and item.get('exclusive_window') is True,
              'An approved exclusive change window is required.')
    h.require(isinstance(item.get('valid_until'), int) and now() < item['valid_until'] <= now() + 14400, 'Approval is expired or exceeds four hours.')
    if target_type == 'nodegroup':
        h.require(item.get('cluster') == 'contract2whale-dev-eks' and item.get('nodegroup') == 'contract2whale-dev-eks-app', 'Only the course Dev app nodegroup is supported.')
        h.require(re.fullmatch(r'arn:aws:eks:ap-northeast-2:' + ctx['account'] + r':nodegroup/contract2whale-dev-eks/contract2whale-dev-eks-app/[A-Za-z0-9-]+', item.get('arn', '')), 'Exact nodegroup identity is required.')
        h.require(type(item.get('approved_max')) is int and item['approved_max'] == 3 and item.get('incident_max') == 2, 'Only approved max 3 and incident max 2 are supported.')
    else:
        expected = 'cp-dev-observability-writer'
        # Trace installations use a reviewed exact role, never a CI identity.
        role = item.get('role', '')
        h.require(role == expected, 'Only the fixed workload writer role is supported.')
        h.require(item.get('arn') == f'arn:aws:iam::{ctx["account"]}:role/platform/{role}' and re.fullmatch(r'AROA[A-Z0-9]+', item.get('role_id', '')), 'Exact writer ARN and RoleId required.')
        name = item.get('policy_name', '')
        pattern = r'incident-[0-9]{8}-[0-9]{4}' if target_type == 'metrics' else r'incident-trace-put-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        h.require(re.fullmatch(pattern, name), 'Unrecognized incident policy name.')
        validate_deny(item['document'], item['object_arn'])
        expected_object = f'arn:aws:s3:::cp-dev-observability-{target_type if target_type == "metrics" else "traces"}-{ctx["account"]}-{ctx["region"]}/dev/' + ('metrics/*' if target_type == 'metrics' else 'traces-epoch-3/*')
        h.require(item['object_arn'] == expected_object, 'Object prefix does not match this fixed operation.')
        if target_type == 'trace' and action == 'remove':
            expiry = item['document']['Statement'][0]['Condition']['DateLessThan']['aws:CurrentTime']
            h.require(dt.datetime.fromisoformat(expiry.replace('Z', '+00:00')).timestamp() > now()+600 or item.get('probe_recovery_only') is True, 'Trace fault must remain active during bounded in-operation probes; recovery-only is explicit.')
        if action == 'rollback':
            expiry = item['document']['Statement'][0]['Condition']['DateLessThan']['aws:CurrentTime']
            h.require(dt.datetime.fromisoformat(expiry.replace('Z', '+00:00')).timestamp() > now(), 'Never reinsert an expired Deny.')
    return item


def validate_deny(doc, object_arn):
    h.require(isinstance(object_arn, str) and re.fullmatch(r'arn:aws:s3:::cp-dev-[a-z0-9-]+/dev/(metrics|traces-epoch-3)/\*', object_arn), 'Exact course object prefix required.')
    h.require(set(doc) == {'Version','Statement'} and doc['Version'] == '2012-10-17' and len(doc['Statement']) == 1, 'Unexpected incident policy structure.')
    statement = doc['Statement'][0]
    h.require(set(statement) == {'Effect','Action','Resource','Condition'} and statement['Effect'] == 'Deny' and statement['Action'] == ['s3:PutObject'] and statement['Resource'] == [object_arn], 'Only the exact incident PutObject Deny is permitted.')
    condition = statement['Condition']
    h.require(set(condition) == {'DateLessThan'} and set(condition['DateLessThan']) == {'aws:CurrentTime'}, 'Deny expiry required.')
    h.require(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', condition['DateLessThan']['aws:CurrentTime']), 'Invalid expiry.')


def marker_key(ctx):
    return f'ci-incidents/{ctx["repository_id"]}/dev/active.json'


def check_retention(store, ctx):
    rules = store.call('get-bucket-lifecycle-configuration').get('Rules')
    h.require(isinstance(rules, list), 'Marker retention cannot be verified.')
    for rule in rules:
        if rule.get('Status') != 'Enabled' or not any(k in rule for k in ('Expiration', 'NoncurrentVersionExpiration')):
            continue
        condition = rule.get('Filter', {})
        prefix = condition.get('Prefix', condition.get('And', {}).get('Prefix', rule.get('Prefix', '')))
        h.require(isinstance(prefix, str) and not marker_key(ctx).startswith(prefix), 'An expiration rule can remove incident recovery evidence.')


def check_course(store, ctx):
    for key, validator in ((lc.course_marker_key(ctx['repository_id']), lc.validate_course),
                           (lc.marker_key(ctx['repository_id']), lc.validate)):
        record, _ = lc.read_json(store, key)
        if record is not None:
            validator(record, ctx['repository_id'], ctx['account'], ctx['bucket'], ctx['region'])
            h.require(record['phase'] == 'active', 'Lifecycle pause blocks fixed AWS changes.')


def target_identity(item):
    return {k: v for k, v in item.items() if k not in ('valid_until', 'approval_reference', 'exclusive_window','probe_recovery_only')}


def check_marker(marker, ctx, item):
    if marker is None:
        h.require(OPERATIONS[ctx['operation']][1] not in ('rollback', 'restore'), 'Recovery requires the original incident marker.')
        return
    h.require(marker.get('schema') == 1 and marker.get('phase') in ('idle','active','recovery-required') and
              all(marker.get(k) == ctx[k] for k in ('repository_id','environment','account','bucket','region')), 'Invalid incident control record.')
    action = OPERATIONS[ctx['operation']][1]
    if marker['phase'] != 'idle' or action in ('rollback','restore'):
        h.require(marker.get('owner') == OWNER and marker.get('target') == target_identity(item), 'Another incident owns this change window.')
        expected = ('nodegroup-limit', 'nodegroup-restore') if action == 'restore' else (ctx['operation'],)
        if action == 'rollback': expected = (ctx['operation'].replace('rollback','remove'),)
        if action == 'remove': expected = (ctx['operation'], ctx['operation'].replace('remove','rollback'))
        h.require(marker.get('operation') in expected, 'Recovery does not match the original operation.')
        h.require(action != 'limit', 'An active nodegroup incident must be restored first.')


def observe(item, target_type):
    if target_type == 'nodegroup':
        group = h.aws('eks','describe-nodegroup','--region',item['region'],'--cluster-name',item['cluster'],'--nodegroup-name',item['nodegroup'])['nodegroup']
        h.require(group['nodegroupArn'] == item['arn'] and group['status'] == 'ACTIVE', 'Nodegroup identity or status changed.')
        return {'arn': group['nodegroupArn'], 'scaling': group['scalingConfig']}
    role = h.aws('iam','get-role','--role-name',item['role'])['Role']
    h.require(role['Arn'] == item['arn'] and role['RoleId'] == item['role_id'], 'Writer role was replaced.')
    names = h.aws('iam','list-role-policies','--role-name',item['role'])['PolicyNames']
    doc = None
    if item['policy_name'] in names:
        raw = h.aws('iam','get-role-policy','--role-name',item['role'],'--policy-name',item['policy_name'])['PolicyDocument']
        doc = json.loads(unquote(raw)) if isinstance(raw, str) else raw
    return {'arn': role['Arn'], 'role_id': role['RoleId'], 'document': doc}


def desired(before, item, operation, marker):
    target_type, action = OPERATIONS[operation]
    if target_type == 'nodegroup':
        scaling = before['scaling']
        h.require(set(scaling) == {'minSize','maxSize','desiredSize'}, 'Unexpected scaling fields.')
        target = item['incident_max'] if action == 'limit' else marker['baseline']['scaling']['maxSize']
        h.require(target == (2 if action == 'limit' else item['approved_max']), 'Rollback baseline differs from approved max.')
        h.require(scaling['minSize'] <= scaling['desiredSize'] <= target and scaling['maxSize'] in (2,3), 'Scaling state exceeds the approved bounds.')
        if action == 'limit': h.require(scaling['maxSize'] == item['approved_max'], 'Incident must start from the approved baseline.')
        return {**before, 'scaling': {**scaling, 'maxSize': target}}
    if action == 'remove':
        h.require(before['document'] == item['document'] or (before['document'] is None and marker and marker.get('owner') == OWNER and marker.get('operation') == operation), 'Current policy differs from approved incident document.')
        return {**before, 'document': None}
    h.require(marker['phase'] == 'idle' and before['document'] is None and marker.get('baseline',{}).get('document') == item['document'], 'Rollback requires the exact completed removal and absent policy.')
    return {**before, 'document': marker['baseline']['document']}


def mutate(item, operation, after, temp, token):
    target_type, action = OPERATIONS[operation]
    if target_type == 'nodegroup':
        result = h.aws('eks','update-nodegroup-config','--region',item['region'],'--cluster-name',item['cluster'],
                       '--nodegroup-name',item['nodegroup'],'--scaling-config',f'maxSize={after["scaling"]["maxSize"]}', '--client-request-token', token)
        return {'update_id': result['update']['id']}
    if action == 'remove':
        h.aws('iam','delete-role-policy','--role-name',item['role'],'--policy-name',item['policy_name'])
    else:
        path = temp / 'deny.json'; path.write_bytes(h.canonical(after['document']))
        h.aws('iam','put-role-policy','--role-name',item['role'],'--policy-name',item['policy_name'],'--policy-document','file://' + str(path))
    return {}


def wait_result(item, operation, after, result):
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        if 'update_id' in result:
            update = h.aws('eks','describe-update','--region',item['region'],'--name',item['cluster'],'--nodegroup-name',item['nodegroup'],'--update-id',result['update_id'])['update']
            h.require(update['status'] not in ('Failed','Cancelled'), 'Nodegroup update failed; retain incident marker.')
            if update['status'] != 'Successful': time.sleep(10); continue
            h.require(update.get('id') == result['update_id'] and update.get('params') == [{'type':'MaxSize','value':str(after['scaling']['maxSize'])}], 'Update parameters differ from the approved max-only change.')
        current = observe(item, OPERATIONS[operation][0])
        if OPERATIONS[operation][0] == 'nodegroup':
            scaling = current['scaling']; expected = after['scaling']
            if current['arn'] == after['arn'] and scaling['minSize'] == expected['minSize'] and scaling['maxSize'] == expected['maxSize'] and scaling['minSize'] <= scaling['desiredSize'] <= scaling['maxSize']:
                return current
        elif current == after: return current
        time.sleep(5)
    raise h.SafeError('Result not verified within the bounded window; retain incident marker.')


def prefix(ctx):
    return f'ci-ops-plans/{ctx["repository_id"]}/{ctx["run_id"]}/{ctx["run_attempt"]}/{ctx["source_sha"]}/dev/{ctx["operation"]}/'


def upload(store, key, value, temp):
    path = temp / 'object.json'; path.write_bytes(h.canonical(value)); return store.put(key,path)


def run(mode):
    ctx = context(mode); item = request(ctx)
    store = h.Store(ctx['bucket'],ctx['account']); store.check(); check_retention(store,ctx); check_course(store,ctx)
    marker, info = lc.read_json(store, marker_key(ctx)); check_marker(marker,ctx,item)
    with tempfile.TemporaryDirectory(prefix='aws-fixed-operations-') as directory:
        temp = Path(directory)
        if mode == 'plan':
            before = observe(item, OPERATIONS[ctx['operation']][0]); after = desired(before,item,ctx['operation'],marker)
            manifest = {'schema':1,'context':ctx,'request':item,'before':before,'after':after,'marker':info,
                        'created_at':now(),'expires_at':min(now()+3600,item['valid_until'])}
            if ctx['operation']=='trace-deny-remove':
                probe=module('fixed_trace_probe','trace-fault-probe.py')
                fresh=probe.snapshot(h,ctx,item)
                recovery=bool(marker and marker.get('trace_probe') and before['document'] is None)
                h.require(item.get('probe_recovery_only',False) is recovery,'Explicit recovery-only decision must match original completed Deny removal')
                manifest['trace_probe']=copy.deepcopy(marker['trace_probe']) if recovery else fresh
                manifest['trace_probe_recovery_only']=recovery
                h.require(not recovery or manifest['trace_probe']['bindings']==fresh['bindings'],'Private probe State binding changed before recovery')
            desc = upload(store,prefix(ctx)+'manifest.json',manifest,temp)
            h.emit({'manifest_key':desc['key'],'manifest_version':desc['version'],'manifest_sha':desc['sha256']})
            with open(h.required('GITHUB_STEP_SUMMARY'),'a') as out:
                out.write('## 고정 AWS 작업 검토 대기\n\n작업: '+ctx['operation']+'\n\n')
                out.write('비공개 manifest의 exact version을 내려받아 전체 변경 전후·대상·승인 기한을 검토한 뒤 같은 실행의 aws-ops-dev-apply를 승인하세요.\n\n')
                out.write('Key: `'+desc['key']+'`\n\nVersionId: `'+desc['version']+'`\n\nSHA256: `'+desc['sha256']+'`\n')
            return
        desc = {'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('MANIFEST_SHA')}
        h.require(desc['key'] == prefix(ctx)+'manifest.json','Manifest belongs to another run.')
        path = temp/'manifest.json'; store.get(desc,path); manifest=json.loads(path.read_bytes())
        h.require(manifest['schema'] == 1 and manifest['context'] == ctx and manifest['request'] == item and
                  manifest['created_at'] <= now() < manifest['expires_at'] <= manifest['created_at']+3600,'Stale or changed operation plan.')
        h.require(info == manifest['marker'],'Incident marker changed after planning.')
        before = observe(item, OPERATIONS[ctx['operation']][0])
        h.require(before == manifest['before'] and desired(before,item,ctx['operation'],marker) == manifest['after'],'Target changed after planning.')
        check_course(store,ctx); h.ensure_current_main({'sha':ctx['source_sha']})
        baseline = marker['baseline'] if marker and marker.get('owner') == OWNER and marker.get('target') == target_identity(item) and marker.get('baseline') else before
        record = {**{k:ctx[k] for k in ('repository_id','environment','account','bucket','region')},
                  'schema':1,'owner':OWNER,'phase':'active','operation':ctx['operation'],'request_context':ctx,
                  'target':target_identity(item),'baseline':baseline,'generation':ctx['run_id']+'-'+ctx['run_attempt'], 'manifest':desc}
        if ctx['operation']=='trace-deny-remove':
            probe=module('fixed_trace_probe','trace-fault-probe.py');fresh=probe.snapshot(h,ctx,item)
            h.require(fresh['bindings']==manifest['trace_probe']['bindings'],'Private probe State changed after approval')
            if not manifest['trace_probe_recovery_only']:h.require(fresh==manifest['trace_probe'],'Reviewed synthetic probe specification changed')
            record['trace_probe']=copy.deepcopy(manifest['trace_probe'])
        info = lc.update(store,marker_key(ctx),record,info)
        # IAM has no compare-and-swap DeleteRolePolicy; exclusive writer control
        # remains a required operational prerequisite, not a claimed API guarantee.
        h.require(observe(item,OPERATIONS[ctx['operation']][0]) == before,'Target changed after acquiring incident marker.')
        result = {};probe_failure=None
        if ctx['operation']=='trace-deny-remove':
            target=record['trace_probe']
            def probe_mark(phase,current):
                nonlocal info
                record['trace_probe']=copy.deepcopy(current)
                info=lc.update(store,marker_key(ctx),record,info)
            with probe.session(h,target,temp) as io:
                if not manifest['trace_probe_recovery_only']:
                    try:probe.during(io,target,probe_mark)
                    except Exception:probe_failure='during-fault-probe-inconclusive'
                # Restore the exact approved Deny even when the synthetic probe fails.
                h.require(observe(item,'trace')==before,'Writer policy changed during fault observation')
                if before != manifest['after']:result=mutate(item,ctx['operation'],manifest['after'],temp,fingerprint(ctx))
                record['result']=result;info=lc.update(store,marker_key(ctx),record,info)
                actual=wait_result(item,ctx['operation'],manifest['after'],result)
                if not probe_failure and not manifest['trace_probe_recovery_only']:
                    try:probe.after(io,target,probe_mark)
                    except Exception:probe_failure='recovered-probe-inconclusive'
                try:probe.cleanup(io,target,probe_mark)
                except Exception:probe_failure='probe-cleanup-requires-exact-identity-reconciliation'
        else:
            if before != manifest['after']:result=mutate(item,ctx['operation'],manifest['after'],temp,fingerprint(ctx))
            info=lc.update(store,marker_key(ctx),{**record,'result':result},info)
            actual=wait_result(item,ctx['operation'],manifest['after'],result)
        receipt = {'schema':1,'context':ctx,'manifest':desc,'result':result,'observed':actual,'verified_at':now(),
                   'mutation_requested':before != manifest['after'],'trace_probe':record.get('trace_probe'),'probe_failure':probe_failure,'trace_probe_recovery_only':manifest.get('trace_probe_recovery_only',False)}
        rd = upload(store,prefix(ctx).replace('ci-ops-plans/','ci-ops-receipts/',1)+'completion.json',receipt,temp)
        h.emit({'receipt_key':rd['key'],'receipt_version':rd['version'],'receipt_sha':rd['sha256']})
        # Restriction and rollback deliberately leave the incident active.
        phase = 'recovery-required' if probe_failure else ('idle' if OPERATIONS[ctx['operation']][1] in ('remove','restore') else 'active')
        lc.update(store,marker_key(ctx),{**record,'phase':phase,'result':result,'receipt':rd},info)
        h.require(probe_failure is None,'Writer Deny restoration and synthetic probe outcome differ; inspect private receipt and exact recovery marker')
        with open(h.required('GITHUB_STEP_SUMMARY'),'a') as out:
            out.write('AWS 결과를 확인했습니다. 비공개 receipt key: `'+rd['key']+'`, VersionId: `'+rd['version']+'`, SHA256: `'+rd['sha256']+'`. 장애 상태: '+phase+'.\n')


if __name__ == '__main__':
    try:
        h.require(len(sys.argv)==2,'Expected plan or apply.'); run(sys.argv[1])
    except Exception:
        print('::error::고정 AWS 작업이 완료되지 않았습니다. marker를 보존하고 승인된 비공개 증거를 확인하세요. 변경을 무작정 반복하지 마세요.')
        sys.exit(1)
