#!/usr/bin/env python3
"""Authenticate completed hook receipts against their reviewed private action plan."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

h=load('barrier_saved_plan','saved-plan.py')
c=load('barrier_course_control','lifecycle-state.py')
BASIC_HOOKS=frozenset({'hook:platform-core','hook:platform-mesh','hook:platform-gateway'})
ASSET_HOOKS=frozenset({'hook:queue-credentials-provision','hook:argocd-external-secrets-provision','hook:operator-image-publish'})
APPLICATION_HOOKS=frozenset('hook:'+name for name in (
    'queue-credentials-provision','argocd-external-secrets-provision','operator-image-publish',
    'platform-operations','platform-observability','platform-alerting','platform-delivery',
    'self-managed-queue-topics-acl','platform-queue','trace-drain-switch','application-namespace',
    'database-bootstrap','application-runtime','application-mesh','application-dashboards','migration-and-seed'))
PROBE_HOOKS=frozenset({'hook:node-network-probes','hook:cluster-private-api-check'})
VELERO_HOOKS=frozenset({'hook:velero-backup-restore'})
SEMANTIC_HOOKS=frozenset({'hook:external-log-consumer-drain','hook:incident-quiescence-and-baseline','hook:out-of-state-pitr-inventory','hook:reviewed-cleanup','hook:service-absence-audit'})
HOOKS=BASIC_HOOKS|APPLICATION_HOOKS|PROBE_HOOKS|SEMANTIC_HOOKS|VELERO_HOOKS
PLAN_FIELDS=frozenset({'manifest_key','manifest_version','manifest_sha','plan_sha'})
RECEIPT_FIELDS=frozenset({'receipt_key','receipt_version','receipt_sha'})

def descriptor(value, fields):
    h.require(isinstance(value,dict) and set(value)==fields and all(isinstance(x,str) and x for x in value.values()),'Invalid private barrier descriptor.')
    h.require(all(re.fullmatch('[0-9a-f]{64}',value[key]) for key in fields if key.endswith('_sha')) and all(value[key]!='null' for key in fields if key.endswith('_version')),'Invalid barrier version/hash.')

def read(store, value):
    with tempfile.TemporaryDirectory(prefix='private-hook-proof-') as directory:
        path=Path(directory)/'proof.json';store.get(value,path)
        return json.loads(path.read_bytes())

def unchanged_subset(original, survivor):
    h.require(isinstance(original,dict) and isinstance(survivor,dict) and set(original)==set(survivor),'Residual contract shape changed.')
    h.require(all(survivor[key]==value for key,value in original.items() if key!='approved_residuals'),'Residual cluster/source/session changed.')
    before=original.get('approved_residuals');after=survivor.get('approved_residuals')
    h.require(isinstance(before,list) and isinstance(after,list),'Residual inventory is missing.')
    def index(rows):
        result={}
        for row in rows:
            h.require(isinstance(row,dict) and {'resource','namespace','name','uid','spec_sha256'} <= set(row) <= {'resource','namespace','name','uid','spec_sha256','metadata_policy_sha256'} and all(isinstance(x,str) for x in row.values()),'Invalid reviewed residual object.')
            h.require('metadata_policy_sha256' not in row or re.fullmatch('[0-9a-f]{64}',row['metadata_policy_sha256']),'Invalid residual metadata policy digest.')
            key=(row['resource'],row['namespace'],row['name'])
            h.require(key not in result and row['uid'] and re.fullmatch('[0-9a-f]{64}',row['spec_sha256']),'Duplicate or invalid residual identity.')
            result[key]=row
        return result
    old,new=index(before),index(after)
    h.require(all(old.get(key)==row for key,row in new.items()),'Receipt expanded or changed reviewed residual identities.')


def validate_result(step,operation,snapshot,result,generation,context=None,binding=None):
    """Authenticate exact declared completion without claiming unimplemented cloud absence."""
    if step in SEMANTIC_HOOKS:
        return load('barrier_semantic_obligations','lifecycle-obligations.py').validate_result(step,operation,snapshot,result,generation,context,binding)
    if step in VELERO_HOOKS:
        return load('barrier_velero','velero-lifecycle.py').validate_result(step,operation,snapshot,result,generation,context,binding)
    if step=='hook:cluster-private-api-check':
        return load('barrier_private_readiness','eks-probe-lifecycle.py').validate_private_result(snapshot,result,generation,context,binding)
    if step in PROBE_HOOKS:
        h.require(result.get('checkpoint_generation')==generation,'Probe completion generation differs.')
        if operation=='down':
            h.require(result.get('no_mutation') is True and result.get('retained_probe_contract')==snapshot,'Probe Down must retain the exact semantic diagnostic checkpoint.')
            return
        proof=result.get('functional_probes');h.require(isinstance(proof,dict),'Functional probe proof is missing.')
        h.require(proof.get('schema')==1 and proof.get('kind')=='bu07-functional-probes' and proof.get('state_binding')==binding and proof.get('checkpoint_generation')==generation and proof.get('snapshot_sha')==context['snapshot_sha'],'Probe State/bootstrap/source proof differs from reviewed action.')
        scope=proof.get('scope',{})
        h.require(all(scope.get(k)==context[v] for k,v in [('account','account'),('source_sha','snapshot_sha'),('run_id','run_id'),('run_attempt','run_attempt')]) and scope.get('images')==snapshot['probe_inputs'],'Functional probe execution identity differs.')
        h.require(scope.get('cleanup')=='uid-precondition-pod-deletes-confirmed' and scope.get('namespace',{}).get('name')=='course-node-probes' and bool(scope.get('namespace',{}).get('uid')),'Probe cleanup is incomplete or namespace identity missing.')
        checks=scope.get('checks',{});h.require(set(checks)=={'dns','tls','public_dns','public_tls','nxdomain','imdsv1','imdsv2'},'Probe check inventory is incomplete.')
        probe=load('barrier_probe_semantics','eks-network-probes.py')
        for kind,value in checks.items():probe.validate_probe(kind,value,scope['endpoint']['ips'])
        logs=scope.get('logs',{});h.require(set(logs)=={'dns','flow'},'Correlated probe log proof is incomplete.')
        for value in logs.values():
            h.require(isinstance(value,dict) and all(isinstance(value.get(k),str) and value[k] for k in ('bucket','key','version_id','sha256')) and re.fullmatch('[0-9a-f]{64}',value['sha256']),'Probe log identity must be version/hash bound.')
        return
    if step not in APPLICATION_HOOKS:
        return
    if step in ASSET_HOOKS:
        h.require(isinstance(snapshot.get('retained_assets'),dict) and bool(snapshot['retained_assets']) and result.get('retained_assets')==snapshot['retained_assets'],'Retained credential/publication prerequisite proof is missing or changed.')
    rows=snapshot.get('applications')
    h.require(isinstance(rows,list) and (rows or step in ASSET_HOOKS) and all(isinstance(r,dict) and isinstance(r.get('name'),str) and type(r.get('retained_until_cluster_deletion')) is bool for r in rows),'Reviewed application identities are missing.')
    names=[r['name'] for r in rows]
    h.require(len(names)==len(set(names)),'Duplicate reviewed Application identity.')
    if operation=='down':
        h.require(result.get('retired')==[r['name'] for r in reversed(rows) if not r['retained_until_cluster_deletion']],'Application retirement order/scope differs from the reviewed plan.')
        h.require(result.get('retained_until_cluster_deletion')==[r['name'] for r in rows if r['retained_until_cluster_deletion']],'Retained Application identity scope changed.')
        h.require(result.get('retained_assets')==snapshot.get('retained_assets',{}),'Retained assets changed during cleanup.')
        volumes=snapshot.get('disposable_volumes',[])
        h.require(isinstance(volumes,list),'Invalid reviewed volume inventory.')
        if volumes:
            expected=[v['contract']['volume_id'] for v in volumes]
            h.require(result.get('volumes',{}).get('deleted_volume_ids')==expected,'Volume cleanup did not complete exact reviewed identities.')
    else:
        expected=[] if step in ASSET_HOOKS else names
        h.require(result.get('restored')==expected and result.get('checkpoint_generation')==generation,'Application restore scope/checkpoint differs.')
        if step in ASSET_HOOKS:
            h.require(result.get('retained_assets')==snapshot.get('retained_assets') and bool(result.get('retained_assets')),'Retained restoration prerequisites changed or are missing.')

def validate_database_action(operation, payload, result, context, marker):
    """Bind the fixed Job proof to approved action bytes and its durable owner."""
    if operation == 'down':
        planned = payload.get('database_bootstrap_cleanup')
        if planned is None:
            h.require(result.get('bootstrap_cleanup') is None, 'Unplanned database bootstrap cleanup receipt.')
            return
        completed = result.get('bootstrap_cleanup', {})
        owner = marker.get('database_bootstrap_cleanup', {})
        expected = [planned[key]['uid'] for key in ('created_job', 'created_configmap')]
        h.require(owner.get('phase') == 'idle' and owner.get('target', {}).get('result') == completed and
                  completed.get('deleted_uids') == expected and completed.get('creation_receipt') == planned.get('creation_receipt') and
                  completed.get('bootstrap_run_id') == planned.get('bootstrap_run_id'), 'Database bootstrap cleanup did not complete exact reviewed objects.')
        return
    action = payload.get('database_bootstrap', {})
    h.require(action.get('mode') in ('create', 'observe') and isinstance(action.get('target'), dict), 'Fresh database bootstrap action is missing.')
    planned = action['target']; completed = result.get('database_bootstrap', {})
    owner = marker.get('database_bootstrap', {}); actual = owner.get('target', {})
    def stable(value):
        return {key: item for key, item in value.items() if key not in ('created_job', 'created_configmap', 'result')}
    digest = h.digest(h.canonical(stable(planned)))
    h.require(owner.get('phase') == 'idle' and stable(actual) == stable(planned) and actual.get('result') == completed,
              'Database bootstrap result lacks its exact durable mutation owner.')
    h.require(completed.get('complete') is True and completed.get('raw_job_logs_published') is False and
              completed.get('source_sha') == planned.get('source_sha') == context['snapshot_sha'] and
              completed.get('target_sha256') == digest and completed.get('database') == planned.get('db') and
              completed.get('bootstrap_run_id') == planned.get('bootstrap_run_id'), 'Database bootstrap source/incarnation/action binding differs.')
    db = planned.get('db', {})
    h.require(isinstance(db.get('resource_id'), str) and db['resource_id'] and
              isinstance(planned.get('region'), str) and
              db.get('arn', '').startswith('arn:aws:rds:' + planned['region'] + ':' + context['account'] + ':db:'),
              'Database bootstrap target is not the reviewed account incarnation.')
    for field, source in (('created_job', 'job'), ('created_configmap', 'configmap')):
        row = completed.get(field, {})
        h.require(row == actual.get(field) and isinstance(row.get('uid'), str) and row['uid'] and
                  row.get('namespace') == 'contract2whale-demo' and row.get('name') == planned.get(source, {}).get('metadata', {}).get('name') and
                  all(isinstance(row.get(k), str) and re.fullmatch('[0-9a-f]{64}', row[k]) for k in ('body_sha256', 'metadata_sha256')),
                  'Database bootstrap created object identity differs from approved action.')
    h.require(result.get('bootstrap_job_uid') == completed['created_job']['uid'], 'Database bootstrap compatibility UID differs.')


def authenticate(store, course, target, step, proof):
    """Validate immutable proof even on a later fresh run after its plan TTL ended."""
    c.validate_course(course,**target)
    h.require(step in HOOKS and step in course.get('steps',[]),'Unregistered completed hook barrier.')
    h.require(isinstance(proof,dict) and set(proof)=={'plan','receipt','operation'} and proof['operation'] in ('down','up'),'Invalid hook barrier proof.')
    planned,completed=proof['plan'],proof['receipt']
    descriptor(planned,PLAN_FIELDS);descriptor(completed,RECEIPT_FIELDS)
    manifest=read(store,{'key':planned['manifest_key'],'version':planned['manifest_version'],'sha256':planned['manifest_sha']})
    context=manifest.get('context',{})
    environment=target.get('environment',course.get('environment','dev'))
    h.require(environment in ('dev','prod'),'Unknown hook environment.')
    expected=dict(repository_id=target['repository_id'],account=target['account'],environment=environment,step_id=step,
                  snapshot_sha=course['snapshot_sha'],generation=course['generation'],registry_sha256=course['registry_sha256'],
                  completed_chapter=course['completed_chapter'],operation=proof['operation'])
    h.require(manifest.get('schema')==1 and manifest.get('kind')=='gitops-lifecycle' and isinstance(context,dict) and all(context.get(k)==v for k,v in expected.items()),'Hook proof belongs to another source/session/account.')
    h.require(all(isinstance(context.get(k),str) and context[k].isdigit() for k in ('run_id','run_attempt')) and isinstance(context.get('sha'),str) and re.fullmatch('[0-9a-f]{40}',context['sha']),'Invalid hook proof run identity.')
    namespace='ci-plans' if proof['operation']=='down' else 'ci-up-plans'
    suffix=f"{target['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{environment}/hooks/{step[5:]}/lifecycle-{proof['operation']}/"
    prefix=namespace+'/'+suffix
    h.require(context.get('prefix')==prefix and planned['manifest_key']==prefix+'manifest.json' and completed['receipt_key']=='ci-logs/'+suffix+'apply/receipt.json','Hook proof namespace differs from reviewed scope.')
    action=manifest.get('plan',{})
    h.require(isinstance(action,dict) and action.get('key')==prefix+'actions.json' and action.get('sha256')==planned['plan_sha'],'Hook action bytes differ from approved plan.')
    payload=read(store,action)
    receipt=read(store,{'key':completed['receipt_key'],'version':completed['receipt_version'],'sha256':completed['receipt_sha']})
    h.require(receipt.get('schema')==1 and receipt.get('kind')=='gitops-lifecycle-completion' and receipt.get('context')==context and receipt.get('plan_sha')==planned['plan_sha'],'Hook receipt does not complete the reviewed action list.')
    when=receipt.get('completed_at');created=manifest.get('created_at');expires=manifest.get('expires_at')
    h.require(type(when) in (int,float) and type(created) in (int,float) and type(expires) in (int,float) and created<=when<expires and expires-created==h.TTL_SECONDS,'Hook did not complete within its reviewed plan validity.')
    h.require(payload.get('step_id')==step and payload.get('operation')==proof['operation'],'Hook action scope changed.')
    marker,_=c.read_json(store,f"ci-lifecycle/{target['repository_id']}/{environment}/hook-{step[5:]}.json")
    h.require(isinstance(marker,dict) and all(marker.get(k)==context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')) and marker.get('operation')==proof['operation'] and marker.get('request_context')==context and marker.get('last_result')==proof['operation']+'-complete' and marker.get('receipt')=={'key':completed['receipt_key'],'version':completed['receipt_version'],'sha256':completed['receipt_sha']},'Hook completion checkpoint changed or is incomplete.')
    result=receipt.get('result');h.require(isinstance(result,dict),'Hook completion result is missing.')
    validate_result(step,proof['operation'],payload.get('snapshot',{}),result,course['generation'],context,manifest.get('binding'))
    if step == 'hook:database-bootstrap':
        validate_database_action(proof['operation'], payload, result, context, marker)
    if proof['operation']=='down' and step in BASIC_HOOKS:
        h.require(result.get('load_balancers_absent') is True,'Hook cleanup did not prove LB absence.')
        if step=='hook:platform-core':
            unchanged_subset(payload.get('snapshot',{}).get('residual_contract'),result.get('residual_contract'))
    return result

def for_consumer(store, context, descriptors, *, step='hook:platform-core'):
    """Do not trust env JSON: exact descriptors must match the current CAS checkpoint."""
    environment=context.get('environment','dev')
    target=dict(repository_id=context['repository_id'],account=context['account'],bucket=context['backend']['bucket'],region=context['backend']['region'],environment=environment)
    course,_=c.read_json(store,c.course_marker_key(target['repository_id'],environment))
    h.require(course is not None,'Course checkpoint is missing for hook handoff.')
    c.validate_course(course,**target)
    h.require(course['phase']=='paused' and course['operation']==context['operation']=='down' and course['generation']==context['generation'] and course['snapshot_sha']==context['source_sha'] and course['registry_sha256']==context['lifecycle_registry_sha256'] and step in course['completed'],'Hook handoff is outside the active completed dependency prefix.')
    proof=course.get('barriers',{}).get(step)
    h.require(isinstance(descriptors,dict) and isinstance(proof,dict) and descriptors.get(step)==proof.get('receipt'),'Untrusted hook receipt descriptor.')
    return authenticate(store,course,target,step,proof)
