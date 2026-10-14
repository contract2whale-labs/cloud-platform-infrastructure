#!/usr/bin/env python3
"""Saved semantic private-API and node-probe barriers, sharing one CAS engine."""
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

h=load('probe_saved_plan','saved-plan.py')
c=load('probe_control','lifecycle-state.py')
g=load('probe_ownership','eks-lifecycle-guard.py')
p=load('probe_actions','eks-network-probes.py')
STEP='hook:node-network-probes'
PRIVATE_STEP='hook:cluster-private-api-check'
STEPS={STEP,PRIVATE_STEP}

def is_private(context):return context['step_id']==PRIVATE_STEP

def early_residuals(context):return is_private(context) and context['completed_chapter']=='BU07'

def validate_source(workspace,context):
    sha=context['snapshot_sha'];h.require(re.fullmatch('[0-9a-f]{40}',sha),'Invalid probe source SHA.')
    h.execute(['git','merge-base','--is-ancestor',sha,context['sha']],cwd=workspace)
    h.execute(['git','diff','--quiet',sha,context['sha'],'--','terraform','modules'],cwd=workspace)
    data=h.execute(['git','archive',sha,'--','terraform','modules'],cwd=workspace)
    with tempfile.TemporaryDirectory(prefix='probe-source-') as directory:
        base=Path(directory)
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:archive.extractall(base,filter='data')
        h.require(not any(x.is_symlink() for x in base.rglob('*')),'Probe source symlink forbidden.')
        return g.source_capability(base,context,context['completed_chapter'])

def probe_context(context):
    return {**context,'source_sha':context['snapshot_sha'],'probe_inputs':context['probe_inputs']}

def settings(stage):
    step=h.required('LIFECYCLE_STEP_ID');h.require(step in STEPS,'Unregistered probe hook.')
    env=h.required('LIFECYCLE_ENVIRONMENT');h.require(env in ('dev','prod'),'Unknown probe environment.')
    h.require(h.required('GITHUB_ACTIONS')=='true' and h.required('GITHUB_REF')=='refs/heads/main' and h.required('GITHUB_EVENT_NAME')=='workflow_dispatch','Probe hook is trusted CI dispatch only.')
    operation=h.required('OPERATION');h.require(operation in ('down','up'),'Unknown probe operation.')
    workspace=Path(h.required('GITHUB_WORKSPACE')).resolve()
    context={k:h.required(v) for k,v in {'repository_id':'GITHUB_REPOSITORY_ID','run_id':'GITHUB_RUN_ID','run_attempt':'GITHUB_RUN_ATTEMPT','sha':'GITHUB_SHA','snapshot_sha':'LIFECYCLE_SNAPSHOT_SHA','generation':'LIFECYCLE_GENERATION','registry_sha256':'LIFECYCLE_CONFIG_SHA256','completed_chapter':'COMPLETED_CHAPTER'}.items()}
    h.require(all(context[k].isdigit() for k in ('repository_id','run_id','run_attempt')) and re.fullmatch('[0-9a-f]{40}',context['sha']) and re.fullmatch(r'\d+-\d+',context['generation']) and re.fullmatch('[0-9a-f]{64}',context['registry_sha256']),'Invalid probe checkpoint/run identity.')
    account=h.required('EXPECTED_ACCOUNT_ID');region=h.required('AWS_REGION');bucket=h.required('STATE_BUCKET')
    h.require(re.fullmatch(r'\d{12}',account) and region=='ap-northeast-2','Unknown probe target.')
    expected='lifecycle-destroy' if operation=='down' else 'plan' if env=='prod' and stage=='plan' else 'apply'
    role=f'arn:aws:iam::{account}:role/gha-infra-{env}-{expected}'
    h.require(h.required('AWS_ROLE_ARN')==role,'Probe lifecycle role mismatch.')
    h.refresh_profile_guard();h.check_identity(account,role)
    h.require(h.execute(['git','rev-parse','HEAD'],cwd=workspace).decode().strip()==context['sha'],'Probe helper checkout mismatch.')
    h.ensure_current_main(context)
    config=p.registration(workspace,env)
    h.require(config['account_id']==account and config['region']==region,'Probe access registration target mismatch.')
    images={} if step==PRIVATE_STEP else p.validate_inputs({'probe_image':h.required('EKS_PROBE_IMAGE'),'pause_image':h.required('EKS_PAUSE_IMAGE')},region,account)
    context.update(step_id=step,operation=operation,environment=env,account=account,root=f'terraform/environments/{env}/eks',backend={'bucket':bucket,'region':region},probe_inputs=images,
                   registration_sha256=h.digest(h.canonical(config)),probe_policy_sha256=h.digest((HERE/'eks-network-probes.py').read_bytes()))
    if is_private(context):context['private_api_contract']={'schema':1,'mode':'authenticated-private-readyz','bootstrap_required':context['completed_chapter']!='BU06','early_bootstrap_residuals':early_residuals(context)}
    context['source_capability']=validate_source(workspace,context)
    h.require(context['source_capability'].get('operations_access') is True,'Functional barrier requires the reviewed operations-access source capability.')
    namespace='ci-up-plans' if operation=='up' else 'ci-plans'
    context['prefix']=f"{namespace}/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{env}/hooks/{step[5:]}/lifecycle-{operation}/"
    store=h.Store(bucket,account);store.check()
    key=f"ci-lifecycle/{context['repository_id']}/{env}/hook-{step[5:]}.json"
    lifecycle=load('probe_retention','eks-lifecycle.py');lifecycle.check_retention(store,key)
    c.assert_incident_clear(store,context)
    course,_=c.read_json(store,c.course_marker_key(context['repository_id'],env))
    h.require(isinstance(course,dict),'Probe hook requires the retained course checkpoint.')
    c.validate_course(course,context['repository_id'],account,bucket,region,env)
    h.require(course['phase']=='paused' and course['operation']==operation and course['generation']==context['generation'] and course['snapshot_sha']==context['snapshot_sha'] and course['registry_sha256']==context['registry_sha256'] and step in course['steps'],'Probe hook differs from retained paused course scope.')
    return workspace,config,store,key,context

def snapshot(context):
    keys=('step_id','snapshot_sha','generation','probe_inputs','probe_policy_sha256','source_capability')
    if is_private(context):keys+=('private_api_contract',)
    return {k:copy.deepcopy(context[k]) for k in keys}

def retained_snapshot(context,store,config):
    original=snapshot(context)
    if early_residuals(context):
        contract,fingerprints=p.inspect_bootstrap_residuals(probe_context(context),store,config)
        original.update(residual_contract=contract,bootstrap_binding=fingerprints)
    return original

def verify_early_residuals(context,store,config,original):
    if context['operation']=='down' and early_residuals(context):
        contract,fingerprints=p.inspect_bootstrap_residuals(probe_context(context),store,config)
        h.require(contract==original['residual_contract'] and fingerprints==original['bootstrap_binding'],'Early bootstrap residual identities or binding changed; explicit recovery required.')

def binding(context,store,config):
    if context['operation']=='up' or is_private(context):
        _,fingerprints,_,_=p.private_binding(probe_context(context),store,config) if is_private(context) else p.probe_binding(probe_context(context),store,config)
        return fingerprints
    reader=g.VersionedStateReader(store.bucket,context['account'],context['backend']['region'])
    _,eks,relay,vpc=g.roots(context)
    return {root:reader(g.key(root))['fingerprint'] for root in (eks,relay,vpc)}

def validate_record(record,context):
    base=snapshot(context);original=record.get('original') if isinstance(record,dict) else None
    extras={'residual_contract','bootstrap_binding'} if early_residuals(context) else set()
    h.require(isinstance(record,dict) and record.get('schema')==1 and all(record.get(k)==context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')) and isinstance(original,dict) and set(original)==set(base)|extras and all(original[k]==v for k,v in base.items()),'Probe checkpoint/source/images/policy changed; explicit recovery required.')
    if extras:h.require(all(isinstance(original[k],dict) and original[k] for k in extras),'Early bootstrap residual checkpoint is missing.')

def validate_manifest(manifest,context,control,fingerprints,now):
    h.require(manifest.get('schema')==1 and manifest.get('kind')=='gitops-lifecycle' and manifest.get('context')==context and manifest.get('control')==control and manifest.get('binding')==fingerprints,'Probe plan scope/control/State/bootstrap binding changed.')
    h.require(manifest['created_at']<=now<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==h.TTL_SECONDS,'Probe saved plan expired; start a fresh run.')

def validate_private_result(original,result,generation,context,fingerprints):
    """Pure receipt semantics used by the central authenticated hook barrier."""
    h.require(isinstance(context,dict) and is_private(context) and context.get('operation') in ('up','down'),'Wrong private readiness completion scope.')
    operation=context['operation'];base=snapshot(context);extras={'residual_contract','bootstrap_binding'} if early_residuals(context) else set()
    h.require(isinstance(original,dict) and set(original)==set(base)|extras and all(original.get(k)==v for k,v in base.items()),'Private readiness semantic source/capability contract differs.')
    capability=original.get('source_capability',{})
    h.require(capability.get('operations_access') is True and capability.get('operations_source_sha256')==h.digest((HERE/'eks-operations-access.tf').read_bytes()),'Private readiness requires the exact reviewed operations-access source.')
    h.require(original['probe_inputs']=={} and original['private_api_contract']=={'schema':1,'mode':'authenticated-private-readyz','bootstrap_required':context['completed_chapter']!='BU06','early_bootstrap_residuals':early_residuals(context)},'Private readiness contract is not the bounded image-free check.')
    h.require(isinstance(result,dict) and result.get('checkpoint_generation')==generation==context.get('generation'),'Private readiness completion generation differs.')
    expected_roots=set(g.roots(context)[1:])|({'operations_access'} if context['completed_chapter']!='BU06' else set())
    h.require(isinstance(fingerprints,dict) and set(fingerprints)==expected_roots,'Private readiness requires exact EKS/relay/VPC and bootstrap binding.')
    access=fingerprints.get('operations_access')
    h.require(context['completed_chapter']=='BU06' or (isinstance(access,dict) and set(access)=={'key','version','sha256'} and re.fullmatch('operation-access/'+context['environment']+'/[0-9a-f]{64}/complete.json',access.get('key','')) and isinstance(access.get('version'),str) and access['version'] not in ('','null') and re.fullmatch('[0-9a-f]{64}',access.get('sha256',''))),'Private readiness bootstrap descriptor is incomplete.')
    proof=result.get('private_api_readiness')
    h.require(isinstance(proof,dict) and proof.get('schema')==1 and proof.get('kind')=='cluster-private-api-readiness' and proof.get('state_binding')==fingerprints and proof.get('checkpoint_generation')==generation and proof.get('snapshot_sha')==context['snapshot_sha'],'Private readiness proof differs from reviewed State/bootstrap/source.')
    scope=proof.get('scope',{})
    expected={k:context[v] for k,v in [('account','account'),('source_sha','snapshot_sha'),('run_id','run_id'),('run_attempt','run_attempt')]}
    expected.update(readyz='ok',authenticated=True,private_endpoint=True,authenticated_group='cp:'+context['environment']+':lifecycle-'+('destroy' if operation=='down' else 'apply'))
    h.require(isinstance(scope,dict) and all(scope.get(k)==v and (type(scope.get(k)) is bool if type(v) is bool else True) for k,v in expected.items()),'Private readiness execution/authentication identity differs.')
    h.require(isinstance(scope.get('cluster_arn'),str) and scope['cluster_arn'].startswith('arn:aws:eks:'+context['backend']['region']+':'+context['account']+':cluster/') and re.fullmatch(r'i-[0-9a-f]+',scope.get('relay_instance_id','')) and re.fullmatch(r'vpc-[0-9a-f]+',scope.get('vpc_id','')),'Private readiness live target identity is missing.')
    try:created=dt.datetime.fromisoformat(scope.get('cluster_created_at','').replace('Z','+00:00'))
    except (TypeError,ValueError,AttributeError):raise h.SafeError('Private readiness cluster incarnation is invalid.') from None
    h.require(created.tzinfo is not None,'Private readiness cluster incarnation lacks timezone.')
    if operation=='down':
        h.require(result.get('no_mutation') is True and result.get('retained_probe_contract')==original,'Private readiness Down must retain the same semantic checkpoint without mutation.')
        if early_residuals(context):
            before=original.get('residual_contract');after=result.get('residual_contract')
            h.require(isinstance(before,dict) and before==after and result.get('bootstrap_binding')==original.get('bootstrap_binding')==fingerprints,'Early bootstrap residuals or authenticated binding changed.')
            h.require(set(before)=={'schema_version','cluster_arn','cluster_created_at','source_sha','generation','approved_residuals'} and before['schema_version']==1 and before['cluster_arn']==scope['cluster_arn'] and before['cluster_created_at']==scope['cluster_created_at'] and before['source_sha']==context['snapshot_sha'] and before['generation']==generation,'Early residual contract belongs to another cluster/checkpoint.')
            rows=before['approved_residuals'];h.require(isinstance(rows,list) and rows,'Early residual inventory is missing.')
            seen=set()
            for row in rows:
                h.require(isinstance(row,dict) and set(row)=={'resource','namespace','name','uid','spec_sha256','metadata_policy_sha256'} and all(isinstance(v,str) for v in row.values()),'Early residual identity/metadata proof is incomplete.')
                identity=(row['resource'],row['namespace'],row['name'])
                h.require(identity not in seen and row['resource'] in {x[1] for x in p.BOOTSTRAP_RESOURCES.values()} and row['name'] and row['uid'] and all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in ('spec_sha256','metadata_policy_sha256')),'Early residual identity/hash is invalid or duplicated.')
                seen.add(identity)
        else:h.require('residual_contract' not in result and 'bootstrap_binding' not in result,'Later chapters must use the platform-core residual handoff.')
    else:h.require('residual_contract' not in result and 'bootstrap_binding' not in result and 'no_mutation' not in result,'Up readiness cannot authorize Down residuals.')

def run(stage):
    h.require(stage in ('start','plan','verify','apply'),'Unknown probe lifecycle stage.')
    os.umask(0o077)
    workspace,config,store,key,context=settings(stage);record,control=c.read_json(store,key)
    operation=context['operation']
    if stage=='start':
        if record is None or (record.get('phase')=='active' and operation=='down'):
            h.require(operation=='down','No retained functional probe checkpoint exists for Up.')
            record={'schema':1,**{k:context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')},'original':retained_snapshot(context,store,config),'phase':'paused'}
        validate_record(record,context)
        record.update(request_context=context,operation=operation,phase='paused')
        c.update(store,key,record,control);h.emit({'snapshot_sha':context['snapshot_sha']});return
    validate_record(record,context)
    h.require(record.get('phase')=='paused' and record.get('request_context')==context and record.get('operation')==operation,'Probe request ownership changed.')
    fingerprints=binding(context,store,config)
    verify_early_residuals(context,store,config,record['original'])
    prefix=context['prefix'];payload={'step_id':context['step_id'],'operation':operation,'snapshot':record['original']}
    with tempfile.TemporaryDirectory(prefix='private-probe-hook-') as directory:
        temp=Path(directory)
        if stage=='plan':
            now=dt.datetime.now(dt.timezone.utc).timestamp();path=temp/'actions.json';path.write_bytes(h.canonical(payload))
            review=temp/'review.json';review.write_bytes(h.canonical({'context':context,'actions':payload,'binding':fingerprints,'effect':'authenticated no-mutation retention' if operation=='down' else 'authenticated private API readiness only' if is_private(context) else 'bounded protected-namespace Pods and exact UID cleanup'}))
            manifest={'schema':1,'kind':'gitops-lifecycle','context':context,'control':control,'binding':fingerprints,'created_at':now,'expires_at':now+h.TTL_SECONDS,'plan':store.put(prefix+'actions.json',path),'review':store.put(prefix+'review.json',review)}
            mp=temp/'manifest.json';mp.write_bytes(h.canonical(manifest));saved=store.put(prefix+'manifest.json',mp)
            h.emit({'manifest_key':saved['key'],'manifest_version':saved['version'],'manifest_sha':saved['sha256'],'plan_sha':manifest['plan']['sha256']});return
        desc={'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('EXPECTED_MANIFEST_SHA')}
        h.require(desc['key']==prefix+'manifest.json','Probe manifest belongs to another run.')
        mp=temp/'manifest.json';store.get(desc,mp);manifest=json.loads(mp.read_bytes())
        validate_manifest(manifest,context,control,fingerprints,dt.datetime.now(dt.timezone.utc).timestamp())
        h.require(manifest['plan']['key']==prefix+'actions.json' and manifest['plan']['sha256']==h.required('EXPECTED_PLAN_SHA'),'Probe action plan differs from approved bundle.')
        path=temp/'actions.json';store.get(manifest['plan'],path)
        h.require(json.loads(path.read_bytes())==payload,'Probe semantic action contract changed.')
        if stage=='verify':return
        h.ensure_current_main(context)
        latest,info=c.read_json(store,key)
        h.require(latest==record and info==control and binding(context,store,config)==fingerprints,'Probe preconditions changed before apply.')
        # Claim before any mutation; the same saved plan/control cannot replay.
        record.update(last_result=operation+'-applying',claimed_manifest=desc)
        control=c.update(store,key,record,control)
        if operation=='down':
            result={'retained_probe_contract':record['original'],'no_mutation':True,'checkpoint_generation':context['generation']}
            if is_private(context):
                proof=p.run_private_api_completion(probe_context(context),store,config)
                h.require(proof['state_binding']==fingerprints,'Private readiness State differs from reviewed plan.')
                result['private_api_readiness']=proof
                if early_residuals(context):
                    verify_early_residuals(context,store,config,record['original'])
                    result.update(residual_contract=record['original']['residual_contract'],bootstrap_binding=fingerprints)
        elif is_private(context):
            proof=p.run_private_api_completion(probe_context(context),store,config)
            h.require(proof['state_binding']==fingerprints,'Private readiness State differs from reviewed plan.')
            result={'private_api_readiness':proof,'checkpoint_generation':context['generation']}
        else:
            try:proof=p.run_probe_completion(probe_context(context),store,config,evidence_file=temp/'functional-probes-progress.json')
            finally:
                progress=temp/'functional-probes-progress.json'
                if progress.is_file():store.put(prefix.replace('ci-up-plans/','ci-logs/',1)+'apply/functional-probes-progress.json',progress)
            h.require(proof['state_binding']==fingerprints,'Functional completion State differs from reviewed plan.')
            result={'functional_probes':proof,'checkpoint_generation':context['generation']}
        h.require(dt.datetime.now(dt.timezone.utc).timestamp()<manifest['expires_at'],'Probe completed after plan expiry; keep course paused.')
        receipt=temp/'receipt.json';receipt.write_bytes(h.canonical({'schema':1,'kind':'gitops-lifecycle-completion','context':context,'plan_sha':manifest['plan']['sha256'],'completed_at':dt.datetime.now(dt.timezone.utc).timestamp(),'result':result}))
        saved=store.put(prefix.replace('ci-up-plans/','ci-logs/',1).replace('ci-plans/','ci-logs/',1)+'apply/receipt.json',receipt)
        record.update(last_result=operation+'-complete',receipt=saved,phase='active' if operation=='up' else 'paused')
        c.update(store,key,record,control)
        h.emit({'receipt_key':saved['key'],'receipt_version':saved['version'],'receipt_sha':saved['sha256']})

if __name__=='__main__':
    try:run(sys.argv[1])
    except Exception:raise SystemExit('Private API/probe barrier stopped; course remains paused and this job releases the lifecycle mutex. If fresh bootstrap proof is missing, complete protected gitops-access-bootstrap.yml for this checkpoint, then rerun the same Up checkpoint. Inspect private evidence and use a fresh saved plan; no inline bootstrap wait.')
