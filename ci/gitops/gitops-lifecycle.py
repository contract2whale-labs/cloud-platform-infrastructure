#!/usr/bin/env python3
"""Cumulative engine adapter. Only registered hook IDs; no arbitrary action strings."""
import copy, datetime as dt, importlib.util, json, os, pathlib, re, sys, tempfile
BASE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
import gitops_ops as ops
import lifecycle_hooks as hooks

def dependency(filename,folder):
    return ops.shared_file(filename)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=load('gitops_saved_plan',ops.shared_file('saved-plan.py'))
state=load('gitops_marker',ops.shared_file('lifecycle-state.py'))
GROUPS={'platform-core':ops.ORDER[:4], 'platform-mesh':ops.ORDER[4:9], 'platform-gateway':hooks.GATEWAY}

def settings(stage):
    step=h.required('LIFECYCLE_STEP_ID'); h.require(step.startswith('hook:') and step[5:] in GROUPS,'Unregistered GitOps hook.')
    hook=step[5:];environment=h.required('LIFECYCLE_ENVIRONMENT');h.require(environment in ('dev','prod'),'Unknown protected lifecycle environment')
    h.require(h.required('GITHUB_REF')=='refs/heads/main' and h.required('GITHUB_EVENT_NAME')=='workflow_dispatch','Lifecycle requires trusted main dispatch.')
    h.require(h.required('OPERATION') in ('up','down'),'Unsupported lifecycle action.')
    h.require(re.fullmatch('[0-9a-f]{40}',h.required('LIFECYCLE_SNAPSHOT_SHA')) and re.fullmatch('[0-9]+-[0-9]+',h.required('LIFECYCLE_GENERATION')),'Invalid retained checkpoint.')
    h.require(re.fullmatch('[0-9a-f]{64}',h.required('LIFECYCLE_CONFIG_SHA256')),'Invalid registry digest.')
    h.require(h.execute(['git','rev-parse','HEAD']).decode().strip()==h.required('GITHUB_SHA'),'Helper source mismatch.')
    h.ensure_current_main({'sha':h.required('GITHUB_SHA')})
    cfg=json.loads((BASE/'operations.json').read_text()); h.require(cfg.get('enabled') is True,'GitOps activation incomplete.')
    c=copy.deepcopy(cfg['environments'][environment])
    c['operator_image']=cfg['operator_image'];c['environment']=environment
    expected=c['lifecycle_destroy_role_arn'] if h.required('OPERATION')=='down' else c['lifecycle_plan_role_arn'] if environment=='prod' and stage=='plan' else c['lifecycle_apply_role_arn']
    ops.check_tools(c)
    for app in c['applications']:ops.validate_app(app,environment,c['repository'])
    ops.validate_authorities(c,environment);c['_all_applications']=copy.deepcopy(c['applications'])
    h.require(h.required('AWS_ROLE_ARN')==expected and h.required('EXPECTED_ACCOUNT_ID')==c['account_id'],'Unregistered lifecycle identity.')
    h.check_identity(c['account_id'],expected)
    c['rbac_applications']=copy.deepcopy(c['applications']+c.get('authority_applications',[]));c['_registered_names']=[a['metadata']['name'] for a in c['applications']+c.get('authority_applications',[])];c['_hook']=hook
    c['applications']=[a for a in c['applications'] if a['metadata']['name'] in {ops.app_name(x,environment) for x in GROUPS[hook]}]
    h.require(c['applications'],'Selected hook has no registered applications.')
    store=h.Store(h.required('STATE_BUCKET'),c['account_id']);store.check()
    repo=h.required('GITHUB_REPOSITORY_ID');h.require(repo.isdigit(),'Invalid repository ID.')
    key=f'ci-lifecycle/{repo}/{environment}/hook-{hook}.json'
    for rule in store.call('get-bucket-lifecycle-configuration').get('Rules',[]):
        if rule.get('Status')=='Enabled' and ('Expiration' in rule or 'NoncurrentVersionExpiration' in rule):
            f=rule.get('Filter',{});prefix=f.get('Prefix',f.get('And',{}).get('Prefix',rule.get('Prefix','')))
            h.require(not key.startswith(prefix),'Lifecycle snapshot must not expire.')
    context={k:h.required(v) for k,v in {'repository_id':'GITHUB_REPOSITORY_ID','run_id':'GITHUB_RUN_ID','run_attempt':'GITHUB_RUN_ATTEMPT','sha':'GITHUB_SHA','snapshot_sha':'LIFECYCLE_SNAPSHOT_SHA','generation':'LIFECYCLE_GENERATION','registry_sha256':'LIFECYCLE_CONFIG_SHA256','operation':'OPERATION','completed_chapter':'COMPLETED_CHAPTER'}.items()}
    context.update(step_id=step,environment=environment,account=c['account_id'],registration_sha256=hooks.digest(c))
    namespace='ci-up-plans' if context['operation']=='up' else 'ci-plans'
    context['prefix']=f"{namespace}/{repo}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{environment}/hooks/{hook}/lifecycle-{context['operation']}/"
    return c,store,key,context

def live_binding(c, store):
    guard=load('gitops_eks_guard',ops.shared_file('eks-lifecycle-guard.py'))
    reader=guard.VersionedStateReader(store.bucket,c['account_id'],c['region'])
    eks=reader('eks/terraform.tfstate');relay=reader('platform/private-api/terraform.tfstate')
    erows=guard.managed_resources(eks['state']);rrows=guard.managed_resources(relay['state'])
    clusters=[r['values'] for r in erows if r['type']=='aws_eks_cluster'];instances=[r['values'] for r in rrows if r['type']=='aws_instance']
    h.require(len(clusters)==len(instances)==1,'Fresh EKS/relay state binding unavailable.')
    effective=copy.deepcopy(c);effective.update(cluster=clusters[0]['name'],cluster_arn=clusters[0]['arn'],relay=instances[0]['id'],vpc_id=clusters[0]['vpc_config'][0]['vpc_id'],role_arn=h.required('AWS_ROLE_ARN'))
    ops.own(effective)
    live=json.loads(ops.run(['aws','eks','describe-cluster','--name',effective['cluster'],'--region',effective['region']]))['cluster']
    h.require(dt.datetime.fromisoformat(live['createdAt'].replace('Z','+00:00'))==dt.datetime.fromisoformat(clusters[0]['created_at'].replace('Z','+00:00')),'Live EKS creation differs from versioned State.')
    effective['cluster_created_at']=live['createdAt']
    effective['role_arn']=c['role_arn']
    return effective,{'eks':eks['fingerprint'],'relay':relay['fingerprint']}

def validate_manifest(manifest, context, control, fingerprints, now):
    h.require(manifest.get('schema')==1 and manifest.get('kind')=='gitops-lifecycle' and manifest.get('context')==context and manifest.get('control')==control and manifest.get('binding')==fingerprints,'Hook context/control/live binding changed.')
    h.require(manifest['created_at']<=now<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==h.TTL_SECONDS,'Hook plan expired.')

def operation_context_is_new(record, context):
    return bool(record and record.get('phase')=='active' and context['operation']=='down')

def run(stage):
    h.require(stage in ('start','plan','verify','apply'),'Unknown lifecycle adapter stage.')
    os.umask(0o077)
    os.environ['LIFECYCLE_HOOK_STAGE']=stage
    c,store,key,context=settings(stage);record,control=state.read_json(store,key)
    operation=context['operation'];generation=context['generation'];environment=context['environment']
    if stage=='start' and operation_context_is_new(record,context):
        record=None
    if record:
        h.require(record['step_id']==context['step_id'] and record['generation']==generation and record['snapshot_sha']==context['snapshot_sha'] and record['registration_sha256']==context['registration_sha256'],'Hook checkpoint differs; explicit recovery needed.')
    if stage=='start' and operation=='up':
        h.require(record is not None,'No retained GitOps checkpoint exists for Up.')
        record.update(request_context=context,operation=operation,phase='paused');state.update(store,key,record,control);h.emit({'snapshot_sha':context['snapshot_sha']});return
    effective,fingerprints=live_binding(c,store)
    effective['environment']=context['environment']
    if operation=='up':effective['lifecycle_snapshot_sha']=context['snapshot_sha']
    access=load('gitops_access',ops.shared_file('operations-access.py'))
    proof=access.verify_bootstrap_receipt(effective,store,generation=generation if operation=='up' else None,config_sha256=c['operations_access_config_sha256'])
    fingerprints['operations_access']={k:proof[k] for k in ('key','version','sha256')}
    effective['_bootstrap_verified']=True
    effective['_installer_residual_resources']=proof['receipt']['installer_residual_resources']
    h.require(isinstance(proof['receipt'].get('bootstrap_residual_resources'),list) and proof['receipt']['bootstrap_residual_resources'],'Protected bootstrap proof lacks exact chart residual identities; reviewed recovery required.')
    effective['_bootstrap_residual_resources']=proof['receipt']['bootstrap_residual_resources']
    private=load('gitops_private',ops.shared_file('private-api-session.py'))
    with tempfile.TemporaryDirectory(prefix='private-gitops-hook-') as d:
        temp=pathlib.Path(d)
        with private.private_api(effective['cluster'],effective['relay'],effective['region'],temp/'kubeconfig') as (env,cluster):
            os.environ['KUBECONFIG']=env['KUBECONFIG']
            if stage=='start':
                if record is None:
                    h.require(operation=='down','No retained GitOps checkpoint exists for Up.')
                    snapshot=hooks.plan(effective,environment,generation)
                    record=dict(schema=1,step_id=context['step_id'],generation=generation,snapshot_sha=context['snapshot_sha'],registration_sha256=context['registration_sha256'],phase='paused',original=snapshot,completed=[],bootstrap_done=False)
                record.update(request_context=context,operation=operation)
                state.update(store,key,record,control);h.emit({'snapshot_sha':context['snapshot_sha']});return
            h.require(record is not None and record.get('request_context')==context and record['phase']=='paused','Hook request ownership changed.')
            prefix=context['prefix']
            if stage=='plan':
                # Refresh only review TTL. Original identities/specs are never recaptured.
                action=copy.deepcopy(record['original']);now=dt.datetime.now(dt.timezone.utc)
                action.update(created_at=now.isoformat(),expires_at=(now+dt.timedelta(seconds=h.TTL_SECONDS)).isoformat())
                if operation=='down':hooks.verify(effective,environment,action,generation,record['completed'])
                payload={'operation':operation,'step_id':context['step_id'],'snapshot':action,'completed':record['completed'],'bootstrap_done':record['bootstrap_done']}
                path=temp/'actions.json';path.write_bytes(h.canonical(payload))
                review=temp/'review.json';review.write_bytes(h.canonical({'context':context,'actions':payload,'binding':fingerprints,'preserved':'all external S3; namespaces/CRDs until EKS deletion'}))
                manifest={'schema':1,'kind':'gitops-lifecycle','context':context,'control':control,'binding':fingerprints,'created_at':now.timestamp(),'expires_at':now.timestamp()+h.TTL_SECONDS,'plan':store.put(prefix+'actions.json',path),'review':store.put(prefix+'review.json',review)}
                mp=temp/'manifest.json';mp.write_bytes(h.canonical(manifest));descriptor=store.put(prefix+'manifest.json',mp)
                h.emit({'manifest_key':descriptor['key'],'manifest_version':descriptor['version'],'manifest_sha':descriptor['sha256'],'plan_sha':manifest['plan']['sha256']});return
            descriptor={'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('EXPECTED_MANIFEST_SHA')}
            h.require(descriptor['key']==prefix+'manifest.json','Manifest belongs to another hook/run.')
            mp=temp/'manifest.json';store.get(descriptor,mp);manifest=json.loads(mp.read_bytes())
            validate_manifest(manifest,context,control,fingerprints,dt.datetime.now(dt.timezone.utc).timestamp())
            h.require(manifest['plan']['key']==prefix+'actions.json' and manifest['plan']['sha256']==h.required('EXPECTED_PLAN_SHA'),'Action plan differs from reviewed bundle.')
            path=temp/'actions.json';store.get(manifest['plan'],path);payload=json.loads(path.read_bytes());snapshot=payload['snapshot']
            h.require(payload['step_id']==context['step_id'] and payload['operation']==operation and payload['completed']==record['completed'],'Action scope mismatch.')
            if operation=='down':hooks.verify(effective,environment,snapshot,generation,record['completed'])
            if stage=='verify':return
            h.ensure_current_main(context)
            def progress(item):
                nonlocal control
                if item=='bootstrap-done':record['bootstrap_done']=True
                elif item not in record['completed']:record['completed'].append(item)
                control=state.update(store,key,record,control)
            if operation=='down':result=hooks.down(effective,environment,snapshot,generation,progress,record['completed'])
            else:result=hooks.up(effective,environment,snapshot,generation,temp,record['bootstrap_done'],progress)
            receipt=temp/'receipt.json';receipt.write_bytes(h.canonical({'schema':1,'kind':'gitops-lifecycle-completion','completed_at':int(dt.datetime.now(dt.timezone.utc).timestamp()),'context':context,'result':result,'plan_sha':manifest['plan']['sha256']}))
            record.update(last_result=operation+'-complete',receipt=store.put(prefix.replace('ci-up-plans/','ci-logs/',1).replace('ci-plans/','ci-logs/',1)+'apply/receipt.json',receipt))
            if operation=='up':record['phase']='active'
            state.update(store,key,record,control)
            h.emit({'receipt_key':record['receipt']['key'],'receipt_version':record['receipt']['version'],'receipt_sha':record['receipt']['sha256']})

if __name__=='__main__':
    try:run(sys.argv[1])
    except Exception:raise SystemExit('GitOps lifecycle stopped safely; checkpoint remains paused. For a fresh-cluster Up, complete protected gitops-access-bootstrap.yml with this checkpoint and resume. No private command output published.')
