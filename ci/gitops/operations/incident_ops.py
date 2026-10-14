#!/usr/bin/env python3
"""Explicit BU16 mutation handlers. No shell, arbitrary API verb, or script input."""
import argparse, contextlib, copy, datetime as dt, hashlib, importlib.util, json, os, pathlib, re, sys, tempfile, time, uuid
BASE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(BASE.parent))
sys.path.insert(0,str(BASE))
import gitops_ops as ops

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=load('incident_saved_plan',ops.shared_file('saved-plan.py'))
state=load('incident_state',ops.shared_file('lifecycle-state.py'))
OPERATION_IDS=('query-pod-create','selfheal-demo','selfheal-restore','builder-cycle','builder-restore','job-cleanup','ecr-cleanup','pitr-read-source','pitr-read-restored','pitr-fix-row','pitr-read-after','pool-diagnostic','db-connect-during','db-connect-after','db-connect-cleanup')
TARGETS={'selfheal-demo':('rollouts.argoproj.io','contract2whale-demo','commerce-web','commerce-web'), 'builder-cycle':('statefulsets.apps','monitoring','platform-tempo-e3-block-builder','platform-tempo-e3'), 'builder-restore':('statefulsets.apps','monitoring','platform-tempo-e3-block-builder','platform-tempo-e3')}
SHA=re.compile('[0-9a-f]{40}');DIGEST=re.compile('sha256:[0-9a-f]{64}')

def require(value,message):h.require(value,message)
def now():return dt.datetime.now(dt.timezone.utc)
def canonical_hash(value):return h.digest(h.canonical(value))
def request_live(r):
    require(SHA.fullmatch(r['source_sha']) and now()<dt.datetime.fromisoformat(r['expires_at'].replace('Z','+00:00')),'Expired/invalid incident request.')
    require(r.get('change_request') and r.get('data_decision'),'Explicit reviewed change/data decision required.')

def kube(kind, namespace, name, optional=False):
    cmd=['kubectl']+(['-n',namespace] if namespace else [])+['get',kind,name,'-o','json']
    if optional:cmd.append('--ignore-not-found')
    raw=ops.run(cmd);return json.loads(raw) if raw.strip() else None

def identity(obj):
    require(obj is not None and obj['metadata'].get('uid'),'Missing object identity.')
    return {'uid':obj['metadata']['uid'],'name':obj['metadata']['name'],'namespace':obj['metadata'].get('namespace',''),'body_sha256':canonical_hash({k:v for k,v in obj.items() if k not in ('metadata','status')}),'metadata_sha256':canonical_hash({k:obj['metadata'].get(k) for k in ('labels','annotations','ownerReferences')})}

def same(obj, captured):require(identity(obj)==captured,'Object changed/replaced since incident review.')

def verify_app(app, revision, selfheal=False):
    spec=app['spec'];src=spec.get('sources') or [spec.get('source',{})]
    require(all(s.get('targetRevision')==revision for s in src if not s.get('chart')),'Application does not point to reviewed immutable revision.')
    result=app.get('status',{}).get('operationState',{})
    require(result.get('phase')=='Succeeded','No completed Application operation.')
    revisions=result.get('syncResult',{}).get('revisions') or [result.get('syncResult',{}).get('revision')]
    require(revision in revisions,'Application completed revision mismatch.')
    if selfheal:
        auto=spec.get('syncPolicy',{}).get('automated',{})
        require(auto.get('selfHeal') is True and auto.get('enabled',True) is True,'Self-heal demonstration requires enabled selfHeal.')
    else:
        auto=spec.get('syncPolicy',{}).get('automated')
        require(auto is None or auto.get('enabled') is False,'Builder reconciliation must be suspended by reviewed Git change.')
    require(not app.get('operation'),'Concurrent Application operation is running.')

def replica_snapshot(operation,r,env):
    if operation=='builder-cycle':require(type(r.get('hold_seconds')) is int and 1<=r['hold_seconds']<=900,'Approved bounded observation interval required before planning.')
    kind,ns,name,base=TARGETS[operation];obj=kube(kind,ns,name);app=kube('applications.argoproj.io','argocd',base+'-'+env)
    auto=app['spec'].get('syncPolicy',{}).get('automated')
    temporary_selfheal=operation=='selfheal-demo' and (auto is None or auto.get('enabled') is False)
    verify_app(app,r['source_sha'],selfheal=operation=='selfheal-demo' and not temporary_selfheal)
    tracking=obj['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id','')
    require(tracking.startswith(base+'-'+env+':'),'Workload is not tracked by exact Application.')
    hpas=json.loads(ops.run(['kubectl','-n',ns,'get','hpa','-o','json']))['items']
    require(not any(x['spec']['scaleTargetRef']['name']==name for x in hpas),'HPA can race incident replicas.')
    normal=r['normal_replicas'];require(type(normal) is int and 1<=normal<=10,'Invalid registered normal replicas.')
    if operation=='selfheal-demo':require(normal==2 and obj['spec']['replicas']==2,'Self-heal demo is exactly 2 to 3 to 2.')
    elif operation=='builder-cycle':require(obj['spec']['replicas']==normal,'Builder baseline differs from approved normal.')
    return {'kind':kind,'namespace':ns,'name':name,'object':identity(obj),'application_spec':copy.deepcopy(app['spec']),'temporary_selfheal':temporary_selfheal,'application':identity(app),'application_name':base+'-'+env,'normal_replicas':normal,'injected_replicas':3 if operation=='selfheal-demo' else 0,'spec':obj['spec'],'hpa_sha256':canonical_hash(hpas)}

def patch_replicas(target,expected,wanted):
    obj=kube(target['kind'],target['namespace'],target['name'])
    require(obj['metadata']['uid']==target['object']['uid'],'Workload UID changed; no recovery adoption.')
    require(obj['spec'].get('replicas')==expected,'Replicas changed concurrently.')
    original=copy.deepcopy(target['spec']);actual=copy.deepcopy(obj['spec']);original.pop('replicas',None);actual.pop('replicas',None)
    require(original==actual,'Non-replica workload specification changed.')
    patch=[{'op':'test','path':'/metadata/uid','value':target['object']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'test','path':'/spec/replicas','value':expected},{'op':'replace','path':'/spec/replicas','value':wanted}]
    ops.run(['kubectl','-n',target['namespace'],'patch',target['kind'],target['name'],'--type=json','-p',json.dumps(patch)])

def wait_replicas(target,wanted,timeout=300):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        obj=kube(target['kind'],target['namespace'],target['name'])
        require(obj['metadata']['uid']==target['object']['uid'],'Workload replaced during wait.')
        if obj['spec'].get('replicas')==wanted and (wanted==0 and obj.get('status',{}).get('replicas',0)==0 or wanted>0 and obj.get('status',{}).get('readyReplicas',0)==wanted):return
        time.sleep(5)
    raise h.SafeError('Replica/readiness wait timed out; recovery marker remains.')

def restore(target):
    obj=kube(target['kind'],target['namespace'],target['name']);wanted=target['normal_replicas']
    same(kube('applications.argoproj.io','argocd',target['application_name']),target['application'])
    hpas=json.loads(ops.run(['kubectl','-n',target['namespace'],'get','hpa','-o','json']))['items']
    require(not any(x['spec']['scaleTargetRef']['name']==target['name'] for x in hpas),'HPA appeared before recovery.')
    require(obj['spec'].get('replicas') in (wanted,target['injected_replicas']),'Unrelated replica change; do not override external writer.')
    if obj['spec'].get('replicas')!=wanted:patch_replicas(target,obj['spec']['replicas'],wanted)
    else:require(obj['metadata']['uid']==target['object']['uid'],'Recovery UID mismatch.')
    wait_replicas(target,wanted,600)

def selfheal_policy(target,enabled):
    if not target.get('temporary_selfheal'):return
    app=kube('applications.argoproj.io','argocd',target['application_name'])
    original=target['application_spec'];fault=copy.deepcopy(original);fault.setdefault('syncPolicy',{})['automated']={'enabled':True,'selfHeal':True,'prune':False,'allowEmpty':False}
    require(app['metadata']['uid']==target['application']['uid'] and app['spec'] in (original,fault),'Self-heal policy identity/spec drift; no overwrite')
    wanted=fault if enabled else original
    if app['spec']!=wanted:
        patch=[{'op':'test','path':'/metadata/uid','value':target['application']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':app['metadata']['resourceVersion']},{'op':'test','path':'/spec','value':app['spec']},{'op':'replace','path':'/spec','value':wanted}]
        ops.run(['kubectl','-n','argocd','patch','application',target['application_name'],'--type=json','-p',json.dumps(patch)])
    require(kube('applications.argoproj.io','argocd',target['application_name'])['spec']==wanted,'Temporary self-heal policy not verified')

def run_replica(operation,target,r,mark):
    import builder_trace
    def trace_mark(phase,trace):
        target['trace']=trace;mark(phase,target)
    if operation in ('builder-restore','selfheal-restore'):
        selfheal_policy(target,False);restore(target)
        if target.get('trace'):builder_trace.cleanup_probes(fixture_io(),target['trace'],trace_mark)
        mark('idle',target);return {'restored':True,'trace_observations':target.get('trace',{}).get('observations',{})}
    mark('active',target)
    succeeded=False
    try:
        if operation=='selfheal-demo':selfheal_policy(target,True)
        patch_replicas(target,target['normal_replicas'],3 if operation=='selfheal-demo' else 0)
        if operation=='selfheal-demo':wait_replicas(target,2,300)
        else:
            wait_replicas(target,0,300)
            hold=r['hold_seconds'];require(type(hold) is int and 1<=hold<=900,'Bounded hold must be 1–900 seconds.')
            # Observation window is explicit in the approved action plan; no unbounded pause.
            require(builder_trace.probe(fixture_io(),target['trace'],'fault','send',trace_mark)['accepted'],'During-fault synthetic trace was not accepted')
            time.sleep(hold)
            builder_trace.probe(fixture_io(),target['trace'],'fault','query',trace_mark)
        succeeded=True
    finally:
        try:
            selfheal_policy(target,False);restore(target)
            if target.get('trace'):
                try:
                    if succeeded:builder_trace.probe(fixture_io(),target['trace'],'fault','requery',trace_mark)
                finally:builder_trace.cleanup_probes(fixture_io(),target['trace'],trace_mark)
            mark('idle',target)
        except Exception:mark('recovery-required',target);raise
    return {'restored':True,'experiment_completed':succeeded,'trace_observations':target.get('trace',{}).get('observations',{}),'diagnosis':'Use exact send/query/requery evidence; replica readiness alone does not prove trace persistence'}

def job_snapshot(r):
    t7='attempt_id' in r
    experiment=r['attempt_id'] if t7 else str(uuid.UUID(r['experiment_id']));jobs=r['jobs']
    if t7:require(re.fullmatch(r'dbe-[0-9]{8}t[0-9]{6}',experiment),'Typed T7 attempt ID required.')
    require(isinstance(jobs,list) and 1<=len(jobs)<=10,'A bounded explicit Job list is required.')
    result=[];seen=set()
    for item in jobs:
        name=item['name'];require(name not in seen and re.fullmatch(r'incident-[a-z0-9-]+',name) and name.endswith(experiment[4:] if t7 else experiment),'Invalid/duplicate experiment Job name.');seen.add(name)
        obj=kube('jobs.batch','contract2whale-demo',name,True)
        require(obj is not None,'Do not infer absence or adopt missing prepared Job.')
        require(obj['metadata']['uid']==item['uid'] and obj['metadata'].get('labels',{}).get('incident.course/attempt' if t7 else 'recovery.course/experiment-id')==experiment,'Job creation UID/experiment mismatch.')
        require(not obj['metadata'].get('ownerReferences'),'Externally controlled Job cannot be cleaned by this operation.')
        require(obj['spec']['template']['spec'].get('serviceAccountName')=='database-operator','Unexpected Job service account.')
        require(not obj.get('status',{}).get('active',0),'Active DB Job must finish before cleanup approval.')
        result.append(identity(obj))
    return result

def delete_job(target):
    obj=kube('jobs.batch','contract2whale-demo',target['name']);same(obj,target)
    require(not obj.get('status',{}).get('active',0),'Job became active after review.')
    options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':target['uid'],'resourceVersion':obj['metadata']['resourceVersion']}}
    with tempfile.TemporaryDirectory() as d:
        f=pathlib.Path(d)/'delete.json';f.write_bytes(h.canonical(options))
        ops.run(['kubectl','delete','--raw','/apis/batch/v1/namespaces/contract2whale-demo/jobs/'+target['name'],'-f',str(f)])
    for _ in range(60):
        current=kube('jobs.batch','contract2whale-demo',target['name'],True)
        if current is None:
            pods=json.loads(ops.run(['kubectl','-n','contract2whale-demo','get','pods','-o','json']))['items']
            require(not any(any(x['uid']==target['uid'] for x in p['metadata'].get('ownerReferences',[])) for p in pods),'Job-owned Pods remain after foreground deletion.')
            return
        require(current['metadata']['uid']==target['uid'],'Replacement Job detected; not deleting it.')
        time.sleep(5)
    raise h.SafeError('Job cleanup timeout; no forced finalizer removal.')

def repository_consumers_absent(c,repositories):
    # The supplied course uses one EKS cluster per account, no ECS consumers.
    clusters=json.loads(ops.run(['aws','eks','list-clusters','--region',c['region']]))['clusters']
    require(clusters==[c['cluster']],'Additional EKS cluster needs a separate consumer inventory.')
    require(not json.loads(ops.run(['aws','ecs','list-clusters','--region',c['region']]))['clusterArns'],'ECS consumers require separate reviewed inventory.')
    functions=json.loads(ops.run(['aws','lambda','list-functions','--region',c['region']]))['Functions']
    for fn in functions:
        if fn.get('PackageType')=='Image':
            value=json.loads(ops.run(['aws','lambda','get-function','--function-name',fn['FunctionArn'],'--region',c['region']]))
            require(not any(value.get('Code',{}).get('ResolvedImageUri','').startswith(repo+'@') for repo in repositories),'Lambda references a retiring image repository.')
    apps=json.loads(ops.run(['kubectl','-n','argocd','get','applications','-o','json']))['items']
    for app in apps:
        auto=app['spec'].get('syncPolicy',{}).get('automated')
        require(auto is None or auto.get('enabled') is False,'Suspend all Argo automatic reconciliation before final image retirement.')
        require(app['metadata']['name'] not in ('commerce-web-dev','commerce-api-dev','commerce-web-prod','commerce-api-prod'),'Application still depends on image repository.')
    def no_reference(node):
        if isinstance(node,dict):
            if isinstance(node.get('image'),str):require(not any(node['image'].startswith(repo+':') or node['image'].startswith(repo+'@') for repo in repositories),'Live workload still references retiring repository.')
            for value in node.values():no_reference(value)
        elif isinstance(node,list):
            for value in node:no_reference(value)
    for kind in ('pods','deployments','statefulsets','daemonsets','jobs','cronjobs','rollouts.argoproj.io'):
        no_reference(json.loads(ops.run(['kubectl','get',kind,'--all-namespaces','-o','json'])))

def ecr_snapshot(c,r,store):
    require(r['data_decision']=='delete-exact-approved-image-digests','Explicit ECR data/signature retention decision required.')
    lifecycle=load('incident_gitops_adapter',BASE.parent/'gitops-lifecycle.py')
    guard=lifecycle.load('incident_eks_state',lifecycle.dependency('eks-lifecycle-guard.py','eks-adapter-proposal'))
    value=guard.VersionedStateReader(store.bucket,c['account_id'],c['region'])('delivery/terraform.tfstate')
    repos={x['values']['name']:x['values'] for x in guard.managed_resources(value['state']) if x['type']=='aws_ecr_repository'}
    requested=r['repositories'];require(set(requested)<= {'commerce-web','commerce-api'} and requested,'Only the two delivery repositories are registered.')
    result=[]
    for name,decision in requested.items():
        require(name in repos,'Repository missing from versioned delivery State.')
        repo=json.loads(ops.run(['aws','ecr','describe-repositories','--repository-names',name,'--region',c['region']]))['repositories'][0]
        require(repo['repositoryArn']==repos[name]['arn'] and repo['registryId']==c['account_id'],'ECR State/live ownership mismatch.')
        delete=decision['delete_digests'];retain=decision['retain_digests']
        require(1<=len(delete)<=100 and len(delete)==len(set(delete)) and all(DIGEST.fullmatch(x) for x in delete+retain),'Exact 1–100 unique image digests per approved request required.')
        require(not set(delete)&set(retain),'Delete/retain image conflict.')
        images=json.loads(ops.run(['aws','ecr','describe-images','--repository-name',name,'--region',c['region']]))['imageDetails']
        inventory=sorted([{'digest':x['imageDigest'],'tags':sorted(x.get('imageTags',[])),'pushed_at':x['imagePushedAt']} for x in images],key=lambda x:x['digest'])
        require({x['digest'] for x in inventory}==set(delete)|set(retain),'Every current image/signature digest needs an explicit retain/delete classification.')
        result.append({'name':name,'arn':repo['repositoryArn'],'url':repo['repositoryUri'],'created_at':repo['createdAt'],'inventory':inventory,'delete_digests':delete,'retain_digests':retain})
    repository_consumers_absent(c,[x['url'] for x in result])
    return {'repositories':result,'delivery_state':value['fingerprint']}

def delete_ecr(c,target,mark):
    repository_consumers_absent(c,[x['url'] for x in target['repositories']])
    completed=[];mark('active',dict(target,completed=completed))
    try:
        for repo in target['repositories']:
            result=json.loads(ops.run(['aws','ecr','batch-delete-image','--registry-id',c['account_id'],'--repository-name',repo['name'],'--image-ids',json.dumps([{'imageDigest':x} for x in repo['delete_digests']]),'--region',c['region']]))
            require(result.get('failures')==[],'ECR reported partial deletion/failure; review recovery marker.')
            require({x['imageDigest'] for x in result['imageIds']}==set(repo['delete_digests']),'ECR deletion response differs from approved set.')
            remaining=json.loads(ops.run(['aws','ecr','list-images','--repository-name',repo['name'],'--region',c['region']]))['imageIds']
            require({x['imageDigest'] for x in remaining}==set(repo['retain_digests']),'Unexpected remaining/deleted images; repository deletion prohibited.')
            completed.append(repo['name']);mark('active',dict(target,completed=completed))
    except Exception:mark('recovery-required',dict(target,completed=completed));raise
    mark('idle',dict(target,completed=completed))
    return {'repositories_completed':completed,'retained_digests':{x['name']:x['retain_digests'] for x in target['repositories']},'repository_deletion_permitted':all(not x['retain_digests'] for x in target['repositories'])}

def fill_template(operation,r,c):
    """Only shipped fixed Job templates. Substitutions are typed coordinates, never SQL/shell."""
    if operation in ('db-connect-during','db-connect-after'):
        attempt=r['attempt_id'];require(re.fullmatch(r'dbe-[0-9]{8}t[0-9]{6}',attempt),'Typed unique DB-connect attempt ID required.')
        value=json.loads((BASE/'templates/db-connect.json').read_text());value['metadata']['name']='incident-db-connect-'+('during' if operation.endswith('during') else 'after')+'-'+attempt[4:]
        require(r['job_name']==value['metadata']['name'],'Fixed DB-connect Job name differs.')
        value['metadata']['labels']['incident.course/attempt']=attempt;value['spec']['template']['metadata']['labels']['incident.course/attempt']=attempt
        require(ops.DIGEST.fullmatch(r['operator_image']) and r['operator_image'].startswith(c['account_id']+'.dkr.ecr.'+c['region']+'.amazonaws.com/contract2whale/database-operator@'),'Locked account-local operator image required.')
        require(re.fullmatch('database-bootstrap-[a-z0-9-]+',r['configmap_name']),'Reviewed database-bootstrap ConfigMap required.')
        container=value['spec']['template']['spec']['containers'][0];container['image']=r['operator_image'];container['envFrom'][0]['configMapRef']['name']=r['configmap_name'];container['env'][0]['value']=r['operator_role_arn']
        return value
    experiment=str(uuid.UUID(r['experiment_id']));name=r['job_name']
    prefixes={'pitr-read-source':'incident-read-source-','pitr-read-restored':'incident-read-restored-','pitr-fix-row':'incident-status-fix-','pitr-read-after':'incident-read-after-','pool-diagnostic':'incident-db-after-'}
    require(name==prefixes[operation]+experiment and len(name)<=63,'Job name must match fixed operation and experiment UUID.')
    image=r['operator_image'];require(re.fullmatch(re.escape(c['account_id'])+r'\.dkr\.ecr\.'+re.escape(c['region'])+r'\.amazonaws\.com/contract2whale/database-operator@sha256:[0-9a-f]{64}',image),'Reviewed account-local operator image digest required.')
    template='pool-diagnostic.json' if operation=='pool-diagnostic' else 'pitr-fix.json' if operation=='pitr-fix-row' else 'pitr-read.json'
    text=(BASE/'templates'/template).read_text()
    replacements={'__RUN_ID__':experiment,'__READ_JOB_NAME__':name,'__FIX_JOB_NAME__':name,'__OPERATOR_IMAGE__':image,'${INCIDENT_AFTER_DIAGNOSTIC_JOB}':name,'${INCIDENT_EXP}':experiment,'${INCIDENT_OPERATOR_IMAGE}':image}
    if operation=='pool-diagnostic':
        require(re.fullmatch(r'incident-[a-z0-9-]+',r['configmap_name']),'Fixed diagnostic ConfigMap name required.')
        require(re.fullmatch(r'arn:aws:iam::'+c['account_id']+r':role/[A-Za-z0-9+=,.@_/-]+',r['operator_role_arn']),'Operator role account mismatch.')
        replacements.update({'${INCIDENT_DIAGNOSTIC_CM}':r['configmap_name'],'${INCIDENT_OPERATOR_ROLE_ARN}':r['operator_role_arn']})
    else:
        require(re.fullmatch(r'[a-zA-Z0-9-]{1,80}',r['sample_handle']),'SQL handle must be alphanumeric/hyphen.')
        require(re.fullmatch(r'[a-zA-Z0-9.-]+\.rds\.amazonaws\.com',r['db_host']),'Registered RDS TLS hostname required.')
        require(re.fullmatch(r'arn:aws:secretsmanager:'+re.escape(c['region'])+':'+c['account_id']+r':secret:[A-Za-z0-9/_+=.@-]+',r['runtime_secret_arn']),'Runtime secret account/region mismatch.')
        replacements.update({'__SAMPLE_HANDLE__':r['sample_handle'],'__DB_HOST__':r['db_host'],'__APP_SECRET_ARN__':r['runtime_secret_arn']})
        if operation=='pitr-fix-row':
            require(re.fullmatch(r'[A-Za-z0-9_-]{1,100}',r['sample_id']),'Invalid exact sample product ID.')
            require(r['expected_status'] in ('draft','published') and r['new_status'] in ('draft','published') and r['expected_status']!=r['new_status'],'Only reviewed single-row publication status correction permitted.')
            require(r['data_decision']=='update-one-exact-synthetic-product-row','Explicit exact row change approval required.')
            replacements.update({'__SAMPLE_ID__':r['sample_id'],'__EXPECT_STATUS__':r['expected_status'],'__NEW_STATUS__':r['new_status']})
    for key,value in replacements.items():text=text.replace(key,value)
    require(not re.search(r'__[A-Z_]+__|\$\{INCIDENT_',text),'Unresolved Job coordinates.')
    result=json.loads(text)
    result['metadata']['labels'].update({'recovery.course/run-id':h.required('GITHUB_RUN_ID'),'recovery.course/source-sha':r['source_sha']})
    return result

def restored_db_receipt(r,c,store):
    descriptor=r['restore_receipt'];require(descriptor['key'].startswith('ci-logs/'+h.required('GITHUB_REPOSITORY_ID')+'/') and '/dev/incident/rds-pitr-create/apply/receipt.json' in descriptor['key'],'Untrusted restored DB creation receipt namespace.')
    with tempfile.TemporaryDirectory() as d:
        path=pathlib.Path(d)/'receipt';store.get(descriptor,path);receipt=json.loads(path.read_bytes())
    require(receipt.get('status')=='verified' and receipt['context']['account']==c['account_id'] and receipt['context']['repository_id']==h.required('GITHUB_REPOSITORY_ID') and receipt['request']['incident_run']==r['experiment_id'],'Restored DB creation receipt identity/outcome differs.')
    observed=receipt['observations'];require(observed['target_arn']==r['db_arn'] and observed['target_resource_id']==r['db_resource_id'] and observed['endpoint']==r['db_host'],'Restored DB Job coordinates differ from original creation receipt.')
    return descriptor

def job_create_snapshot(operation,r,c,store):
    manifest=fill_template(operation,r,c)
    require(kube('jobs.batch','contract2whale-demo',manifest['metadata']['name'],True) is None,'Job already exists; never adopt it.')
    sa=kube('serviceaccounts','contract2whale-demo','database-operator');require(sa['metadata']['uid']==r['serviceaccount_uid'],'ServiceAccount creation identity changed.')
    assoc=json.loads(ops.run(['aws','eks','describe-pod-identity-association','--cluster-name',c['cluster'],'--association-id',r['association_id'],'--region',c['region']]))['association']
    require(assoc['namespace']=='contract2whale-demo' and assoc['serviceAccount']=='database-operator' and assoc['roleArn']==r['operator_role_arn'],'Operator association/role mismatch.')
    inputs={'serviceaccount':identity(sa),'association':assoc}
    if operation in ('pool-diagnostic','db-connect-during','db-connect-after'):
        cm=kube('configmaps','contract2whale-demo',r['configmap_name']);require(cm['metadata']['uid']==r['configmap_uid'],'Diagnostic ConfigMap changed.');inputs['configmap']=identity(cm)
    else:
        db=json.loads(ops.run(['aws','rds','describe-db-instances','--db-instance-identifier',r['db_identifier'],'--region',c['region']]))['DBInstances'][0]
        require(db['DBInstanceArn']==r['db_arn'] and db['DbiResourceId']==r['db_resource_id'] and db['Endpoint']['Address']==r['db_host'],'Exact approved RDS resource identity/hostname mismatch.')
        secret=json.loads(ops.run(['aws','secretsmanager','describe-secret','--secret-id',r['runtime_secret_arn'],'--region',c['region']]))
        require(secret['ARN']==r['runtime_secret_arn'] and not secret.get('DeletedDate'),'Runtime secret is missing/pending deletion.')
        if operation=='pitr-read-restored':inputs['restore_receipt']=restored_db_receipt(r,c,store)
        inputs.update(db={'arn':db['DBInstanceArn'],'resource_id':db['DbiResourceId'],'host':db['Endpoint']['Address']},secret_arn=secret['ARN'])
    return {'manifest':manifest,'input_identities':inputs,'expected_outcome':'failed' if operation=='db-connect-during' else 'succeeded'}

def create_job(target,mark):
    manifest=target['manifest'];name=manifest['metadata']['name']
    require(kube('jobs.batch','contract2whale-demo',name,True) is None,'Job appeared after review; do not adopt.')
    # create, not apply: API AlreadyExists is a stop, never overwrite prior experiment.
    created=json.loads(ops.run(['kubectl','create','-f','-','-o','json'],content=h.canonical(manifest)))
    ident=identity(created)
    mark('active',{'created_job':ident})
    for _ in range(48):
        obj=kube('jobs.batch','contract2whale-demo',name);require(obj['metadata']['uid']==ident['uid'],'Job replaced while executing.')
        if obj.get('status',{}).get('succeeded',0)==1:
            require(target['expected_outcome']=='succeeded','During-fault connection unexpectedly succeeded; do not claim isolation.')
            return {'created_job':ident,'complete':True,'outcome':'succeeded','raw_job_logs_published':False}
        if obj.get('status',{}).get('failed',0) and target['expected_outcome']=='failed':return {'created_job':ident,'complete':True,'outcome':'expected-failure-observed','raw_job_logs_published':False}
        require(not obj.get('status',{}).get('failed',0),'Fixed Job failed; inspect protected Kubernetes evidence; do not rerun a write blindly.')
        time.sleep(5)
    raise h.SafeError('Job completion timed out; retain its UID for explicit recovery/cleanup.')

def gate_name(environment,operation):return 'incident-'+environment+('-destructive' if operation in ('ecr-cleanup','job-cleanup') or operation.endswith(('-cleanup','-retire')) else '-mutate')
def check_gate(environment,operation):
    name=gate_name(environment,operation);endpoint='repos/'+h.required('GITHUB_REPOSITORY')+'/environments/'+name
    value=json.loads(h.execute(['gh','api',endpoint]));rules=value.get('protection_rules',[])
    require(any(x.get('type')=='required_reviewers' and x.get('reviewers') and x.get('prevent_self_review') is True for x in rules),'Incident mutation requires reviewers and no self-review.')
    require(value.get('can_admins_bypass') is False and value.get('deployment_branch_policy',{}).get('custom_branch_policies') is True,'Incident Environment must prohibit bypass and restrict main.')
    policies=json.loads(h.execute(['gh','api',endpoint+'/deployment-branch-policies']))
    require(policies.get('total_count')==1 and policies['branch_policies'][0]['name']=='main','Only trusted main may execute incident mutations.')

def incident_key(repo,environment):
    require(repo.isdigit() and environment in ('dev','prod'),'Invalid incident identity.')
    return f'ci-incidents/{repo}/{environment}/active.json'

def course_check(store,c,environment):
    course,_=state.read_json(store,state.course_marker_key(h.required('GITHUB_REPOSITORY_ID'),environment))
    if course:
        state.validate_course(course,h.required('GITHUB_REPOSITORY_ID'),c['account_id'],c['state_bucket'],c['region'],environment)
        require(course['phase']=='active','Course lifecycle paused; incident workflow cannot mutate.')

def config(environment,operation,stage):
    require(os.environ.get('GITHUB_REF')=='refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','Trusted-main explicit incident dispatch required.')
    require(operation in OPERATION_IDS and environment in ('dev','prod'),'Unknown operation/environment.')
    require(operation in ('ecr-cleanup',)+PLATFORM_PROD_IDS+BOOTSTRAP_IDS+VELERO_IDS+QUEUE_IDS+RDS_PROTECTION_IDS+ARGO_PROD_IDS or environment=='dev','Kubernetes incident exercises are Dev only.')
    cfg=json.loads((BASE.parent/'operations.json').read_text());require(cfg.get('enabled') is True,'Complete registered account/toolchain prerequisites first.')
    c=copy.deepcopy(cfg['environments'][environment]);c['operator_image']=cfg['operator_image'];c['environment']=environment
    r=json.loads((BASE/'requests.json').read_text())['environments'][environment][operation]
    request_live(r)
    require(re.fullmatch('[0-9a-f]{40}',h.required('GITHUB_SHA')),'Full workflow SHA required.')
    require(h.execute(['git','rev-parse','HEAD']).decode().strip()==h.required('GITHUB_SHA'),'Helper checkout differs from workflow SHA.')
    h.execute(['git','merge-base','--is-ancestor',r['source_sha'],h.required('GITHUB_SHA')])
    h.ensure_current_main({'sha':h.required('GITHUB_SHA')});ops.check_tools(c);check_gate(environment,operation)
    expected=c['incident_plan_role_arn'] if stage=='plan' else c['incident_apply_role_arn']
    require(h.required('AWS_ROLE_ARN')==expected,'Wrong incident role.');h.check_identity(c['account_id'],expected)
    store=h.Store(c['state_bucket'],c['account_id']);store.check();course_check(store,c,environment)
    context={'schema_version':1,'operation':operation,'environment':environment,'account':c['account_id'],'region':c['region'],'repository_id':h.required('GITHUB_REPOSITORY_ID'),'source_sha':r['source_sha'],'workflow_sha':h.required('GITHUB_SHA'),'run_id':h.required('GITHUB_RUN_ID'),'run_attempt':h.required('GITHUB_RUN_ATTEMPT'),'request_sha256':canonical_hash(r),'registration_sha256':canonical_hash(c)}
    return c,r,store,context

def fixture_io():
    import types
    return types.SimpleNamespace(h=h,ops=ops,require=require,kube=kube,identity=identity)

def snapshot(operation,r,c,env,store,marker):
    if operation in ENDPOINT_IDS:
        import endpoint_policy_ops
        return endpoint_policy_ops.snapshot(fixture_io(),operation,r,c,store)
    if operation in PRODUCER_IDS:
        import producer_acl_ops
        return producer_acl_ops.snapshot(fixture_io(),operation,r,c,store,marker)
    if operation in ARGO_IDS:
        import argo_reviewed_ops
        return argo_reviewed_ops.snapshot(fixture_io(),operation,r,c,marker,store)
    if operation in QUEUE_IDS:
        import managed_queue_ops
        return managed_queue_ops.snapshot(fixture_io(),operation,r,c,store)
    if operation in RDS_PROTECTION_IDS:
        import rds_protection_ops
        return rds_protection_ops.snapshot(fixture_io(),operation,r,c,store)
    if operation in BOOTSTRAP_IDS:
        import bootstrap_job_ops
        if operation=='database-bootstrap-observe':return bootstrap_job_ops.observe_snapshot(fixture_io(),r,marker)
        return bootstrap_job_ops.snapshot(fixture_io(),operation,r,c,store,marker)
    if operation in VELERO_IDS:
        import velero_ops
        return velero_ops.snapshot(fixture_io(),operation,r,c,marker,store)
    if operation in PLATFORM_IDS:
        import platform_probe_ops
        return platform_probe_ops.snapshot(fixture_io(),operation,r,c,marker,store)
    if operation=='selfheal-restore':
        require(marker and marker.get('operation') in ('selfheal-demo','selfheal-restore'),'Original self-heal marker required.')
        return marker['target']
    if operation in DRAIN_IDS:
        import drain_ops
        return drain_ops.snapshot(fixture_io(),operation,r,c,marker)
    if operation=='query-pod-create':
        require(re.fullmatch('[a-z0-9-]{1,40}',r['query_id']),'Invalid fixed query ID.')
        name='incident-kafka-'+r['query_id'];require(kube('pods','monitoring',name,True) is None,'Query Pod already exists; no adoption.')
        image=c['kafka_query_image'];require(ops.DIGEST.fullmatch(image),'Kafka client image must be instructor-published digest; no mutable source tag.')
        return {'pod':{'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'monitoring','labels':{'course-query-id':r['query_id']}},'spec':{'restartPolicy':'Never','activeDeadlineSeconds':1800,'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'query','image':image,'command':['sleep','1800'],'resources':{'requests':{'cpu':'100m','memory':'256Mi'},'limits':{'cpu':'500m','memory':'512Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}}}]}}}

    if operation in NODE_IDS:
        import node_ops
        return node_ops.snapshot(fixture_io(),operation,r,c,marker)
    if operation.startswith('fixture-'):
        import fixture_ops
        return fixture_ops.snapshot(fixture_io(),operation,r,c,marker,store)
    if operation=='demand-restore':
        require(marker and marker.get('operation') in ('demand-scale','demand-restore'),'Original demand baseline marker required.')
        row=copy.deepcopy(marker['target']['objects'][0]);obj=kube(row['kind'],row['namespace'],row['name']);a=dict(obj['spec']);a.pop('replicas',None);b=dict(row['spec']);b.pop('replicas',None)
        require(obj['metadata']['uid']==row['object']['uid'] and a==b and obj['spec']['replicas'] in (row['old_value'],row['new_value']),'Demand recovery target differs.')
        row.update(object=identity(obj),old_value=obj['spec']['replicas'],new_value=row['spec']['replicas']);return {'objects':[row]}
    if operation in FIXED_IDS:return fixed_snapshot(operation,r,c,marker)
    if operation in ('selfheal-demo','builder-cycle'):
        target=replica_snapshot(operation,r,env)
        if operation=='builder-cycle':
            import builder_trace
            target['trace']=builder_trace.prepare(fixture_io(),r,c)
        return target
    if operation=='builder-restore':
        require(marker and marker.get('owner')=='kubernetes-fixed-operations' and marker.get('phase') in ('active','recovery-required') and marker.get('operation')=='builder-cycle','Exact unresolved builder incident marker required.')
        target=marker['target'];require(target['name']=='platform-tempo-e3-block-builder' and target['namespace']=='monitoring','Unrecognized recovery target.')
        require(kube(target['kind'],target['namespace'],target['name'])['metadata']['uid']==target['object']['uid'],'Recovery target replaced.')
        return target
    if operation in ('job-cleanup','db-connect-cleanup'):return {'jobs':job_snapshot(r)}
    if operation=='ecr-cleanup':return ecr_snapshot(c,r,store)
    return job_create_snapshot(operation,r,c,store)

def validate_manifest(manifest,context,marker_info,bindings,clock=None):
    clock=time.time() if clock is None else clock
    require(manifest.get('schema')==1 and manifest.get('kind')=='incident-plan' and manifest.get('context')==context,'Incident plan context mismatch.')
    require(manifest['marker']==marker_info and manifest['bindings']==bindings,'Incident marker or underlying State changed.')
    require(manifest['created_at']<=clock<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==3600,'Incident plan expired.')

def recovery_authorized(operation,r,marker):
    if not marker or marker.get('phase')=='idle':return True
    if marker.get('owner')!='kubernetes-fixed-operations':return False
    if operation=='node-drain-restore':return marker.get('operation') in DRAIN_IDS
    if operation=='node-protection-restore':return marker.get('operation') in NODE_IDS
    if operation.startswith('fixture-'):
        case=operation.split('-')[1]
        return operation.endswith(('-restore','-cleanup')) and marker.get('operation','').startswith('fixture-'+case+'-')
    if operation=='builder-restore':return marker.get('operation')=='builder-cycle'
    if operation=='selfheal-restore':return marker.get('operation') in ('selfheal-demo','selfheal-restore')
    target=marker.get('target',{})
    if operation=='producer-acl-recover':return marker.get('operation') in PRODUCER_IDS and target.get('credential_run_id')==r.get('experiment_id') and target.get('pod',{}).get('uid')==r.get('pod_uid') and target.get('cluster_arn')==r.get('cluster_arn')
    if operation in ARGO_IDS:
        import argo_reviewed_ops
        return argo_reviewed_ops.recovery_authorized(operation,r,marker)
    if operation=='database-protection-restore' and marker.get('operation')=='database-protection-disable':return r.get('db_arn')==target.get('db_arn') and r.get('db_resource_id')==target.get('resource_id')
    if operation=='database-bootstrap-observe':return marker.get('operation') in BOOTSTRAP_IDS
    if operation=='database-bootstrap-cleanup':return marker.get('operation')=='database-bootstrap-cleanup' and target.get('bootstrap_run_id')==r.get('bootstrap_run_id')
    if operation=='velero-lab-cleanup':return marker.get('operation') in VELERO_IDS
    if operation in PLATFORM_IDS:
        original=marker.get('operation','');return (operation.endswith('-cleanup') and original.removesuffix('-create').removesuffix('-cleanup')==operation.removesuffix('-cleanup')) or (operation=='application-strict-restore' and original in ('application-strict-cycle','application-strict-restore'))
    if operation=='query-pod-cleanup' and target.get('created_pod'):
        pod=target['created_pod'];return r.get('target_uids')=={'pods/monitoring/'+pod['name']:pod['uid']}
    if operation in FIXED_IDS and operation.endswith('-cleanup') and marker.get('operation')==operation:
        expected={x['kind']+'/'+x['namespace']+'/'+x['name']:x['object']['uid'] for x in target.get('objects',[]) if x['object']['uid'] not in target.get('completed',[])}
        return r.get('target_uids')==expected
    if operation=='demand-restore':return marker.get('operation') in ('demand-scale','demand-restore')
    if operation in ('job-cleanup','db-connect-cleanup'):
        if 'created_job' in target:
            expected={target['created_job']['name']:target['created_job']['uid']}
        elif 'jobs' in target:
            expected={x['name']:x['uid'] for x in target['jobs'] if x['uid'] not in target.get('completed',[])}
        else:return False # creation outcome unknown requires explicit separate reconciliation
        return bool(r.get('jobs')) and all(expected.get(x['name'])==x['uid'] for x in r['jobs'])
    if operation=='ecr-cleanup' and marker.get('operation')=='ecr-cleanup':
        expected={x['name']:set(x['delete_digests']) for x in target.get('repositories',[])}
        return bool(r.get('repositories')) and all(name in expected and set(x['delete_digests'])<=expected[name] for name,x in r['repositories'].items())
    return False

def run(stage,environment,operation):
    import signal
    def interrupted(signum,frame):raise h.SafeError('Incident interrupted; attempt bounded recovery.')
    signal.signal(signal.SIGTERM,interrupted)
    os.umask(0o077);c,r,store,context=config(environment,operation,stage)
    key=incident_key(context['repository_id'],environment);marker,marker_info=state.read_json(store,key)
    if marker and marker.get('phase') in ('active','recovery-required'):
        require(recovery_authorized(operation,r,marker),'Unresolved incident requires its exact recovery; no unrelated mutation.')
    # Never let a retention policy erase the recovery marker.
    for rule in store.call('get-bucket-lifecycle-configuration').get('Rules',[]):
        if rule.get('Status')=='Enabled' and ('Expiration' in rule or 'NoncurrentVersionExpiration' in rule):
            f=rule.get('Filter',{});prefix=f.get('Prefix',f.get('And',{}).get('Prefix',rule.get('Prefix','')))
            require(not key.startswith(prefix),'Incident recovery marker must not expire.')
    adapter=load('incident_binding',BASE.parent/'gitops-lifecycle.py')
    effective,bindings=adapter.live_binding(c,store)
    proof=ops.bootstrap_proof(effective,store)
    effective['fixture_namespace_uids']=proof['receipt']['fixture_namespace_uids']
    bindings['operations_access']={k:proof[k] for k in ('key','version','sha256')}
    private=load('incident_private',adapter.dependency('private-api-session.py','eks-adapter-proposal'))
    prefix=f"ci-plans/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['workflow_sha']}/{environment}/incidents/{operation}/"
    with tempfile.TemporaryDirectory(prefix='private-incident-') as d:
        temp=pathlib.Path(d)
        with private.private_api(effective['cluster'],effective['relay'],effective['region'],temp/'kubeconfig') as (session,cluster):
            os.environ['KUBECONFIG']=session['KUBECONFIG']
            current=snapshot(operation,r,effective,environment,store,marker)
            if stage=='plan':
                payload={'operation':operation,'request':r,'target':current};path=temp/'action.json';path.write_bytes(h.canonical(payload))
                stamp=time.time();manifest={'schema':1,'kind':'incident-plan','context':context,'marker':marker_info,'bindings':bindings,'created_at':stamp,'expires_at':stamp+3600,'plan':store.put(prefix+'action.json',path)}
                review=temp/'review.json';review.write_bytes(h.canonical({'context':context,'action':payload,'recovery':'UID-bound original replica restore; no arbitrary mutation retries','approval_environment':gate_name(environment,operation)}));manifest['review']=store.put(prefix+'review.json',review)
                path=temp/'manifest.json';path.write_bytes(h.canonical(manifest));desc=store.put(prefix+'manifest.json',path)
                h.emit({'manifest_key':desc['key'],'manifest_version':desc['version'],'manifest_sha':desc['sha256'],'plan_sha':manifest['plan']['sha256']});return
            require(stage=='apply','Unknown incident stage.')
            desc={'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('EXPECTED_MANIFEST_SHA')}
            require(desc['key']==prefix+'manifest.json','Incident manifest belongs to another run.')
            path=temp/'manifest.json';store.get(desc,path);manifest=json.loads(path.read_bytes());validate_manifest(manifest,context,marker_info,bindings)
            require(manifest['plan']['key']==prefix+'action.json' and manifest['plan']['sha256']==h.required('EXPECTED_PLAN_SHA'),'Approved action digest mismatch.')
            path=temp/'action.json';store.get(manifest['plan'],path);action=json.loads(path.read_bytes())
            require(action=={'operation':operation,'request':r,'target':current},'Live operation/target differs from exact reviewed action bytes.')
            request_live(r);course_check(store,c,environment);h.ensure_current_main({'sha':context['workflow_sha']})
            last_target=current
            def mark(phase,target):
                nonlocal marker_info,last_target
                last_target=target
                value={'schema':1,'owner':'kubernetes-fixed-operations','phase':phase,'environment':environment,'account':c['account_id'],'repository_id':context['repository_id'],'bucket':c['state_bucket'],'region':c['region'],'operation':('builder-cycle' if operation=='builder-restore' and phase!='idle' else operation),'request_context':context,'target':target,'generation':context['run_id']+'-'+context['run_attempt']}
                marker_info=state.update(store,key,value,marker_info)
            result=None;failure=False
            try:
                if operation=='query-pod-create':
                    mark('active',current);created=json.loads(ops.run(['kubectl','create','-f','-','-o','json'],content=h.canonical(current['pod'])))
                    result={'created_pod':identity(created)};mark('active',dict(current,**result))
                    ops.run(['kubectl','-n','monitoring','wait','--for=condition=Ready','pod/'+created['metadata']['name'],'--timeout=180s']);mark('idle',result)
                elif operation in ENDPOINT_IDS:
                    import endpoint_policy_ops
                    result=endpoint_policy_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in PRODUCER_IDS:
                    import producer_acl_ops
                    result=producer_acl_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in ARGO_IDS:
                    import argo_reviewed_ops
                    result=argo_reviewed_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in QUEUE_IDS:
                    import managed_queue_ops
                    result=managed_queue_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in RDS_PROTECTION_IDS:
                    import rds_protection_ops
                    result=rds_protection_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in BOOTSTRAP_IDS:
                    import bootstrap_job_ops
                    result=bootstrap_job_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in VELERO_IDS:
                    import velero_ops
                    result=velero_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in PLATFORM_IDS:
                    import platform_probe_ops
                    result=platform_probe_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in DRAIN_IDS:
                    import drain_ops
                    result=drain_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in NODE_IDS:
                    import node_ops
                    result=node_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation.startswith('fixture-'):
                    import fixture_ops
                    result=fixture_ops.apply(fixture_io(),operation,current,r,mark)
                elif operation in FIXED_IDS:result=fixed_apply(operation,current,mark)
                elif operation in TARGETS or operation=='selfheal-restore':result=run_replica(operation,current,r,mark)
                elif operation in ('job-cleanup','db-connect-cleanup'):
                    mark('active',current)
                    completed=[]
                    for job in current['jobs']:delete_job(job);completed.append(job['uid']);mark('active',dict(current,completed=completed))
                    result={'deleted_job_uids':completed};mark('idle',dict(current,completed=completed))
                elif operation=='ecr-cleanup':result=delete_ecr(effective,current,mark)
                else:
                    mark('active',current);result=create_job(current,mark);mark('idle',result)
            except Exception:
                failure=True
                # Keep original operation target for explicit recovery after cancel/failure.
                record,_=state.read_json(store,key)
                if not record or record.get('phase')!='idle':mark('recovery-required',last_target)
                result={'complete':False,'recovery_required':not record or record.get('phase')!='idle'}
            receipt={'schema':1,'kind':'incident-completion','completed_at':int(time.time()),'context':context,'plan_sha':manifest['plan']['sha256'],'result':result,'success':not failure}
            path=temp/'receipt.json';path.write_bytes(h.canonical(receipt));receipt_desc=store.put(prefix.replace('ci-plans/','ci-logs/',1)+'apply/receipt.json',path)
            h.emit({'receipt_key':receipt_desc['key'],'receipt_version':receipt_desc['version'],'receipt_sha':receipt_desc['sha256']})
            require(not failure,'Incident action failed; inspect private receipt and exact recovery marker.')


FIXED_IDS=('demand-scale','demand-restore','t8-pdb-cleanup','t8a-cleanup','query-pod-cleanup','probe-configmap-cleanup')
GVR={'deployments.apps':('/apis/apps/v1','deployments'),'serviceaccounts':('/api/v1','serviceaccounts'),'configmaps':('/api/v1','configmaps'),'services':('/api/v1','services'),'networkpolicies.networking.k8s.io':('/apis/networking.k8s.io/v1','networkpolicies'),'poddisruptionbudgets.policy':('/apis/policy/v1','poddisruptionbudgets'),'namespaces':('/api/v1','namespaces'),'priorityclasses.scheduling.k8s.io':('/apis/scheduling.k8s.io/v1','priorityclasses'),'pods':('/api/v1','pods')}

def fixed_scope(operation,r):
    ns='contract2whale-demo'
    if operation=='demand-scale':return [('deployments.apps','incident-t8a','incident-t8a-demand')]
    if operation=='t8-pdb-cleanup':return [('poddisruptionbudgets.policy',ns,x) for x in ('incident-t8-web','incident-t8-api')]
    if operation=='t8a-cleanup':return [('deployments.apps','incident-t8a','incident-t8a-demand'),('priorityclasses.scheduling.k8s.io','','incident-t8a-low')]
    if operation=='query-pod-cleanup':
        require(re.fullmatch('[a-z0-9-]{1,40}',r['query_id']),'Invalid fixed query ID.')
        return [('pods','monitoring','incident-kafka-'+r['query_id'])]
    if operation=='probe-configmap-cleanup':
        require(re.fullmatch('incident-[a-z0-9-]{1,50}',r['configmap_name']),'Invalid incident probe ConfigMap name.')
        return [('configmaps',ns,r['configmap_name'])]
    raise h.SafeError('Unregistered fixed Kubernetes operation.')

def fixed_snapshot(operation,r,c,marker=None):
    rows=[];scope=fixed_scope(operation,r)
    if marker and marker.get('phase')!='idle' and marker.get('operation')==operation and operation.endswith('-cleanup'):
        completed=set(marker['target'].get('completed',[]));prior={x['kind']+'/'+x['namespace']+'/'+x['name']:x['object']['uid'] for x in marker['target']['objects']}
        scope=[x for x in scope if prior.get('/'.join(x)) not in completed]
    require(isinstance(r.get('target_uids'),dict) and set(r['target_uids'])=={kind+'/'+ns+'/'+name for kind,ns,name in scope},'Exact fixed target creation UID inventory required.')
    for kind,ns,name in scope:
        obj=kube(kind,ns,name);require(obj['metadata']['uid']==r['target_uids'][kind+'/'+ns+'/'+name],'Prepared fixed target UID differs.')
        require(not obj['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id'),'Tracked GitOps object must be changed through reviewed Git revision.')
        row={'kind':kind,'namespace':ns,'name':name,'object':identity(obj),'spec':obj.get('spec',{})}
        if operation=='demand-scale':
            desired=r['replicas'];require(type(desired) is int and 0<=desired<=50 and type(r['approved_max_replicas']) is int and desired<=r['approved_max_replicas']<=50,'Bounded approved demand/cost limit required.')
            hpas=json.loads(ops.run(['kubectl','-n',ns,'get','hpa','-o','json']))['items'];require(not any(x['spec']['scaleTargetRef']['name']==name for x in hpas),'HPA would race demand test.')
            require(type(r.get('hold_seconds')) is int and 1<=r['hold_seconds']<=900,'Demand is a bounded cycle; hold_seconds 1–900 required.')
            row.update(old_value=obj['spec']['replicas'],new_value=desired,field='/spec/replicas',hold_seconds=r['hold_seconds'])
        elif operation=='query-pod-cleanup':require(obj['metadata'].get('labels',{}).get('course-query-id')==r['query_id'],'Query Pod ownership label differs.')
        elif operation=='probe-configmap-cleanup':
            require(obj['metadata'].get('labels',{}).get('recovery.course/experiment-id')==str(uuid.UUID(r['experiment_id'])),'Probe ConfigMap experiment ownership differs.')
        rows.append(row)
    return {'objects':rows}

def fixed_apply(operation,target,mark):
    completed=[];mark('active',target)
    for row in target['objects']:
        obj=kube(row['kind'],row['namespace'],row['name']);same(obj,row['object'])
        if 'field' in row:
            patch=[{'op':'test','path':'/metadata/uid','value':row['object']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'test','path':row['field'],'value':row['old_value']},{'op':'replace','path':row['field'],'value':row['new_value']}]
            try:
                ops.run(['kubectl','-n',row['namespace'],'patch',row['kind'],row['name'],'--type=json','-p',json.dumps(patch)])
                ops.run(['kubectl','-n',row['namespace'],'rollout','status','deployment/'+row['name'],'--timeout=300s'])
                if operation=='demand-scale':time.sleep(row['hold_seconds'])
            finally:
                if operation=='demand-scale':
                    live=kube(row['kind'],row['namespace'],row['name']);spec=dict(live['spec']);spec.pop('replicas',None);before=dict(row['spec']);before.pop('replicas',None)
                    require(live['metadata']['uid']==row['object']['uid'] and spec==before and live['spec']['replicas'] in (row['old_value'],row['new_value']),'Demand recovery identity/spec drift; no overwrite.')
                    recovery=[{'op':'test','path':'/metadata/uid','value':row['object']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':live['metadata']['resourceVersion']},{'op':'test','path':'/spec/replicas','value':live['spec']['replicas']},{'op':'replace','path':'/spec/replicas','value':row['old_value']}]
                    ops.run(['kubectl','-n',row['namespace'],'patch',row['kind'],row['name'],'--type=json','-p',json.dumps(recovery)])
                    ops.run(['kubectl','-n',row['namespace'],'rollout','status','deployment/'+row['name'],'--timeout=300s'])
                    mark('idle',target)
        else:
            if row['kind']=='priorityclasses.scheduling.k8s.io':
                pods=json.loads(ops.run(['kubectl','get','pods','-A','-o','json']))['items'];require(not any(x['spec'].get('priorityClassName')==row['name'] for x in pods),'PriorityClass still referenced by live Pod; keep it.')
            base,resource=GVR[row['kind']];path=base+('/namespaces/'+row['namespace'] if row['namespace'] else '')+'/'+resource+'/'+row['name']
            options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':row['object']['uid'],'resourceVersion':obj['metadata']['resourceVersion']}}
            with tempfile.TemporaryDirectory() as d:
                f=pathlib.Path(d)/'delete.json';f.write_bytes(h.canonical(options));ops.run(['kubectl','delete','--raw',path,'-f',str(f)])
            for _ in range(60):
                current=kube(row['kind'],row['namespace'],row['name'],True)
                if current is None:break
                require(current['metadata']['uid']==row['object']['uid'],'Replacement cleanup object; stop without adopting it.')
                time.sleep(5)
            else:raise h.SafeError('Fixed cleanup timed out; finalizers are not force-removed.')
        completed.append(row['object']['uid']);mark('active',dict(target,completed=completed))
    mark('idle',dict(target,completed=completed));return {'completed_object_uids':completed,'operation':operation}

from fixture_ops import IDS as FIXTURE_IDS
from node_ops import IDS as NODE_IDS
from drain_ops import IDS as DRAIN_IDS
from platform_probe_ops import IDS as PLATFORM_IDS, PROD_IDS as PLATFORM_PROD_IDS
from bootstrap_job_ops import IDS as BOOTSTRAP_IDS
from velero_ops import IDS as VELERO_IDS
from managed_queue_ops import IDS as QUEUE_IDS
from rds_protection_ops import IDS as RDS_PROTECTION_IDS
from argo_reviewed_ops import IDS as ARGO_IDS, PROD_IDS as ARGO_PROD_IDS
from endpoint_policy_ops import IDS as ENDPOINT_IDS
from producer_acl_ops import IDS as PRODUCER_IDS
OPERATION_IDS=OPERATION_IDS+FIXED_IDS+FIXTURE_IDS+NODE_IDS+DRAIN_IDS+PLATFORM_IDS+BOOTSTRAP_IDS+VELERO_IDS+QUEUE_IDS+RDS_PROTECTION_IDS+ARGO_IDS+PRODUCER_IDS+ENDPOINT_IDS

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--stage',choices=('plan','apply'),required=True);parser.add_argument('--environment',choices=('dev','prod'),required=True);parser.add_argument('--operation',choices=OPERATION_IDS,required=True);args=parser.parse_args()
    try:run(args.stage,args.environment,args.operation)
    except Exception:raise SystemExit('Incident operation stopped safely. No private command output was published; inspect protected request/receipt/recovery state.')
