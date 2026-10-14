"""Fixed BU13 bootstrap Job. Credentials never enter request, runner, or receipt."""
import copy, json, pathlib, re, tempfile, time, uuid
IDS=('database-bootstrap','database-bootstrap-observe','database-bootstrap-cleanup')
NS='contract2whale-demo'
BASE=pathlib.Path(__file__).resolve().parent

def aws(io,c,*args):
    return json.loads(io.ops.run(['aws',*args,'--region',c['region'],'--output','json']))

def state_reader(io,c):
    adapter=io.ops.load_module('bootstrap_state_reader',io.ops.shared_file('vpc-lifecycle-guard.py')) if hasattr(io.ops,'load_module') else None
    if adapter is None:
        import importlib.util
        spec=importlib.util.spec_from_file_location('bootstrap_state_reader',io.ops.shared_file('vpc-lifecycle-guard.py'));adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
    return adapter,adapter.VersionedStateReader(c['state_bucket'],c['account_id'],c['region'])

def database_snapshot(io,c):
    """Only contract coordinates and resource identities leave private State."""
    adapter,reader=state_reader(io,c);saved=reader('data/terraform.tfstate')
    io.require(isinstance(saved.get('state'),dict),'Current data State is required')
    data=saved['state']['outputs']['data_contract']['value'];db=data['database']
    env=c.get('environment',c.get('_environment','dev'))
    io.require(env in ('dev','prod') and data['account_id']==c['account_id'] and data['environment']==env and data['region']==c['region'] and data['cluster_name']==c['cluster'] and data['namespace']==NS,'Data State target mismatch')
    rows=[row['values'] for row in adapter.managed_resources(saved['state']) if row['type']=='aws_db_instance']
    io.require(len(rows)==1,'Exactly one managed database incarnation required')
    original=rows[0]
    io.require(original.get('identifier')==db['identifier'] and bool(original.get('resource_id')) and original.get('arn')=='arn:aws:rds:'+c['region']+':'+c['account_id']+':db:'+db['identifier'],'Database State identity differs from data contract')
    response=aws(io,c,'rds','describe-db-instances','--db-instance-identifier',db['identifier'])
    live_rows=response.get('DBInstances',[])
    io.require(len(live_rows)==1 and not response.get('Marker'),'Exactly one live database incarnation required')
    live=live_rows[0]
    io.require(live.get('DBInstanceIdentifier')==db['identifier'] and live.get('DBInstanceArn')==original['arn'] and live.get('DbiResourceId')==original['resource_id'] and live.get('Endpoint',{}).get('Address')==db['address'] and live.get('DBInstanceStatus')=='available' and live.get('Engine')=='postgres','DB State/live identity or readiness mismatch')
    return saved,data,live

def operator_snapshot(io,c):
    adapter,reader=state_reader(io,c);saved=reader('identity/terraform.tfstate')
    io.require(isinstance(saved.get('state'),dict),'Current operator identity State is required')
    rows=adapter.managed_resources(saved['state'])
    matches=[row['values'] for row in rows if row['type']=='aws_eks_pod_identity_association' and row['values'].get('cluster_name')==c['cluster'] and row['values'].get('namespace')==NS and row['values'].get('service_account')=='database-operator']
    io.require(len(matches)==1,'Exactly one State operator association required')
    original=matches[0];association_id=original.get('association_id')
    role=original.get('role_arn','')
    io.require(association_id and re.fullmatch(r'arn:aws:iam::'+re.escape(c['account_id'])+r':role/[A-Za-z0-9+=,.@_/-]+',role),'Operator State association/role identity missing')
    roles=[row for row in rows if row['type']=='aws_iam_role' and row['values'].get('arn')==role]
    io.require(len(roles)==1,'Operator association must use its exact managed State role')
    listed=aws(io,c,'eks','list-pod-identity-associations','--cluster-name',c['cluster'],'--namespace',NS,'--service-account','database-operator')
    associations=listed.get('associations',[])
    io.require(not listed.get('nextToken') and len(associations)==1 and associations[0].get('associationId')==association_id,'Live operator association differs or is ambiguous')
    assoc=aws(io,c,'eks','describe-pod-identity-association','--cluster-name',c['cluster'],'--association-id',association_id)['association']
    io.require(assoc.get('associationId')==association_id and assoc.get('clusterName')==c['cluster'] and assoc.get('namespace')==NS and assoc.get('serviceAccount')=='database-operator' and assoc.get('roleArn')==role,'Operator State/live identity association mismatch')
    if original.get('association_arn'):
        io.require(assoc.get('associationArn')==original['association_arn'],'Operator association ARN differs from State')
    sa=io.kube('serviceaccounts',NS,'database-operator')
    io.require(sa['metadata'].get('name')=='database-operator' and sa['metadata'].get('namespace')==NS and sa['metadata'].get('uid'),'Current operator service account identity required')
    return saved,sa,assoc

def lifecycle_request(io,c,source_sha,bootstrap_run_id):
    """Build a fresh metadata-only request; the normal snapshot reviews it."""
    io.require(isinstance(source_sha,str) and re.fullmatch('[0-9a-f]{40}',source_sha),'Invalid lifecycle source revision')
    decision=c.get('completion',{}).get('bootstrap_data_decision')
    io.require(decision=='bootstrap-reviewed-database-roles-and-secret-stages','Explicit bootstrap credential transition approval required')
    run=str(uuid.UUID(bootstrap_run_id));name='database-bootstrap-'+run
    _,data,live=database_snapshot(io,c);_,sa,assoc=operator_snapshot(io,c)
    records=c.get('retained_operator_images')
    io.require(isinstance(records,list),'Retained operator publications required')
    matches=[row for row in records if isinstance(row,dict) and isinstance(row.get('image'),str) and row['image'].split('@')[0]==data['operator']['repository_url']]
    io.require(len(matches)==1,'Exactly one retained publication for the data operator repository required')
    publication=matches[0]
    io.require(set(publication)=={'image','signing_key_arn','source_sha','publication_receipt'},'Unexpected retained publication fields')
    io.require(re.fullmatch(re.escape(data['operator']['repository_url'])+r'@sha256:[0-9a-f]{64}',publication['image']) and re.fullmatch('[0-9a-f]{40}',publication['source_sha']),'Immutable operator image/source required')
    return {'source_sha':source_sha,'data_decision':decision,'bootstrap_run_id':run,'job_name':name,'configmap_name':name,'db_arn':live['DBInstanceArn'],'db_resource_id':live['DbiResourceId'],'serviceaccount_uid':sa['metadata']['uid'],'association_id':assoc['associationId'],'operator_role_arn':assoc['roleArn'],'operator_image':publication['image'],'operator_source_sha':publication['source_sha'],'operator_publication_receipt':copy.deepcopy(publication['publication_receipt'])}

def target_sha256(io,target):
    return io.h.digest(io.h.canonical({key:value for key,value in target.items() if key not in ('created_job','created_configmap','result')}))

def verify_database(io,c,target):
    io.require(re.fullmatch('[0-9a-f]{40}',target.get('source_sha','')),'Missing original bootstrap source revision')
    expected=c.get('source_sha',c.get('_source_sha',target['source_sha']))
    io.require(target['source_sha']==expected,'Bootstrap source revision changed')
    saved,data,live=database_snapshot(io,c)
    io.require(saved['fingerprint']==target['state'] and target['db']=={'arn':live['DBInstanceArn'],'resource_id':live['DbiResourceId']} and target['db_identifier']==data['database']['identifier'] and target['region']==c['region'],'Original bootstrap database State/incarnation changed')
    return target['db']

def verify_completion(io,target,result):
    io.require(result.get('complete') is True and result.get('raw_job_logs_published') is False and result.get('bootstrap_run_id')==target['bootstrap_run_id'] and result.get('database')==target['db'],'Bootstrap completion target differs')
    io.require(re.fullmatch('[0-9a-f]{40}',target.get('source_sha','')) and result.get('source_sha')==target['source_sha'] and result.get('target_sha256')==target_sha256(io,target),'Bootstrap completion source/target binding differs')
    for field,kind in [('created_job','jobs.batch'),('created_configmap','configmaps')]:
        original=target.get(field)
        io.require(isinstance(original,dict) and original.get('uid') and original.get('name')==target[field.removeprefix('created_')]['metadata']['name'] and result.get(field)==original,'Original bootstrap creation identity is missing or differs')
        obj=io.kube(kind,NS,original['name']);io.require(io.identity(obj)==original,'Bootstrap completion object replaced or changed')
        if kind=='jobs.batch':
            status=obj.get('status',{})
            io.require(status.get('succeeded')==1 and not status.get('active',0) and not status.get('failed',0) and not any(condition.get('type') in ('Failed','FailureTarget') and condition.get('status')=='True' for condition in status.get('conditions',[])),'Bootstrap Job is not completed successfully')
    live=aws(io,{'region':target['region']},'rds','describe-db-instances','--db-instance-identifier',target['db_identifier'])
    rows=live.get('DBInstances',[])
    io.require(len(rows)==1 and not live.get('Marker') and rows[0].get('DBInstanceIdentifier')==target['db_identifier'] and rows[0].get('DBInstanceArn')==target['db']['arn'] and rows[0].get('DbiResourceId')==target['db']['resource_id'] and rows[0].get('DBInstanceStatus')=='available','Bootstrap completion database incarnation changed')
    return result

def snapshot(io,operation,r,c,store,marker=None):
    if operation=='database-bootstrap-cleanup':return cleanup_snapshot(io,r,c,store,marker)
    io.require(set(r)<={'source_sha','expires_at','change_request','data_decision' }|{'bootstrap_run_id','job_name','configmap_name','db_arn','db_resource_id','serviceaccount_uid','association_id','operator_role_arn','operator_image','operator_source_sha','operator_publication_receipt'},'Unknown request fields; plaintext credentials and arbitrary commands forbidden')
    io.require(operation in IDS,'Unregistered bootstrap operation')
    io.require(operation=='database-bootstrap','Observe requires exact original marker, not fresh snapshot')
    run=str(uuid.UUID(r['bootstrap_run_id']));name='database-bootstrap-'+run
    io.require(r['data_decision']=='bootstrap-reviewed-database-roles-and-secret-stages','Explicit bootstrap credential transition approval required')
    io.require(r['job_name']==name and r['configmap_name']==name,'Fixed run-bound Job and ConfigMap names required')
    env=c.get('environment',c.get('_environment','dev'));io.require(env in ('dev','prod'),'Unknown bootstrap environment')
    io.require(re.fullmatch('[0-9a-f]{40}',r.get('source_sha','')),'Invalid bootstrap source revision')
    saved,data,live=database_snapshot(io,c);db=data['database'];cred=data['credentials'];redis=data['redis']
    io.require(data['service_accounts']['operator']=='database-operator' and redis is not None,'Source bootstrap requires operator and Redis contract')
    io.require(live['DBInstanceArn']==r['db_arn'] and live['DbiResourceId']==r['db_resource_id'] and live['Endpoint']['Address']==db['address'] and live['DBInstanceStatus']=='available' and live['Engine']=='postgres','DB identity/readiness mismatch')
    io.require(live['MasterUserSecret']['SecretArn']==cred['master_secret_arn'],'Master secret is not current RDS credential')
    secrets={}
    for key in ('master_secret_arn','migration_secret_arn','runtime_secret_arn','app_secret_arn'):
        meta=aws(io,c,'secretsmanager','describe-secret','--secret-id',cred[key]);io.require(meta['ARN']==cred[key] and not meta.get('DeletedDate'),'Secret missing or pending deletion')
        secrets[key]={'arn':meta['ARN'],'versions':meta.get('VersionIdsToStages',{}),'kms':meta.get('KmsKeyId')}
    workloads=json.loads(io.ops.run(['kubectl','--request-timeout=30s','-n',NS,'get','pods,deployments,statefulsets,cronjobs','-o','json']))
    io.require(not workloads.get('metadata',{}).get('continue'),'Incomplete bootstrap writer inventory')
    for obj in workloads['items']:
        kind=obj['kind'];spec=obj.get('spec',{})
        if kind=='Pod':io.require(obj.get('status',{}).get('phase') in ('Succeeded','Failed'),'Application/operator Pod still running during credential bootstrap')
        elif kind in ('Deployment','StatefulSet'):io.require(spec.get('replicas',1)==0,'App controller can race bootstrap credentials')
        elif kind=='CronJob':io.require(spec.get('suspend') is True,'Scheduled writer can race bootstrap credentials')
    identity_state,sa,assoc=operator_snapshot(io,c);io.require(sa['metadata']['uid']==r['serviceaccount_uid'],'Operator SA replaced')
    io.require(assoc['associationId']==r['association_id'] and assoc['roleArn']==r['operator_role_arn'],'Operator request identity association mismatch')
    image=r['operator_image'];io.require(re.fullmatch(re.escape(data['operator']['repository_url'])+r'@sha256:[0-9a-f]{64}',image),'Immutable account-local operator image required')
    desc=r['operator_publication_receipt'];io.require(desc['key'].startswith('operator-publication/'+env+'/') and desc['key'].endswith('/operator-publication.json'),'Wrong publication receipt namespace')
    io.require(c.get('operator_evidence_account',c['account_id'])==c['account_id'],'Cross-account publication evidence forbidden')
    evidence_store=io.h.Store(c.get('operator_evidence_bucket',c['state_bucket']),c['account_id']);evidence_store.check()
    with tempfile.TemporaryDirectory() as directory:
        file=pathlib.Path(directory)/'receipt';evidence_store.get(desc,file);publication=json.loads(file.read_bytes())
    io.require(publication.get('signature_verified') is True and publication.get('spdx_attestation_verified') is True and publication.get('account_id')==c['account_id'] and publication.get('region')==c['region'] and publication.get('environment')==env and publication['source_revision']==r['operator_source_sha'] and publication['repository']==data['operator']['repository_url'] and publication['operator_image_digest']==image.split('@')[1],'Operator publication provenance mismatch')
    io.require(re.fullmatch('[0-9a-f]{40}',r['operator_source_sha']),'Invalid operator source revision')
    # No source/script input: only the already published fixed bootstrap entrypoint.
    cm=json.loads((BASE/'templates/database-bootstrap-configmap.json').read_text());job=json.loads((BASE/'templates/database-bootstrap-job.json').read_text())
    for obj in (cm,job):obj['metadata']['name']=name;obj['metadata']['labels']['contract2whale.course/run-id']=run;obj['metadata'].pop('annotations',None)
    cm['data']={'DATA_ENVIRONMENT':env,'DATA_ACCOUNT_ID':c['account_id'],'DATA_REGION':c['region'],'DATA_DB_ADDRESS':db['address'],'DATA_DB_PORT':str(db['port']),'DATA_DB_NAME':db['name'],'DATA_DB_SCHEMA':db['schema'],'DATA_DB_ENGINE_VERSION':str(db['engine_version_actual']),'DATA_REDIS_ADDRESS':redis['address'],'DATA_REDIS_PORT':str(redis['port']),'DATA_REDIS_TLS':'true','DATA_DB_MIGRATION_ROLE':'commerce_migrator','DATA_DB_RUNTIME_ROLE':'commerce_runtime',**{'DATA_'+k.upper():cred[k] for k in ('master_secret_arn','migration_secret_arn','runtime_secret_arn','app_secret_arn')}}
    job['spec'].pop('ttlSecondsAfterFinished',None)
    pod=job['spec']['template'];pod['metadata']['labels']['contract2whale.course/run-id']=run
    container=pod['spec']['containers'][0];container['image']=image;container['envFrom'][0]['configMapRef']['name']=name
    container['env']=[{'name':'BOOTSTRAP_RUN_ID','value':run},{'name':'EXPECTED_OPERATOR_ROLE_ARN','value':r['operator_role_arn']}]
    for kind in ('jobs.batch','configmaps'):io.require(io.kube(kind,NS,name,True) is None,'Bootstrap request already exists; never adopt or rerun')
    return {'job':job,'configmap':cm,'source_sha':r['source_sha'],'region':c['region'],'db_identifier':db['identifier'],'identity_state':identity_state['fingerprint'],'state':saved['fingerprint'],'db':{'arn':live['DBInstanceArn'],'resource_id':live['DbiResourceId']},'secrets':secrets,'serviceaccount':io.identity(sa),'association':assoc,'publication':desc,'bootstrap_run_id':run,'writer_inventory_sha256':io.h.digest(io.h.canonical(workloads))}

def apply(io,operation,target,r,mark):
    if operation=='database-bootstrap-observe':return observe(io,target,mark)
    if operation=='database-bootstrap-cleanup':return cleanup(io,target,mark)
    io.require(operation=='database-bootstrap','Unknown bootstrap operation')
    io.require(r.get('source_sha')==target.get('source_sha') and re.fullmatch('[0-9a-f]{40}',target.get('source_sha','')) and r.get('bootstrap_run_id')==target['bootstrap_run_id'],'Bootstrap execution request source/run differs')
    name=target['job']['metadata']['name'];current=copy.deepcopy(target)
    for kind in ('jobs.batch','configmaps'):io.require(io.kube(kind,NS,name,True) is None,'Bootstrap appeared after review')
    mark('active',copy.deepcopy(current)) # durable marker before the first API write
    for key in ('configmap','job'):
        obj=json.loads(io.ops.run(['kubectl','--request-timeout=30s','create','-f','-','-o','json'],content=io.h.canonical(target[key])))
        current['created_'+key]=io.identity(obj);mark('active',copy.deepcopy(current))
    uid=current['created_job']['uid']
    for _ in range(125):
        job=io.kube('jobs.batch',NS,name);io.require(job['metadata']['uid']==uid,'Bootstrap Job replaced')
        io.require(not job.get('status',{}).get('failed',0),'Bootstrap failed; retain exact objects and inspect protected evidence; no blind retry')
        if job.get('status',{}).get('succeeded')==1:
            result={'created_job':current['created_job'],'created_configmap':current['created_configmap'],'bootstrap_run_id':target['bootstrap_run_id'],'database':target['db'],'complete':True,'raw_job_logs_published':False,'source_sha':target['source_sha'],'target_sha256':target_sha256(io,target)}
            verify_completion(io,current,result)
            mark('idle',dict(current,result=result));return result
        time.sleep(5)
    raise io.h.SafeError('Bootstrap timeout; recovery marker and exact Job UID remain')


def observe_snapshot(io,r,marker):
    io.require(set(r)<={'source_sha','expires_at','change_request','data_decision','bootstrap_run_id'},'Observation accepts metadata only')
    io.require(marker and marker.get('operation') in IDS and marker.get('phase') in ('active','recovery-required'),'Original unresolved bootstrap marker required')
    target=marker['target'];io.require(target['bootstrap_run_id']==r['bootstrap_run_id'] and target.get('source_sha')==r.get('source_sha'),'Cannot adopt another bootstrap run/source')
    io.require('created_job' in target and 'created_configmap' in target,'Creation result is uncertain; protected identity reconciliation required, never infer UID')
    for field,kind in [('created_job','jobs.batch'),('created_configmap','configmaps')]:
        original=target[field];obj=io.kube(kind,NS,original['name']);io.require(io.identity(obj)==original,'Original bootstrap object identity/spec changed')
    return target

def observe(io,target,mark):
    # Read-only recovery; never repeats role/password or Secret-stage mutations.
    for field,kind in [('created_job','jobs.batch'),('created_configmap','configmaps')]:
        original=target[field];obj=io.kube(kind,NS,original['name']);io.require(io.identity(obj)==original,'Bootstrap object changed during observation')
    job=io.kube('jobs.batch',NS,target['created_job']['name'])
    io.require(job.get('status',{}).get('succeeded')==1,'Bootstrap not successful; retain recovery marker for explicit diagnosis')
    result={'complete':True,'bootstrap_run_id':target['bootstrap_run_id'],'created_job':target['created_job'],'created_configmap':target['created_configmap'],'database':target['db'],'raw_job_logs_published':False,'replayed':False,'source_sha':target['source_sha'],'target_sha256':target_sha256(io,target)}
    verify_completion(io,target,result)
    mark('idle',dict(target,result=result));return result


def cleanup_snapshot(io,r,c,store,marker=None):
    io.require(set(r)<={'source_sha','expires_at','change_request','data_decision','bootstrap_run_id','creation_receipt'},'Cleanup accepts exact metadata receipt only')
    io.require(r['data_decision']=='remove-completed-bootstrap-job-and-configmap','Explicit exact bootstrap cleanup approval required')
    desc=r['creation_receipt'];prefix='ci-logs/'+io.h.required('GITHUB_REPOSITORY_ID')+'/'
    io.require(desc['key'].startswith(prefix) and any(desc['key'].endswith('/'+c['environment']+'/incidents/'+op+'/apply/receipt.json') for op in ('database-bootstrap','database-bootstrap-observe')),'Untrusted bootstrap receipt namespace')
    with tempfile.TemporaryDirectory() as directory:
        path=pathlib.Path(directory)/'receipt';store.get(desc,path);receipt=json.loads(path.read_bytes())
    rc=receipt['context'];result=receipt['result']
    io.require(receipt.get('kind')=='incident-completion' and receipt.get('success') is True and rc['account']==c['account_id'] and rc['environment']==c['environment'] and rc['repository_id']==io.h.required('GITHUB_REPOSITORY_ID') and result['complete'] is True and result['bootstrap_run_id']==r['bootstrap_run_id'],'Bootstrap creation/completion receipt mismatch')
    target={'bootstrap_run_id':r['bootstrap_run_id'],'creation_receipt':desc,'created_job':result['created_job'],'created_configmap':result['created_configmap']}
    recovery=marker if marker and marker.get('operation')=='database-bootstrap-cleanup' and marker.get('phase') in ('active','recovery-required') else None
    return cleanup_target(io,target,recovery)

def lifecycle_cleanup_snapshot(io,c,store,descriptor,marker=None):
    """Retire only the exact objects named by a prior lifecycle Up receipt."""
    env=c.get('environment',c.get('_environment','dev'));repo=io.h.required('GITHUB_REPOSITORY_ID')
    io.require(isinstance(descriptor,dict) and set(descriptor)=={'key','version','sha256'} and descriptor.get('version') not in (None,'','null') and re.fullmatch('[0-9a-f]{64}',descriptor.get('sha256','')),'Immutable lifecycle bootstrap receipt required')
    io.require(descriptor['key'].startswith('ci-logs/'+repo+'/') and descriptor['key'].endswith('/'+env+'/hooks/database-bootstrap/lifecycle-up/apply/receipt.json'),'Untrusted lifecycle bootstrap receipt namespace')
    with tempfile.TemporaryDirectory() as directory:
        path=pathlib.Path(directory)/'receipt';store.get(descriptor,path);receipt=json.loads(path.read_bytes())
    rc=receipt.get('context',{});result=receipt.get('result',{}).get('database_bootstrap',{})
    io.require(receipt.get('kind')=='gitops-lifecycle-completion' and rc.get('operation')=='up' and rc.get('step_id')=='hook:database-bootstrap' and rc.get('account')==c['account_id'] and rc.get('environment')==env and rc.get('repository_id')==repo,'Lifecycle bootstrap receipt context differs')
    io.require(result.get('complete') is True and result.get('raw_job_logs_published') is False and re.fullmatch('[0-9a-f]{40}',result.get('source_sha','')) and result['source_sha']==rc.get('snapshot_sha') and re.fullmatch('[0-9a-f]{64}',result.get('target_sha256','')),'Lifecycle bootstrap completion/source proof differs')
    run=str(uuid.UUID(result['bootstrap_run_id']));name='database-bootstrap-'+run
    for field in ('created_job','created_configmap'):
        row=result.get(field,{})
        io.require(row.get('uid') and row.get('name')==name and row.get('namespace')==NS and re.fullmatch('[0-9a-f]{64}',row.get('body_sha256','')) and re.fullmatch('[0-9a-f]{64}',row.get('metadata_sha256','')),'Lifecycle bootstrap receipt lacks exact creation identities')
    target={'bootstrap_run_id':run,'creation_receipt':copy.deepcopy(descriptor),'source_sha':result['source_sha'],'created_job':result['created_job'],'created_configmap':result['created_configmap']}
    return cleanup_target(io,target,marker)

def cleanup_target(io,target,marker=None):
    if marker:
        io.require(marker.get('operation','database-bootstrap-cleanup')=='database-bootstrap-cleanup' and marker.get('phase') in ('planned','active','recovery-required','idle'),'Original cleanup recovery marker required')
        prior=marker['target']
        io.require(all(prior.get(key)==value for key,value in target.items()),'Cleanup recovery differs from original approved target')
        target=copy.deepcopy(prior)
    for field,kind in [('created_job','jobs.batch'),('created_configmap','configmaps')]:
        obj=io.kube(kind,NS,target[field]['name'],True)
        if obj is None:
            io.require(target[field]['uid'] in target.get('delete_attempted_uids',[]),'Unexpected absence before approved delete attempt')
            continue
        io.require(io.identity(obj)==target[field],'Original completed bootstrap identity/spec changed')
        if kind=='jobs.batch':
            status=obj.get('status',{})
            io.require(status.get('succeeded')==1 and not status.get('active',0) and not status.get('failed',0) and not any(condition.get('type') in ('Failed','FailureTarget') and condition.get('status')=='True' for condition in status.get('conditions',[])),'Only completed inactive bootstrap Job may be removed')
    return target

def cleanup(io,target,mark):
    cleanup_target(io,target)
    current=copy.deepcopy(target);mark('active',copy.deepcopy(current))
    for field,kind,path in [('created_job','jobs.batch','/apis/batch/v1/namespaces/'+NS+'/jobs/'),('created_configmap','configmaps','/api/v1/namespaces/'+NS+'/configmaps/')]:
        row=target[field];obj=io.kube(kind,NS,row['name'],True)
        if obj is None:
            io.require(row['uid'] in current.get('delete_attempted_uids',[]),'Missing target without original delete attempt')
            if row['uid'] not in current.setdefault('deleted_uids',[]):current['deleted_uids'].append(row['uid'])
            mark('active',copy.deepcopy(current));continue
        io.require(io.identity(obj)==row,'Bootstrap cleanup target drift')
        if row['uid'] not in current.setdefault('delete_attempted_uids',[]):current['delete_attempted_uids'].append(row['uid'])
        mark('active',copy.deepcopy(current))
        options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':row['uid'],'resourceVersion':obj['metadata']['resourceVersion']}}
        with tempfile.TemporaryDirectory() as directory:
            file=pathlib.Path(directory)/'delete';file.write_bytes(io.h.canonical(options));io.ops.run(['kubectl','--request-timeout=30s','delete','--raw',path+row['name'],'-f',str(file)])
        for _ in range(60):
            obj=io.kube(kind,NS,row['name'],True)
            if obj is None:break
            io.require(obj['metadata']['uid']==row['uid'],'Replacement appeared; do not delete it');time.sleep(2)
        io.require(obj is None,'Exact bootstrap deletion absence not observed')
        current.setdefault('deleted_uids',[]).append(row['uid']);mark('active',copy.deepcopy(current))
    result={'bootstrap_run_id':target['bootstrap_run_id'],'deleted_uids':current['deleted_uids'],'creation_receipt':target['creation_receipt']};mark('idle',dict(current,result=result));return result
