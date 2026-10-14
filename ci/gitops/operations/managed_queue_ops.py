"""Reviewed existing managed-topic/ACL script, bounded temporary SCRAM credentials."""
import hashlib,io,json,os,pathlib,re,subprocess,tarfile,tempfile,uuid
IDS=('managed-queue-setup',)
def snapshot(api,operation,r,c,store):
    api.require(set(r)<={'source_sha','expires_at','change_request','data_decision' }|{'credential_run_id','pod_uid','cluster_arn','script_sha256'},'Unknown request fields; plaintext credentials and arbitrary commands forbidden')
    api.require(operation in IDS,'Unknown managed queue operation')
    run=str(uuid.UUID(r['credential_run_id']));env=c['environment']
    api.require(r['data_decision']=='create-temporary-admin-topics-acls-and-recoverable-cleanup','Explicit credential/topic/ACL approval required')
    script='platform/environments/'+env+'/queue/scripts/setup-managed-topics.sh'
    body=api.ops.run(['git','show',r['source_sha']+':'+script])
    api.require(hashlib.sha256(body).hexdigest()==r['script_sha256'],'Reviewed helper source differs')
    api.require(b'--force-delete-without-recovery' not in body and b'--recovery-window-in-days 7' in body and b'APPROVED_QUEUE_ADMIN_UID' in body and b'MANAGED_QUEUE_RUN_ID' in body,'Only bounded recoverable helper supported')
    root='platform/environments/'+env+'/queue'
    archive=api.ops.run(['git','archive',r['source_sha'],'--',root,'automation'])
    import importlib.util
    spec=importlib.util.spec_from_file_location('managed_queue_state',api.ops.shared_file('vpc-lifecycle-guard.py'));reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    saved=reader.VersionedStateReader(c['state_bucket'],c['account_id'],c['region'])('platform/queue/terraform.tfstate')
    contract=saved['state']['outputs']['queue_managed_contract']['value']
    api.require(contract['cluster_arn']==r['cluster_arn'],'Managed cluster differs from current versioned queue State')
    pod=api.kube('pods','monitoring','queue-admin');api.require(pod['metadata']['uid']==r['pod_uid'] and pod['status']['phase']=='Running','Exact running queue-admin Pod required')
    cluster=json.loads(api.ops.run(['aws','kafka','describe-cluster-v2','--cluster-arn',r['cluster_arn'],'--region',c['region']]))['ClusterInfo']
    api.require(cluster['ClusterArn']==r['cluster_arn'] and cluster['State']=='ACTIVE' and r['cluster_arn'].startswith('arn:aws:kafka:'+c['region']+':'+c['account_id']+':cluster/'),'MSK account/state mismatch')
    name='AmazonMSK_'+cluster['ClusterName']+'_queue-admin_'+run
    # Exhaustive metadata list, no GetSecretValue on the runner; exact name must be unused.
    secrets=json.loads(api.ops.run(['aws','secretsmanager','list-secrets','--include-planned-deletion','--region',c['region']]))
    api.require(not secrets.get('NextToken') and all(x['Name']!=name for x in secrets['SecretList']),'Admin request already issued or incomplete inventory')
    return {'queue_state':saved['fingerprint'],'script':script,'source_sha':r['source_sha'],'script_sha256':r['script_sha256'],'archive_sha256':hashlib.sha256(archive).hexdigest(),'pod':api.identity(pod),'cluster_arn':cluster['ClusterArn'],'cluster_uuid':cluster['ClusterArn'].split('/')[-1],'cluster_version':cluster['CurrentVersion'],'temporary_secret_name':name,'credential_run_id':run,'environment':env,'account':c['account_id'],'region':c['region'],'eks_cluster':c['cluster'],'retention_days':7,'request_id':'managed-'+run}

def apply(api,operation,target,r,mark):
    api.require(operation in IDS,'Unknown managed queue operation')
    pod=api.kube('pods','monitoring','queue-admin');api.require(api.identity(pod)==target['pod'],'Admin Pod changed after review')
    archive=api.ops.run(['git','archive',target['source_sha'],'--','platform/environments/'+target['environment']+'/queue','automation'])
    api.require(hashlib.sha256(archive).hexdigest()==target['archive_sha256'],'Approved source archive changed')
    with tempfile.TemporaryDirectory() as directory:
        root=pathlib.Path(directory)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as stream:stream.extractall(root,filter='data')
        api.require(not any(x.is_symlink() for x in root.rglob('*')),'Helper source symlinks forbidden')
        script=root/target['script'];api.require(hashlib.sha256(script.read_bytes()).hexdigest()==target['script_sha256'],'Helper bytes differ')
        env={**os.environ,'GITHUB_ACTIONS':'true','KUBE_CONTEXT':target['eks_cluster'],'ENVIRONMENT':target['environment'],'EXPECTED_ACCOUNT_ID':target['account'],'AWS_REGION':target['region'],'MANAGED_QUEUE_APPROVED_CLUSTER_ARN':target['cluster_arn'],'MANAGED_QUEUE_RUN_ID':target['credential_run_id'],'MANAGED_QUEUE_REQUEST_ID':target['request_id'],'APPROVED_QUEUE_ADMIN_UID':target['pod']['uid'],'CI_MANAGED_QUEUE_APPROVAL_SHA':api.h.required('EXPECTED_PLAN_SHA')}
        mark('active',target)
        result=subprocess.run(['bash',str(script)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=900,check=False)
        api.require(result.returncode==0,'Managed helper failed; original UUID retained, no blind credential retry; inspect private service metadata')
        receipt=json.loads((script.parent.parent/'local-inputs'/('managed-credentials-'+target['credential_run_id']+'.json')).read_text())
        api.require(receipt['run_id']==target['credential_run_id'] and receipt['request_id']==target['request_id'] and receipt['cleanup_verified'] is True,'Exact recoverable cleanup receipt required')
        completion={'credential_run_id':target['credential_run_id'],'temporary_secret_name':target['temporary_secret_name'],'helper_receipt':receipt,'retention_days':7,'permanent_absence_claimed':False,'raw_logs_published':False}
        mark('idle',dict(target,result=completion));return completion
