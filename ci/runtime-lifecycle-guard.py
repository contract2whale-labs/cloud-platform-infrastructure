#!/usr/bin/env python3
"""Actual saved-plan runtime guard and authenticated AWS observation receipts.

All cloud calls are reads. Deletion remains the reviewed Terraform binary's job.
"""
import datetime as dt,hashlib,importlib.util,json,os,re,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
CI=HERE.parent/'ci'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
v=load('later_state_reader',CI/'vpc-lifecycle-guard.py')
h=load('later_saved_plan',CI/'saved-plan.py')
g=load('later_pure_guard',HERE/'runtime_guard.py')
SafeError,require=v.SafeError,v.require
managed_resources,VersionedStateReader=v.managed_resources,v.VersionedStateReader
ROOTS={'terraform/environments/'+env+'/'+suffix:name for env in ('dev','prod') for suffix,name in (('data','data'),('delivery','delivery'),('platform/queue','queue-managed'))}
def environment(root):
 require(root in ROOTS,'Unknown environment/root');return root.split('/')[2]
def scoped(root,path):return path.replace('/dev/','/'+environment(root)+'/')
EKS='terraform/environments/dev/eks';VPC='terraform/environments/dev/network/vpc';RELAY='terraform/environments/dev/platform/private-api'
DEPS={
 'data':[EKS,VPC,'terraform/environments/dev/delivery'],
 'delivery':[EKS,'terraform/environments/dev/account-baseline','terraform/environments/dev/platform/operations','terraform/environments/dev/platform/app-auth'],
 'queue-managed':[EKS,VPC]}
BOUND={}
IDENTITY_FIELDS=('id','arn','name','identifier','cluster_name','cluster_arn','association_id','role','role_name','policy_name','vpc_id','security_group_id','security_group_rule_id','database_name','engine','created_at','namespace','service_account','resource_id')

def module(root):require(root in ROOTS,'Unknown later root');return ROOTS[root]
def allowed_types(root):return {x.split('.')[0] for x in g.MANIFEST['roots'][module(root)]['runtime_addresses']}|{'terraform_data'}
def key(root):return '/'.join(root.split('/')[3:])+'/terraform.tfstate'
def normalize_resources(state):
 rows=sorted([dict(address=r['address'],type=r['type'],**{k:r['values'][k] for k in IDENTITY_FIELDS if isinstance(r['values'].get(k),(str,int,bool))}) for r in managed_resources(state)],key=lambda r:r['address'])
 delivery=state.get('outputs',{}).get('delivery_contract',{}).get('value',{})
 for row in rows:
  if row['address']=='module.component.aws_iam_role.argocd_secrets':
   namespace=delivery.get('argocd',{}).get('namespace');require(namespace,'Original Argo namespace output missing')
   row['consumer_namespace']=namespace
 return rows

def validate_contract(contract,root):
 name=module(root);require(isinstance(contract,dict) and contract.get('schema')==1,'Lifecycle contract schema required')
 allowed={'schema','environment','root','completion_sha256','disposable_runtime_approved','application_namespace','mode','fixture_sha256','migration_sha256','seed_receipt_sha256','fixture_source_path','application_source_sha','application_image_digest','application_repository','application_repository_id','seed_reset_approved','cache_reset_approved','media_consistency_verified','queue_mode','epoch_inventory_verified','drain_script_sha256','prod_lab_reset_approved','prod_protection_receipt','prod_protection_request_sha256'}
 require(set(contract)<=allowed,'Unknown contract fields; secrets/arbitrary commands are forbidden')
 require(contract.get('environment')==environment(root) and contract.get('root')==root,'Wrong runtime scope')
 require(re.fullmatch('[0-9a-f]{64}',contract.get('completion_sha256','')),'Completion digest required')
 if environment(root)=='prod':require(contract.get('prod_lab_reset_approved') is True,'Explicit production-account lab reset approval required')
 require(contract.get('disposable_runtime_approved') is True,'Explicit disposable runtime approval required')
 require(isinstance(contract.get('application_namespace'),str) and re.fullmatch('[a-z0-9][a-z0-9-]{0,62}',contract['application_namespace']),'Original application namespace required')
 if name=='data':
  require(contract.get('mode')=='seed','No main DB/Redis restore implementation; restore mode is blocked')
  for field in ('fixture_sha256','migration_sha256','seed_receipt_sha256'):
   require(re.fullmatch('[0-9a-f]{64}',contract.get(field,'')),'Actual source provenance required: '+field)
  require(contract.get('fixture_source_path')=='src/migration-scripts/initial-data-seed.ts','Actual seed source path required')
  require(re.fullmatch('[0-9a-f]{40}',contract.get('application_source_sha','')),'Pinned app source required')
  require(re.fullmatch('sha256:[0-9a-f]{64}',contract.get('application_image_digest','')),'Pinned signed application image required')
  require(contract.get('seed_reset_approved') is True and contract.get('cache_reset_approved') is True and contract.get('media_consistency_verified') is True,'Explicit DB/cache reset and media consistency decision required')
 if name=='queue-managed':
  require(contract.get('queue_mode')=='drained-disposable' and contract.get('epoch_inventory_verified') is True,'Explicit disposable queue plus all epochs inventory required')
  require(re.fullmatch('[0-9a-f]{64}',contract.get('drain_script_sha256','')),'Pinned real drain script required')
def validate_contract_state(contract,root,state):
 name=module(root);outputs=state.get('outputs',{})
 if name=='data':namespace=outputs.get('data_contract',{}).get('value',{}).get('namespace')
 elif name=='delivery':namespace=outputs.get('delivery_contract',{}).get('value',{}).get('application',{}).get('namespace')
 else:return
 require(namespace and namespace==contract['application_namespace'],'Requested writer namespace differs from original completed root output')

def bind(context,contract,original):
 validate_contract(contract,context['root']);BOUND.clear();BOUND.update(context=context,contract=contract,original=original)
 require(context['contract_sha256']==h.digest(h.canonical(contract)),'Contract hash mismatch')
def read_upstreams(workspace,context,load_state=None):
 name=module(context['root']);reader=load_state or VersionedStateReader(context['backend']['bucket'],context['account'],context['backend']['region'])
 roots=[scoped(context['root'],x) for x in DEPS[name]+['terraform/environments/dev/retained/'+name]]
 return {root:reader(key(root)) for root in roots}
def upstream_fingerprints(workspace,context,load_state=None):return {k:x['fingerprint'] for k,x in read_upstreams(workspace,context,load_state).items()}
def validate_state(context,state,expected_resources=None,upstream_states=None):
 rows=managed_resources(state);name=module(context['root'])
 for r in rows:
  require(g.allowed(name,r['address']) and r['type'] in allowed_types(context['root']),'Unknown runtime State address/type')
  require(r['address'].removeprefix('module.component.').split('.')[0]==r['type'],'State address/type mismatch')
  require(isinstance(r['values'].get('id'),str) and r['values']['id'],'Missing stable resource identity')
  arn=r['values'].get('arn')
  if arn:require(arn.split(':')[4]==context['account'],'Runtime ARN belongs to another account')
 if expected_resources is not None:
  approved={r['address']:r for r in expected_resources}
  require(all(r['address'] in approved and r['values']['id']==approved[r['address']]['id'] for r in rows),'Current runtime identity differs from checkpoint')
 if upstream_states:
  producer=upstream_states.get(scoped(context['root'],'terraform/environments/dev/retained/'+name),{})
  require(producer.get('state') is not None,'Retained root is not installed')
  retained=managed_resources(producer['state']);require(retained,'Retained root is empty')
  wanted={x['to'] for x in g.MANIFEST['roots'][name]['migration']}
  actual={re.sub(r'\[(?:"[^"\\]*"|[0-9]+)\]$','',r['address']) for r in retained if r['type']!='terraform_data'}
  optional={'module.retained.aws_kms_alias.signing_previous','module.retained.aws_ecr_registry_scanning_configuration.account'}
  require(actual<=wanted and (wanted-optional)<=actual,'Retained asset declarations incomplete/different')
  for r in retained:
   if r['type']=='aws_s3_bucket':require(r['values'].get('force_destroy') is False,'Retained bucket force deletion enabled')
 return rows

def decision(context):
 d=dict(BOUND['contract']);d.update(writers_quiesced=True,retained_verified=True,owner_cleanup_verified=True,drain_verified=True)
 # These represent required gate predicates in the planned contract, not proof.
 # apply invokes real live checks below; no caller boolean bypasses that gate.
 return d

def validate_plan_contracts(context,plan,upstream):
 name=module(context['root']);original={r['address']:r for r in BOUND['original']}
 for row in plan.get('resource_changes',[]):
  if row.get('mode')=='data':continue
  require(g.allowed(name,row['address']) and row['type'] in allowed_types(context['root']),'Unknown runtime plan resource')
  require(row['address'] in original,'Uncompleted source expansion detected')
  acts=row['change']['actions']
  if context['operation']=='up':require(acts in (['no-op'],['create']),'Runtime Up cannot replace/update/delete an existing resource')
  elif acts!=['delete']:require(acts in (['no-op'],['create']),'Unapplied source/input changes before destroy')
  if acts==['create']:
   after=row['change'].get('after') or {}
   for field in ('name','identifier','cluster_name'):
    if original[row['address']].get(field) is not None:require(after.get(field)==original[row['address']][field],'Stable naming changed or unknown')
 # Validate the retained producer independently, even when the runtime is empty.
 validate_state(context,{'version':4,'resources':[]},upstream_states=upstream)

def guard_destroy(workspace,context,raw,plan,expected_resources=None,upstream_states=None,stage='plan'):
 rows=validate_state(context,raw,expected_resources,upstream_states)
 validate_plan_contracts(context,plan,upstream_states)
 active={r['address']:dict(expected_resources[[x['address'] for x in expected_resources].index(r['address'])]) for r in rows}
 g.validate_plan(module(context['root']),'down',plan,decision(context),active)
 # Planning cannot assert absence of consumers that later approved hook steps remove.
 return require_barriers(context) if stage=='apply' else {'deferred_runtime_consumer_check':True,'barriers':['source-bound writer absence','retained outputs','real queue drain where applicable']}

READS={
 'aws_db_instance':('rds','describe-db-instances','--db-instance-identifier','identifier','DBInstances','DBInstanceNotFound'),
 'aws_db_parameter_group':('rds','describe-db-parameter-groups','--db-parameter-group-name','id','DBParameterGroups','DBParameterGroupNotFound'),
 'aws_db_subnet_group':('rds','describe-db-subnet-groups','--db-subnet-group-name','id','DBSubnetGroups','DBSubnetGroupNotFoundFault'),
 'aws_elasticache_serverless_cache':('elasticache','describe-serverless-caches','--serverless-cache-name','name','ServerlessCaches','ServerlessCacheNotFoundFault'),
 'aws_security_group':('ec2','describe-security-groups','--group-ids','id','SecurityGroups','InvalidGroup.NotFound'),
 'aws_vpc_security_group_ingress_rule':('ec2','describe-security-group-rules','--security-group-rule-ids','id','SecurityGroupRules','InvalidSecurityGroupRuleId.NotFound'),
 'aws_vpc_security_group_egress_rule':('ec2','describe-security-group-rules','--security-group-rule-ids','id','SecurityGroupRules','InvalidSecurityGroupRuleId.NotFound'),
 'aws_iam_role':('iam','get-role','--role-name','name','Role','NoSuchEntity'),
 'aws_msk_cluster':('kafka','describe-cluster-v2','--cluster-arn','arn','ClusterInfo','NotFoundException'),
 'aws_msk_configuration':('kafka','describe-configuration','--arn','arn',None,'NotFoundException')}

def read_observation(context,row,runner=subprocess.run):
 kind=row['type']
 if kind=='terraform_data':return {'address':row['address'],'id':row['id'],'status':'terraform-only'}
 if kind=='aws_iam_role_policy':
  role=row.get('role') or row.get('role_name');name=row.get('name') or row.get('policy_name')
  require(role and name,'Inline policy parent/name missing')
  service,operation,bucket,code='iam','get-role-policy',None,'NoSuchEntity';args=['--role-name',role,'--policy-name',name]
 elif kind=='aws_eks_pod_identity_association':
  require(row.get('cluster_name') and row.get('association_id'),'Pod Identity identifiers missing')
  service,operation,bucket,code='eks','describe-pod-identity-association','association','ResourceNotFoundException';args=['--cluster-name',row['cluster_name'],'--association-id',row['association_id']]
 else:
  require(kind in READS,'No authenticated absence verifier for resource type')
  service,operation,opt,field,bucket,code=READS[kind];value=row.get(field)
  require(isinstance(value,str) and value,'Service identifier missing');args=[opt,value]
 command=['aws',service,operation,*args,'--region',context['backend']['region'],'--output','json','--no-cli-pager']
 try:r=runner(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
 except (OSError,subprocess.TimeoutExpired):raise SafeError('Service observation unavailable; status UNKNOWN') from None
 if r.returncode:
  match=re.search(rb'An error occurred \(([^)]+)\) when calling the ([A-Za-z0-9]+) operation',r.stderr)
  require(match and match[1].decode()==code and match[2].decode().lower()==operation.replace('-',''),'Service read failed; AccessDenied/timeout is UNKNOWN, not absent')
  return {'address':row['address'],'id':row['id'],'service':service,'operation':operation,'status':'absent','aws_error_code':code}
 try:value=json.loads(r.stdout)
 except ValueError:raise SafeError('Invalid service JSON; UNKNOWN') from None
 require(isinstance(value,dict) and not any(value.get(k) for k in ('NextToken','nextToken','Marker','NextMarker','IsTruncated')),'Incomplete service response; UNKNOWN')
 found=value if bucket is None else value.get(bucket)
 require(isinstance(found,(dict,list)) and bool(found),'Missing service identity response; UNKNOWN')
 return {'address':row['address'],'id':row['id'],'service':service,'operation':operation,'status':'present','response_sha256':hashlib.sha256(r.stdout).hexdigest()}

def identity(context):
 expected=os.environ.get('AWS_ROLE_ARN');require(expected,'Bound execution role required');session=h.check_identity(context['account'],expected)
 return {'account':context['account'],'role_arn':expected,'session_arn':session,'observed_at':dt.datetime.now(dt.timezone.utc).isoformat()}

def verify_absent(context,original,observer=None,sleeper=time.sleep):
 auth=identity(context);observer=observer or read_observation
 for attempt in range(12):
  results=[observer(context,row) for row in original]
  if all(x['status'] in ('absent','terraform-only') for x in results):return {'identity':auth,'resources':results,'source_sha':context['source_sha'],'generation':context['generation']}
  if attempt<11:sleeper(10)
 raise SafeError('Resource still present after bounded absence polling; pause retained, use a fresh run')

def verify_present(context,raw):
 auth=identity(context);rows=normalize_resources(raw);results=[read_observation(context,row) for row in rows]
 require(all(x['status'] in ('present','terraform-only') for x in results),'Up resource readback is incomplete')
 return {'identity':auth,'resources':results,'source_sha':context['source_sha'],'generation':context['generation'],'application_reseed':'required later hook; not asserted by infrastructure creation'}

def verify_fixture_source(contract):
 """Read actual approved application source; a lesson comment is not seed proof."""
 import base64
 repo=contract.get('application_repository','')
 require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo),'Approved application repository required')
 meta=json.loads(h.execute(['gh','api','repos/'+repo]))
 require(str(meta.get('id'))==str(contract.get('application_repository_id')),'Application repository identity differs')
 sha=contract['application_source_sha'];path=contract['fixture_source_path']
 obj=json.loads(h.execute(['gh','api',f'repos/{repo}/contents/{path}?ref={sha}']))
 require(obj.get('type')=='file' and obj.get('encoding')=='base64' and obj.get('path')==path,'Actual seed source unavailable')
 body=base64.b64decode(obj['content'],validate=False)
 require(body and hashlib.sha256(body).hexdigest()==contract['fixture_sha256'],'Actual seed source hash differs')
 workspace=Path(os.environ['GITHUB_WORKSPACE'])
 migration=h.execute(['git','show',BOUND['context']['source_sha']+':gitops/apps/commerce-api/base/migration-job.yaml'],cwd=workspace)
 require(hashlib.sha256(migration).hexdigest()==contract['migration_sha256'],'Pinned migration manifest differs')
 require(b'./node_modules/.bin/medusa' in migration and b'db:migrate' in migration and b'--execute-safe-links' in migration,'Existing source migration command missing')
 return {'repository_id':meta['id'],'application_source_sha':sha,'fixture_sha256':contract['fixture_sha256'],'migration_sha256':contract['migration_sha256'],'image_digest':contract['application_image_digest'],'assertion':'source verified; execution and functional seed assertions still required after Up'}

def check_workload_inventory(items,namespace,queue=False):
 require(isinstance(items,list),'Incomplete Kubernetes inventory')
 for obj in items:
  md=obj.get('metadata',{});spec=obj.get('spec',{});kind=obj.get('kind');ns=md.get('namespace')
  relevant=(ns==namespace) if not queue else md.get('labels',{}).get('app.kubernetes.io/instance')=='platform-tempo-e2'
  if not relevant:continue
  if kind=='Pod':require(obj.get('status',{}).get('phase') in ('Succeeded','Failed'),'A live writer/consumer Pod remains')
  elif kind in ('Deployment','StatefulSet','ReplicaSet'):require(spec.get('replicas',1)==0,'Writer controller can recreate Pods')
  elif kind=='DaemonSet':raise SafeError('Writer DaemonSet remains')
  elif kind=='CronJob':require(spec.get('suspend') is True,'Writer CronJob can run')
  elif kind=='Job':require(obj.get('status',{}).get('active',0)==0 and any(c.get('status')=='True' and c.get('type') in ('Complete','Failed') for c in obj.get('status',{}).get('conditions',[])),'Writer Job unfinished')

def require_barriers(context):
 """Fresh account/EKS/Kubernetes reads, never caller boolean or arbitrary receipt."""
 import io,tarfile
 auth=identity(context);name=module(context['root']);contract=BOUND['contract']
 reader=VersionedStateReader(context['backend']['bucket'],context['account'],context['backend']['region'])
 eks=reader(key(scoped(context['root'],EKS)));relay=reader(key(scoped(context['root'],RELAY)))
 erows=managed_resources(eks['state']);rrows=managed_resources(relay['state'])
 clusters=[r['values'] for r in erows if r['type']=='aws_eks_cluster'];relays=[r['values'] for r in rrows if r['type']=='aws_instance']
 require(len(clusters)==len(relays)==1,'Current private cluster/relay identity missing')
 cluster=clusters[0];p=load('later_private_session',CI/'private-api-session.py')
 evidence={'identity':auth,'eks_state':eks['fingerprint'],'relay_state':relay['fingerprint']}
 with tempfile.TemporaryDirectory(prefix='later-preapply-') as directory:
  temp=Path(directory)
  with p.private_api(cluster['name'],relays[0]['id'],context['backend']['region'],temp/'kubeconfig') as (env,live):
   require(live['arn']==cluster['arn'] and dt.datetime.fromisoformat(live['createdAt'].replace('Z','+00:00'))==dt.datetime.fromisoformat(cluster['created_at'].replace('Z','+00:00')),'Live cluster differs from versioned State')
   workloads=json.loads(p.command(['kubectl','--request-timeout=30s','get','pods,deployments,statefulsets,replicasets,daemonsets,jobs,cronjobs','-A','-o','json'],env=env))
   require(not workloads.get('metadata',{}).get('continue'),'Incomplete workload inventory')
   check_workload_inventory(workloads.get('items'),contract['application_namespace'],name=='queue-managed')
   if name=='delivery':
    namespaces={r.get('consumer_namespace') or r.get('namespace') for r in BOUND['original'] if r.get('consumer_namespace') or r.get('namespace')}
    require(namespaces,'Original delivery controller namespaces missing')
    for namespace in namespaces:check_workload_inventory(workloads.get('items'),namespace)
   apps=json.loads(p.command(['kubectl','--request-timeout=30s','get','applications.argoproj.io','-A','-o','json'],env=env))
   require(not apps.get('metadata',{}).get('continue') and isinstance(apps.get('items'),list),'Incomplete Argo inventory')
   require(all(a.get('spec',{}).get('syncPolicy',{}).get('automated') is None for a in apps['items']),'Automated Argo writer remains enabled')
   evidence['workload_inventory_sha256']=h.digest(h.canonical(workloads));evidence['argo_inventory_sha256']=h.digest(h.canonical(apps))
   if name=='queue-managed' and context['operation']=='down':
    workspace=Path(os.environ['GITHUB_WORKSPACE']);script='platform/environments/'+environment(context['root'])+'/queue/scripts/check-drain.sh'
    body=h.execute(['git','show',context['source_sha']+':'+script],cwd=workspace)
    require(hashlib.sha256(body).hexdigest()==contract['drain_script_sha256'],'Real source drain script differs')
    archive=h.execute(['git','archive',context['source_sha'],'--','platform/environments/'+environment(context['root'])+'/queue','automation'],cwd=workspace)
    source=temp/'source';source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as stream:stream.extractall(source,filter='data')
    require(all(not x.is_symlink() for x in source.rglob('*')),'Drain source symlinks forbidden')
    queue=[r for r in BOUND['original'] if r['type']=='aws_msk_cluster'];require(len(queue)==1 and queue[0].get('arn'),'Original managed queue ARN missing')
    admin=json.loads(p.command(['kubectl','--request-timeout=30s','-n','monitoring','get','pod','queue-admin','-o','json'],env=env))
    require(admin['metadata'].get('uid') and admin.get('status',{}).get('phase')=='Running','Exact managed drain admin Pod missing')
    runenv={**env,'KUBE_CONTEXT':cluster['name'],'ENVIRONMENT':environment(context['root']),'EXPECTED_ACCOUNT_ID':context['account'],'AWS_REGION':context['backend']['region'],'MANAGED_QUEUE_APPROVED_CLUSTER_ARN':queue[0]['arn'],'DRAIN_APPROVED_SOURCE':'managed','DRAIN_APPROVED_POD_UID':admin['metadata']['uid'],'QUEUE_EKS_CLUSTER':cluster['name'],'MANAGED_QUEUE_REQUEST_ID':'lifecycle-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']}
    result=subprocess.run(['bash',str(source/script),'--source','managed'],env=runenv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
    require(result.returncode==0 and b'DRAINED stable_end_offsets=true lag=0' in result.stdout,'Managed queue drain not established')
    evidence['drain_result_sha256']=hashlib.sha256(result.stdout).hexdigest()
 if name=='data':
  evidence['fixture_provenance']=verify_fixture_source(contract)
  if environment(context['root'])=='prod' and context['operation']=='down':evidence['production_protection_transition']=verify_prod_protection(context,contract)

 evidence['retained_approval_contract_sha256']=context['contract_sha256']
 return evidence


def verify_prod_protection(context,contract):
 descriptor=contract.get('prod_protection_receipt')
 require(isinstance(descriptor,dict) and set(descriptor)=={'key','version','sha256'},'Exact versioned production protection receipt required')
 require(descriptor['key'].startswith('ci-logs/'+context['repository_id']+'/') and descriptor['key'].endswith('/prod/incidents/database-protection-disable/apply/receipt.json'),'Wrong production protection receipt namespace')
 require(re.fullmatch('[0-9a-f]{64}',contract.get('prod_protection_request_sha256','')),'Reviewed production transition request hash required')
 store=h.Store(context['backend']['bucket'],context['account'])
 with tempfile.TemporaryDirectory() as directory:
  path=Path(directory)/'receipt';store.get(descriptor,path);receipt=json.loads(path.read_bytes())
 rc=receipt.get('context',{});result=receipt.get('result',{})
 require(receipt.get('kind')=='incident-completion' and receipt.get('success') is True and rc.get('operation')=='database-protection-disable' and rc.get('environment')=='prod' and rc.get('account')==context['account'] and rc.get('repository_id')==context['repository_id'] and rc.get('request_sha256')==contract['prod_protection_request_sha256'],'Unverified production protection transition')
 databases=[x for x in BOUND['original'] if x['type']=='aws_db_instance']
 require(len(databases)==1 and result.get('db_arn')==databases[0].get('arn') and result.get('resource_id')==databases[0].get('resource_id') and result.get('deletion_protection') is False,'Protection receipt is for a different database or state')
 return {'receipt':descriptor,'request_sha256':rc['request_sha256'],'db_arn':result['db_arn'],'resource_id':result['resource_id']}
