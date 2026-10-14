#!/usr/bin/env python3
"""Fixed BU16 AWS drill actions. Plan/verify/apply only, no generic CLI passthrough.

Network mutations occur only in apply using the identical approved private JSON
plan after a protected workflow gate. Tests inject all external calls.
"""
import datetime as dt,importlib.util,json,os,re,sys,tempfile,time,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parent
CI=BASE.parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
h=load('incident_saved',CI/'saved-plan.py')
v=load('incident_state',CI/'vpc-lifecycle-guard.py')
c=load('incident_cas',CI/'lifecycle-state.py')
OPS={'rds-pitr-create','rds-clone-delete','scram-admin-disassociate','scram-admin-schedule-delete'}

def require(ok,msg):h.require(ok,msg)
def aws(region,service,operation,*args):return json.loads(h.execute(['aws',service,operation,*args,'--region',region,'--output','json','--no-cli-pager']))
def utc(value):
 result=dt.datetime.fromisoformat(value.replace('Z','+00:00'));require(result.tzinfo,'UTC/timezone required');return result

def validate_request(r,allow_expired=False):
 require(isinstance(r,dict) and r.get('schema')==1 and r.get('operation') in OPS,'Unsupported fixed operation')
 allowed={'schema','operation','environment','account','region','incident_run','expires_at','approved_disposable_drill','retain_all_s3_and_existing_backups','operation_authorization','source_db_identifier','source_db_arn','source_db_resource_id','target_db_identifier','restore_time','final_snapshot_identifier','creation_receipt','diagnostic_jobs_removed_receipt','diagnostic_job_uids','diagnostic_cleanup_request_sha256','secret_arn','secret_name','secret_kms_key_id','cluster_arn','secret_tags','temporary_admin_issuance_receipt','recovery_window_days'}
 require(set(r)<=allowed,'Unknown request fields; credentials and arbitrary commands forbidden')
 require(r.get('environment')=='dev' and re.fullmatch(r'\d{12}',r.get('account','')),'Dev account required')
 require(r.get('region')=='ap-northeast-2','Reviewed source uses Seoul region')
 require(str(uuid.UUID(r.get('incident_run','')))==r['incident_run'],'Exact canonical drill UUID required')
 require(r.get('approved_disposable_drill') is True and r.get('retain_all_s3_and_existing_backups') is True,'Explicit drill and retention decision required')
 require(allow_expired or utc(r['expires_at'])>dt.datetime.now(dt.timezone.utc),'Drill request expired')
 require(r.get('operation_authorization')==r['operation'],'Exact consequential action approval must be in reviewed request')
 if r['operation'].startswith('rds-'):
  for field in ('source_db_identifier','source_db_arn','source_db_resource_id','target_db_identifier'):
   require(isinstance(r.get(field),str) and r[field],'Missing exact DB identity')
  require(r['source_db_identifier']!=r['target_db_identifier'],'Never mutate/delete the source database')
  require(re.fullmatch(r'[a-z][a-z0-9-]{0,62}',r['target_db_identifier']),'Invalid clone identifier')
  require(r['source_db_arn'].split(':')[4]==r['account'],'Source account differs')
  if r['operation']=='rds-clone-delete':
   require(r.get('final_snapshot_identifier') and r['final_snapshot_identifier']!=r['target_db_identifier'],'Explicit unique final snapshot required')
   require(isinstance(r.get('creation_receipt'),dict),'Authenticated original clone creation receipt required')
 else:
  for field in ('secret_arn','secret_name','secret_kms_key_id','cluster_arn','secret_tags'):
   require(r.get(field),'Exact temporary admin Secret metadata required')
  require(r['secret_arn'].split(':')[4]==r['account'] and r['cluster_arn'].split(':')[4]==r['account'],'Secret/cluster account differs')
  require(r.get('temporary_admin_issuance_receipt'),'Original temporary-admin issuance evidence required')
  if r['operation']=='scram-admin-schedule-delete':require(type(r.get('recovery_window_days')) is int and 7<=r['recovery_window_days']<=30,'Recoverable deletion window must be 7–30 days')

def state_exclusion(r,store):
 reader=v.VersionedStateReader(store.bucket,r['account'],r['region'])
 observed={};protected=[]
 for key in ('data/terraform.tfstate','retained/data/terraform.tfstate','platform/queue/terraform.tfstate','retained/queue-managed/terraform.tfstate'):
  value=reader(key);require(value['state'] is not None,'Required source/retained State unavailable')
  observed[key]=value['fingerprint'];protected+=v.managed_resources(value['state'])
 target=r.get('target_db_identifier') or r.get('secret_arn')
 require(not any(target in [x['values'].get(k) for k in ('id','arn','name','identifier')] for x in protected),'Target is Terraform-managed/protected, not an isolated drill asset')
 source=[x['values'] for x in protected if x['type']=='aws_db_instance' and x['values'].get('identifier')==r.get('source_db_identifier')]
 if r['operation'].startswith('rds-'):require(len(source)==1 and source[0].get('arn')==r['source_db_arn'],'Original main DB not verified from source State')
 return observed

def owned_artifact(store,descriptor,context,segment):
 require(set(descriptor)>={'key','version','sha256'} and descriptor['key'].startswith('ci-logs/'+context['repository_id']+'/') and '/dev/incident/'+segment+'/apply/' in descriptor['key'],'Untrusted drill receipt namespace')
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory)/'receipt';store.get(descriptor,p);value=json.loads(p.read_bytes())
 require(value['context']['account']==context['account'] and value['request']['incident_run']==context['incident_run'],'Drill receipt ownership differs')
 return value

def inspect(r,store,context):
 states=state_exclusion(r,store);op=r['operation'];region=r['region']
 if op.startswith('rds-'):
  rows=aws(region,'rds','describe-db-instances','--db-instance-identifier',r['source_db_identifier'])['DBInstances']
  require(len(rows)==1,'Source DB observation ambiguous');source=rows[0]
  require(source['DBInstanceArn']==r['source_db_arn'] and source['DbiResourceId']==r['source_db_resource_id'],'Source database replaced')
  require(source['StorageEncrypted'] is True and source.get('KmsKeyId'),'Encrypted source/key required')
  require(source.get('Engine')=='postgres' and source.get('PubliclyAccessible') is False and source.get('Endpoint',{}).get('Port')==5432,'Source differs from private PostgreSQL course contract')
  if op=='rds-pitr-create':
   target_time=utc(r['restore_time']);require(utc(source['EarliestRestorableTime'])<=target_time<=utc(source['LatestRestorableTime']),'Restore point outside live backup window')
   listing=aws(region,'rds','describe-db-instances');require(not listing.get('Marker'),'Incomplete RDS listing')
   require(all(d['DBInstanceIdentifier']!=r['target_db_identifier'] for d in listing['DBInstances']),'Target clone name already exists')
   command=['rds','restore-db-instance-to-point-in-time','--source-db-instance-identifier',r['source_db_identifier'],'--target-db-instance-identifier',r['target_db_identifier'],'--restore-time',r['restore_time'],'--db-subnet-group-name',source['DBSubnetGroup']['DBSubnetGroupName'],'--vpc-security-group-ids',*[x['VpcSecurityGroupId'] for x in source['VpcSecurityGroups']],'--db-parameter-group-name',source['DBParameterGroups'][0]['DBParameterGroupName'],'--db-instance-class',source['DBInstanceClass'],'--storage-type','gp3','--port','5432','--no-multi-az','--no-publicly-accessible','--no-auto-minor-version-upgrade','--no-deletion-protection','--tags','Key=Environment,Value=dev','Key=Purpose,Value=incident-pitr-drill','Key=IncidentRun,Value='+r['incident_run']]
   identity={'source_arn':source['DBInstanceArn'],'source_resource_id':source['DbiResourceId'],'kms_key':source['KmsKeyId'],'source_configuration_sha256':h.digest(h.canonical({k:source[k] for k in ('DBSubnetGroup','VpcSecurityGroups','DBParameterGroups','DBInstanceClass')}))}
  else:
   original=owned_artifact(store,r['creation_receipt'],context,'rds-pitr-create')
   rows=aws(region,'rds','describe-db-instances','--db-instance-identifier',r['target_db_identifier'])['DBInstances'];require(len(rows)==1,'Clone not found/ambiguous');target=rows[0]
   created=original['result']['DBInstance'];require(target['DBInstanceArn']==created['DBInstanceArn'] and target['DbiResourceId']==created['DbiResourceId'],'Clone identity differs from original creation receipt')
   tags=aws(region,'rds','list-tags-for-resource','--resource-name',target['DBInstanceArn'])['TagList'];tags={x['Key']:x['Value'] for x in tags}
   require(all(tags.get(k)==val for k,val in {'Environment':'dev','Purpose':'incident-pitr-drill','IncidentRun':r['incident_run']}.items()),'Drill tags mismatch')
   require(target['DeletionProtection'] is False and target['DBInstanceStatus']=='available','Clone not in approved deletable state')
   require(target['KmsKeyId']==source['KmsKeyId'],'Clone backup key differs')
   verify_job_cleanup(store,r,context)
   snapshots=aws(region,'rds','describe-db-snapshots');require(not snapshots.get('Marker'),'Incomplete snapshot inventory')
   require(all(x['DBSnapshotIdentifier']!=r['final_snapshot_identifier'] for x in snapshots['DBSnapshots']),'Final snapshot name already exists')
   # Existing automated backups and a named final snapshot are retained. Never
   # silently adopt the old lesson's skip-final-snapshot/delete-backups shortcut.
   command=['rds','delete-db-instance','--db-instance-identifier',r['target_db_identifier'],'--no-skip-final-snapshot','--final-db-snapshot-identifier',r['final_snapshot_identifier'],'--no-delete-automated-backups']
   identity={'target_arn':target['DBInstanceArn'],'target_resource_id':target['DbiResourceId'],'kms_key':target['KmsKeyId']}
 else:
  issued=owned_artifact(store,r['temporary_admin_issuance_receipt'],context,'scram-admin-issue')
  secret=aws(region,'secretsmanager','describe-secret','--secret-id',r['secret_arn'])
  require(secret['ARN']==r['secret_arn'] and secret['Name']==r['secret_name'] and secret['KmsKeyId']==r['secret_kms_key_id'] and sorted(secret.get('Tags',[]),key=lambda x:x['Key'])==sorted(r['secret_tags'],key=lambda x:x['Key']),'Temporary Secret metadata differs')
  require(issued['result']['ARN']==secret['ARN'] and issued['result']['Name']==secret['Name'],'Temporary admin issuance identity mismatch')
  require(not secret.get('DeletedDate'),'Secret already scheduled; reconcile original request instead of repeating')
  associations=aws(region,'kafka','list-scram-secrets','--cluster-arn',r['cluster_arn']);require(not associations.get('NextToken'),'Incomplete SCRAM association listing')
  attached=r['secret_arn'] in associations['SecretArnList']
  if op=='scram-admin-disassociate':
   require(attached,'Secret is not associated; do not repeat request');command=['kafka','batch-disassociate-scram-secret','--cluster-arn',r['cluster_arn'],'--secret-arn-list',r['secret_arn']]
  else:
   require(not attached,'Secret still associated with managed queue')
   command=['secretsmanager','delete-secret','--secret-id',r['secret_arn'],'--recovery-window-in-days',str(r['recovery_window_days'])]
  identity={'secret_arn':secret['ARN'],'secret_name':secret['Name'],'kms_key':secret['KmsKeyId'],'last_changed':secret.get('LastChangedDate')}
 return {'command':command,'identity':identity,'source_states':states}

def verify_job_cleanup(store,r,context):
 d=r.get('diagnostic_jobs_removed_receipt');require(isinstance(d,dict),'Exact Kubernetes cleanup receipt required')
 require(d.get('key','').startswith('ci-logs/'+context['repository_id']+'/') and '/dev/incidents/job-cleanup/apply/receipt.json' in d['key'],'Wrong cleanup receipt namespace')
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory)/'receipt';store.get(d,p);value=json.loads(p.read_bytes())
 require(value.get('kind')=='incident-completion' and value.get('success') is True and value['context'].get('operation')=='job-cleanup' and value['context'].get('account')==r['account'] and value['context'].get('repository_id')==context['repository_id'],'Cleanup receipt ownership/outcome differs')
 expected=r.get('diagnostic_job_uids');require(isinstance(expected,list) and expected and len(set(expected))==len(expected),'Exact created Job UIDs required')
 require(set(value['result'].get('deleted_job_uids',[]))==set(expected) and value['context'].get('request_sha256')==r.get('diagnostic_cleanup_request_sha256'),'Cleanup receipt does not cover exact reviewed drill Job UIDs/request')

def observe_result(r,result,reader=aws,sleeper=time.sleep):
 op=r['operation'];region=r['region']
 for attempt in range(90):
  if op=='rds-pitr-create':
   rows=reader(region,'rds','describe-db-instances','--db-instance-identifier',r['target_db_identifier'])['DBInstances']
   require(len(rows)==1 and rows[0]['DBInstanceArn']==result['DBInstance']['DBInstanceArn'] and rows[0]['DbiResourceId']==result['DBInstance']['DbiResourceId'],'Created clone was replaced/ambiguous')
   if rows[0]['DBInstanceStatus']=='available':return {'target_arn':rows[0]['DBInstanceArn'],'target_resource_id':rows[0]['DbiResourceId'],'status':'available','endpoint':rows[0]['Endpoint']['Address']}
  elif op=='rds-clone-delete':
   listing=reader(region,'rds','describe-db-instances');require(not listing.get('Marker'),'Incomplete RDS absence inventory')
   remaining=[x for x in listing['DBInstances'] if x['DBInstanceIdentifier']==r['target_db_identifier']]
   if not remaining:
    snapshots=reader(region,'rds','describe-db-snapshots','--db-snapshot-identifier',r['final_snapshot_identifier'])['DBSnapshots']
    require(len(snapshots)==1 and snapshots[0]['DBInstanceIdentifier']==r['target_db_identifier'] and snapshots[0].get('Encrypted') is True,'Final snapshot ownership/encryption differs')
    require(snapshots[0].get('KmsKeyId')==result['DBInstance'].get('KmsKeyId'),'Final snapshot key differs from deleted clone')
    if snapshots[0]['Status']=='available':return {'status':'absent','retained_final_snapshot_arn':snapshots[0]['DBSnapshotArn'],'kms_key':snapshots[0]['KmsKeyId']}
  elif op=='scram-admin-disassociate':
   live=reader(region,'kafka','list-scram-secrets','--cluster-arn',r['cluster_arn']);require(not live.get('NextToken'),'Incomplete SCRAM list')
   if r['secret_arn'] not in live['SecretArnList']:return {'status':'disassociated','secret_retained':r['secret_arn']}
  else:
   live=reader(region,'secretsmanager','describe-secret','--secret-id',r['secret_arn']);require(live['ARN']==r['secret_arn'],'Secret identity changed')
   if live.get('DeletedDate'):return {'status':'scheduled-recoverable-deletion','secret_arn':live['ARN'],'deletion_date':live['DeletedDate'],'recovery_window_days':r['recovery_window_days']}
  if attempt<89:sleeper(20)
 raise h.SafeError('Observation window ended without confirmed result; persistent recovery marker remains. Never replay mutation.')

def gate_settings():
 endpoint='repos/'+h.required('GITHUB_REPOSITORY')+'/environments/incident-dev-aws-mutate'
 value=json.loads(h.execute(['gh','api',endpoint]))
 require(any(x.get('type')=='required_reviewers' and x.get('reviewers') for x in value.get('protection_rules',[])) and value.get('can_admins_bypass') is False,'Protected AWS drill reviewer gate required; no admin bypass')
 require(value.get('deployment_branch_policy',{}).get('custom_branch_policies') is True,'Gate must use explicit main branch policy')
 branches=json.loads(h.execute(['gh','api',endpoint+'/deployment-branch-policies?per_page=100']))
 require(branches.get('total_count')==1 and branches.get('branch_policies',[{}])[0].get('name')=='main','Only main can enter mutation gate')

def run(stage):
 require(stage in ('plan','verify','apply','observe'),'Expected fixed stage')
 require(os.environ.get('GITHUB_REF')=='refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','Trusted protected main dispatch only')
 request_path=Path(h.required('INCIDENT_REQUEST_PATH'));require(re.fullmatch(r'incidents/requests/[0-9a-f-]{36}\.json',str(request_path)),'Only reviewed repository drill requests')
 r=json.loads(request_path.read_text());validate_request(r,allow_expired=stage=='observe')
 require(h.execute(['git','rev-parse','HEAD']).decode().strip()==h.required('GITHUB_SHA'),'Current helper SHA differs')
 h.execute(['git','diff','--exit-code','HEAD','--',str(request_path)]);h.execute(['git','ls-files','--error-unmatch',str(request_path)])
 h.ensure_current_main({'sha':h.required('GITHUB_SHA')});gate_settings();session=h.check_identity(r['account'],h.required('AWS_ROLE_ARN'))
 store=h.Store(h.required('STATE_BUCKET'),r['account']);store.check()
 course,_=c.read_json(store,c.course_marker_key(h.required('GITHUB_REPOSITORY_ID')))
 if course is not None:c.validate_course(course,h.required('GITHUB_REPOSITORY_ID'),r['account'],store.bucket,r['region'])
 require(course is None or course.get('phase')=='active','Course lifecycle is paused; ordinary drill mutation is blocked')
 context={k:h.required(v) for k,v in {'repository_id':'GITHUB_REPOSITORY_ID','run_id':'GITHUB_RUN_ID','run_attempt':'GITHUB_RUN_ATTEMPT','sha':'GITHUB_SHA'}.items()}
 context.update(account=r['account'],incident_run=r['incident_run'],operation=r['operation'],request_sha256=h.digest(h.canonical(r)))
 prefix=f"ci-plans/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/dev/incident/{r['operation']}/"
 if stage=='observe':
  marker_key='ci-lifecycle/'+context['repository_id']+'/dev/incident-aws-'+r['incident_run']+'.json'
  marker,info=c.read_json(store,marker_key)
  require(marker is not None and marker.get('phase')=='accepted-pending-observation' and marker['context']['request_sha256']==context['request_sha256'],'Only the exact accepted pending request can be observed; uncertain request requires review')
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory)/'accepted';store.get(marker['accepted'],p);accepted=json.loads(p.read_bytes())
  require(accepted['request']==r and accepted['context']==marker['context'],'Accepted receipt changed')
  observed=observe_result(r,accepted['result'])
  # An observation job performs no cloud mutation and does not clear recovery
  # ownership. The protected apply/admin role can review and CAS-reconcile it.
  h.emit({'observation_sha256':h.digest(h.canonical(observed)),'observation_status':observed['status']})
  return
 current=inspect(r,store,context)
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory)/'plan.json'
  if stage=='plan':
   now=int(time.time());plan={'schema':1,'kind':'incident-fixed-action','context':context,'request':r,'observation':current,'created_at':now,'expires_at':min(now+h.TTL_SECONDS,int(utc(r['expires_at']).timestamp()))}
   p.write_bytes(h.canonical(plan));d=store.put(prefix+'plan.json',p)
   with open(h.required('GITHUB_STEP_SUMMARY'),'a') as summary:
    summary.write('\n## Exact AWS drill action to review\nOperation: '+r['operation']+'\n\nRequest SHA-256: '+context['request_sha256']+'\n\nPrivate plan key: '+d['key']+'\n\nVersionId: '+d['version']+'\n\nSHA-256: '+d['sha256']+'\n\nReview the exact target identities, fixed command, backup/retention choices and request before approving incident-dev-aws-mutate.\n')
   h.emit({'plan_key':d['key'],'plan_version':d['version'],'plan_sha':d['sha256']});return
  descriptor={'key':h.required('PLAN_KEY'),'version':h.required('PLAN_VERSION'),'sha256':h.required('PLAN_SHA')};require(descriptor['key']==prefix+'plan.json','Wrong approved action plan')
  store.get(descriptor,p);plan=json.loads(p.read_bytes())
  require(plan['kind']=='incident-fixed-action' and plan['context']==context and plan['request']==r and plan['observation']==current and plan['created_at']<=time.time()<plan['expires_at'],'Approved action/context/identity/state/TTL changed')
  if stage=='verify':return
  marker_key='ci-lifecycle/'+context['repository_id']+'/dev/incident-aws-'+r['incident_run']+'.json'
  for rule in store.call('get-bucket-lifecycle-configuration').get('Rules',[]):
   filt=rule.get('Filter',{});prefix_filter=filt.get('Prefix',filt.get('And',{}).get('Prefix',rule.get('Prefix','')))
   require(not (rule.get('Status')=='Enabled' and any(x in rule for x in ('Expiration','NoncurrentVersionExpiration')) and marker_key.startswith(prefix_filter)),'Incident recovery marker must not expire')
  marker,marker_info=c.read_json(store,marker_key)
  require(marker is None or marker.get('phase')=='idle','Prior incident request may have executed; reconcile its receipt/live identity before any retry')
  marker={'schema':1,'phase':'requesting','context':context,'plan':descriptor,'target':current['identity']}
  marker_info=c.update(store,marker_key,marker,marker_info)
  require(inspect(r,store,context)==current,'Target/source ownership changed immediately before request; recovery marker retained')
  result=aws(r['region'],*current['command'])
  if r['operation']=='scram-admin-disassociate':require(result.get('UnprocessedScramSecrets')==[],'SCRAM disassociation partly failed')
  if r['operation']=='scram-admin-schedule-delete':require(result.get('ARN')==r['secret_arn'] and result.get('DeletionDate'),'Recoverable deletion not confirmed')
  receipt={'context':context,'request':r,'plan':descriptor,'session_arn':session,'result':result,'status':'request-accepted-not-absence','completed_at':dt.datetime.now(dt.timezone.utc).isoformat()}
  p.write_bytes(h.canonical(receipt));d=store.put(prefix.replace('ci-plans/','ci-logs/',1)+'apply/accepted.json',p)
  marker.update(phase='accepted-pending-observation',accepted=d);marker_info=c.update(store,marker_key,marker,marker_info)
  observed=observe_result(r,result)
  receipt.update(status='verified',observations=observed)
  p.write_bytes(h.canonical(receipt));d=store.put(prefix.replace('ci-plans/','ci-logs/',1)+'apply/receipt.json',p)
  marker.update(phase='idle',completion=d);c.update(store,marker_key,marker,marker_info)
  h.emit({'receipt_key':d['key'],'receipt_version':d['version'],'receipt_sha':d['sha256']})
if __name__=='__main__':
 try:run(sys.argv[1])
 except Exception:raise SystemExit('Incident action stopped; preserve private evidence and reconcile before retry. No secret values published.')
