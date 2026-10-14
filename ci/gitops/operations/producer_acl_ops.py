"""BU16 T13: one saved bounded issue/fault/restore/recoverable-cleanup action."""
import copy,datetime,hashlib,json,pathlib,re,secrets,tempfile,time,uuid
import managed_queue_ops as managed
from verify_managed_acls import parse_acls,expected_acls
IDS=('producer-acl-cycle','producer-acl-recover')
NS='monitoring'
def aws(io,t,*args,content=None):
 return json.loads(io.ops.run(['aws',*args,'--region',t['region'],'--output','json'],**({'content':content} if content is not None else {})))
def same_pod(io,t):
 obj=io.kube('pods',NS,'queue-admin');io.require(io.identity(obj)==t['pod'],'Original admin Pod identity/spec changed')
def kube_exec(io,t,args,content=None):
 same_pod(io,t)
 return io.ops.run(['kubectl','--request-timeout=30s','-n',NS,'exec','-i','queue-admin','--',*args],**({'content':content} if content is not None else {}))
def acl(io,t,*args):
 return kube_exec(io,t,['bin/kafka-acls.sh','--bootstrap-server',t['bootstrap'],'--command-config',t['config'],*args])
def acl_set(io,t):return set(parse_acls(acl(io,t,'--list').decode()))
def canonical(rows):return sorted([list(x) for x in rows])
def deny(t):return ('TOPIC',t['topic'],'LITERAL','User:tempo-distributor','*','WRITE','DENY')
def snapshot(io,operation,r,c,store,marker=None):
 io.require(c['environment']=='dev' and operation in IDS,'T13 is Dev-only')
 io.require(set(r)<={'source_sha','expires_at','change_request','data_decision','experiment_id','pod_uid','cluster_arn','setup_script_sha256','hold_seconds'},'Unknown fields; credentials and arbitrary commands forbidden')
 run=str(uuid.UUID(r['experiment_id']))
 io.require(r['data_decision']=='bounded-one-producer-deny-restore-and-seven-day-admin-cleanup','Explicit complete drill authorization required')
 if operation=='producer-acl-recover':
  io.require(marker and marker.get('operation') in IDS and marker.get('phase') in ('active','recovery-required'),'Original unresolved ACL marker required')
  t=copy.deepcopy(marker['target']);io.require(t['credential_run_id']==run and t['cluster_arn']==r['cluster_arn'] and t['pod']['uid']==r['pod_uid'],'Recovery scope differs from original action')
  same_pod(io,t);return t
 io.require(type(r.get('hold_seconds')) is int and 30<=r['hold_seconds']<=120,'Fault observation window must be 30–120 seconds')
 mr={k:r[k] for k in ('source_sha','expires_at','change_request','pod_uid','cluster_arn')}
 mr.update(credential_run_id=run,script_sha256=r['setup_script_sha256'],data_decision='create-temporary-admin-topics-acls-and-recoverable-cleanup')
 t=managed.snapshot(io,'managed-queue-setup',mr,c,store)
 # Query the same actual source-defined contract. Only metadata reaches the plan.
 import importlib.util
 spec=importlib.util.spec_from_file_location('acl_state',io.ops.shared_file('vpc-lifecycle-guard.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
 state=v.VersionedStateReader(c['state_bucket'],c['account_id'],c['region'])('platform/queue/terraform.tfstate')
 q=state['state']['outputs']['queue_managed_contract']['value']
 io.require(q['cluster_arn']==t['cluster_arn'] and re.fullmatch('[A-Za-z0-9._-]+',q['topic_name']),'Exact source topic required')
 image=c['trace_probe_image'];io.require(io.ops.DIGEST.fullmatch(image),'Published immutable curl image required')
 assoc=aws(io,t,'kafka','list-scram-secrets','--cluster-arn',t['cluster_arn']);io.require(not assoc.get('NextToken'),'Incomplete original SCRAM association inventory')
 distributor=io.kube('deployments.apps',NS,'platform-tempo-e2-distributor');io.require(distributor['spec'].get('replicas',0)>0,'Expected E2 producer deployment is not running')
 t['distributor']=io.identity(distributor)
 t.update(topic=q['topic_name'],bootstrap=q['bootstrap_brokers_scram'],kms_key=q['kms_key_arn'],config='/tmp/queue-admin-'+run+'.properties',hold_seconds=r['hold_seconds'],original_associations=sorted(assoc['SecretArnList']),trace_image=image,probe_pods=[],trace_ids={phase:hashlib.sha256((run+phase).encode()).hexdigest()[:32] for phase in ('baseline','fault','recovered')},observations={})
 for phase in ('baseline','fault','recovered'):
  for action in (('send','query','requery') if phase=='fault' else ('send','query')):
   name='acl-'+phase+'-'+action+'-'+run
   io.require(io.kube('pods','observability',name,True) is None,'Probe name exists; no adoption')
 return t

def persist(mark,t):mark('active',copy.deepcopy(t))
def issue(io,t,mark):
 password=secrets.token_urlsafe(36)
 body=io.h.canonical({'username':'queue-admin','password':password})
 # Private stdin only; never put password/SecretString in argv, plan, marker or logs.
 result=aws(io,t,'secretsmanager','create-secret','--name',t['temporary_secret_name'],'--kms-key-id',t['kms_key'],'--client-request-token',t['credential_run_id'],'--secret-string','file:///dev/stdin','--tags','Key=platform-queue-run,Value='+t['credential_run_id'],'Key=platform-queue-request,Value='+t['request_id'],content=body)
 io.require(result['Name']==t['temporary_secret_name'] and result['VersionId']==t['credential_run_id'],'Issuance acknowledgement mismatch')
 t['issued']={'arn':result['ARN'],'version_id':result['VersionId']};persist(mark,t)
 associate=aws(io,t,'kafka','batch-associate-scram-secret','--cluster-arn',t['cluster_arn'],'--secret-arn-list',result['ARN'])
 io.require(associate.get('UnprocessedScramSecrets')==[],'SCRAM association not acknowledged')
 t['association_acknowledged']=True;persist(mark,t)
 t['config_write_attempted']=True;persist(mark,t)
 configure(io,t,password);password=None;body=None
 t['config_written']=True;persist(mark,t)
 for _ in range(30):
  try:acl_set(io,t);return
  except Exception:time.sleep(10)
 raise io.h.SafeError('Temporary admin authentication timeout; exact issuance retained for recovery')
def configure(io,t,password):
 io.require(re.fullmatch('[A-Za-z0-9_-]{12,64}',password),'Unexpected issued password format')
 value=('security.protocol=SASL_SSL\nsasl.mechanism=SCRAM-SHA-512\nsasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="queue-admin" password="'+password+'";\n').encode()
 kube_exec(io,t,['sh','-c','umask 077; cat > "$1"','sh',t['config']],content=value)
def restore(io,t,mark):
 if 'baseline_acls' not in t:return # no fault write was attempted
 baseline={tuple(x) for x in t['baseline_acls']};current=acl_set(io,t);injected=baseline|{deny(t)}
 io.require(current in (baseline,injected),'Unrelated ACL drift; no broad replacement or cleanup')
 if current==injected:
  acl(io,t,'--remove','--deny-principal','User:tempo-distributor','--deny-host','*','--operation','Write','--topic',t['topic'],'--resource-pattern-type','literal','--force')
 io.require(acl_set(io,t)==baseline,'Exact full original ACL set not restored')
 t['acl_restored']=True;t['acl_restored_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();persist(mark,t)
def cleanup(io,t,mark):
 io.require('baseline_acls' not in t or t.get('acl_restored') is True,'Do not remove recovery credentials before exact ACL restore')
 if 'issued' not in t:return
 arn=t['issued']['arn']
 if t.get('config_write_attempted') or t.get('config_written'):
  kube_exec(io,t,['rm','-f','--',t['config']]);t['config_removed']=True;persist(mark,t)
 response=aws(io,t,'kafka','batch-disassociate-scram-secret','--cluster-arn',t['cluster_arn'],'--secret-arn-list',arn)
 io.require(response.get('UnprocessedScramSecrets')==[],'SCRAM disassociation not acknowledged')
 current=aws(io,t,'kafka','list-scram-secrets','--cluster-arn',t['cluster_arn']);io.require(not current.get('NextToken') and sorted(current['SecretArnList'])==t['original_associations'],'Original association set not restored')
 response=aws(io,t,'secretsmanager','delete-secret','--secret-id',arn,'--recovery-window-in-days','7')
 io.require(response['ARN']==arn and response.get('DeletionDate'),'Recoverable deletion was not acknowledged')
 meta=aws(io,t,'secretsmanager','describe-secret','--secret-id',arn);io.require(meta['ARN']==arn and meta.get('DeletedDate'),'Deletion scheduling not observed')
 t['recoverable_cleanup']={'secret_arn':arn,'version_id':t['issued']['version_id'],'recovery_days':7,'scheduled':True,'permanent_absence_claimed':False};persist(mark,t)

def probe(io,t,phase,action,mark):
 trace=t['trace_ids'][phase];family=t.get('probe_family','acl');io.require(family in ('acl','aws-trace'),'Unknown fixed probe family');name=family+'-'+phase+'-'+action+'-'+t['credential_run_id']
 io.require(io.kube('pods','observability',name,True) is None,'Probe appeared after review; never adopt')
 if action=='send':
  stamp=time.time_ns();body={'resourceSpans':[{'resource':{'attributes':[{'key':'service.name','value':{'stringValue':'platform-trace-probe'}}]},'scopeSpans':[{'scope':{'name':'trace-probe'},'spans':[{'traceId':trace,'spanId':hashlib.sha256(trace.encode()).hexdigest()[:16],'name':'probe','kind':1,'startTimeUnixNano':str(stamp),'endTimeUnixNano':str(stamp+5000000),'status':{}}]}]}]}
  command=['curl','--max-time','30','-sS','-w','\n%{http_code}','-X','POST','http://collection-gateway.observability:4318/v1/traces','-H','Content-Type: application/json','-d',json.dumps(body,separators=(',',':'))]
 else:
  # Fixed original query endpoint. Only 404 is retried; auth/API errors stop.
  attempts='1' if phase=='fault' and action=='query' else ('120' if family=='aws-trace' and phase=='recovered' else '30')
  command=['sh','-c','for i in $(seq '+attempts+'); do code=$(curl --max-time 5 -sS -o /tmp/body -w "%{http_code}" "$1") || exit 2; [ "$code" = 404 ] || break; sleep 5; done; cat /tmp/body; printf "\\n%s" "$code"','sh',('http://platform-tempo-e3-querier.monitoring:3200' if t.get('query_mode')=='blocks' else 'http://platform-tempo-active-query.monitoring:3200')+'/api/traces/'+trace+('?mode=blocks' if t.get('query_mode')=='blocks' else '')]
 pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'observability','labels':{'incident.course/acl-run':t['credential_run_id']}},'spec':{'restartPolicy':'Never','activeDeadlineSeconds':1320 if family=='aws-trace' and phase=='recovered' else 330,'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':100,'fsGroup':100,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'probe','image':t['trace_image'],'command':command,'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'100m','memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'temp','mountPath':'/tmp'}]}],'volumes':[{'name':'temp','emptyDir':{'sizeLimit':'8Mi'}}]}}
 t['pending_probe']=name;persist(mark,t)
 created=json.loads(io.ops.run(['kubectl','--request-timeout=30s','create','-f','-','-o','json'],content=io.h.canonical(pod)));ident=io.identity(created);t['probe_pods'].append(ident);t.pop('pending_probe',None);persist(mark,t)
 for _ in range(270 if family=='aws-trace' and phase=='recovered' else 70):
  obj=io.kube('pods','observability',name);io.require(obj['metadata']['uid']==ident['uid'],'Probe Pod replaced')
  state=obj.get('status',{}).get('phase')
  if state in ('Succeeded','Failed'):break
  time.sleep(5)
 io.require(state=='Succeeded','Probe transport failed or timed out; not evidence of trace absence')
 raw=io.ops.run(['kubectl','--request-timeout=30s','-n','observability','logs',name,'-c','probe']).decode();payload,code=raw.rstrip().rsplit('\n',1)
 io.require(code in ('200','404') if action!='send' else code in ('200','400','429','500','502','503','504'),'Trace authorization or unknown API error; inconclusive')
 data=json.loads(payload) if code=='200' else None
 if action=='send' and code=='200':
  io.require(isinstance(data,dict) and not data.get('partialSuccess',{}).get('rejectedSpans',0) and not data.get('partialSuccess',{}).get('errorMessage'),'Trace partial rejection; not successful ingestion proof')
 found=False
 if action!='send' and code=='200':
  import base64
  def matches(value):
   if isinstance(value,dict):
    candidate=value.get('traceId')
    if isinstance(candidate,str):
     if candidate.lower()==trace:return True
     try:
      if base64.b64decode(candidate,validate=True).hex()==trace:return True
     except ValueError:pass
    return any(matches(v) for v in value.values())
   return isinstance(value,list) and any(matches(v) for v in value)
  found=matches(data);io.require(found,'Successful response did not contain exact trace ID')
 result={'observed_at_unix_ns':time.time_ns(),'trace_id':trace,'http_status':int(code),'found':found if action!='send' else None,'accepted':action=='send' and code=='200'}
 t['observations'][phase+'-'+action]=result;persist(mark,t);return result

def cleanup_probes(io,t,mark):
 for ident in t['probe_pods']:
  if ident['uid'] in t.get('deleted_probe_uids',[]):continue
  obj=io.kube('pods','observability',ident['name']);io.require(io.identity(obj)==ident,'Probe identity/spec drift; refuse deletion')
  options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':ident['uid'],'resourceVersion':obj['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
  with tempfile.TemporaryDirectory() as directory:
   file=pathlib.Path(directory)/'delete.json';file.write_bytes(io.h.canonical(options))
   io.ops.run(['kubectl','--request-timeout=30s','delete','--raw','/api/v1/namespaces/observability/pods/'+ident['name'],'-f',str(file)])
  for _ in range(30):
   remaining=io.kube('pods','observability',ident['name'],True)
   if remaining is None:break
   io.require(remaining['metadata']['uid']==ident['uid'],'Replacement Pod appeared; never delete replacement');time.sleep(2)
  io.require(remaining is None,'Exact probe absence not observed');t.setdefault('deleted_probe_uids',[]).append(ident['uid']);persist(mark,t)

def recover_credentials(io,t,mark):
 # Recover only the exact acknowledged UUID version. No reissue or fresh password.
 io.require(t.get('issued'),'Unknown create outcome requires protected identity reconciliation, never fabricate issuance receipt')
 meta=aws(io,t,'secretsmanager','describe-secret','--secret-id',t['issued']['arn'])
 io.require(meta['Name']==t['temporary_secret_name'] and not meta.get('DeletedDate') and t['credential_run_id'] in meta.get('VersionIdsToStages',{}) and {x['Key']:x['Value'] for x in meta.get('Tags',[])}.get('platform-queue-run')==t['credential_run_id'],'Original temporary credential metadata changed')
 result=aws(io,t,'secretsmanager','get-secret-value','--secret-id',t['issued']['arn'],'--version-id',t['issued']['version_id'])
 value=json.loads(result['SecretString']);io.require(value['username']=='queue-admin' and result['VersionId']==t['issued']['version_id'],'Temporary admin version mismatch')
 configure(io,t,value['password']);value=None;result=None;t['config_written']=True;persist(mark,t)

def apply(io,operation,target,r,mark):
 io.require(operation in IDS,'Unknown ACL operation');t=copy.deepcopy(target);persist(mark,t)
 if operation=='producer-acl-recover':
  io.require(not t.get('pending_probe'),'Unknown probe creation outcome requires protected UID reconciliation')
  if not t.get('recoverable_cleanup'):recover_credentials(io,t,mark);restore(io,t,mark);cleanup(io,t,mark)
  cleanup_probes(io,t,mark)
 else:
  succeeded=False
  try:
   issue(io,t,mark)
   baseline=acl_set(io,t);app={x for x in baseline if x[3] in ('User:tempo-distributor','User:tempo-consumer','User:*')}
   io.require(app==expected_acls(t['topic'],'tempo-distributor','tempo-consumer','platform-tempo-e2') and deny(t) not in baseline,'Source expected ACL boundary differs; no fault injected')
   t['baseline_acls']=canonical(baseline);persist(mark,t)
   io.require(probe(io,t,'baseline','send',mark)['accepted'],'Baseline send failed; no injection');io.require(probe(io,t,'baseline','query',mark)['found'],'Baseline trace is not queryable; no injection')
   t['deny_write_attempted']=True;persist(mark,t)
   acl(io,t,'--add','--deny-principal','User:tempo-distributor','--deny-host','*','--operation','Write','--topic',t['topic'],'--resource-pattern-type','literal')
   io.require(acl_set(io,t)==baseline|{deny(t)},'Fault ACL acknowledgement/set differs')
   t['deny_verified']=True;t['deny_verified_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();persist(mark,t)
   probe(io,t,'fault','send',mark);time.sleep(t['hold_seconds']);probe(io,t,'fault','query',mark)
   live=io.kube('deployments.apps',NS,'platform-tempo-e2-distributor');io.require(io.identity(live)==t['distributor'],'Producer deployment changed during fault')
   logs=io.ops.run(['kubectl','--request-timeout=30s','-n',NS,'logs','deployment/platform-tempo-e2-distributor','--since-time='+t['deny_verified_at'],'--tail=200'])
   t['observations']['producer-errors']={'source_deployment_uid':t['distributor']['uid'],'topic_authorization_failed_observed':b'TOPIC_AUTHORIZATION_FAILED' in logs,'raw_sha256':hashlib.sha256(logs).hexdigest(),'since':t['deny_verified_at']};persist(mark,t)
   restore(io,t,mark)
   io.require(probe(io,t,'recovered','send',mark)['accepted'],'Recovered send failed');io.require(probe(io,t,'recovered','query',mark)['found'],'Recovered trace missing; ACL restored but service recovery not proven')
   probe(io,t,'fault','requery',mark);succeeded=True
  finally:
   restore(io,t,mark);cleanup(io,t,mark);cleanup_probes(io,t,mark)
  io.require(succeeded,'Drill failed; cleanup evidence remains separate from recovery proof')
 result={'experiment_id':t['credential_run_id'],'issuance':t.get('issued'),'baseline_acls':t.get('baseline_acls',[]),'injected_tuple':list(deny(t)),'acl_restored':t.get('acl_restored',False),'deny_verified':t.get('deny_verified',False),'cleanup':t.get('recoverable_cleanup'),'deny_verified_at':t.get('deny_verified_at'),'acl_restored_at':t.get('acl_restored_at'),'trace_observations':t['observations'],'deleted_probe_uids':t.get('deleted_probe_uids',[]),'raw_credentials_or_logs_published':False,'recovery_only':operation.endswith('recover')}
 mark('idle',dict(t,result=result));return result
