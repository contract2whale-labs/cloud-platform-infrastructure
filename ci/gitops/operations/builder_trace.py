#!/usr/bin/env python3
"""Fixed synthetic trace probe within the single approved builder incident."""
import copy, hashlib, json, pathlib, tempfile, time, uuid

def persist(mark,target): mark('active',target)

def prepare(io,r,c):
 io.require(r.get('data_decision')=='pause-builder-send-one-synthetic-trace-restore-and-uid-cleanup','Explicit combined builder/probe decision required')
 run=str(uuid.UUID(r['experiment_id']))
 image=c['trace_probe_image'];io.require(io.ops.DIGEST.fullmatch(image),'Pinned trace image required')
 target={'experiment_id':run,'trace_image':image,'trace_ids':{'fault':hashlib.sha256((run+'builder-fault').encode()).hexdigest()[:32]},'probe_pods':[],'observations':{}}
 target['namespace']=io.identity(io.kube('namespaces','','observability'))
 for action in ('send','query','requery'):
  io.require(io.kube('pods','observability','builder-fault-'+action+'-'+run,True) is None,'Probe name already exists')
 return target

def validate_namespace(io,t):
 io.require(io.identity(io.kube('namespaces','','observability'))==t['namespace'],'Probe namespace changed')

def probe(io,t,phase,action,mark):
 validate_namespace(io,t)
 trace=t['trace_ids'][phase];name='builder-'+phase+'-'+action+'-'+t['experiment_id']
 io.require(io.kube('pods','observability',name,True) is None,'Probe appeared after review; never adopt')
 if action=='send':
  stamp=time.time_ns();body={'resourceSpans':[{'resource':{'attributes':[{'key':'service.name','value':{'stringValue':'platform-trace-probe'}}]},'scopeSpans':[{'scope':{'name':'trace-probe'},'spans':[{'traceId':trace,'spanId':hashlib.sha256(trace.encode()).hexdigest()[:16],'name':'probe','kind':1,'startTimeUnixNano':str(stamp),'endTimeUnixNano':str(stamp+5000000),'status':{}}]}]}]}
  command=['curl','--max-time','30','-sS','-w','\n%{http_code}','-X','POST','http://collection-gateway.observability:4318/v1/traces','-H','Content-Type: application/json','-d',json.dumps(body,separators=(',',':'))]
 else:
  # Fixed original query endpoint. Only 404 is retried; auth/API errors stop.
  attempts='1' if phase=='fault' and action=='query' else '30'
  command=['sh','-c','for i in $(seq '+attempts+'); do code=$(curl --max-time 5 -sS -o /tmp/body -w "%{http_code}" "$1") || exit 2; [ "$code" = 404 ] || break; sleep 5; done; cat /tmp/body; printf "\\n%s" "$code"','sh','http://platform-tempo-active-query.monitoring:3200/querier/api/traces/'+trace+'?mode=blocks']
 pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'observability','labels':{'incident.course/builder-run':t['experiment_id']}},'spec':{'restartPolicy':'Never','activeDeadlineSeconds':330,'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':100,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'probe','image':t['trace_image'],'command':command,'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'100m','memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'temp','mountPath':'/tmp'}]}],'volumes':[{'name':'temp','emptyDir':{'sizeLimit':'8Mi'}}]}}
 t['pending_probe']=name;persist(mark,t)
 created=json.loads(io.ops.run(['kubectl','--request-timeout=30s','create','-f','-','-o','json'],content=io.h.canonical(pod)));ident=io.identity(created);t['probe_pods'].append(ident);t.pop('pending_probe',None);persist(mark,t)
 for _ in range(70):
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
 io.require(not t.get('pending_probe'),'Unknown probe creation outcome requires protected UID reconciliation')
 validate_namespace(io,t)
 for ident in t['probe_pods']:
  if ident['uid'] in t.get('deleted_probe_uids',[]):continue
  obj=io.kube('pods','observability',ident['name'],True)
  if obj is None:
   io.require(ident['uid'] in t.get('delete_attempted_uids',[]),'Probe disappeared before acknowledged delete intent')
   t.setdefault('deleted_probe_uids',[]).append(ident['uid']);persist(mark,t);continue
  io.require(io.identity(obj)==ident,'Probe identity/spec drift; refuse deletion')
  if ident['uid'] not in t.setdefault('delete_attempted_uids',[]):t['delete_attempted_uids'].append(ident['uid']);persist(mark,t)
  options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':ident['uid'],'resourceVersion':obj['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
  with tempfile.TemporaryDirectory() as directory:
   file=pathlib.Path(directory)/'delete.json';file.write_bytes(io.h.canonical(options))
   io.ops.run(['kubectl','--request-timeout=30s','delete','--raw','/api/v1/namespaces/observability/pods/'+ident['name'],'-f',str(file)])
  for _ in range(30):
   remaining=io.kube('pods','observability',ident['name'],True)
   if remaining is None:break
   io.require(remaining['metadata']['uid']==ident['uid'],'Replacement Pod appeared; never delete replacement');time.sleep(2)
  io.require(remaining is None,'Exact probe absence not observed');t.setdefault('deleted_probe_uids',[]).append(ident['uid']);persist(mark,t)

