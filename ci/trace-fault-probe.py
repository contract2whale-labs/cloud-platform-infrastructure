"""Fixed synthetic T14 probes embedded in the existing AWS incident owner."""
import contextlib,datetime,hashlib,importlib.util,json,os,pathlib,re,subprocess,sys,types,uuid
HERE=pathlib.Path(__file__).resolve().parent
CI=HERE if (HERE/'saved-plan.py').exists() else HERE.parents[1]/'ci'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def producer():
 directory=CI/'gitops/operations'
 if not directory.exists():directory=CI.parent/'gitops-ci-proposal/operations'
 sys.path.insert(0,str(directory));return load('aws_trace_fixed_probe',directory/'producer_acl_ops.py')
def snapshot(h,ctx,item):
 image=item.get('trace_probe_image','');h.require(re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',image),'Reviewed immutable trace curl image required')
 v=load('trace_probe_state',CI/'vpc-lifecycle-guard.py');reader=v.VersionedStateReader(ctx['bucket'],ctx['account'],ctx['region'])
 eks=reader('eks/terraform.tfstate');relay=reader('platform/private-api/terraform.tfstate')
 clusters=[x['values'] for x in v.managed_resources(eks['state']) if x['type']=='aws_eks_cluster'];relays=[x['values'] for x in v.managed_resources(relay['state']) if x['type']=='aws_instance']
 h.require(len(clusters)==len(relays)==1,'Exact private EKS/relay State required')
 cluster=clusters[0];h.require(cluster['arn'].split(':')[4]==ctx['account'],'EKS account mismatch')
 run=str(uuid.uuid5(uuid.NAMESPACE_URL,ctx['repository_id']+'/'+ctx['run_id']+'/'+ctx['run_attempt']+'/trace-deny-remove'))
 target={'bindings':{'eks':eks['fingerprint'],'relay':relay['fingerprint']},'cluster':cluster['name'],'cluster_arn':cluster['arn'],'created_at':cluster['created_at'],'relay':relays[0]['id'],'region':ctx['region'],'probe_family':'aws-trace','credential_run_id':run,'trace_image':image,'probe_pods':[],'trace_ids':{p:hashlib.sha256((run+p).encode()).hexdigest()[:32] for p in ('fault','recovered')},'observations':{}}
 directory=CI/'gitops'
 if not directory.exists():directory=CI.parent/'gitops-ci-proposal'
 cfg=json.loads((directory/'operations.json').read_text());h.require(cfg.get('enabled') is True,'Reviewed operations registration required for embedded probe')
 c=dict(cfg['environments']['dev'],environment='dev',operator_image=cfg['operator_image'],cluster_arn=cluster['arn'],cluster_created_at=cluster['created_at'])
 h.require(c['account_id']==ctx['account'] and c['state_bucket']==ctx['bucket'] and c['cluster']==cluster['name'] and c['trace_probe_image']==image,'AWS and Kubernetes protected probe registrations differ')
 ops=load('trace_probe_gitops_tools',directory/'gitops_ops.py');ops.check_tools(c)
 receipt=load('trace_probe_access',CI/'operations-access.py').verify_bootstrap_receipt(c,h.Store(ctx['bucket'],ctx['account']))
 target['access_proof']={k:receipt[k] for k in ('key','version','sha256')}
 import tempfile
 with tempfile.TemporaryDirectory() as temp:
  with session(h,target,temp) as io:
   ns=io.kube('namespaces','','observability');target['namespace_uid']=ns['metadata']['uid']
   for phase,actions in [('fault',('send','query','requery')),('recovered',('send','query'))]:
    for action in actions:h.require(io.kube('pods','observability','aws-trace-'+phase+'-'+action+'-'+run,True) is None,'Synthetic probe name already exists; no adoption')
 return target
@contextlib.contextmanager
def session(h,t,directory):
 private=load('trace_probe_private',CI/'private-api-session.py')
 with private.private_api(t['cluster'],t['relay'],t['region'],pathlib.Path(directory)/'trace-kubeconfig') as (env,cluster):
  h.require(cluster['arn']==t['cluster_arn'] and datetime.datetime.fromisoformat(cluster['createdAt'].replace('Z','+00:00'))==datetime.datetime.fromisoformat(t['created_at'].replace('Z','+00:00')),'Live EKS creation identity differs')
  def run(args,content=None):
   result=subprocess.run(args,env=env,input=content,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
   h.require(result.returncode==0,'Private synthetic probe API failed; no private command output published');return result.stdout
  def kube(kind,ns,name,optional=False):
   raw=run(['kubectl','--request-timeout=30s']+(['-n',ns] if ns else [])+['get',kind,name,'-o','json']+(['--ignore-not-found'] if optional else []));return json.loads(raw) if raw.strip() else None
  def identity(obj):
   md=obj['metadata'];return {'uid':md['uid'],'name':md['name'],'namespace':md.get('namespace',''),'body_sha256':h.digest(h.canonical({k:v for k,v in obj.items() if k not in ('metadata','status')})),'metadata_sha256':h.digest(h.canonical({k:md.get(k) for k in ('labels','annotations','ownerReferences')}))}
  if t.get('namespace_uid'):h.require(kube('namespaces','','observability')['metadata']['uid']==t['namespace_uid'],'Probe namespace incarnation changed')
  yield types.SimpleNamespace(h=h,ops=types.SimpleNamespace(run=run),require=h.require,kube=kube,identity=identity)
def during(io,t,mark):
 fixed=producer();fixed.probe(io,t,'fault','send',mark);fixed.probe(io,t,'fault','query',mark)
 # Live read and object-block read are separate evidence during the same active Deny.
 t['query_mode']='blocks';fixed.probe(io,t,'fault','requery',mark);t.pop('query_mode',None)
def after(io,t,mark):
 fixed=producer();io.require(fixed.probe(io,t,'recovered','send',mark)['accepted'],'Recovered synthetic trace rejected')
 t['query_mode']='blocks'
 io.require(fixed.probe(io,t,'recovered','query',mark)['found'],'Recovered exact trace ID not queryable')
def cleanup(io,t,mark):
 io.require(not t.get('pending_probe'),'Unknown probe creation response requires exact identity reconciliation')
 producer().cleanup_probes(io,t,mark)
