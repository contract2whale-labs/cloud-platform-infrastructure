#!/usr/bin/env python3
"""BU07 bounded CI-only diagnostics. No account-wide cleanup or mutable images."""
import datetime as dt
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('probe_private_api',HERE/'private-api-session.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
require=p.require
# Runs inside the approved Python3 probe image. No dependency downloads, secrets,
# API credentials, host networking, privileged mode, or token body in evidence.
POD_CODE=r'''
import json,socket,sys,urllib.request,urllib.error
kind,target=sys.argv[1:]
out={'kind':kind}
try:
 if kind in ('dns','public_dns'):
  out['addresses']=sorted({x[4][0] for x in socket.getaddrinfo(target,None,socket.AF_INET)})
 elif kind=='nxdomain':
  try:socket.getaddrinfo(target,None);out['result']='unexpected-answer'
  except socket.gaierror as e:out['result']='nxdomain' if e.errno==socket.EAI_NONAME else 'dns-error'
 else:
  request=urllib.request.Request(target,method='PUT' if kind=='imdsv2' else 'GET')
  if kind=='imdsv2':request.add_header('X-aws-ec2-metadata-token-ttl-seconds','60')
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  try:
   with opener.open(request,timeout=3 if kind.startswith('imds') else 10) as response:out['status']=response.status
  except urllib.error.HTTPError as e:out['status']=e.code
  except (TimeoutError,socket.timeout):out['result']='timeout'
  except urllib.error.URLError as e:out['result']='timeout' if isinstance(e.reason,(TimeoutError,socket.timeout)) else 'transport-error'
except Exception as e:out['result']='error';out['error_type']=type(e).__name__
print(json.dumps(out,sort_keys=True))
'''

def validate_inputs(value,region,account):
    require(isinstance(value,dict) and set(value)=={'probe_image','pause_image'},'Two exact protected diagnostic image inputs required.')
    for image in value.values():require(isinstance(image,str) and re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}',image),'Approved immutable image digest required.')
    registry=account+'.dkr.ecr.'+region+'.amazonaws.com/'
    require(value['pause_image'].startswith(registry+'course-bu07-pause@sha256:'),'Pause image must be mirrored into exact own-account retained repository.')
    require(value['probe_image'].startswith(registry+'course-bu07-python@sha256:'),'Python3 probe must be mirrored into exact own-account retained repository.')
    return value

def command(argv,env,body=None):
    result=subprocess.run(['kubectl','--request-timeout=180s',*argv],env=env,input=None if body is None else json.dumps(body).encode(),capture_output=True,timeout=200)
    require(result.returncode==0,'Diagnostic kubectl operation failed; inspect private runner evidence.')
    return result.stdout

def get(env,*argv):return json.loads(command(['get',*argv,'-o','json'],env))

def pod(name,namespace,image):
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':namespace},'spec':{
      'restartPolicy':'Never','automountServiceAccountToken':False,'terminationGracePeriodSeconds':0,
      'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}},
      'containers':[{'name':name,'image':image,'imagePullPolicy':'Always','resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'100m','memory':'128Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}}}]}}

def validate_probe(kind,result,endpoint_ips):
    require(result.get('kind')==kind,'Diagnostic result identity mismatch.')
    if kind=='dns':require(bool(result.get('addresses')) and set(result['addresses']) <= set(endpoint_ips),'ECR DNS did not resolve exclusively to owned endpoint ENIs.')
    elif kind=='public_dns':require(bool(result.get('addresses')) and all(ipaddress.ip_address(x).is_global for x in result['addresses']),'Public ECR DNS must resolve globally routable addresses for NAT probe.')
    elif kind in ('tls','public_tls'):require(result.get('status') in (200,400,401,403,404,405),'ECR private TLS/HTTP reachability unconfirmed.')
    elif kind=='nxdomain':require(result.get('result')=='nxdomain','Unique .invalid query did not return NXDOMAIN.')
    elif kind=='imdsv1':require(result.get('status')==401,'IMDSv1 must return token-required 401; other failures are inconclusive.')
    elif kind=='imdsv2':require(result.get('result')=='timeout','IMDSv2 token response must time out from normal Pod; other failures are inconclusive.')
    else:raise p.GuardError('Unknown diagnostic.')

def endpoint_targets(region,vpc,account):
    rows=p.aws(region,'ec2','describe-vpc-endpoints','--filters',json.dumps([{'Name':'vpc-id','Values':[vpc]},{'Name':'service-name','Values':['com.amazonaws.'+region+'.ecr.api']}]))['VpcEndpoints']
    require(len(rows)==1,'Exactly one owned ECR API endpoint required.')
    endpoint=rows[0]
    require(endpoint['VpcId']==vpc and endpoint['OwnerId']==account and endpoint['State']=='available' and endpoint['PrivateDnsEnabled'] is True,'Wrong-account/unready/nonprivate ECR endpoint.')
    ids=endpoint['NetworkInterfaceIds'];require(ids and len(ids)==len(set(ids)),'Endpoint ENIs missing/duplicate.')
    enis=p.aws(region,'ec2','describe-network-interfaces','--network-interface-ids',*ids)['NetworkInterfaces']
    require({x['NetworkInterfaceId'] for x in enis}==set(ids),'Incomplete endpoint ENI lookup.')
    require(all(x['VpcId']==vpc and x['OwnerId']==account for x in enis),'Foreign endpoint ENI.')
    return {'endpoint_id':endpoint['VpcEndpointId'],'eni_ids':ids,'ips':[str(ipaddress.ip_address(x['PrivateIpAddress'])) for x in enis]}

def dns_match(line,scope):
    try:x=json.loads(line)
    except ValueError:return False
    stamp=x.get('query_timestamp','')
    try:epoch=dt.datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp()
    except (ValueError,TypeError):return False
    return x.get('account_id')==scope['account'] and x.get('vpc_id')==scope['vpc'] and x.get('query_name','').rstrip('.')==scope['query'] and x.get('rcode')=='NXDOMAIN' and epoch>=scope['started_at']-1

def flow_match(text,scope):
    lines=text.splitlines()
    if not lines:return False
    fields=lines[0].split()
    required={'account-id','interface-id','srcaddr','dstaddr','dstport','start','end','action','log-status'}
    if not required<=set(fields):return False
    for line in lines[1:]:
        values=line.split()
        if len(values)!=len(fields):continue
        x=dict(zip(fields,values))
        try:recent=int(x['end'])>=scope['started_at'] and int(x['start'])<=scope['finished_probes_at']+60
        except ValueError:continue
        if recent and x['account-id']==scope['account'] and x['interface-id'] in scope['endpoint']['eni_ids'] and x['dstaddr'] in scope['endpoint']['ips'] and scope['pod_ip'] in (x['srcaddr'],x.get('pkt-srcaddr')) and x['dstport']=='443' and x['action']=='ACCEPT' and x['log-status']=='OK':return True
    return False

def wait_logs(region,bucket,scope,directory,timeout=900):
    deadline=time.monotonic()+timeout;found={};seen=set();reads=0
    # Date rollover is explicit: derive prefixes for both start and current UTC day.
    while time.monotonic()<deadline:
        dates={dt.datetime.fromtimestamp(scope['started_at'],dt.timezone.utc).strftime('%Y/%m/%d'),dt.datetime.now(dt.timezone.utc).strftime('%Y/%m/%d')}
        for kind in ('dns','flow'):
            if kind in found:continue
            for day in dates:
                prefix=(f"dns/AWSLogs/{scope['account']}/vpcdnsquerylogs/{scope['vpc']}/{day}/" if kind=='dns' else f"flow/AWSLogs/{scope['account']}/vpcflowlogs/{region}/{day}/")
                result=p.aws(region,'s3api','list-objects-v2','--bucket',bucket,'--expected-bucket-owner',scope['account'],'--prefix',prefix)
                require(not result.get('IsTruncated') and not result.get('NextToken'),'Incomplete log object listing.')
                for obj in result.get('Contents',[]):
                    if obj['Key'] in seen:continue
                    modified=dt.datetime.fromisoformat(obj['LastModified'].replace('Z','+00:00')).timestamp()
                    if modified<scope['started_at'] or not obj['Key'].endswith('.gz'):continue
                    require(obj['Size']<=16*1024*1024,'Log object too large for bounded diagnostic.')
                    reads+=1;require(reads<=200,'Diagnostic log read limit exceeded; delivery unconfirmed.')
                    path=Path(directory)/('log-'+str(reads)+'.gz')
                    meta=p.aws(region,'s3api','head-object','--bucket',bucket,'--key',obj['Key'],'--expected-bucket-owner',scope['account'])
                    version=meta.get('VersionId');require(version not in (None,'','null'),'Retained network log bucket must be versioned.')
                    p.aws(region,'s3api','get-object','--bucket',bucket,'--key',obj['Key'],'--version-id',version,'--expected-bucket-owner',scope['account'],str(path))
                    with gzip.open(path,'rt') as stream:text=stream.read(64*1024*1024+1)
                    require(len(text)<=64*1024*1024,'Expanded log object exceeds bounded diagnostic.')
                    matched=any(dns_match(line,scope) for line in text.splitlines()) if kind=='dns' else flow_match(text,scope)
                    seen.add(obj['Key'])
                    if matched:
                        found[kind]={'bucket':bucket,'key':obj['Key'],'version_id':version,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()};break
        if set(found)=={'dns','flow'}:return found
        time.sleep(min(30,max(0,deadline-time.monotonic())))
    raise p.GuardError('Network probe log arrival unconfirmed within 15 minutes; keep lifecycle paused.')

def delete_owned_namespace(env,name,uid):
    current=get(env,'namespace',name)
    require(current['metadata']['uid']==uid,'Namespace UID changed; refuse cleanup.')
    # Atomic apiserver UID precondition closes the read/delete race.
    options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'propagationPolicy':'Foreground'}
    command(['delete','--raw','/api/v1/namespaces/'+name,'-f','-'],env,options)
    command(['wait','--for=delete','namespace/'+name,'--timeout=180s'],env)
    require(command(['get','namespace',name,'--ignore-not-found','-o','name'],env).strip()==b'','Namespace cleanup remains incomplete.')

def delete_owned_pod(env,namespace,name,uid):
    require(namespace=='course-node-probes' and name in ('probe-pull','probe-net'),'Unknown bounded probe cleanup target.')
    current=get(env,'pod',name,'-n',namespace)
    require(current['metadata']['uid']==uid,'Probe Pod UID changed; refuse cleanup.')
    options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'propagationPolicy':'Foreground'}
    command(['delete','--raw','/api/v1/namespaces/'+namespace+'/pods/'+name,'-f','-'],env,options)
    command(['-n',namespace,'wait','--for=delete','pod/'+name,'--timeout=180s'],env)
    require(command(['get','pod',name,'-n',namespace,'--ignore-not-found','-o','name'],env).strip()==b'','Owned probe Pod cleanup incomplete.')

def run(context,cluster,relay,vpc,bucket,images,evidence_file=None):
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','Probe mutation is CI workflow_dispatch only.')
    account=context['account'];region=context['backend']['region'];validate_inputs(images,region,account)
    require(p.aws(region,'sts','get-caller-identity')['Account']==account,'Diagnostic AWS account mismatch.')
    environment=context.get('environment','dev')
    require(environment in ('dev','prod'),'Unknown diagnostic environment.')
    require(re.fullmatch(r'vpc-[0-9a-f]+',vpc) and bucket==f'cp-{environment}-network-logs-{account}-{region}','Diagnostic VPC/log bucket must come from exact retained contracts.')
    scope={'account':account,'vpc':vpc,'cluster':cluster,'started_at':time.time(),'run_id':context['run_id'],'run_attempt':context['run_attempt'],'source_sha':context['source_sha'],'images':images}
    scope['endpoint']=endpoint_targets(region,vpc,account)
    name='course-node-probes';scope['query']='nodes-probe-'+uuid.uuid4().hex+'.invalid'
    with tempfile.TemporaryDirectory(prefix='bu07-probes-') as directory:
        with p.private_api(cluster,relay,region,Path(directory)/'kubeconfig') as (env,live):
            require(live['arn'].split(':')[4]==account and live['resourcesVpcConfig']['vpcId']==vpc,'Private cluster differs from pinned account/VPC.')
            if context.get('cluster_arn'):
                require(live['arn']==context['cluster_arn'] and dt.datetime.fromisoformat(live['createdAt'].replace('Z','+00:00'))==dt.datetime.fromisoformat(context['cluster_created_at'].replace('Z','+00:00')),'Probe cluster incarnation differs from authenticated bootstrap State.')
            ns=get(env,'namespace',name)
            require(ns['metadata'].get('labels',{}).get('course-lifecycle/probe-namespace')=='true' and ns['metadata'].get('labels',{}).get('pod-security.kubernetes.io/enforce')=='restricted','Protected precreated probe namespace label/security mismatch.')
            require(not context.get('probe_namespace_uid') or ns['metadata']['uid']==context['probe_namespace_uid'],'Probe namespace incarnation differs from protected bootstrap receipt.')
            uid=ns['metadata']['uid'];scope['namespace']={'name':name,'uid':uid};owned=[]
            for pod_name in ('probe-pull','probe-net'):
                require(command(['get','pod',pod_name,'-n',name,'--ignore-not-found','-o','name'],env).strip()==b'','A prior probe Pod remains; review its owner and evidence before retrying.')
            try:
                for pod_name,image in (('probe-pull',images['pause_image']),('probe-net',images['probe_image'])):
                    manifest=pod(pod_name,name,image)
                    manifest['metadata']['labels']={'course-lifecycle/probe-run':context['run_id']}
                    if pod_name=='probe-net':manifest['spec']['containers'][0]['command']=['python3','-c','import time; time.sleep(1200)']
                    result=json.loads(command(['create','-f','-','-o','json'],env,manifest))
                    require(result['metadata']['name']==pod_name and result['metadata']['namespace']==name,'Created probe Pod identity mismatch.')
                    owned.append((pod_name,result['metadata']['uid']))
                scope['pods']=[{'name':n,'uid':u} for n,u in owned]
                command(['-n',name,'wait','--for=condition=Ready','pod/probe-pull','pod/probe-net','--timeout=180s'],env)
                info=get(env,'pod','probe-net','-n',name);scope['pod_ip']=str(ipaddress.ip_address(info['status']['podIP']))
                node=get(env,'node',info['spec']['nodeName'])
                provider=node['spec']['providerID'];require(re.fullmatch(r'aws:///[^/]+/i-[0-9a-f]+',provider),'Unknown diagnostic node provider ID.')
                reservations=p.aws(region,'ec2','describe-instances','--instance-ids',provider.rsplit('/',1)[1])['Reservations']
                require(len(reservations)==1 and reservations[0]['OwnerId']==account and len(reservations[0]['Instances'])==1,'Diagnostic node account/identity mismatch.')
                instance=reservations[0]['Instances'][0];require(instance['VpcId']==vpc and instance['MetadataOptions']['HttpTokens']=='required' and instance['MetadataOptions']['HttpPutResponseHopLimit']==1,'Diagnostic node VPC/IMDS settings differ from course.')
                subnets=p.aws(region,'ec2','describe-subnets','--subnet-ids',instance['SubnetId'])['Subnets']
                require(len(subnets)==1 and subnets[0]['VpcId']==vpc and subnets[0]['OwnerId']==account and ipaddress.ip_address(scope['pod_ip']) in ipaddress.ip_network(subnets[0]['CidrBlock']),'Diagnostic Pod IP is outside exact owned node subnet.')
                scope['node']={'uid':node['metadata']['uid'],'name':node['metadata']['name'],'instance_id':instance['InstanceId'],'subnet_id':instance['SubnetId']}
                host='api.ecr.'+region+'.amazonaws.com'
                targets={'dns':host,'tls':'https://'+host+'/','public_dns':'public.ecr.aws','public_tls':'https://public.ecr.aws/','nxdomain':scope['query'],'imdsv1':'http://169.254.169.254/latest/meta-data/','imdsv2':'http://169.254.169.254/latest/api/token'}
                scope['checks']={}
                for kind,target in targets.items():
                    result=json.loads(command(['-n',name,'exec','probe-net','--','python3','-c',POD_CODE,kind,target],env))
                    scope['checks'][kind]=result
                    if evidence_file:Path(evidence_file).write_text(json.dumps({'schema':1,'kind':'bu07-functional-probes-progress','scope':scope},sort_keys=True))
                    validate_probe(kind,result,scope['endpoint']['ips'])
                scope['finished_probes_at']=time.time()
                scope['logs']=wait_logs(region,bucket,scope,directory)
            finally:
                try:
                    require(get(env,'namespace',name)['metadata']['uid']==uid,'Probe namespace UID changed; refuse cleanup.')
                    for pod_name,pod_uid in reversed(owned):delete_owned_pod(env,name,pod_name,pod_uid)
                    scope['cleanup']='uid-precondition-pod-deletes-confirmed'
                finally:
                    if evidence_file:Path(evidence_file).write_text(json.dumps({'schema':1,'kind':'bu07-functional-probes-progress','scope':scope},sort_keys=True))
            scope['cleanup']='uid-precondition-pod-deletes-confirmed';scope['completed_at']=time.time()
    return {'schema':1,'kind':'bu07-functional-probes','scope':scope}


def load_shared(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def registration(workspace,environment):
    """Read the enabled, reviewed GitOps access registration at its fixed path."""
    base=Path(workspace);path=base/'ci/gitops/operations.json'
    if not path.is_file():path=base/'gitops-ci-proposal/operations.json'
    cfg=json.loads(path.read_bytes())
    require(cfg.get('enabled') is True,'Register the reviewed operations-access and toolchain contract before network probes.')
    c=dict(cfg['environments'][environment]);c.update(environment=environment,operator_image=cfg['operator_image'])
    return c


def probe_binding(context,store,bootstrap_contract,*,require_bootstrap=True,require_probe_namespace=True):
    """Fresh version-pinned State with no caller-provided resource identifiers."""
    guard=load_shared('probe_owned_eks','eks-lifecycle-guard.py')
    env,eks,relay,vpc_root=guard.roots(context)
    require(bootstrap_contract.get('environment')==env and bootstrap_contract.get('account_id')==context['account'] and bootstrap_contract.get('region')==context['backend']['region'],'Probe registration account/environment/region mismatch.')
    require(store.bucket==context['backend']['bucket'] and store.owner==context['account'],'Probe State store differs from protected target.')
    reader=guard.VersionedStateReader(store.bucket,context['account'],context['backend']['region'])
    states={root:reader(guard.key(root)) for root in (eks,relay,vpc_root)}
    require(all(isinstance(item.get('state'),dict) for item in states.values()),'Network probes require existing versioned EKS/relay/VPC State.')
    erows=guard.validate_state({**context,'root':eks},states[eks]['state'])
    rrows=guard.validate_state({**context,'root':relay},states[relay]['state'])
    clusters=[r['values'] for r in erows if r['type']=='aws_eks_cluster']
    relays=[r['values'] for r in rrows if r['type']=='aws_instance']
    require(len(clusters)==len(relays)==1,'Exact probe cluster/relay State owners missing.')
    cluster=clusters[0];instance=relays[0];outputs=states[vpc_root]['state'].get('outputs',{})
    vpc=outputs.get('vpc_id',{}).get('value');bucket=outputs.get('network_logs_bucket_name',{}).get('value')
    subnet_map=outputs.get('vpc_contract',{}).get('value',{}).get('transit_subnet_ids_by_az',outputs.get('transit_subnet_ids_by_az',{}).get('value',{}))
    require(cluster['vpc_config'][0]['vpc_id']==vpc and instance.get('subnet_id') in subnet_map.values(),'Probe EKS/relay placement differs from pinned VPC State.')
    live=p.aws(context['backend']['region'],'eks','describe-cluster','--name',cluster['name'])['cluster']
    require(live.get('arn')==cluster['arn'] and dt.datetime.fromisoformat(live['createdAt'].replace('Z','+00:00'))==dt.datetime.fromisoformat(cluster['created_at'].replace('Z','+00:00')),'Probe live cluster incarnation differs from pinned State.')
    require(live.get('name')==cluster['name'] and live.get('status')=='ACTIVE' and live.get('endpoint')==cluster.get('endpoint') and live.get('certificateAuthority',{}).get('data')==cluster.get('certificate_authority',[{}])[0].get('data'),'Probe live endpoint/CA/readiness differs from pinned State.')
    require(live.get('resourcesVpcConfig',{}).get('vpcId')==vpc and live['resourcesVpcConfig'].get('endpointPrivateAccess') is True and live['resourcesVpcConfig'].get('endpointPublicAccess') is False,'Probe live cluster network is not the pinned private VPC.')
    effective=dict(bootstrap_contract);effective.update(cluster=cluster['name'],cluster_arn=cluster['arn'],cluster_created_at=live['createdAt'],relay=instance['id'],vpc_id=vpc)
    if context.get('operation')!='down':effective['lifecycle_snapshot_sha']=context['source_sha']
    fingerprints={root:item['fingerprint'] for root,item in states.items()}
    if require_bootstrap:
        access=load_shared('probe_bootstrap_receipt','operations-access.py')
        proof=access.verify_bootstrap_receipt(effective,store,generation=context.get('generation') if context.get('operation')!='down' else None,config_sha256=effective['operations_access_config_sha256'])
        fingerprints['operations_access']={k:proof[k] for k in ('key','version','sha256')}
        effective['_bootstrap_receipt']=proof['receipt']
        effective['probe_namespace_uid']=proof['receipt'].get('node_probe_namespace_uid')
        if require_probe_namespace:
            require(isinstance(effective['probe_namespace_uid'],str) and effective['probe_namespace_uid'],'Bootstrap receipt is missing the bounded node-probe namespace UID.')
    return effective,fingerprints,states,bucket


def run_probe_completion(context,store,bootstrap_contract,*,evidence_file=None):
    """Post-bootstrap functional barrier. Does not clear course/root pause itself."""
    guard=load_shared('probe_completion_guard','eks-lifecycle-guard.py')
    effective,before,states,bucket=probe_binding(context,store,bootstrap_contract)
    env,eks,relay,vpc_root=guard.roots(context)
    require(context['root']==eks and context.get('operation') in ('up','initial-probe'),'Network functional completion is Up/initial-probe only.')
    require(os.environ.get('AWS_ROLE_ARN')=='arn:aws:iam::'+context['account']+':role/gha-infra-'+env+'-apply','Network probe mutation requires exact ordinary apply role.')
    images=validate_inputs(context['probe_inputs'],context['backend']['region'],context['account'])
    guard.after_up(context,states[eks]['state'],{k:v for k,v in states.items() if k!=eks})
    bound={**context,'cluster_arn':effective['cluster_arn'],'cluster_created_at':effective['cluster_created_at'],'probe_namespace_uid':effective['probe_namespace_uid']}
    result=run(bound,effective['cluster'],effective['relay'],effective['vpc_id'],bucket,images,evidence_file=evidence_file)
    _,after,_,_=probe_binding(context,store,bootstrap_contract)
    require(before==after,'Probe State/bootstrap identity changed during diagnostics; completion is unconfirmed.')
    result.update(state_binding=before,checkpoint_generation=context.get('generation'),snapshot_sha=context['source_sha'])
    return result


# Exact API identities accepted from the authenticated protected installer receipt.
# The ordinary Up role never reads this inventory or any Kubernetes Secret.
BOOTSTRAP_RESOURCES={
    'Namespace':('v1','namespaces',False),
    'ServiceAccount':('v1','serviceaccounts',True),
    'ConfigMap':('v1','configmaps',True),
    'Secret':('v1','secrets',True),
    'Service':('v1','services',True),
    'Deployment':('apps/v1','deployments',True),
    'StatefulSet':('apps/v1','statefulsets',True),
    'Role':('rbac.authorization.k8s.io/v1','roles',True),
    'RoleBinding':('rbac.authorization.k8s.io/v1','rolebindings',True),
    'ClusterRole':('rbac.authorization.k8s.io/v1','clusterroles',False),
    'ClusterRoleBinding':('rbac.authorization.k8s.io/v1','clusterrolebindings',False),
    'CustomResourceDefinition':('apiextensions.k8s.io/v1','customresourcedefinitions',False),
    'ValidatingAdmissionPolicy':('admissionregistration.k8s.io/v1','validatingadmissionpolicies',False),
    'ValidatingAdmissionPolicyBinding':('admissionregistration.k8s.io/v1','validatingadmissionpolicybindings',False),
    'AppProject':('argoproj.io/v1alpha1','appprojects',True),
    'NetworkPolicy':('networking.k8s.io/v1','networkpolicies',True),
    'PodDisruptionBudget':('policy/v1','poddisruptionbudgets',True),
    'Job':('batch/v1','jobs',True),
    'Pod':('v1','pods',True),
}


def bootstrap_resource_rows(effective):
    """No discovery/label/name exemption: every full row is from the signed-in installer."""
    rows=effective.get('_bootstrap_receipt',{}).get('bootstrap_residual_resources')
    require(isinstance(rows,list) and rows,'Fresh bootstrap receipt lacks exact residual identities; reviewed bootstrap recovery required.')
    keys={'gvr','resource','base','namespaced','kind','namespace','name','uid','spec_sha256','metadata_policy_sha256'}
    seen=set()
    for row in rows:
        require(isinstance(row,dict) and set(row)==keys and row.get('kind') in BOOTSTRAP_RESOURCES,'Unknown bootstrap residual schema/kind.')
        gv,resource,namespaced=BOOTSTRAP_RESOURCES[row['kind']]
        base='/api/v1' if gv=='v1' else '/apis/'+gv
        require(row['resource']==resource and row['gvr']==gv+'/'+resource and row['base']==base and type(row['namespaced']) is bool and row['namespaced']==namespaced,'Bootstrap resource API identity/scope mismatch.')
        require(isinstance(row['namespace'],str) and bool(row['namespace'])==namespaced and (not namespaced or re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?',row['namespace'])),'Invalid bootstrap residual namespace.')
        require(all(isinstance(row[k],str) and row[k] for k in ('name','uid','spec_sha256','metadata_policy_sha256')) and re.fullmatch(r'[A-Za-z0-9][-A-Za-z0-9:._]*',row['name']),'Invalid exact bootstrap resource identity.')
        require(all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in ('spec_sha256','metadata_policy_sha256')),'Bootstrap resource digest missing.')
        identity=(resource,row['namespace'],row['name']);require(identity not in seen,'Duplicate bootstrap resource.');seen.add(identity)
    return rows


def private_binding(context,store,bootstrap_contract):
    bootstrap=context.get('completed_chapter')!='BU06'
    result=probe_binding(context,store,bootstrap_contract,require_bootstrap=bootstrap,require_probe_namespace=False)
    if not bootstrap:
        guard=load_shared('nodeless_private_guard','eks-lifecycle-guard.py')
        _,eks,_,_=guard.roots(context)
        require(not any(row['type']=='aws_eks_node_group' for row in guard.managed_resources(result[2][eks]['state'])),'BU06 private readiness is control-plane-only; node groups require BU07 bootstrap contract.')
    return result


def private_identity(env,context):
    """A successful public-info /readyz alone cannot prove authenticated membership."""
    role='destroy' if context['operation']=='down' else 'apply'
    group='cp:'+context['environment']+':lifecycle-'+role
    identity=json.loads(command(['auth','whoami','-o','json'],env)).get('status',{}).get('userInfo',{})
    groups=identity.get('groups',[])
    require(isinstance(groups,list) and group in groups and 'system:unauthenticated' not in groups and identity.get('username') not in (None,'','system:anonymous'),'Private readiness requires the exact authenticated lifecycle group.')
    require(command(['get','--raw=/readyz'],env).strip()==b'ok','Authenticated private API /readyz failed.')
    return group


def check_private_live(context,effective,live):
    require(live.get('arn')==effective['cluster_arn'] and live.get('createdAt')==effective['cluster_created_at'] and live.get('resourcesVpcConfig',{}).get('vpcId')==effective['vpc_id'],'Private API cluster differs from authenticated State/bootstrap incarnation.')
    require(live['resourcesVpcConfig'].get('endpointPrivateAccess') is True and live['resourcesVpcConfig'].get('endpointPublicAccess') is False,'Private-only readiness required.')


def inspect_bootstrap_residuals(context,store,bootstrap_contract):
    """BU07 Down: only the dedicated destroy role reads exact receipt rows."""
    require(context.get('operation')=='down' and context.get('completed_chapter')=='BU07','Early bootstrap residual capture is BU07 Down only.')
    expected='arn:aws:iam::'+context['account']+':role/gha-infra-'+context['environment']+'-lifecycle-destroy'
    require(os.environ.get('AWS_ROLE_ARN')==expected,'Bootstrap residual inventory requires the dedicated lifecycle-destroy role.')
    effective,before,_,_=private_binding(context,store,bootstrap_contract)
    rows=bootstrap_resource_rows(effective)
    with tempfile.TemporaryDirectory(prefix='private-bootstrap-residual-') as directory:
        with p.private_api(effective['cluster'],effective['relay'],context['backend']['region'],Path(directory)/'kubeconfig') as (env,live):
            check_private_live(context,effective,live);private_identity(env,context)
            for row in rows:
                path=row['base']+('/namespaces/'+row['namespace'] if row['namespaced'] else '')+'/'+row['resource']+'/'+row['name']
                obj=json.loads(command(['get','--raw',path],env));md=obj.get('metadata',{})
                spec_hash=hashlib.sha256(json.dumps({k:v for k,v in obj.items() if k not in ('metadata','status')},sort_keys=True,separators=(',',':')).encode()).hexdigest()
                metadata_hash=hashlib.sha256(json.dumps({k:md.get(k) for k in ('labels','annotations','finalizers','ownerReferences')},sort_keys=True,separators=(',',':')).encode()).hexdigest()
                require(obj.get('kind')==row['kind'] and obj.get('apiVersion')+'/'+row['resource']==row['gvr'] and md.get('namespace','')==row['namespace'] and md.get('name')==row['name'] and md.get('uid')==row['uid'] and spec_hash==row['spec_sha256'] and metadata_hash==row['metadata_policy_sha256'],'Bootstrap residual was replaced or changed; preserve the checkpoint.')
                if row['kind'] in ('Job','Pod'):
                    require(md.get('namespace')=='argocd' and bool(md.get('annotations',{}).get('helm.sh/hook')),'Only exact Argo install hooks may be retained.')
                    if row['kind']=='Job':require(not obj.get('status',{}).get('active') and not obj.get('status',{}).get('failed') and any(x.get('type')=='Complete' and x.get('status')=='True' for x in obj.get('status',{}).get('conditions',[])),'Chart hook Job is not successfully complete.')
                    else:require(obj.get('status',{}).get('phase')=='Succeeded','Chart hook Pod is not successfully complete.')
    _,after,_,_=private_binding(context,store,bootstrap_contract)
    require(before==after,'Bootstrap residual State/receipt changed during review.')
    contract={'schema_version':1,'cluster_arn':effective['cluster_arn'],'cluster_created_at':effective['cluster_created_at'],'source_sha':context['source_sha'],'generation':context['generation'],
              'approved_residuals':sorted([{k:row[k] for k in ('resource','namespace','name','uid','spec_sha256','metadata_policy_sha256')} for row in rows],key=lambda row:(row['resource'],row['namespace'],row['name']))}
    return contract,before


def run_private_api_completion(context,store,bootstrap_contract):
    """Bounded, read-only semantic barrier after the separate protected bootstrap."""
    require(context.get('operation') in ('up','down'),'Private readiness is a lifecycle operation only.')
    expected='arn:aws:iam::'+context['account']+':role/gha-infra-'+context['environment']+('-lifecycle-destroy' if context['operation']=='down' else '-apply')
    require(os.environ.get('AWS_ROLE_ARN')==expected,'Private readiness requires the exact lifecycle operation role.')
    effective,before,_,_=private_binding(context,store,bootstrap_contract)
    with tempfile.TemporaryDirectory(prefix='private-api-readiness-') as directory:
        with p.private_api(effective['cluster'],effective['relay'],context['backend']['region'],Path(directory)/'kubeconfig') as (env,live):
            check_private_live(context,effective,live);group=private_identity(env,context)
    _,after,_,_=private_binding(context,store,bootstrap_contract)
    require(before==after,'Private readiness State/bootstrap identity changed during check.')
    return {'schema':1,'kind':'cluster-private-api-readiness','state_binding':before,'checkpoint_generation':context['generation'],'snapshot_sha':context['source_sha'],
            'scope':{**{k:context[k] for k in ('account','source_sha','run_id','run_attempt')},'cluster_arn':effective['cluster_arn'],'cluster_created_at':effective['cluster_created_at'],'relay_instance_id':effective['relay'],'vpc_id':effective['vpc_id'],'readyz':'ok','authenticated':True,'authenticated_group':group,'private_endpoint':True}}
