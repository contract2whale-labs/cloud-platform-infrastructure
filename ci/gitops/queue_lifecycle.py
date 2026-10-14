"""Fixed Strimzi lab retirement, no arbitrary scripts/commands or cloud deletes."""
import json,re,time,pathlib,tempfile
TOPICS=('platform-traces','dev-tempo-traces-epoch-3')
POOLS=tuple(role+'-'+az for role in ('broker','controller') for az in ('2a','2b','2c'))
KINDS={'Kafka','KafkaNodePool','KafkaTopic','KafkaUser','StrimziPodSet'}

def approved(c,objects,api):
    q=c.get('queue_reset',{})
    api.check(c.get('environment_class')=='disposable-lab' and q.get('approved_reset') is True and q.get('source_sha')==api.os.environ['LIFECYCLE_SNAPSHOT_SHA'],'Exact disposable Kafka lab reset approval required')
    env=c['_environment'];topics=('platform-traces',env+'-tempo-traces-epoch-3')
    relevant=[i['object'] for i in objects if i['object']['kind'] in KINDS and i['object']['metadata'].get('namespace')=='messaging']
    allowed={'Kafka':{'platform-queue'},'KafkaNodePool':set(POOLS),'KafkaTopic':set(topics),'KafkaUser':{'tempo-consumer','tempo-distributor'}}
    for obj in relevant:
        k=obj['kind'];md=obj['metadata']
        if k=='StrimziPodSet':
            api.check(any(r.get('kind') in ('Kafka','KafkaNodePool') for r in md.get('ownerReferences',[])),'StrimziPodSet owner missing');continue
        api.check(md['name'] in allowed[k],'Unknown Kafka data object')
        api.check(md.get('annotations',{}).get('argocd.argoproj.io/tracking-id','').split(':')[0]==api.app_name('kafka',env),'Kafka object not exactly tracked')
        if k=='KafkaNodePool':
            volumes=obj['spec']['storage'].get('volumes',[])
            api.check(len(volumes)==1 and volumes[0].get('type')=='persistent-claim' and volumes[0].get('deleteClaim') is False,'Unexpected node pool storage policy')
    api.check({o['metadata']['name'] for o in relevant if o['kind']=='KafkaNodePool'}==set(POOLS),'Six source node pools required')
    api.check({o['metadata']['name'] for o in relevant if o['kind']=='KafkaTopic'}==set(topics),'All self-managed epochs must be inventoried')
    brokers=[i['object'] for i in objects if i['object']['kind']=='Pod' and i['object']['metadata'].get('namespace')=='messaging' and i['object']['metadata'].get('labels',{}).get('strimzi.io/cluster')=='platform-queue' and i['object']['metadata'].get('labels',{}).get('strimzi.io/pool-name')=='broker-2a']
    api.check(len(brokers)==1,'Exact broker Pod unavailable');broker=brokers[0]
    return {'uids':[o['metadata']['uid'] for o in relevant],'broker_name':broker['metadata']['name'],'broker_uid':broker['metadata']['uid'],'topics':list(topics),'groups':['block-builder'],'source_sha':q['source_sha']}

def offsets(text,topic,api):
    result={}
    for line in text.decode().splitlines():
        parts=line.split(':');api.check(len(parts)==3 and parts[0]==topic and parts[1].isdigit() and parts[2].isdigit(),'Kafka offset response invalid')
        p=int(parts[1]);api.check(p not in result,'Duplicate partition');result[p]=int(parts[2])
    api.check(set(result)=={0,1,2},'All three partitions required');return result

def lag(text,topic,group,api):
    columns=None;found={}
    for line in text.decode().splitlines():
        row=line.split()
        if not row:continue
        if row[0]=='GROUP':columns={k:i for i,k in enumerate(row)};continue
        if not columns or row[0]!=group:continue
        api.check(all(k in columns for k in ('TOPIC','PARTITION','CURRENT-OFFSET','LAG')),'Kafka group header invalid')
        api.check(len(row)>max(columns.values()),'Kafka group row incomplete')
        if row[columns['TOPIC']]!=topic:continue
        p,committed,delta=[row[columns[k]] for k in ('PARTITION','CURRENT-OFFSET','LAG')]
        api.check(p.isdigit() and committed.isdigit() and delta=='0' and int(p) not in found,'Kafka consumer not drained')
        found[int(p)]=int(committed)
    api.check(set(found)=={0,1,2},'Kafka group missing committed partitions');return found

def drain(c,snapshot,api):
    # Every producer epoch is gone/paused before the read-only broker check.
    objects=api.core.api_inventory()
    for item in objects:
        o=item['object'];md=o['metadata'];labels=md.get('labels',{})
        if md.get('namespace')!='monitoring' or labels.get('app.kubernetes.io/component')!='distributor':continue
        api.check(labels.get('app.kubernetes.io/instance') in {'platform-tempo','platform-tempo-e2','platform-tempo-e3'},'Unregistered trace distributor')
        if o['kind']=='Pod':api.check(o.get('status',{}).get('phase') in ('Succeeded','Failed'),'Trace producer still running')
        elif o['kind'] in ('Deployment','StatefulSet','ReplicaSet'):api.check(o.get('spec',{}).get('replicas',1)==0,'Trace producer controller still active')
    def run(args):
        pod=api.get('pod',snapshot['broker_name'],'messaging')
        api.check(pod['metadata']['uid']==snapshot['broker_uid'],'Broker Pod replaced since review')
        return api.ops.run(['kubectl','--request-timeout=30s','-n','messaging','exec',snapshot['broker_name'],'-c','kafka','--',*args])
    evidence=[]
    for topic in snapshot['topics']:
        cmd=['bin/kafka-get-offsets.sh','--bootstrap-server','localhost:9092','--topic',topic]
        before=offsets(run(cmd),topic,api);time.sleep(10);after=offsets(run(cmd),topic,api)
        api.check(before==after,'Kafka end offsets still changing')
        if all(value==0 for value in after.values()):
            evidence.append({'topic':topic,'end_offsets':after,'empty_epoch':True});continue
        for group in snapshot['groups']:
            committed=lag(run(['bin/kafka-consumer-groups.sh','--bootstrap-server','localhost:9092','--describe','--group',group]),topic,group,api)
            api.check(committed==after,'Committed offsets do not equal stable end offsets')
            evidence.append({'topic':topic,'group':group,'end_offsets':after,'committed_offsets':committed})
    return {'broker_uid':snapshot['broker_uid'],'epochs':evidence,'lossless_delivery_proven':False}

def delete_retained_claims(c,volumes,api):
    # Strimzi deleteClaim:false deliberately retains claims. Delete only exact
    # pre-reviewed lab PVC UIDs after their Kafka authority and Pods are gone.
    objects=api.core.api_inventory()
    api.check(not any(i['object']['kind'] in ('Kafka','KafkaNodePool','StrimziPodSet') and i['object']['metadata'].get('namespace')=='messaging' for i in objects),'Kafka authority still exists')
    for old in volumes:
        contract=old['contract'];pvc=api.get('pvc',contract['pvc'],contract['namespace'])
        api.check(pvc['metadata']['uid']==old['pvc_uid'] and api.core.object_digest(pvc)==old['pvc_spec_sha256'],'Retained queue PVC identity differs')
        api.check(not any(i['object']['kind']=='Pod' and i['object']['metadata'].get('namespace')==contract['namespace'] and any(v.get('persistentVolumeClaim',{}).get('claimName')==contract['pvc'] for v in i['object'].get('spec',{}).get('volumes',[])) for i in objects),'A Pod still mounts queue claim')
        options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':old['pvc_uid'],'resourceVersion':pvc['metadata']['resourceVersion']}}
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'delete.json';path.write_text(json.dumps(options))
            api.ops.run(['kubectl','delete','--raw','/api/v1/namespaces/'+contract['namespace']+'/persistentvolumeclaims/'+contract['pvc'],'-f',str(path)])

def quiesce_plan(objects,api):
    rows=[]
    for item in objects:
        obj=item['object'];md=obj['metadata'];labels=md.get('labels',{})
        if md.get('namespace')!='monitoring' or labels.get('app.kubernetes.io/component')!='distributor':continue
        if obj['kind'] not in ('Deployment','StatefulSet'):continue
        api.check(labels.get('app.kubernetes.io/instance') in {'platform-tempo','platform-tempo-e2','platform-tempo-e3'},'Unregistered producer')
        tracking=md.get('annotations',{}).get('argocd.argoproj.io/tracking-id','').split(':')[0]
        api.check(tracking in {api.app_name(k,api.os.environ['LIFECYCLE_ENVIRONMENT']) for k in ('tempo','tempo-e2','tempo-e3')},'Producer owner is not registered epoch Application')
        paused=api.copy.deepcopy(obj);paused['spec']['replicas']=0
        rows.append({'kind':obj['kind'],'namespace':md['namespace'],'name':md['name'],'uid':md['uid'],'spec_sha256':api.core.object_digest(obj),'paused_sha256':api.core.object_digest(paused)})
    api.check(rows,'No reviewed trace distributors found');return rows

def quiesce(rows,api):
    for row in rows:
        obj=api.get(row['kind'],row['name'],row['namespace'])
        api.check(obj['metadata']['uid']==row['uid'] and api.core.object_digest(obj) in (row['spec_sha256'],row['paused_sha256']),'Producer changed before pause')
        if obj['spec'].get('replicas',1)==0:continue
        patch=[{'op':'test','path':'/metadata/uid','value':row['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'test','path':'/spec','value':obj['spec']},{'op':'add','path':'/spec/replicas','value':0}]
        api.ops.run(['kubectl','-n',row['namespace'],'patch',row['kind'],row['name'],'--type=json','-p',json.dumps(patch)])
        fresh=api.get(row['kind'],row['name'],row['namespace'])
        api.check(fresh['metadata']['uid']==row['uid'] and api.core.object_digest(fresh)==row['paused_sha256'],'Producer pause not confirmed')
    for attempt in range(90):
        objects=api.core.api_inventory()
        live=[i['object'] for i in objects if i['object']['kind']=='Pod' and i['object']['metadata'].get('namespace')=='monitoring' and i['object']['metadata'].get('labels',{}).get('app.kubernetes.io/component')=='distributor' and i['object'].get('status',{}).get('phase') not in ('Succeeded','Failed')]
        if not live:return {'paused':rows,'producer_pods_absent':True}
        time.sleep(5)
    raise api.core.HookBlocked('Producer shutdown timed out; consumers/queues retained')

def managed_plan(c,objects,api):
    q=c['queue_reset'];arn=q.get('managed_cluster_arn','')
    api.check(re.fullmatch(r'arn:aws:kafka:'+re.escape(c['region'])+':'+c['account_id']+r':cluster/[A-Za-z0-9_-]+/[A-Za-z0-9-]+',arn),'Exact managed epoch cluster ARN missing')
    pods=[i['object'] for i in objects if i['object']['kind']=='Pod' and i['object']['metadata'].get('namespace')=='monitoring' and i['object']['metadata']['name']=='queue-admin']
    api.check(len(pods)==1,'Pinned managed queue admin Pod unavailable')
    script='platform/environments/'+c['_environment']+'/queue/scripts/check-drain.sh'
    source=api.ops.run(['git','show',q['source_sha']+':'+script])
    api.check(__import__('hashlib').sha256(source).hexdigest()==q.get('managed_drain_sha256'),'Managed drain source differs')
    return {'pod_uid':pods[0]['metadata']['uid'],'cluster_arn':arn,'source_sha':q['source_sha'],'script':script,'script_sha256':q['managed_drain_sha256']}

def managed_drain(c,snapshot,api):
    import io,tarfile,hashlib,subprocess,os
    pod=api.get('pod','queue-admin','monitoring');api.check(pod['metadata']['uid']==snapshot['pod_uid'],'Managed admin Pod replaced')
    source=api.ops.run(['git','show',snapshot['source_sha']+':'+snapshot['script']])
    api.check(hashlib.sha256(source).hexdigest()==snapshot['script_sha256'],'Managed drain source changed')
    root='platform/environments/'+c['_environment']+'/queue'
    archive=api.ops.run(['git','archive',snapshot['source_sha'],'--',root,'automation'])
    with tempfile.TemporaryDirectory() as d:
        directory=pathlib.Path(d)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as tar:tar.extractall(directory,filter='data')
        api.check(not any(p.is_symlink() for p in directory.rglob('*')),'Drain archive symlinks forbidden')
        env={**os.environ,'KUBE_CONTEXT':c['cluster'],'ENVIRONMENT':c['_environment'],'EXPECTED_ACCOUNT_ID':c['account_id'],'AWS_REGION':c['region'],'MANAGED_QUEUE_APPROVED_CLUSTER_ARN':snapshot['cluster_arn'],'DRAIN_APPROVED_SOURCE':'managed','DRAIN_APPROVED_POD_UID':snapshot['pod_uid'],'QUEUE_EKS_CLUSTER':c['cluster'],'MANAGED_QUEUE_REQUEST_ID':'lifecycle-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']}
        result=subprocess.run(['bash',str(directory/snapshot['script']),'--source','managed'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
        api.check(result.returncode==0 and b'DRAINED stable_end_offsets=true lag=0' in result.stdout,'Managed epoch drain incomplete; consumers retained')
        return {'admin_uid':snapshot['pod_uid'],'cluster_arn':snapshot['cluster_arn'],'drain_sha256':hashlib.sha256(result.stdout).hexdigest()}
