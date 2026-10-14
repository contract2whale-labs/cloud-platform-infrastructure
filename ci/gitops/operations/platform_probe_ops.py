"""Bounded course probes. Source assets are fixed; requests never contain code/manifests.

Source-derived templates intentionally preserve the course experiments. Collection's
client is a Deployment (the lesson does not define a diagnostic Job). Notification's
source is a PrometheusRule, despite its historical operations/jobs filename.
"""
import copy, datetime as dt, hashlib, json, pathlib, re, tempfile, time, uuid
BASE = pathlib.Path(__file__).resolve().parent
IDS = ('mesh-probes-create','mesh-probes-cleanup','collection-probe-create','collection-probe-cleanup',
       'seed-readback-create','seed-readback-cleanup','trace-probe-create','trace-probe-cleanup',
       'application-strict-cycle','application-strict-restore','grafana-secret-refresh',
       'notification-probe-create','notification-probe-cleanup')
PROD_IDS = tuple(x for x in IDS if not x.startswith(('mesh-', 'collection-')))
RESOURCES = {'Deployment':('deployments.apps','apis/apps/v1','deployments'),
             'Job':('jobs.batch','apis/batch/v1','jobs'),'Pod':('pods','api/v1','pods'),
             'PeerAuthentication':('peerauthentications.security.istio.io','apis/security.istio.io/v1','peerauthentications'),
             'PrometheusRule':('prometheusrules.monitoring.coreos.com','apis/monitoring.coreos.com/v1','prometheusrules')}
PATHS = {'mesh':'tests/e2e/mesh/checks/mesh-probes.yaml',
         'collection':'platform/environments/dev/observability/checks/collection-probe.yaml',
         'seed-dev':'operations/jobs/seed-readback-dev.yaml','seed-prod':'operations/jobs/seed-readback-prod.yaml',
         'notification':'operations/jobs/notification-probe-prod.yaml'}
LABEL='platform.course/probe-run'

def template(name):
    return json.loads((BASE/'templates/platform'/f'{name}.json').read_text())

def normalized(objects):
    """Only typed image, run identity and fixed notification expiry may differ."""
    objects=copy.deepcopy(objects)
    for obj in objects:
        md=obj['metadata']
        for key in ('labels','annotations'):
            for k in list(md.get(key,{})):
                if k in (LABEL,'contract2whale.course/run-id','platform.example/validation-run-id','platform-course-probe-id'):
                    md[key][k]='RUN'
        pod=obj.get('spec',{}).get('template',{}).get('spec',{})
        for container in pod.get('containers',[]):container['image']='IMAGE'
        for k in list(obj.get('spec',{}).get('template',{}).get('metadata',{}).get('labels',{})):
            if k=='contract2whale.course/run-id':obj['spec']['template']['metadata']['labels'][k]='RUN'
        if obj['kind']=='PrometheusRule':obj['spec']['groups'][0]['rules'][0]['expr']='EXPIRY'
    return objects

def source(io,key,r):
    import yaml
    path=PATHS[key]
    raw=io.ops.run(['git','show',r['source_sha']+':'+path])
    objects=list(yaml.safe_load_all(raw))
    io.require(normalized(objects)==normalized(template(key)), 'Reviewed source differs from fixed course probe. Update handler/template through code review first.')
    return objects, {'path':path,'sha256':hashlib.sha256(raw.encode() if isinstance(raw,str) else raw).hexdigest(),'source_sha':r['source_sha']}

def list_identity(io,kind,namespace=None):
    args=['kubectl']+(['-n',namespace] if namespace else [])+['get',kind]+([] if namespace else ['-A'])+['-o','json']
    return sorted([io.identity(x) for x in json.loads(io.ops.run(args))['items']],key=lambda x:(x['namespace'],x['name']))

def strict_baseline(io,env):
    apps=[]
    for name in ('commerce-api-'+env,'commerce-web-'+env,'platform-root-'+env,'delivery-root-'+env):
        obj=io.kube('applications.argoproj.io','argocd',name)
        auto=obj['spec'].get('syncPolicy',{}).get('automated')
        io.require(not obj.get('operation') and (auto is None or auto.get('enabled') is False),'Suspend exact app/root reconciliation by approved Git change before strict drill.')
        io.require(obj.get('status',{}).get('operationState',{}).get('phase')=='Succeeded','Strict drill requires successful baseline applications.')
        apps.append(io.identity(obj))
    return {'policies':list_identity(io,'peerauthentications.security.istio.io'),'applications':apps}

def receipt_target(io,operation,r,c,marker,store):
    family=operation.rsplit('-',1)[0]
    if marker and marker.get('owner')=='kubernetes-fixed-operations' and marker.get('operation','').rsplit('-',1)[0]==family:
        return copy.deepcopy(marker['target'])
    descriptor=r.get('creation_receipt');io.require(descriptor and store,'Versioned private creation receipt required; never adopt an object by name.')
    prefix='ci-logs/'+io.h.required('GITHUB_REPOSITORY_ID')+'/'
    io.require(descriptor['key'].startswith(prefix) and '/'+c['environment']+'/incidents/'+family+'-create/apply/receipt.json' in descriptor['key'],'Untrusted creation receipt location.')
    with tempfile.TemporaryDirectory() as d:
        file=pathlib.Path(d)/'receipt';store.get(descriptor,file);value=json.loads(file.read_bytes())
    io.require(value['kind']=='incident-completion' and value['success'] is True and value['context']['account']==c['account_id'] and value['context']['environment']==c['environment'],'Creation receipt identity/outcome mismatch.')
    return value['result']['probe_target']

def snapshot(io,operation,r,c,marker,store=None):
    io.require(operation in IDS,'Unknown probe operation.')
    env=c['environment'];io.require(env in ('dev','prod') and (env=='dev' or operation in PROD_IDS),'Probe is not registered for environment.')
    if operation.startswith('notification-'):io.require(env=='prod','Notification experiment is Prod only.')
    if operation.endswith(('-cleanup','-restore')):
        target=receipt_target(io,operation,r,c,marker,store)
        io.require(target.get('family')==operation.rsplit('-',1)[0] and target.get('created'),'Original exact probe creation target required.')
        for item in target['created']:
            live=io.kube(item['resource'],item['namespace'],item['name'],True)
            if live is not None:io.require(io.identity(live)==item['identity'],'Probe changed/replaced since creation; no cleanup adoption.')
        target['cleanup_inventory']=descendants(io,target)
        return target
    run=str(uuid.UUID(r['experiment_id']))
    if operation=='grafana-secret-refresh':
        obj=io.kube('externalsecrets.external-secrets.io','monitoring','grafana-admin')
        io.require(obj['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id'),'ExternalSecret must be GitOps tracked.')
        return {'object':io.identity(obj),'force_sync':run,'old_annotations':obj['metadata'].get('annotations',{})}
    target={'family':operation.rsplit('-',1)[0],'created':[],'source':{},'manifests':[],'environment':env}
    if operation=='trace-probe-create':
        io.require(re.fullmatch('[0-9a-f]{32}',r['trace_id']) and re.fullmatch('[0-9a-f]{16}',r['span_id']),'Fixed hexadecimal trace/span IDs required.')
        endpoint={'direct':'http://platform-tempo-e2-distributor.monitoring:4318','routed':'http://collection-gateway.observability:4318'}.get(r.get('trace_route'))
        io.require(endpoint,'Only direct e2 or routed collection gateway trace destinations are allowed.')
        started=r['trace_start_ns'];io.require(type(started) is int and started>0,'Reviewed trace nanosecond timestamp required.')
        body={'resourceSpans':[{'resource':{'attributes':[{'key':'service.name','value':{'stringValue':'platform-trace-probe'}}]},'scopeSpans':[{'scope':{'name':'trace-probe'},'spans':[{'traceId':r['trace_id'],'spanId':r['span_id'],'name':'probe','kind':1,'startTimeUnixNano':str(started),'endTimeUnixNano':str(started+5000000),'status':{}}]}]}]}
        image=c['trace_probe_image'];io.require(io.ops.DIGEST.fullmatch(image),'Trace curl image must be an immutable published digest.')
        target['manifests']=[{'apiVersion':'v1','kind':'Pod','metadata':{'name':'trace-probe-'+run,'namespace':'observability'},'spec':{'restartPolicy':'Never','activeDeadlineSeconds':120,'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':100,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'probe','image':image,'command':['curl'],'args':['--max-time','90','-sS','-w','\n%{http_code}','-X','POST',endpoint+'/v1/traces','-H','Content-Type: application/json','-d',json.dumps(body,separators=(',',':'))],'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'100m','memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}]
        target['trace_id']=r['trace_id']
    elif operation=='application-strict-cycle':
        io.require(type(r.get('hold_seconds')) is int and 30<=r['hold_seconds']<=600,'Strict experiment requires a bounded 30–600 second observation window.')
        target['manifests']=template('strict-dev')
        if env=='prod':target['manifests'][0]['metadata']['name']='prod-app-strict'
        target['baseline']=strict_baseline(io,env);target['hold_seconds']=r['hold_seconds']
    else:
        key={'mesh-probes-create':'mesh','collection-probe-create':'collection','seed-readback-create':'seed-'+env,'notification-probe-create':'notification'}[operation]
        objects,info=source(io,key,r);target['source']=info;target['manifests']=objects
        if key.startswith('seed'):
            io.require(r['data_decision']=='read-only-seed-count-and-publishable-key-private','Explicit read-only seed data/private output decision required.')
            # Secret values never enter snapshots, Actions logs or receipts.
            es=io.kube('externalsecrets.external-secrets.io','contract2whale-demo','commerce-api-migration')
            target['secret_source']=io.identity(es)
        if key=='notification':
            until=r['probe_until_epoch'];now=int(dt.datetime.now(dt.timezone.utc).timestamp())
            io.require(type(until) is int and now<until<=now+600,'Notification expiry must be reviewed and within ten minutes.')
            objects[0]['spec']['groups'][0]['rules'][0]['expr']='vector(time()) < '+str(until)
            objects[0]['metadata']['labels']['platform-course-probe-id']=run
    for obj in target['manifests']:
        md=obj['metadata'];md.setdefault('labels',{})[LABEL]=run
        for k in ('contract2whale.course/run-id','platform-course-probe-id'):
            if k in md['labels']:md['labels'][k]=run
        if 'platform.example/validation-run-id' in md.get('annotations',{}):md['annotations']['platform.example/validation-run-id']=run
        pod=obj.get('spec',{}).get('template',{}).get('spec')
        if pod:
            obj['spec']['template'].setdefault('metadata',{}).setdefault('labels',{})[LABEL]=run
            if 'contract2whale.course/run-id' in obj['spec']['template']['metadata']['labels']:obj['spec']['template']['metadata']['labels']['contract2whale.course/run-id']=run
            image=c['database_operator_image' if operation.startswith('seed-') else 'platform_probe_image']
            io.require(io.ops.DIGEST.fullmatch(image),'Probe image must have an approved immutable digest.')
            for container in pod['containers']:container['image']=image
            if obj['kind']=='Job':obj['spec'].pop('ttlSecondsAfterFinished',None) # retain UID until explicit reviewed cleanup
        resource=RESOURCES[obj['kind']][0]
        io.require(io.kube(resource,md['namespace'],md['name'],True) is None,'Probe already exists; no overwrite/adoption.')
        ns=io.kube('namespaces','',md['namespace']);target.setdefault('namespaces',{})[md['namespace']]=io.identity(ns)
    return target

def descendants(io,target):
    """Capture full UID/spec/owner closure; no labels-only or namespace deletion."""
    owners={x['identity']['uid'] for x in target['created']};objects=[]
    for ns in sorted(target.get('namespaces',{})):
        for kind in ('replicasets.apps','pods'):
            for obj in json.loads(io.ops.run(['kubectl','-n',ns,'get',kind,'-o','json']))['items']:
                objects.append((kind,obj))
    found={}
    for _ in range(3):
        for kind,obj in objects:
            refs=obj['metadata'].get('ownerReferences',[])
            if any(ref.get('controller') and ref['uid'] in owners for ref in refs):
                owners.add(obj['metadata']['uid']);found[obj['metadata']['uid']]={'kind':kind,'identity':io.identity(obj)}
    return sorted(found.values(),key=lambda x:x['identity']['uid'])

def delete_owned(io,item):
    obj=io.kube(item['resource'],item['namespace'],item['name'],True)
    if obj is None:return
    io.require(io.identity(obj)==item['identity'],'Refuse changed/replaced probe deletion.')
    options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':item['identity']['uid'],'resourceVersion':obj['metadata']['resourceVersion']}}
    with tempfile.TemporaryDirectory() as d:
        file=pathlib.Path(d)/'delete.json';file.write_bytes(io.h.canonical(options));io.ops.run(['kubectl','delete','--raw',item['api_path'],'-f',str(file)])
    for _ in range(60):
        current=io.kube(item['resource'],item['namespace'],item['name'],True)
        if current is None:return
        io.require(current['metadata']['uid']==item['identity']['uid'],'Replacement detected during cleanup.')
        time.sleep(3)
    raise io.h.SafeError('Foreground probe cleanup timed out; recovery marker retained.')

def cleanup(io,target,mark):
    if 'cleanup_inventory' in target:io.require(descendants(io,target)==target['cleanup_inventory'],'Owned Pod/ReplicaSet inventory changed after cleanup review.')
    for ns,ident in target.get('namespaces',{}).items():
        io.require(io.identity(io.kube('namespaces','',ns))==ident,'Cleanup namespace changed.')
    for item in reversed(target['created']):delete_owned(io,item)
    mark('idle',target)

def apply(io,operation,target,r,mark):
    if operation=='grafana-secret-refresh':
        obj=io.kube('externalsecrets.external-secrets.io','monitoring','grafana-admin');io.require(io.identity(obj)==target['object'],'ExternalSecret changed since review.')
        annotations=copy.deepcopy(target['old_annotations']);annotations['force-sync']=target['force_sync']
        patch=[{'op':'test','path':'/metadata/uid','value':obj['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'add','path':'/metadata/annotations','value':annotations}]
        io.ops.run(['kubectl','-n','monitoring','patch','externalsecrets.external-secrets.io','grafana-admin','--type=json','-p',json.dumps(patch)])
        return {'refresh_requested':True,'secret_values_read':False}
    mark('active',target)
    if operation.endswith(('-cleanup','-restore')):
        cleanup(io,target,mark);return {'probe_target':target,'cleaned':True}
    try:
        if operation=='application-strict-cycle':io.require(strict_baseline(io,target['environment'])==target['baseline'],'Strict baseline changed.')
        for manifest in target['manifests']:
            ns=manifest['metadata']['namespace'];io.require(io.identity(io.kube('namespaces','',ns))==target['namespaces'][ns],'Namespace ownership changed.')
            created=json.loads(io.ops.run(['kubectl','create','--field-manager=course-fixed-probe','-f','-','-o','json'],content=io.h.canonical(manifest)))
            resource,api,plural=RESOURCES[created['kind']];md=created['metadata']
            item={'resource':resource,'namespace':md['namespace'],'name':md['name'],'identity':io.identity(created),'api_path':'/'+api+'/namespaces/'+md['namespace']+'/'+plural+'/'+md['name']}
            target['created'].append(item);mark('active',target)
            if created['kind']=='Deployment':io.ops.run(['kubectl','-n',ns,'rollout','status','deployment/'+md['name'],'--timeout=180s'])
            if created['kind']=='Job':io.ops.run(['kubectl','-n',ns,'wait','--for=condition=complete','job/'+md['name'],'--timeout=150s'])
            if created['kind']=='Pod':
                io.ops.run(['kubectl','-n',ns,'wait','--for=jsonpath={.status.phase}=Succeeded','pod/'+md['name'],'--timeout=150s'])
                output=io.ops.run(['kubectl','-n',ns,'logs',md['name'],'-c','probe'])
                if isinstance(output,bytes):output=output.decode()
                body,code=output.strip().rsplit('\n',1)
                io.require(code=='200' and int(json.loads(body).get('partialSuccess',{}).get('rejectedSpans',0))==0,'Trace send HTTP/partialSuccess check failed.')
            live=io.kube(resource,ns,md['name'])
            io.require(live['metadata']['uid']==item['identity']['uid'],'Probe replaced during execution.')
            item['identity']=io.identity(live);mark('active',target)
        if operation=='application-strict-cycle':
            try:time.sleep(target['hold_seconds'])
            finally:cleanup(io,target,mark)
            io.require(strict_baseline(io,target['environment'])==target['baseline'],'Strict policy restored but unrelated baseline changed; retain recovery review.')
        else:mark('idle',target)
        return {'probe_target':target,'created':True,'raw_logs_published':False,'trace_id':target.get('trace_id')}
    except Exception:
        mark('recovery-required',target)
        raise
