"""Newly authored replacement fixtures; no claim these were in the original ZIP."""
import copy, json, pathlib, re, time
BASE=pathlib.Path(__file__).resolve().parent
IDS=tuple('fixture-'+case+'-'+action for case in ('t3','t4','t5','t6') for action in ('cycle','restore','cleanup'))

def manifests(io,c,r,case):
    ns='incident-fixture-'+case;labels={'recovery.course/fixture':case,'recovery.course/run-id':io.h.required('GITHUB_RUN_ID')}
    image=c['fixture_image'];io.require(io.ops.DIGEST.fullmatch(image),'Instructor fixture image must use published immutable digest.')
    io.require(image.rsplit('@',1)[1]==c['operator_image'].rsplit('@',1)[1],'Fixture runtime must be exact published locked toolchain image or digest-preserving mirror.')
    probe=(BASE/'instructor-only/probe.py').read_text()
    def obj(api,kind,name,spec):return {'apiVersion':api,'kind':kind,'metadata':{'name':name,'namespace':ns,'labels':labels},**spec}
    values=[{'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':dict(labels,**{'pod-security.kubernetes.io/enforce':'restricted','platform.course/fixture-namespace':case})}},
      obj('v1','ResourceQuota','fixture',{'spec':{'hard':{'pods':'3','requests.cpu':'1','requests.memory':'256Mi','limits.cpu':'1','limits.memory':'256Mi'}}}),
      obj('v1','ServiceAccount','fixture',{'automountServiceAccountToken':False}),
      obj('v1','ConfigMap','fixture',{'data':{'probe.py':probe}}),
      obj('networking.k8s.io/v1','NetworkPolicy','fixture',{'spec':{'podSelector':{'matchLabels':{'app':'course-fixture'}},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[{'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'kube-system'}},'podSelector':{'matchLabels':{'k8s-app':'kube-dns'}}}],'ports':[{'protocol':'UDP','port':53},{'protocol':'TCP','port':53}]}]}}),
      obj('apps/v1','Deployment','fixture',{'spec':{'replicas':1,'revisionHistoryLimit':1,'strategy':{'type':'Recreate'},'selector':{'matchLabels':{'app':'course-fixture'}},'template':{'metadata':{'labels':dict(labels,app='course-fixture')},'spec':{'serviceAccountName':'fixture','automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':1000,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'fixture','image':image,'command':['python3','-u','/fixture/probe.py'],'args':['dns' if case=='t6' else 'normal'],'ports':[{'containerPort':8080}],'resources':{'requests':{'cpu':'100m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'64Mi'}},'readinessProbe':{'httpGet':{'path':'/fixture.json','port':8080},'periodSeconds':3,'timeoutSeconds':2},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'probe','mountPath':'/fixture','readOnly':True}]}],'volumes':[{'name':'probe','configMap':{'name':'fixture'}}]}}}})]
    return values

def namespace_for(operation):return 'incident-fixture-'+operation.split('-')[1]

def snapshot(io,operation,r,c,marker,store):
    _,case,action=operation.split('-');ns=namespace_for(operation)
    io.require(case in ('t3','t4','t5','t6'),'Unregistered fixture case.')
    if action=='cycle':
        io.require(type(r.get('hold_seconds')) is int and 30<=r['hold_seconds']<=900,'Fixed incident observation window must be 30–900 seconds.')
        namespace=io.kube('namespaces','',ns)
        io.require(namespace['metadata']['uid']==c['fixture_namespace_uids'][case] and namespace['metadata'].get('labels',{}).get('platform.course/fixture-namespace')==case,'Preprovisioned scoped fixture namespace identity required.')
        docs=manifests(io,c,r,case)[1:]
        for doc in docs:io.require(io.kube(resource_kind(doc),ns,doc['metadata']['name'],True) is None,'A fixed fixture object already exists; do not adopt it.')
        result={'case':case,'namespace':ns,'manifests':docs,'created':[dict(io.identity(namespace),kind='namespaces',preprovisioned=True)]}
        if case=='t3':
            missing='sha256:'+'0'*64
            repo=json.loads(io.ops.run(['aws','ecr','describe-repositories','--repository-names','commerce-web','--region',c['region']]))['repositories'][0]
            io.require(repo['registryId']==c['account_id'],'Missing-image drill registry account mismatch.')
            check=json.loads(io.ops.run(['aws','ecr','batch-get-image','--repository-name','commerce-web','--image-ids',json.dumps([{'imageDigest':missing}]),'--region',c['region']]))
            io.require(not check.get('images') and len(check.get('failures',[]))==1 and check['failures'][0].get('failureCode')=='ImageNotFound','Missing digest must be positively confirmed ImageNotFound, not auth/network failure.')
            result['missing_image']=repo['repositoryUri']+'@'+missing
        return result
    target=None
    if marker and marker.get('owner')=='kubernetes-fixed-operations' and marker.get('operation','').startswith('fixture-'+case+'-'):
        target=marker['target']
    elif r.get('creation_receipt'):
        descriptor=r['creation_receipt'];io.require(descriptor['key'].startswith('ci-logs/'+io.h.required('GITHUB_REPOSITORY_ID')+'/') and '/dev/incidents/fixture-'+case+'-cycle/apply/receipt.json' in descriptor['key'],'Untrusted fixture creation receipt.')
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'receipt';store.get(descriptor,path);receipt=json.loads(path.read_bytes())
        io.require(receipt['kind']=='incident-completion' and receipt['success'] is True and receipt['context']['account']==c['account_id'] and receipt['context']['environment']=='dev','Fixture receipt identity/outcome mismatch.')
        target=receipt['result']['fixture_target']
    io.require(target and target.get('namespace')==ns and target.get('created'),'Exact original fixture creation evidence required.')
    namespace=io.kube('namespaces','',ns)
    io.require(namespace['metadata']['uid']==target['created'][0]['uid'],'Fixture namespace was replaced.')
    if action=='restore':io.require(target.get('baseline') and target.get('fault_template'),'No captured baseline/fault; do not fabricate recovery.')
    return target

def resource_kind(obj):return {'Namespace':'namespaces','ResourceQuota':'resourcequotas','ServiceAccount':'serviceaccounts','ConfigMap':'configmaps','NetworkPolicy':'networkpolicies.networking.k8s.io','Deployment':'deployments.apps'}[obj['kind']]

def restore(io,target):
    ns=target['namespace'];before=target['baseline'];obj=io.kube('deployments.apps',ns,'fixture')
    io.require(obj['metadata']['uid']==before['metadata']['uid'],'Fixture workload UID changed.')
    actual=copy.deepcopy(obj['spec']);template=actual.pop('template');normal=copy.deepcopy(before['spec']);normal_template=normal.pop('template')
    io.require(actual==normal and template in (normal_template,target['fault_template']),'Unrelated fixture specification change; stop.')
    if template!=normal_template:
        patch=[{'op':'test','path':'/metadata/uid','value':before['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'test','path':'/spec/template','value':template},{'op':'replace','path':'/spec/template','value':normal_template}]
        io.ops.run(['kubectl','-n',ns,'patch','deployment','fixture','--type=json','-p',json.dumps(patch)])
    io.ops.run(['kubectl','-n',ns,'rollout','status','deployment/fixture','--timeout=300s'])
    current=io.kube('deployments.apps',ns,'fixture');io.require(current['metadata']['uid']==before['metadata']['uid'] and current['spec']['template']==normal_template and current.get('status',{}).get('readyReplicas')==1,'Fixture recovery was not verified.')

def fault_evidence(io,target):
    ns=target['namespace'];case=target['case'];uid=target['baseline']['metadata']['uid']
    replicas=json.loads(io.ops.run(['kubectl','-n',ns,'get','replicasets','-o','json']))['items']
    owners={x['metadata']['uid'] for x in replicas if any(r.get('controller') and r['uid']==uid for r in x['metadata'].get('ownerReferences',[]))}
    pods=json.loads(io.ops.run(['kubectl','-n',ns,'get','pods','-o','json']))['items']
    for pod in pods:
        if not any(r.get('controller') and r['uid'] in owners for r in pod['metadata'].get('ownerReferences',[])):continue
        statuses=pod.get('status',{}).get('containerStatuses',[])
        for status in statuses:
            waiting=status.get('state',{}).get('waiting',{});term=status.get('lastState',{}).get('terminated',{}) or status.get('state',{}).get('terminated',{})
            if case=='t3' and waiting.get('reason') in ('ErrImagePull','ImagePullBackOff'):return {'pod_uid':pod['metadata']['uid'],'reason':waiting['reason']}
            if case=='t4' and term.get('exitCode')==42:return {'pod_uid':pod['metadata']['uid'],'exit_code':42,'reason':term.get('reason')}
            if case=='t5' and term.get('reason')=='OOMKilled':return {'pod_uid':pod['metadata']['uid'],'reason':'OOMKilled','exit_code':term.get('exitCode')}
            if case=='t6' and status.get('state',{}).get('running') and not status.get('ready'):
                code="import socket;\ntry: socket.getaddrinfo('kubernetes.default.svc',443); print('DNS_SUCCESS')\nexcept socket.gaierror: print('DNS_FAILURE')"
                out=io.ops.run(['kubectl','-n',ns,'exec',pod['metadata']['name'],'-c','fixture','--','python3','-c',code])
                if out.strip()==b'DNS_FAILURE':return {'pod_uid':pod['metadata']['uid'],'reason':'pod-local DNS resolution failure'}
    return None

def cleanup(io,target):
    ns=target['namespace'];namespace=io.kube('namespaces','',ns);io.require(namespace['metadata']['uid']==target['created'][0]['uid'],'Fixture namespace UID mismatch.')
    known={(x['kind'],x['name']):x for x in target['created'][1:]}
    for manifest in target['manifests']:
        kind=resource_kind(manifest);name=manifest['metadata']['name'];live=io.kube(kind,ns,name,True)
        io.require(live is None or ((kind,name) in known and live['metadata']['uid']==known[(kind,name)]['uid']),'Unacknowledged/replaced fixture object; protected reconciliation required.')
    paths={'resourcequotas':('/api/v1','resourcequotas'),'serviceaccounts':('/api/v1','serviceaccounts'),'configmaps':('/api/v1','configmaps'),'networkpolicies.networking.k8s.io':('/apis/networking.k8s.io/v1','networkpolicies'),'deployments.apps':('/apis/apps/v1','deployments')}
    import tempfile
    for row in reversed(target['created'][1:]):
        obj=io.kube(row['kind'],ns,row['name'],True)
        if obj is None:continue
        io.require(obj['metadata']['uid']==row['uid'],'Replacement fixture object; no cleanup adoption.')
        if row['kind']=='deployments.apps' and target.get('baseline'):
            before=copy.deepcopy(target['baseline']['spec']);actual=copy.deepcopy(obj['spec']);normal=before.pop('template');template=actual.pop('template')
            io.require(before==actual and template in (normal,target.get('fault_template')),'Foreign workload change before fixture cleanup.')
        else:io.require(io.identity(obj)=={k:v for k,v in row.items() if k not in ('kind','preprovisioned')},'Fixture object changed since creation.')
        base,plural=paths[row['kind']];options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':row['uid'],'resourceVersion':obj['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'delete.json';path.write_bytes(io.h.canonical(options));io.ops.run(['kubectl','delete','--raw',base+'/namespaces/'+ns+'/'+plural+'/'+row['name'],'-f',str(path)])
        for _ in range(60):
            current=io.kube(row['kind'],ns,row['name'],True)
            if current is None:break
            io.require(current['metadata']['uid']==row['uid'],'Replacement during fixture cleanup.');time.sleep(3)
        else:raise io.h.SafeError('Fixture cleanup timeout; no finalizer bypass.')
    io.require(io.kube('namespaces','',ns)['metadata']['uid']==target['created'][0]['uid'],'Preprovisioned namespace unexpectedly changed.')


def apply(io,operation,target,r,mark):
    action=operation.split('-')[2]
    if action=='cleanup':mark('active',target);cleanup(io,target);mark('idle',target);return {'retained_namespace_uid':target['created'][0]['uid'],'cleaned_object_uids':[x['uid'] for x in target['created'][1:]]}
    if action=='restore':mark('active',target);restore(io,target);mark('idle',target);return {'restored':True,'fixture_target':target}
    mark('active',target)
    for manifest in target['manifests']:
        created=json.loads(io.ops.run(['kubectl','create','-f','-','-o','json'],content=io.h.canonical(manifest)))
        target['created'].append(dict(io.identity(created),kind=resource_kind(created)));mark('active',target)
    ns=target['namespace'];io.ops.run(['kubectl','-n',ns,'rollout','status','deployment/fixture','--timeout=300s'])
    target['baseline']=io.kube('deployments.apps',ns,'fixture');fault=copy.deepcopy(target['baseline']['spec']['template']);container=fault['spec']['containers'][0]
    if target['case']=='t3':container['image']=target['missing_image']
    elif target['case']=='t4':container['args']=['crash']
    elif target['case']=='t5':container['args']=['oom']
    else:fault['spec'].update(dnsPolicy='None',dnsConfig={'nameservers':['192.0.2.53'],'options':[{'name':'timeout','value':'1'},{'name':'attempts','value':'1'}]})
    target['fault_template']=fault;mark('active',target)
    observed=None
    try:
        obj=io.kube('deployments.apps',ns,'fixture')
        patch=[{'op':'test','path':'/metadata/uid','value':target['baseline']['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'test','path':'/spec','value':target['baseline']['spec']},{'op':'replace','path':'/spec/template','value':fault}]
        io.ops.run(['kubectl','-n',ns,'patch','deployment','fixture','--type=json','-p',json.dumps(patch)])
        end=time.monotonic()+r['hold_seconds']
        while time.monotonic()<end:
            observed=observed or fault_evidence(io,target);time.sleep(5)
        io.require(observed is not None,'Expected bounded fixture symptom was not observed; do not record an invented result.')
    finally:
        try:restore(io,target);mark('idle',target)
        except Exception:mark('recovery-required',target);raise
    return {'observed':observed,'restored':True,'fixture_target':target,'newly_authored_fixture':True}
