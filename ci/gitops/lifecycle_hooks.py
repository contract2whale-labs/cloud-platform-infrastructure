#!/usr/bin/env python3
"""Reviewed, UID-bound GitOps retirement and checkpoint restoration hooks.

No AWS delete calls. S3 storage belongs to retained Terraform roots, never here.
The cumulative controller owns approval, immutable S3 descriptors, and checkpoint CAS.
"""
import contextlib, datetime, hashlib, importlib.util, json, os, pathlib, tempfile, time
import gitops_ops as ops
# Source order: BU08 / BU08B / BU09. Down reverses this explicit dependency list.
GATEWAY = ('platform-crds','aws-load-balancer-controller','envoy-gateway','external-dns','gateway','gateway-auth')
ORDER = ops.ORDER
CONTROLLERS = ('aws-load-balancer-controller','envoy-gateway')
DATA_KINDS = {'PersistentVolume','PersistentVolumeClaim','VolumeSnapshot','VolumeSnapshotContent','Backup','Restore','Bucket','Object','Database','Kafka','KafkaTopic'}
SAFE_KINDS = {'Namespace','ServiceAccount','Role','RoleBinding','ClusterRole','ClusterRoleBinding','ConfigMap','Secret','Service','Deployment','DaemonSet','StatefulSet','Job','Pod','PodDisruptionBudget','NetworkPolicy','CustomResourceDefinition','ValidatingWebhookConfiguration','MutatingWebhookConfiguration','ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding','Certificate','ClusterIssuer','Issuer','PeerAuthentication','AuthorizationPolicy','RequestAuthentication','GatewayClass','Gateway','HTTPRoute','GRPCRoute','ReferenceGrant','EnvoyProxy','SecurityPolicy','BackendTrafficPolicy','ClientTrafficPolicy','TargetGroupBinding'}
class HookBlocked(ops.Blocked): pass

def data_handoff(c,objects,complete=False):
    # Only selected owner checkpoints may provisionally account for data which
    # their earlier reviewed steps will remove in the same bundle.
    candidates=(pathlib.Path(__file__).parent.parent/'lifecycle-data-handoff.py',pathlib.Path(__file__).parent.parent/'ci'/'lifecycle-data-handoff.py')
    path=next((x for x in candidates if x.is_file()),None)
    relevant=any(i['object']['kind'] in ('PersistentVolume','PersistentVolumeClaim','Kafka','KafkaTopic') for i in objects)
    if not relevant and not complete:return []
    check(path is not None,'Packaged exact data-owner handoff missing')
    spec=importlib.util.spec_from_file_location('gitops_data_handoff',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    stage='apply' if complete else os.environ.get('LIFECYCLE_HOOK_STAGE','start')
    return module.approved(c,objects,stage)

def velero_handoff(c, objects, complete=False):
    relevant=any(i['object']['kind'] in ('Backup','Restore','Schedule','BackupStorageLocation','VolumeSnapshotLocation') for i in objects)
    if not relevant:return {'skip_uids':[],'residuals':[],'rows':[]}
    candidates=(pathlib.Path(__file__).parent.parent/'velero-lifecycle.py',pathlib.Path(__file__).parent.parent/'ci'/'velero-lifecycle.py')
    path=next((x for x in candidates if x.is_file()),None)
    check(path is not None,'Packaged exact Velero retention provider missing')
    spec=importlib.util.spec_from_file_location('gitops_velero_retention',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.for_gitops(c,objects,require_complete=complete)

def check(ok, why):
    if not ok: raise HookBlocked(why)

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def name_id(name, env):
    check(name.startswith('platform-') and name.endswith('-'+env), 'Unregistered Application name')
    key=name[len('platform-'):-(len(env)+1)]
    check(key in ORDER,'Unregistered lifecycle application')
    return key

def inventory(c, env):
    """Applications are fully reviewed declarations, never a free-form hook payload."""
    names=[a['metadata']['name'] for a in c['applications']]
    check(len(names)==len(set(names)), 'Duplicate application')
    positions=[ORDER.index(name_id(n,env)) for n in names]
    check(positions==sorted(positions),'Application dependency order mismatch')
    return names

def get_app(name):
    raw=ops.run(['kubectl','-n','argocd','get','application',name,'--ignore-not-found','-o','json'])
    return json.loads(raw) if raw.strip() else None

def lbs(c, approved=None):
    result=json.loads(ops.run(['aws','elbv2','describe-load-balancers','--region',c['region']]))['LoadBalancers']
    owned=[]
    for lb in result:
        if lb['VpcId']!=c['vpc_id']:continue
        arn=lb['LoadBalancerArn']
        tags=json.loads(ops.run(['aws','elbv2','describe-tags','--resource-arns',arn,'--region',c['region']]))['TagDescriptions'][0]['Tags']
        tags={t['Key']:t['Value'] for t in tags}
        check(tags.get('elbv2.k8s.aws/cluster')==c['cluster'],'Unowned load balancer in planned VPC')
        prior=next((x for x in (approved or []) if x['arn']==arn),None)
        if prior:
            check(prior['dns']==lb['DNSName'] and prior['vpc']==lb['VpcId'],'LB identity changed')
            owned.append(prior);continue
        objects=api_inventory();by_uid={x['object']['metadata']['uid']:x['object'] for x in objects}
        candidates=[x['object'] for x in objects if x['object']['kind']=='Service' and any(i.get('hostname')==lb['DNSName'] for i in x['object'].get('status',{}).get('loadBalancer',{}).get('ingress',[]))]
        check(len(candidates)==1,'LB lacks exact unique Kubernetes Service binding')
        service=candidates[0];front=[service];visited=set();owner_app=None
        while front:
            obj=front.pop();uid=obj['metadata']['uid']
            if uid in visited:continue
            visited.add(uid)
            tracking=obj['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id','').split(':')[0]
            if tracking in c.get('_registered_names',[a['metadata']['name'] for a in c['applications']]):owner_app=tracking;break
            for ref in obj['metadata'].get('ownerReferences',[]):
                parent=by_uid.get(ref['uid']);check(parent is not None and parent['kind']==ref['kind'] and parent['metadata']['name']==ref['name'],'Broken LB Service owner UID chain')
                front.append(parent)
        check(owner_app is not None,'LB Service is not owned by registered GitOps Application')
        owned.append({'arn':arn,'dns':lb['DNSName'],'vpc':lb['VpcId'],'service_uid':service['metadata']['uid'],'service_namespace':service['metadata']['namespace'],'service_name':service['metadata']['name'],'owner_application':owner_app})
    # Classic ELB cannot silently escape the gate.
    classic=json.loads(ops.run(['aws','elb','describe-load-balancers','--region',c['region']]))['LoadBalancerDescriptions']
    check(not any(x.get('VPCId')==c['vpc_id'] for x in classic),'Classic ELB requires separately implemented cleanup')
    return sorted(owned,key=lambda x:x['arn'])

def api_inventory(namespace=None):
    """Discover and list all readable API resources; denied/partial reads fail closed."""
    if namespace is not None:check(isinstance(namespace,str) and namespace and '/' not in namespace,'Invalid inventory namespace')
    versions=[('v1','/api/v1')]
    groups=json.loads(ops.run(['kubectl','get','--raw','/apis']))['groups']
    versions += [(g['preferredVersion']['groupVersion'],'/apis/'+g['preferredVersion']['groupVersion']) for g in groups]
    objects=[]
    for gv,base in versions:
        discovery=json.loads(ops.run(['kubectl','get','--raw',base]))
        for r in discovery['resources']:
            if '/' in r['name'] or 'list' not in r.get('verbs',[]):continue
            if namespace is not None and not r['namespaced']:continue
            path=base+('/namespaces/'+namespace if namespace is not None else '')+'/'+r['name']
            listing=json.loads(ops.run(['kubectl','get','--raw',path]))
            check(not listing.get('metadata',{}).get('continue'),'Incomplete Kubernetes resource inventory')
            for obj in listing.get('items',[]):
                objects.append({'gvr':gv+'/'+r['name'],'resource':r['name'],'base':base,'namespaced':r['namespaced'],'object':obj})
    return objects

def object_digest(obj):return digest({k:v for k,v in obj.items() if k not in ('metadata','status')})
def resource_row(item):
    obj=item['object'];md=obj['metadata']
    return {'gvr':item['gvr'],'resource':item['resource'],'base':item['base'],'namespaced':item['namespaced'],'kind':obj['kind'],'namespace':md.get('namespace',''),'name':md['name'],'uid':md['uid'],'spec_sha256':object_digest(obj),'metadata_policy_sha256':digest({k:md.get(k) for k in ('labels','annotations','finalizers','ownerReferences')})}

def tracked_resources(name, objects):
    found=[]
    for item in objects:
        obj=item['object'];tracking=obj.get('metadata',{}).get('annotations',{}).get('argocd.argoproj.io/tracking-id','')
        if tracking.startswith(name+':'):
            check(obj['kind'] in SAFE_KINDS and obj['kind'] not in DATA_KINDS,'Data-bearing/unknown tracked resource')
            found.append(resource_row(item))
    return sorted(found,key=lambda r:(r['gvr'],r['namespace'],r['name']))

def verify_resource_rows(rows):
    for row in rows:
        path=row['base']+('/namespaces/'+row['namespace'] if row['namespaced'] else '')+'/'+row['resource']+'/'+row['name']
        obj=json.loads(ops.run(['kubectl','get','--raw',path]))
        actual=resource_row(dict(row,object=obj))
        check(actual==row,'Tracked child resource replaced or changed')

def residual_contract(c, objects, checkpoint):
    rows=[]
    env=c.get('environment',c.get('_environment','dev'));retained_apps={f'platform-namespaces-{env}',f'platform-platform-crds-{env}',f'platform-tenant-baseline-{env}'}|{a['metadata']['name'] for a in c.get('authority_applications',[])}
    for item in objects:
        obj=item['object'];md=obj['metadata'];kind=obj['kind'];ns=md.get('namespace','')
        tracking=md.get('annotations',{}).get('argocd.argoproj.io/tracking-id','').split(':')[0]
        owned=tracking in c.get('_registered_names',[])
        keep=kind in ('Namespace','CustomResourceDefinition') and owned
        if ns=='argocd':
            keep = keep or (kind=='Application' and md['name'] in retained_apps) or (kind=='AppProject' and md['name'] in {a['spec']['project'] for a in c.get('rbac_applications',c['applications'])})
        if keep:
            row=resource_row(item)
            rows.append({k:row[k] for k in ('resource','namespace','name','uid','spec_sha256')})
    rows.extend(velero_handoff(c,objects)['residuals'])
    installed=c.get('_installer_residual_resources',[])+c.get('_bootstrap_residual_resources',[])
    live={(i['resource'],i['object']['metadata'].get('namespace',''),i['object']['metadata']['name']):i for i in objects}
    allowed={'Namespace','Role','RoleBinding','ClusterRole','ClusterRoleBinding','ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding','ServiceAccount','ConfigMap','Secret','Service','Deployment','StatefulSet','CustomResourceDefinition','AppProject','NetworkPolicy','PodDisruptionBudget','Job','Pod'}
    for row in installed:
        check(row['kind'] in allowed,'Unregistered installer residual kind')
        item=live.get((row['resource'],row['namespace'],row['name']))
        check(item is not None and resource_row(item)==row,'Installer residual differs from authenticated live-incarnation receipt')
        if row['kind'] in ('Job','Pod'):
            obj=item['object'];check(row['namespace']=='argocd' and obj['metadata'].get('annotations',{}).get('helm.sh/hook'),'Only exact completed Argo chart hook workloads can remain')
            if row['kind']=='Job':check(not obj.get('status',{}).get('active') and not obj.get('status',{}).get('failed') and any(x.get('type')=='Complete' and x.get('status')=='True' for x in obj.get('status',{}).get('conditions',[])),'Chart hook Job is not successfully complete')
            else:check(obj.get('status',{}).get('phase')=='Succeeded','Chart hook Pod is not successfully complete')
        minimal={k:row[k] for k in ('resource','namespace','name','uid','spec_sha256','metadata_policy_sha256')}
        rows=[r for r in rows if (r['resource'],r['namespace'],r['name'])!=(minimal['resource'],minimal['namespace'],minimal['name'])]
        rows.append(minimal)
    return {'schema_version':1,'cluster_arn':c['cluster_arn'],'cluster_created_at':c['cluster_created_at'],'source_sha':os.environ['LIFECYCLE_SNAPSHOT_SHA'],'generation':checkpoint,'approved_residuals':sorted(rows,key=lambda x:(x['resource'],x['namespace'],x['name']))}

def check_resources(app):
    resources=app.get('status',{}).get('resources')
    check(isinstance(resources,list),'Application resource inventory unavailable')
    for r in resources:
        check(r['kind'] not in DATA_KINDS and r['kind'] in SAFE_KINDS,'Data-bearing or unknown kind requires separate retirement adapter')
    return resources

def plan_authorities(c,env):
    rows=[]
    for desired in c.get('authority_applications',[]):
        ops.validate_app(desired,env,c['repository'],authority=True)
        live=get_app(desired['metadata']['name'])
        check(live and live['spec']==desired['spec'] and not live.get('operation') and live.get('status',{}).get('operationState',{}).get('phase')!='Running','Authority changed/running before retirement')
        rows.append({'name':desired['metadata']['name'],'uid':live['metadata']['uid'],'spec':live['spec'],'desired':desired})
    return rows

def verify_authorities(snapshot):
    for row in snapshot.get('authorities',[]):
        live=get_app(row['name'])
        check(live and live['metadata']['uid']==row['uid'] and live['spec']==row['spec'] and not live.get('operation') and live.get('status',{}).get('operationState',{}).get('phase')!='Running','Authority changed/running during leaf retirement')

def restore_authorities(c,env,snapshot,temp):
    """Restore only pinned app-of-apps declarations; never auto-sync leaf workloads."""
    rows=snapshot.get('authorities',[])
    if not rows:return
    import yaml
    restored=dict(c,applications=snapshot['registered_applications'],authority_applications=[x['desired'] for x in rows],authority_children=snapshot['authority_children'])
    tops=ops.validate_authorities(restored,env)
    for app in restored['applications']:
        ops.validate_app(app,env,c['repository']) # rejects automated leaf sync
        live=get_app(app['metadata']['name'])
        check(live is None or live['spec']==app['spec'],'Existing leaf differs from pinned checkpoint; no competing restore owner')
    for app in tops:
        live=get_app(app['metadata']['name'])
        if live is None:ops.run(['kubectl','create','-f','-'],content=yaml.safe_dump(app).encode())
        else:check(live['spec']==app['spec'],'Existing root differs from pinned checkpoint')
    with ops.argo_connection(restored,temp) as argo:
        for app in restored['authority_applications']:
            name=app['metadata']['name'];live=get_app(name)
            check(live and live['spec']==app['spec'],'Authority spec differs before restore sync')
            rendered=list(yaml.safe_load_all(ops.run(argo+['app','manifests',name]+ops.revision_args(app))))
            ops.validate_authority_render(restored,app,rendered)
            ops.run(argo+['app','diff',name]+ops.revision_args(app),allowed=(0,1))
            ops.run(argo+['app','sync',name]+ops.revision_args(app))
            ops.run(argo+['app','wait',name,'--operation','--sync','--timeout','900'])
            ops.validate_receipt(json.loads(ops.run(argo+['app','get',name,'-o','json'])),app,require_health=False)
    for app in restored['applications']:
        live=get_app(app['metadata']['name']);check(live and live['spec']==app['spec'],'Authority did not restore exact child declaration')

def plan(c, env, checkpoint, now=None):
    now=now or datetime.datetime.now(datetime.timezone.utc)
    expected=inventory(c,env)
    all_apps=json.loads(ops.run(['kubectl','-n','argocd','get','applications','-o','json']))['items']
    check({a['metadata']['name'] for a in all_apps}<=set(c.get('_registered_names',expected)),'Unregistered/root Application can recreate retiring apps')
    objects=api_inventory()
    velero=velero_handoff(c,objects);planned_data=data_handoff(c,objects)
    check(all(x['object']['kind'] not in DATA_KINDS or x['object']['metadata']['uid'] in velero['skip_uids']+planned_data for x in objects),'Data-bearing cluster requires separate reviewed data retirement before this hook scope')
    rows=[]
    for desired in c['applications']:
        name=desired['metadata']['name']; live=get_app(name)
        check(live is not None and live['metadata'].get('uid'),'Application absent during plan')
        check(live['spec']==desired['spec'],'Live declaration differs from checkpoint')
        check('automated' not in live['spec'].get('syncPolicy',{}),'Suspend automatic sync in reviewed declaration first')
        check(not live.get('operation') and live.get('status',{}).get('operationState',{}).get('phase')!='Running','Application operation in progress')
        rows.append({'name':name,'uid':live['metadata']['uid'],'spec':live['spec'],'resources':check_resources(live),'resource_identities':tracked_resources(name,objects),'desired':desired,'retained_until_cluster_deletion':name_id(name,env) in ('namespaces','platform-crds')})
    return {'schema_version':1,'environment':env,'checkpoint_generation':checkpoint,'registry_sha256':digest(c),'account_id':c['account_id'],'cluster_arn':c['cluster_arn'],'cluster':c['cluster'],'relay':c['relay'],'vpc_id':c['vpc_id'],'created_at':now.isoformat(),'expires_at':(now+datetime.timedelta(hours=2)).isoformat(),'applications':rows,'authorities':plan_authorities(c,env),'authority_children':c.get('authority_children',{}),'registered_applications':c.get('_all_applications',c['applications']),'installer_residual_resources':c.get('_installer_residual_resources',[]),'bootstrap_residual_resources':c.get('_bootstrap_residual_resources',[]),'residual_contract':residual_contract(c,objects,checkpoint),'load_balancers':lbs(c),'planned_data_uids':planned_data,'data_decision':'retain-all-external-s3;delete-reviewed-ephemeral-kubernetes'}

def verify(c, env, snapshot, checkpoint, completed=()):
    check(snapshot['schema_version']==1 and snapshot['environment']==env,'Snapshot environment mismatch')
    check(snapshot['checkpoint_generation']==checkpoint and snapshot['registry_sha256']==digest(c),'Checkpoint/registry mismatch')
    check(datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat(snapshot['expires_at']),'Hook review expired')
    check(snapshot['account_id']==c['account_id'] and snapshot['cluster_arn']==c['cluster_arn'],'Cluster/account replaced')
    check(snapshot['data_decision']=='retain-all-external-s3;delete-reviewed-ephemeral-kubernetes','Data decision changed')
    check([r['name'] for r in snapshot['applications']]==inventory(c,env),'Application scope changed')
    verify_authorities(snapshot)
    verify_resource_rows(snapshot.get('installer_residual_resources',[]))
    verify_resource_rows(snapshot.get('bootstrap_residual_resources',[]))
    objects=api_inventory()
    velero=velero_handoff(c,objects);planned_data=data_handoff(c,objects)
    check(all(x['object']['kind'] not in DATA_KINDS or x['object']['metadata']['uid'] in velero['skip_uids']+planned_data for x in objects),'New data-bearing consumer blocks cascade')
    for row in snapshot['applications']:
        if row['name'] in completed:continue
        live=get_app(row['name'])
        check(live is not None and live['metadata']['uid']==row['uid'] and live['spec']==row['spec'],'Application replaced/changed')
        check(check_resources(live)==row['resources'],'Application resource inventory changed')
        check(tracked_resources(row['name'],objects)==row['resource_identities'],'Tracked resource set/UID changed')
        verify_resource_rows(row['resource_identities'])
    current=lbs(c,snapshot['load_balancers'])
    check({x['arn'] for x in current}<={x['arn'] for x in snapshot['load_balancers']},'New LB after review')

def cascade(row, clock=time.monotonic, sleep=time.sleep):
    """CAS finalizer + UID-precondition foreground delete; never force/remove finalizers."""
    live=get_app(row['name'])
    check(live and live['metadata']['uid']==row['uid'] and live['spec']==row['spec'],'Application replaced before delete')
    finals=live['metadata'].get('finalizers',[])
    check(all(x=='resources-finalizer.argocd.argoproj.io' for x in finals),'Unknown finalizer requires separate review')
    final='resources-finalizer.argocd.argoproj.io'
    patch=[{'op':'test','path':'/metadata/uid','value':row['uid']},{'op':'test','path':'/metadata/resourceVersion','value':live['metadata']['resourceVersion']},{'op':'test','path':'/spec','value':row['spec']},{'op':'add','path':'/metadata/finalizers','value':[final]}]
    annotations=dict(live['metadata'].get('annotations',{}));annotations['argocd.argoproj.io/deletion-approved']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    patch.append({'op':'add','path':'/metadata/annotations','value':annotations})
    ops.run(['kubectl','-n','argocd','patch','application',row['name'],'--type=json','-p',json.dumps(patch)])
    options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':row['uid']}}
    with tempfile.TemporaryDirectory() as d:
        f=pathlib.Path(d)/'delete.json';f.write_text(json.dumps(options));f.chmod(0o600)
        ops.run(['kubectl','delete','--raw','/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/'+row['name'],'-f',str(f)])
    deadline=clock()+900
    while clock()<deadline:
        current=get_app(row['name'])
        if current is None:return
        check(current['metadata']['uid']==row['uid'],'Replacement Application during deletion')
        sleep(5)
    raise HookBlocked('Cascade timeout; keep controllers/cluster and inspect private evidence')

def wait_lbs_absent(c, snapshot, clock=time.monotonic, sleep=time.sleep):
    deadline=clock()+900
    while clock()<deadline:
        current=lbs(c,snapshot['load_balancers'])
        check({x['arn'] for x in current}<={x['arn'] for x in snapshot['load_balancers']},'Unexpected new LB during cleanup')
        if not current:return
        sleep(10)
    raise HookBlocked('Controller-dependent LB cleanup timed out; do not destroy controllers/EKS/VPC')

def residual_receipt(snapshot):
    verify_resource_rows(snapshot.get('installer_residual_resources',[]))
    verify_resource_rows(snapshot.get('bootstrap_residual_resources',[]))
    planned=snapshot['residual_contract'];objects=api_inventory()
    actual={(x['resource'],x['object']['metadata'].get('namespace',''),x['object']['metadata']['name']):x['object'] for x in objects}
    survivors=[]
    for row in planned['approved_residuals']:
        obj=actual.get((row['resource'],row['namespace'],row['name']))
        if obj is None:continue
        check(obj['metadata']['uid']==row['uid'] and object_digest(obj)==row['spec_sha256'],'Retained resource changed since review')
        if 'metadata_policy_sha256' in row:check(digest({k:obj['metadata'].get(k) for k in ('labels','annotations','finalizers','ownerReferences')})==row['metadata_policy_sha256'],'Retained installer metadata changed since review')
        survivors.append(row)
    for item in objects:
        obj=item['object'];kind=obj['kind']
        check(kind not in DATA_KINDS or any(r['uid']==obj['metadata']['uid'] and r['resource']==item['resource'] for r in survivors),'Data-bearing residual blocks EKS handoff')
        if kind in ('Application','AppProject'):
            key=(item['resource'],obj['metadata'].get('namespace',''),obj['metadata']['name'])
            check(any((r['resource'],r['namespace'],r['name'])==key for r in survivors),'Unknown Argo authority after retirement')
    return dict(planned,approved_residuals=survivors)

def down(c, env, snapshot, checkpoint, progress, completed=()):
    """progress is the central controller's CAS callback, not an untrusted filename."""
    completed=list(completed)
    if snapshot.get('planned_data_uids'):data_handoff(c,api_inventory(),complete=True)
    if any(r['resource'] in {'backups','restores','schedules','backupstoragelocations','volumesnapshotlocations'} for r in snapshot.get('residual_contract',{}).get('approved_residuals',[])):
        velero_handoff(c,api_inventory(),complete=True)
    verify(c,env,snapshot,checkpoint,completed)
    for row in reversed(snapshot['applications']):
        if row['retained_until_cluster_deletion'] or row['name'] in completed:continue
        if name_id(row['name'],env) in CONTROLLERS:wait_lbs_absent(c,snapshot)
        verify(c,env,snapshot,checkpoint,completed)
        cascade(row)
        completed.append(row['name']);progress(row['name'])
    wait_lbs_absent(c,snapshot)
    result={'retired':completed,'retained_until_cluster_deletion':[r['name'] for r in snapshot['applications'] if r['retained_until_cluster_deletion']],'load_balancers_absent':True}
    if c.get('_hook')=='platform-core':result['residual_contract']=residual_receipt(snapshot)
    return result

def up(c, env, snapshot, checkpoint, temp, bootstrap_done=False, progress=lambda stage:None):
    """Restore exact checkpoint declarations against newly verified infrastructure."""
    check(snapshot['checkpoint_generation']==checkpoint and snapshot['account_id']==c['account_id'],'Up checkpoint/account mismatch')
    desired=[r['desired'] for r in snapshot['applications']]
    check([a['metadata']['name'] for a in desired]==inventory(c,env),'Up app scope differs')
    restored=dict(c,applications=desired)
    # New cluster and relay are live Terraform outputs. Do not substitute latest main
    # revisions; the immutable checkpoint remains the source of Application specs.
    for app in desired:
        for source in ops.sources(app['spec']):check(ops.SHA.fullmatch(source['targetRevision']),'Mutable checkpoint source')
    if c.get('_hook')=='platform-core' and not bootstrap_done:
        check(c.get('_bootstrap_verified') is True,'Run protected gitops-access-bootstrap.yml for this checkpoint, then resume Up')
        progress('bootstrap-done')
    if snapshot.get('authorities'):
        restore_authorities(restored,env,snapshot,temp)
    else:
        check(not c.get('authority_applications'),'Missing checkpoint authority inventory')
        import yaml
        ops.run(['kubectl','apply','--server-side','--field-manager=gitops-ci','-f','-'],content=yaml.safe_dump_all(desired).encode())
    with ops.argo_connection(restored,temp) as argo:
        for app in desired:
            name=app['metadata']['name']
            import yaml
            rendered=list(yaml.safe_load_all(ops.run(argo+['app','manifests',name]+ops.revision_args(app))))
            ops.validate_images(rendered);ops.validate_ownership(rendered)
            ops.run(argo+['app','diff',name]+ops.revision_args(app),allowed=(0,1))
            ops.run(argo+['app','sync',name]+ops.revision_args(app))
            ops.run(argo+['app','wait',name,'--operation','--health','--sync','--timeout','900'])
            ops.validate_receipt(json.loads(ops.run(argo+['app','get',name,'-o','json'])),app)
    return {'restored':[a['metadata']['name'] for a in desired],'checkpoint_generation':checkpoint}
