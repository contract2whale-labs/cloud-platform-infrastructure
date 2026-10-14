#!/usr/bin/env python3
"""Bounded later GitOps hooks. No shell hook dispatch; no cloud data deletion."""
import copy, datetime as dt, importlib.util, json, os, pathlib, re, sys
BASE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
import gitops_ops as ops
import lifecycle_hooks as core
import queue_lifecycle as queue
import retained_checks
check=core.check; digest=core.digest
GROUPS={
 'queue-credentials-provision':('queue-secrets',),
 'argocd-external-secrets-provision':('external-secrets',),
 'operator-image-publish':('database-operations',),
 'platform-operations':('metrics-server','cluster-autoscaler','storage','velero','velero-resources','backup-probe'),
 'platform-observability':('grafana-secret','monitoring','monitoring-config','monitoring-resources','loki','thanos','tempo-identities','tempo','collection-policy','collection-gateway','collection-gateway-resources','collection-agent','fluent-bit'),
 'platform-alerting':('monitoring-resources',),
 'platform-delivery':('external-secrets','kyverno','argo-rollouts','reloader','platform-policies'),
 'self-managed-queue-topics-acl':('strimzi','kafka'),
 'platform-queue':('queue-network','queue-secrets','queue-admin','tempo-active-query'),
 'trace-drain-switch':('tempo-e2','tempo-e3'),
 'application-namespace':('tenant-baseline',),
 'database-bootstrap':('database-operations',),
 'application-runtime':('commerce-api','commerce-web'),
 'application-mesh':('tenant-baseline',),
 'application-dashboards':('monitoring-resources',),
 'migration-and-seed':('commerce-api',),
}
ASSET_HOOKS=frozenset({'queue-credentials-provision','argocd-external-secrets-provision','operator-image-publish'})
OBSERVATIONS={'queue-credentials-provision','argocd-external-secrets-provision','operator-image-publish','platform-alerting','application-mesh','application-dashboards','migration-and-seed'}
PLATFORM=set(core.ORDER)|set(x for group in GROUPS.values() for x in group)
DIRECT={'delivery-root','commerce-api','commerce-web','kyverno','argo-rollouts','reloader','platform-policies'}
SAFE=core.SAFE_KINDS|{'StorageClass','ResourceQuota','LimitRange','ExternalSecret','SecretStore','ClusterSecretStore','ClusterPolicy','Policy','ServiceMonitor','PodMonitor','PrometheusRule','Prometheus','Alertmanager','HorizontalPodAutoscaler','CronJob','ReplicaSet'}

def name_id(name,env):
    check(env in ('dev','prod'),'Unknown environment')
    for key in PLATFORM:
        if name==app_name(key,env):return key
    raise core.HookBlocked('Unregistered application')
def app_name(key,env):
    return key if key in {'kyverno','argo-rollouts','reloader','platform-policies'} else (key if key in DIRECT else 'platform-'+key)+'-'+env

def validate_app(app,env,repository):
    key=name_id(app['metadata']['name'],env)
    # Reuse every common validation while translating only static name/project.
    sample=copy.deepcopy(app);sample['metadata']['name']='platform-namespaces-'+env
    check(app['spec']['project']==('delivery' if key in {'commerce-api','commerce-web'} else 'platform'),'Application project differs')
    sample['spec']['project']='platform';ops.validate_app(sample,env,repository)
    paths=[s.get('path') for s in ops.sources(app['spec']) if s.get('path')]
    check(paths and all(p.startswith(('gitops/platform/','gitops/apps/','gitops/clusters/'+env+'/apps','vendor/')) for p in paths),'Source outside static GitOps/vendor roots')
    return app

def inventory(c,env):
    if c['_hook'] in ASSET_HOOKS:
        check(c['applications']==[],'Asset-only hook cannot own Applications')
        return []
    names=[a['metadata']['name'] for a in c['applications']]
    expected=[app_name(k,env) for k in GROUPS[c['_hook']]]
    check(names and len(names)==len(set(names)) and names==[n for n in expected if n in names],'Application scope/order differs')
    return names

def ownership_closure(name,objects):
    owned={i['object']['metadata']['uid'] for i in objects if i['object']['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id','').startswith(name+':')}
    while True:
        more={i['object']['metadata']['uid'] for i in objects if any(r.get('uid') in owned for r in i['object']['metadata'].get('ownerReferences',[]))}
        if more<=owned:break
        owned|=more
    return [i for i in objects if i['object']['metadata']['uid'] in owned]

def child_rows(name,objects,retained=False,volume_uids=(),queue_uids=(),velero_uids=()):
    rows=[]
    for item in ([i for i in objects if i['object']['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id','').startswith(name+':')] if retained else ownership_closure(name,objects)):
        obj=item['object'];kind=obj['kind']
        if obj['metadata']['uid'] in velero_uids:continue
        if kind=='Application' and retained:
            check('automated' not in obj.get('spec',{}).get('syncPolicy',{}) and not obj.get('operation'),'Nested leaf authority is active')
            continue
        check(kind not in ('Application','ApplicationSet','AppProject'),'Nested Argo authority needs its own reviewed retirement')
        check((kind in SAFE and kind not in core.DATA_KINDS) or (kind=='PersistentVolumeClaim' and obj['metadata']['uid'] in volume_uids) or (kind in queue.KINDS and obj['metadata']['uid'] in queue_uids),'Persistent/unknown child needs implemented data retirement, not a disposable flag')
        check(kind not in ('Namespace','CustomResourceDefinition') or retained or 'Delete=false' in obj['metadata'].get('annotations',{}).get('argocd.argoproj.io/sync-options','').split(','),'Namespace/CRD cascade requires source-reviewed Delete=false retention')
        if kind=='ExternalSecret':check(obj.get('spec',{}).get('target',{}).get('deletionPolicy','Retain')=='Retain','ExternalSecret deletion policy must retain')
        rows.append(core.resource_row(item))
    return sorted(rows,key=lambda r:(r['gvr'],r['namespace'],r['name']))

def retained_assets(c):
    check(c['_hook'] in ASSET_HOOKS,'Not a retained asset hook')
    assets=({'operator_images':retained_checks.images(c,sys.modules[__name__])} if c['_hook']=='operator-image-publish' else retained_checks.credentials(c,c['_hook'],sys.modules[__name__]))
    check(isinstance(assets,dict) and bool(assets),'Retained asset evidence must not be empty')
    return assets

def verify_asset_snapshot(c,env,snapshot,generation):
    inventory(c,env)
    check(snapshot['environment']==env and snapshot['checkpoint_generation']==generation and snapshot['registry_sha256']==digest(c) and snapshot['account_id']==c['account_id'],'Retained asset scope/checkpoint differs')
    check(snapshot.get('applications')==[] and snapshot.get('authorities')==[] and snapshot.get('registered_applications')==[] and snapshot.get('authority_children')=={},'Asset-only snapshot contains Argo authority')
    check(not snapshot.get('disposable_volumes') and not snapshot.get('queue') and not snapshot.get('managed_queue') and not snapshot.get('quiesce'),'Asset-only snapshot contains workload actions')
    check(dt.datetime.now(dt.timezone.utc)<dt.datetime.fromisoformat(snapshot['expires_at']),'Review expired')
    assets=retained_assets(c)
    check(assets==snapshot.get('retained_assets'),'Retained credential/publication identity differs')
    return assets

def plan(c,env,generation):
    names=inventory(c,env)
    if c['_hook'] in ASSET_HOOKS:
        now=dt.datetime.now(dt.timezone.utc)
        return {'schema_version':1,'environment':env,'checkpoint_generation':generation,'registry_sha256':digest(c),'account_id':c['account_id'],'created_at':now.isoformat(),'expires_at':(now+dt.timedelta(hours=2)).isoformat(),'applications':[],'authorities':[],'authority_children':{},'registered_applications':[],'retained_assets':retained_assets(c),'disposable_volumes':[],'queue':{},'managed_queue':{},'quiesce':[]}
    objects=core.api_inventory();rows=[]
    velero=core.velero_handoff(c,objects) if c['_hook']=='platform-operations' else {'skip_uids':[],'rows':[]}
    volumes=volume_plan(c,objects);volume_uids=[v['pvc_uid'] for v in volumes]
    queue_plan=queue.approved(c,objects,sys.modules[__name__]) if c['_hook'] in ('self-managed-queue-topics-acl','trace-drain-switch','platform-observability') else {}
    apps=[i['object'] for i in objects if i['object']['kind']=='Application']
    check({a['metadata']['name'] for a in apps}<=set(c['_registered_names']),'Unregistered Argo authority')
    check(not any(i['object']['kind']=='ApplicationSet' for i in objects),'ApplicationSet can recreate retired apps')
    for desired in c['applications']:
        name=desired['metadata']['name'];live=core.get_app(name)
        check(live and live['spec']==desired['spec'] and live['metadata'].get('uid'),'Live declaration differs')
        check('automated' not in live['spec'].get('syncPolicy',{}) and not live.get('operation'),'Unpaused or running Application')
        check(live.get('status',{}).get('operationState',{}).get('phase')!='Running','Operation running')
        retain=c['_hook']=='application-namespace' or c['_hook'] in OBSERVATIONS or name_id(name,env)=='delivery-root'
        rows.append({'name':name,'uid':live['metadata']['uid'],'spec':live['spec'],'desired':desired,'retained_until_cluster_deletion':retain,'resource_identities':child_rows(name,objects,retain,volume_uids,queue_plan.get('uids',[]),velero['skip_uids']),'protected_resources':[core.resource_row(i) for i in ownership_closure(name,objects) if i['object']['kind'] in ('Namespace','CustomResourceDefinition') and 'Delete=false' in i['object']['metadata'].get('annotations',{}).get('argocd.argoproj.io/sync-options','').split(',')]})
    if c['_hook']=='platform-operations':
        for row in rows:
            owned={i['object']['metadata']['uid'] for i in ownership_closure(row['name'],objects)}
            row['protected_resources'] += [x for x in velero['rows'] if x['uid'] in owned]
    retained=retained_checks.credentials(c,c['_hook'],sys.modules[__name__]) if c['_hook'] in ('queue-credentials-provision','argocd-external-secrets-provision') else retained_checks.images(c,sys.modules[__name__]) if c['_hook']=='operator-image-publish' else {}
    now=dt.datetime.now(dt.timezone.utc)
    return {'schema_version':1,'environment':env,'checkpoint_generation':generation,'registry_sha256':digest(c),'account_id':c['account_id'],'cluster_arn':c['cluster_arn'],'created_at':now.isoformat(),'expires_at':(now+dt.timedelta(hours=2)).isoformat(),'applications':rows,'authorities':core.plan_authorities(c,env),'authority_children':c['authority_children'],'registered_applications':c['_all_applications'],'retained_assets':retained,'disposable_volumes':volumes,'queue':queue_plan,'managed_queue':queue.managed_plan(c,objects,sys.modules[__name__]) if c['_hook']=='trace-drain-switch' else {},'quiesce':queue.quiesce_plan(objects,sys.modules[__name__]) if c['_hook'] in ('trace-drain-switch','platform-observability') else []}

def verify(c,env,snapshot,generation,completed=()):
    if c['_hook'] in ASSET_HOOKS:
        check(not completed,'Asset-only hook has no retired Applications')
        verify_asset_snapshot(c,env,snapshot,generation);return
    core.verify_authorities(snapshot)
    check(snapshot['environment']==env and snapshot['checkpoint_generation']==generation and snapshot['registry_sha256']==digest(c),'Scope/checkpoint differs')
    check(snapshot['cluster_arn']==c['cluster_arn'] and snapshot['account_id']==c['account_id'],'Live cluster differs')
    check(dt.datetime.now(dt.timezone.utc)<dt.datetime.fromisoformat(snapshot['expires_at']),'Review expired')
    check([r['name'] for r in snapshot['applications']]==inventory(c,env),'Application scope differs')
    objects=core.api_inventory()
    check({i['object']['metadata']['name'] for i in objects if i['object']['kind']=='Application'}<=set(c['_registered_names']),'Unregistered authority appeared')
    velero=core.velero_handoff(c,objects) if c['_hook']=='platform-operations' else {'skip_uids':[],'rows':[]}
    volumes=snapshot.get('disposable_volumes',[])
    if app_name('kafka' if c['_hook']=='self-managed-queue-topics-acl' else 'monitoring',env) not in completed:check(volume_plan(c,objects)==volumes,'PVC/PV/EBS identity changed')
    volume_uids=[v['pvc_uid'] for v in volumes]
    check(not any(i['object']['kind']=='ApplicationSet' for i in objects),'ApplicationSet authority appeared')
    for row in snapshot['applications']:
        if row['name'] in completed:
            check(core.get_app(row['name']) is None,'Retired Application reappeared');continue
        live=core.get_app(row['name'])
        check(live and live['metadata']['uid']==row['uid'] and live['spec']==row['spec'],'Application replaced/changed')
        check(not live.get('operation') and live.get('status',{}).get('operationState',{}).get('phase')!='Running','Operation appeared')
        actual=child_rows(row['name'],objects,row['retained_until_cluster_deletion'],volume_uids,snapshot.get('queue',{}).get('uids',[]),velero['skip_uids'])
        expected=row['resource_identities']
        if c['_hook'] in ('trace-drain-switch','platform-observability'):
            by_uid={r['uid']:r for r in snapshot['quiesce']}
            for child in actual:
                planned=by_uid.get(child['uid'])
                if planned and child['spec_sha256']==planned['paused_sha256']:child['spec_sha256']=planned['spec_sha256']
        if c['_hook'] in ('trace-drain-switch','platform-observability'):
            current_uids={r['uid'] for r in actual}
            expected=[r for r in expected if r['uid'] in current_uids or r['kind'] not in ('Pod','ReplicaSet')]
        check(actual==expected,'Child UID/spec/ownership changed')

def down(c,env,snapshot,generation,progress,completed=(),bootstrap_cleanup=None,bootstrap_mark=None):
    if c['_hook'] in ASSET_HOOKS:
        check(not completed,'Asset-only hook has no retired Applications')
        return {'retained_assets':verify_asset_snapshot(c,env,snapshot,generation),'retired':[],'retained_until_cluster_deletion':[],'restored':[],'volumes':{'deleted_volume_ids':[]},'external_data':'retained; no credential rotation or asset deletion'}
    done=list(completed)
    if c['_hook']=='platform-operations':core.velero_handoff(c,core.api_inventory(),complete=True)
    verify(c,env,snapshot,generation,done)
    retained=retained_checks.credentials(c,c['_hook'],sys.modules[__name__]) if c['_hook'] in ('queue-credentials-provision','argocd-external-secrets-provision') else retained_checks.images(c,sys.modules[__name__]) if c['_hook']=='operator-image-publish' else {}
    check(retained==snapshot.get('retained_assets',{}),'Retained credentials/images changed since review')
    drain_result={}
    if c['_hook'] in ('trace-drain-switch','platform-observability'):
        quiescence=queue.quiesce(snapshot['quiesce'],sys.modules[__name__])
        drain_result=queue.drain(c,snapshot['queue'],sys.modules[__name__])
        if c['_hook']=='trace-drain-switch':drain_result['managed_epoch']=queue.managed_drain(c,snapshot['managed_queue'],sys.modules[__name__])
    if c['_hook'] not in ('trace-drain-switch','platform-observability') and snapshot.get('queue') and app_name('kafka',env) not in done:drain_result=queue.drain(c,snapshot['queue'],sys.modules[__name__])
    for row in reversed(snapshot['applications']):
        if row['retained_until_cluster_deletion'] or row['name'] in done:continue
        verify(c,env,snapshot,generation,done);core.cascade(row)
        if c['_hook']=='self-managed-queue-topics-acl' and name_id(row['name'],env)=='kafka':queue.delete_retained_claims(c,snapshot.get('disposable_volumes',[]),sys.modules[__name__])
        remaining=[core.resource_row(i) for i in ownership_closure(row['name'],core.api_inventory())]
        check(sorted(remaining,key=lambda r:r['uid'])==sorted(row.get('protected_resources',[]),key=lambda r:r['uid']),'Unexpected tracked children remain after cascade')
        done.append(row['name']);progress(row['name'])
    cleanup_result={}
    if bootstrap_cleanup is not None:
        check(c['_hook']=='database-bootstrap' and bootstrap_mark is not None,'Unregistered bootstrap cleanup')
        cleanup_result=bootstrap_module().cleanup(bootstrap_io(),bootstrap_cleanup,bootstrap_mark)
    volume_result=verify_volume_absence(c,snapshot.get('disposable_volumes',[]))
    return {'bootstrap_cleanup':cleanup_result,'retained_assets':retained,'queue_drain':drain_result,'volumes':volume_result,'retired':done,'retained_until_cluster_deletion':[r['name'] for r in snapshot['applications'] if r['retained_until_cluster_deletion']],'external_data':'retained; no AWS data deletion'}

def get(kind,name,namespace):
    return json.loads(ops.run(['kubectl','--request-timeout=30s','-n',namespace,'get',kind,name,'-o','json']))

def migration_complete(c):
    contract=c['completion'];namespace=contract['namespace'];job=get('job','commerce-api-migrate',namespace)
    check(job['spec']['template']['spec']['serviceAccountName']=='delivery-migration','Migration identity differs')
    containers=job['spec']['template']['spec']['containers'];check(len(containers)==1,'Unexpected migration container')
    ctr=containers[0]
    check(ctr.get('command')==['./node_modules/.bin/medusa','db:migrate','--execute-safe-links'],'Unregistered migration command')
    check(ctr['image']==contract['application_image'],'Migration image differs from pinned registration')
    check(job.get('status',{}).get('failed',0)==0 and any(x.get('type')=='Complete' and x.get('status')=='True' for x in job.get('status',{}).get('conditions',[])),'Migration has not completed')
    return {'job_uid':job['metadata']['uid'],'spec_sha256':core.object_digest(job),'image':ctr['image']}

def functional(c):
    contract=c['completion'];namespace=contract['namespace']
    check(re.fullmatch('[a-z0-9][a-z0-9-]{0,62}',namespace),'Invalid namespace')
    # API server proxy performs live service HTTP reads in the private cluster.
    root='/api/v1/namespaces/'+namespace+'/services/http:commerce-api:9000/proxy'
    health=ops.run(['kubectl','--request-timeout=30s','get','--raw',root+'/health'])
    check(health.strip() in (b'OK',b'OK.',b'{"status":"ok"}'),'Application health failed')
    products=json.loads(ops.run(['kubectl','--request-timeout=30s','get','--raw',root+'/store/products?limit=100']))
    expected=contract.get('seed_product_ids');check(isinstance(expected,list) and expected and len(expected)==len(set(expected)),'Pinned expected fixture product IDs required')
    actual={x['id'] for x in products.get('products',[])}
    check(set(expected)<=actual,'Live DB-backed seed product assertions failed')
    return {'health_sha256':digest(health.decode()),'seed_product_ids':expected,'response_sha256':digest(products)}

def bootstrap_module():
    path=BASE/'operations/bootstrap_job_ops.py'
    if not path.is_file():path=BASE.parent/'gitops-ci-proposal/operations/bootstrap_job_ops.py'
    check(path.is_file(),'Packaged fixed bootstrap handler missing')
    spec=importlib.util.spec_from_file_location('lifecycle_bootstrap_job_ops',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def bootstrap_io():
    import types
    spec=importlib.util.spec_from_file_location('bootstrap_saved_plan',ops.shared_file('saved-plan.py'))
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    def kube(kind,namespace,name,optional=False):
        args=['kubectl','--request-timeout=30s','-n',namespace,'get',kind,name,'-o','json']
        if optional:args.append('--ignore-not-found')
        raw=ops.run(args);return json.loads(raw) if raw.strip() else None
    def identity(obj):
        check(obj is not None and obj['metadata'].get('uid'),'Missing bootstrap object identity')
        return {'uid':obj['metadata']['uid'],'name':obj['metadata']['name'],'namespace':obj['metadata'].get('namespace',''),'body_sha256':digest({k:v for k,v in obj.items() if k not in ('metadata','status')}),'metadata_sha256':digest({k:obj['metadata'].get(k) for k in ('labels','annotations','ownerReferences')})}
    return types.SimpleNamespace(ops=ops,h=helper,require=check,kube=kube,identity=identity)

def prepare_bootstrap(c,context,store,marker=None,request=None):
    import uuid
    check(c['_hook']=='database-bootstrap' and context['operation']=='up','Bootstrap only runs for reviewed database Up')
    io=bootstrap_io();module=bootstrap_module()
    if marker:
        target=marker['target']
        check(target.get('source_sha')==context['snapshot_sha'],'Original bootstrap source differs')
        module.verify_database(io,c,target)
        target=module.observe_snapshot(io,{'bootstrap_run_id':target['bootstrap_run_id'],'source_sha':target['source_sha']},{'operation':'database-bootstrap','phase':'active','target':target})
        return {'mode':'observe','target':target}
    request=request or module.lifecycle_request(io,c,context['snapshot_sha'],str(uuid.uuid4()))
    check(request.get('source_sha')==context['snapshot_sha'],'Bootstrap request source differs')
    return {'mode':'create','request':request,'target':module.snapshot(io,'database-bootstrap',request,c,store)}

def up(c,env,snapshot,generation,temp,bootstrap_done=False,progress=lambda x:None,bootstrap_action=None,bootstrap_mark=None):
    check(snapshot['checkpoint_generation']==generation and snapshot['account_id']==c['account_id'],'Restore scope differs')
    check([r['desired'] for r in snapshot['applications']]==c['applications'],'Checkpoint source differs')
    if c['_hook'] in ASSET_HOOKS:
        return {'restored':[],'retained_assets':verify_asset_snapshot(c,env,snapshot,generation),'checkpoint_generation':generation}
    if c['_hook'] in {'database-bootstrap','application-runtime','migration-and-seed'}:
        contract=c.get('completion',{});check(contract.get('disposable_lab') is True and contract.get('seed_reset_approved') is True and contract.get('cache_reset_approved') is True,'Explicit DB/cache disposable-lab reset approval required')
        check(env!='prod' or c.get('environment_class')=='disposable-lab','Real-production reset is not implemented')
        check(ops.DIGEST.fullmatch(contract.get('application_image','')),'Pinned app image required')
        for field in ('fixture_sha256','migration_sha256'):check(re.fullmatch('[0-9a-f]{64}',contract.get(field,'')),'Pinned actual fixture/migration provenance required')
    if c['_hook'] in {'database-bootstrap','application-runtime','migration-and-seed'}:
        spec=importlib.util.spec_from_file_location('application_runtime_guard',ops.shared_file('runtime-lifecycle-guard.py'))
        guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
        contract=dict(c['completion']);contract['application_image_digest']=contract['application_image'].split('@')[1]
        guard.BOUND['context']={'source_sha':os.environ['LIFECYCLE_SNAPSHOT_SHA']}
        provenance=guard.verify_fixture_source(contract)
    desired=[r['desired'] for r in snapshot['applications']]
    core.restore_authorities(c,env,snapshot,temp)
    with ops.argo_connection(c,temp) as argo:
        for app in desired:
            name=app['metadata']['name'];before=core.get_app(name)
            check(before and before['spec']==app['spec'],'Restored Application identity/spec unavailable')
            before_uid=before['metadata']['uid']
            if c['_hook'] not in OBSERVATIONS and name_id(name,env)!='delivery-root':
                import yaml
                rendered=list(yaml.safe_load_all(ops.run(argo+['app','manifests',name]+ops.revision_args(app))))
                ops.validate_images(rendered);ops.validate_ownership(rendered)
                ops.run(argo+['app','sync',name]+ops.revision_args(app))
                ops.run(argo+['app','wait',name,'--operation','--health','--sync','--timeout','900'])
            after=json.loads(ops.run(argo+['app','get',name,'-o','json']))
            check(after['metadata']['uid']==before_uid,'Application replaced during sync')
            if name_id(name,env)!='delivery-root':ops.validate_receipt(after,app)
    result={'restored':[a['metadata']['name'] for a in desired],'checkpoint_generation':generation}
    if c['_hook'] in ('queue-credentials-provision','argocd-external-secrets-provision'):result['retained_assets']=retained_checks.credentials(c,c['_hook'],sys.modules[__name__])
    if c['_hook']=='operator-image-publish':result['retained_assets']=retained_checks.images(c,sys.modules[__name__])
    if snapshot.get('disposable_volumes'):result['restored_volumes']=restored_volumes(c,snapshot['disposable_volumes'])
    if c['_hook']=='self-managed-queue-topics-acl':
        for kind,names in [('kafka',['platform-queue']),('kafkatopic',['platform-traces',env+'-tempo-traces-epoch-3']),('kafkauser',['tempo-consumer','tempo-distributor'])]:
            for name in names:
                obj=get(kind,name,'messaging')
                check(any(x.get('type')=='Ready' and x.get('status')=='True' for x in obj.get('status',{}).get('conditions',[])),'Kafka/topic/ACL not Ready')
        result['queue_ready']=True
    if c['_hook'] in {'application-runtime','migration-and-seed'}:result.update(migration=migration_complete(c),functional= functional(c))
    if c['_hook']=='application-mesh':
        ns=get('namespace',c['completion']['namespace'],c['completion']['namespace'])
        check(ns['metadata'].get('labels',{}).get('istio.io/dataplane-mode')=='ambient','Application ambient mesh enrollment missing')
        policy=get('peerauthentication',c['completion']['peer_authentication'],c['completion']['namespace'])
        check(policy['spec'].get('mtls',{}).get('mode')=='STRICT','Strict mesh mTLS policy missing')
        result['mesh']={'namespace_uid':ns['metadata']['uid'],'policy_uid':policy['metadata']['uid']}
    if c['_hook']=='application-dashboards':
        cm=get('configmap',c['completion']['dashboard_configmap'],'monitoring')
        check(cm['metadata'].get('labels',{}).get('grafana_dashboard')=='1' and cm.get('data'),'Provisioned dashboard missing')
        for value in cm['data'].values():check(isinstance(json.loads(value).get('panels'),list),'Invalid provisioned dashboard JSON')
        result['dashboard']={'uid':cm['metadata']['uid'],'sha256':core.object_digest(cm)}
    if c['_hook']=='database-bootstrap':
        check(bootstrap_action is not None and bootstrap_mark is not None,'Fresh bootstrap requires its reviewed saved action and durable mutation marker')
        # Argo only restores declarations. The fixed CI handler alone creates the
        # one-shot Job; an old source Job or successful receipt is never replayed.
        io=bootstrap_io();module=bootstrap_module()
        target=bootstrap_action['target']
        if bootstrap_action['mode']=='observe':
            module.verify_database(io,c,target)
            receipt=module.observe(io,target,bootstrap_mark)
        else:
            check(bootstrap_action['mode']=='create','Unknown bootstrap action')
            check(module.snapshot(io,'database-bootstrap',bootstrap_action['request'],c,io.h.Store(c['state_bucket'],c['account_id']))==target,'Bootstrap target changed before execution')
            receipt=module.apply(io,'database-bootstrap',target,bootstrap_action['request'],bootstrap_mark)
        result['database_bootstrap']=receipt
        result['bootstrap_job_uid']=receipt['created_job']['uid']
    return result

# PVC retirement is deliberately separate from the ordinary safe-kind list.
# Only the reviewed Grafana disposable volume can enter this narrow mechanism.
def volume_plan(c,objects):
    contracts=c.get('disposable_volumes',[])
    check(isinstance(contracts,list),'Invalid volume contract')
    if not contracts:return []
    check(c.get('environment_class')=='disposable-lab','Volume reset is limited to disposable lab environments')
    check(c['_hook'] in ('platform-observability','self-managed-queue-topics-acl'),'Only Grafana/Kafka lab volume reset implemented')
    is_queue=c['_hook']=='self-managed-queue-topics-acl'
    by={(i['object']['kind'],i['object']['metadata'].get('namespace',''),i['object']['metadata']['name']):i['object'] for i in objects}
    out=[]
    for contract in contracts:
        check(set(contract)=={'namespace','pvc','volume_id','approved_reset','source_sha','restore_mode','provisioning_sha256'},'Volume contract fields differ')
        check(contract['approved_reset'] is True and contract['source_sha']==os.environ['LIFECYCLE_SNAPSHOT_SHA'] and contract['restore_mode']==('git-declared-empty-kafka' if is_queue else 'git-provisioned-grafana'),'Explicit source-bound Grafana reset required')
        check(re.fullmatch('[0-9a-f]{64}',contract['provisioning_sha256']),'Provisioning source digest missing')
        pvc=by.get(('PersistentVolumeClaim',contract['namespace'],contract['pvc']));check(pvc,'Reviewed PVC missing')
        if is_queue:
            check(pvc['metadata'].get('labels',{}).get('strimzi.io/cluster')=='platform-queue' and pvc['metadata'].get('namespace')=='messaging','Queue PVC ownership differs')
            check(re.fullmatch(r'data-0-platform-queue-(broker|controller)-2[abc]-[0-9]+',contract['pvc']),'Unregistered queue PVC name')
        else:check(pvc['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id','').split(':')[0]==app_name('monitoring',c['_environment']),'PVC is not exactly tracked by monitoring Application')
        pv=by.get(('PersistentVolume','',pvc['spec'].get('volumeName')));check(pv,'Bound PV missing')
        check(pv['spec']['claimRef']['uid']==pvc['metadata']['uid'] and pv['spec']['claimRef']['namespace']==contract['namespace'] and pv['spec']['claimRef']['name']==contract['pvc'],'PV claim binding differs')
        check(pv['spec'].get('persistentVolumeReclaimPolicy')=='Delete','Retained PV cannot be silently changed to Delete')
        csi=pv['spec'].get('csi',{});check(csi.get('driver')=='ebs.csi.aws.com' and csi.get('volumeHandle')==contract['volume_id'] and re.fullmatch('vol-[0-9a-f]+',contract['volume_id']),'Unsupported or changed volume')
        raw=json.loads(ops.run(['aws','ec2','describe-volumes','--volume-ids',contract['volume_id'],'--region',c['region']]))
        check(len(raw.get('Volumes',[]))==1,'Exact EBS volume unavailable');v=raw['Volumes'][0];tags={t['Key']:t['Value'] for t in v.get('Tags',[])}
        check(tags.get('kubernetes.io/created-for/pvc/namespace')==contract['namespace'] and tags.get('kubernetes.io/created-for/pvc/name')==contract['pvc'] and tags.get('kubernetes.io/created-for/pv/name')==pv['metadata']['name'],'EBS ownership tags differ')
        check(v.get('Encrypted') is True,'Unencrypted volume outside reset scope')
        # Pin published restore configuration bytes, not a caller claim.
        path=('gitops/platform/kafka/overlays/'+c['_environment']+'/kustomization.yaml') if is_queue else ('gitops/platform/monitoring/values/'+c['_environment']+'.yaml')
        source=ops.run(['git','show',contract['source_sha']+':'+path])
        check(__import__('hashlib').sha256(source).hexdigest()==contract['provisioning_sha256'],'Provisioned restore source differs')
        if not is_queue:
            baseline=by.get(('ConfigMap','monitoring','lifecycle-course-baseline'))
            check(baseline and baseline['metadata'].get('labels',{}).get('grafana_dashboard')=='1','Course baseline ConfigMap must exist before reset')
            check(json.loads(baseline.get('data',{}).get('lifecycle-course-baseline.json','{}')).get('uid')=='lifecycle-course-baseline','Course baseline dashboard invalid')
            check(b'sidecar:' in source and b'dashboards:' in source and b'provisioned-lifecycle-baseline' in source,'Reviewed Grafana baseline provisioning prerequisites missing')
        out.append({'contract':contract,'pvc_uid':pvc['metadata']['uid'],'pvc_spec_sha256':core.object_digest(pvc),'pv_uid':pv['metadata']['uid'],'pv_name':pv['metadata']['name'],'pv_spec_sha256':core.object_digest(pv),'volume_identity':{k:v.get(k) for k in ('VolumeId','CreateTime','AvailabilityZone','Encrypted','KmsKeyId','Size')},'tags':tags})
    check(len({r['pvc_uid'] for r in out})==len(out),'Duplicate volume reset')
    if is_queue:
        actual={i['object']['metadata']['uid'] for i in objects if i['object']['kind']=='PersistentVolumeClaim' and i['object']['metadata'].get('namespace')=='messaging' and i['object']['metadata'].get('labels',{}).get('strimzi.io/cluster')=='platform-queue'}
        check(len(out)==6 and actual=={r['pvc_uid'] for r in out},'Exact six queue claims must be approved')
    return out

def verify_volume_absence(c,volumes):
    # A successful empty filtered describe is authenticated absence. CLI errors fail closed.
    for row in volumes:
        ident=row['contract']['volume_id']
        raw=json.loads(ops.run(['aws','ec2','describe-volumes','--filters','Name=volume-id,Values='+ident,'--region',c['region']]))
        check(not raw.get('NextToken') and isinstance(raw.get('Volumes'),list),'Incomplete volume inventory')
        if raw['Volumes']:
            import time
            for attempt in range(18):
                time.sleep(10)
                raw=json.loads(ops.run(['aws','ec2','describe-volumes','--filters','Name=volume-id,Values='+ident,'--region',c['region']]))
                check(not raw.get('NextToken') and isinstance(raw.get('Volumes'),list),'Incomplete volume inventory')
                if not raw['Volumes']:break
        check(raw['Volumes']==[],'CSI volume cleanup incomplete; retain EKS and its controllers')
    return {'deleted_volume_ids':[r['contract']['volume_id'] for r in volumes]}

def restored_volumes(c,original):
    restored=[]
    for old in original:
        contract=old['contract'];namespace=contract['namespace']
        pvc=get('pvc',contract['pvc'],namespace)
        check(pvc['metadata']['uid']!=old['pvc_uid'] and pvc.get('status',{}).get('phase')=='Bound','Fresh Grafana PVC not bound')
        pv=get('pv',pvc['spec']['volumeName'],namespace)
        check(pv['spec']['claimRef']['uid']==pvc['metadata']['uid'],'Fresh PV claim UID differs')
        csi=pv['spec'].get('csi',{});volume=csi.get('volumeHandle','')
        check(csi.get('driver')=='ebs.csi.aws.com' and re.fullmatch('vol-[0-9a-f]+',volume) and volume!=contract['volume_id'],'Fresh EBS volume identity missing')
        if c['_hook']=='self-managed-queue-topics-acl':
            restored.append({'pvc_uid':pvc['metadata']['uid'],'pv_uid':pv['metadata']['uid'],'volume_id':volume});continue
        cm=get('configmap','lifecycle-course-baseline','monitoring')
        check(cm['metadata'].get('labels',{}).get('grafana_dashboard')=='1' and json.loads(cm['data']['lifecycle-course-baseline.json'])['uid']=='lifecycle-course-baseline','Baseline dashboard not restored')
        # Grafana must actually be serving after its provisioned volume is recreated.
        response=json.loads(ops.run(['kubectl','--request-timeout=30s','get','--raw','/api/v1/namespaces/monitoring/services/http:platform-monitoring-grafana:80/proxy/api/health']))
        check(response.get('database')=='ok','Grafana database is not ready')
        restored.append({'pvc_uid':pvc['metadata']['uid'],'pv_uid':pv['metadata']['uid'],'volume_id':volume,'dashboard_uid':cm['metadata']['uid'],'grafana_database':'ok'})
    return restored
