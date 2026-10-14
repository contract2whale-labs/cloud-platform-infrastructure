#!/usr/bin/env python3
"""Exact synthetic Velero retirement and retained metadata, never backup deletion.

The actual course uses the AWS snapshot plugin. CSI objects are not silently
adopted. Only current original/restored Pod+PVC pairs from the authenticated
successful lab restore may be deleted, with UID/resourceVersion preconditions.
"""
import contextlib
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

s=load('velero_semantics',HERE/'lifecycle-obligations.py');h=s.h;c=s.c
STEP='hook:velero-backup-restore'
META_KINDS={'Backup','Restore','Schedule','BackupStorageLocation','VolumeSnapshotLocation'}
# Only this exact protected set is exported to the central EKS matcher.
META_RESOURCES={'backups','restores','schedules','backupstoragelocations','volumesnapshotlocations'}


def gitops_dir():
    for path in (HERE/'gitops',HERE.parent/'gitops-ci-proposal'):
        if (path/'gitops-lifecycle.py').is_file():return path
    raise h.SafeError('Packaged GitOps/Velero provider missing.')


def provider():
    base=gitops_dir();sys.path.insert(0,str(base));sys.path.insert(0,str(base/'operations'))
    adapter=load('velero_gitops_adapter',base/'gitops-lifecycle.py')
    incident=load('velero_incident_identity',base/'operations/incident_ops.py')
    return adapter,incident


def index_objects(objects):
    return {(i['object']['kind'],i['object']['metadata'].get('namespace',''),i['object']['metadata']['name']):i for i in objects}


def retained_metadata(obj):
    result=copy.deepcopy(obj);annotations=result['metadata'].setdefault('annotations',{})
    options=[x for x in annotations.get('argocd.argoproj.io/sync-options','').split(',') if x and not x.startswith('Delete=')]
    options.append('Delete=false');annotations['argocd.argoproj.io/sync-options']=','.join(options)
    return result


def source_retention(config,ops):
    """Policy is installed before either initial use or restoration, not after GC."""
    path='modules/runtime-operations/pod-identity.tf'
    raw=ops.run(['git','show',h.required('LIFECYCLE_SNAPSHOT_SHA')+':'+path])
    text=raw.decode() if isinstance(raw,bytes) else raw
    for phrase in ('s3:DeleteObjectVersion','backups/backups/platform-storage-probe/*','ec2:ResourceTag/velero.io/backup','platform-storage-probe'):
        h.require(phrase in text,'Source-bound exact course backup delete protection is missing.')
    # Verify actual role policy, not only a source comment.
    role=config['cluster']+'-velero'
    names=h.aws('iam','list-role-policies','--role-name',role)['PolicyNames']
    statements=[]
    for name in names:
        document=h.aws('iam','get-role-policy','--role-name',role,'--policy-name',name)['PolicyDocument']
        if isinstance(document,str):
            from urllib.parse import unquote
            document=json.loads(unquote(document))
        statements+=document.get('Statement',[])
    def seq(x):return [x] if isinstance(x,str) else x
    prefix='/backups/backups/platform-storage-probe/*'
    object_rows=[x for x in statements if x.get('Effect')=='Deny' and not x.get('Condition') and {'s3:DeleteObject','s3:DeleteObjectVersion'}<=set(seq(x.get('Action',[]))) and any(isinstance(y,str) and y.startswith('arn:aws:s3:::') and y.endswith(prefix) for y in seq(x.get('Resource',[])))]
    snapshot_rows=[x for x in statements if x.get('Effect')=='Deny' and 'ec2:DeleteSnapshot' in seq(x.get('Action',[])) and x.get('Condition')=={'StringEquals':{'ec2:ResourceTag/velero.io/backup':'platform-storage-probe'}} and f"arn:aws:ec2:{config['region']}:{config['account_id']}:snapshot/*" in seq(x.get('Resource',[]))]
    h.require(len(object_rows)==len(snapshot_rows)==1,'Live Velero role lacks exact retained-backup/snapshot protection.')
    return {'role':role,'object_policy':object_rows[0],'snapshot_policy':snapshot_rows[0],'source_sha256':h.digest(raw.encode() if isinstance(raw,str) else raw)}


def restore_receipt(store,context,objects,incident):
    idx=index_objects(objects)
    backup=idx.get(('Backup','velero','platform-storage-probe'),{}).get('object')
    restore=idx.get(('Restore','velero','platform-storage-probe'),{}).get('object')
    h.require(backup and restore,'Completed exact synthetic Backup and Restore are required before retiring their sample volumes.')
    matches=[]
    for item in s.listing(store,'ci-logs/'+context['repository_id']+'/'):
        key=item['Key']
        if not key.endswith('/'+context['environment']+'/incidents/velero-lab-restore/apply/receipt.json'):continue
        value,meta=c.read_json(store,key)
        if not isinstance(value,dict):continue
        rc=value.get('context',{});target=value.get('result',{}).get('velero_target',{})
        if target.get('backup',{}).get('uid')!=backup['metadata']['uid'] or target.get('restore',{}).get('uid')!=restore['metadata']['uid']:continue
        h.require(value.get('schema')==1 and value.get('kind')=='incident-completion' and value.get('success') is True and value['result'].get('completed') is True and all(rc.get(k)==context[k] for k in ('repository_id','account','environment')) and rc.get('region')==context['backend']['region'] and rc.get('operation')=='velero-lab-restore','Synthetic restore receipt ownership/outcome differs.')
        manifest_key=key.replace('ci-logs/','ci-plans/',1).replace('apply/receipt.json','manifest.json')
        manifest,_=c.read_json(store,manifest_key)
        h.require(manifest.get('kind')=='incident-plan' and manifest.get('context')==rc and manifest.get('plan',{}).get('sha256')==value.get('plan_sha'),'Restore receipt does not bind the reviewed fixed action.')
        action=s.read(store,manifest['plan'])
        h.require(action.get('operation')=='velero-lab-restore' and h.digest(h.canonical(action['request']))==rc['request_sha256'] and action['target']['original']==target['original'],'Restore fixed action/source-volume proof differs.')
        h.require(incident.identity(backup)==target['backup'] and incident.identity(restore)==target['restore'],'Synthetic Backup/Restore UID/spec/metadata changed.')
        matches.append({'descriptor':{'key':key,'version':meta['version'],'sha256':h.digest(h.canonical(value))},'receipt':value,'manifest':manifest,'action':action})
    h.require(len(matches)==1,'Exactly one current-incarnation successful synthetic restore proof is required.')
    return matches[0]


def volume_scopes(snapshot):
    return [k for k in ('original','restored') if k in snapshot['target']]


def build_snapshot(config,context,store,objects,incident,core,previous=None):
    continuation=previous is not None
    if not continuation:
        proof=restore_receipt(store,context,objects,incident);target=copy.deepcopy(proof['receipt']['result']['velero_target'])
        h.require(target['original']['volume_id']!=target['restored']['volume_id'],'Synthetic restored copy must use a distinct volume.')
    else:
        prior=previous['original'];completed=s.read(store,previous['receipt'])
        h.require(completed.get('kind')=='gitops-lifecycle-completion' and completed.get('context')==previous['request_context'] and previous.get('operation')=='up' and previous.get('last_result')=='up-complete','Continuation requires exact previous completed Up ownership.')
        validate_result(STEP,'up',prior,completed['result'],previous['generation'])
        path='gitops/platform/backup-probe/overlays/'+context['environment']
        core.ops.run(['git','diff','--exit-code',prior['source_sha'],context['snapshot_sha'],'--',path])
        io=incident.fixture_io();velero=load('continuation_velero_ops',gitops_dir()/'operations/velero_ops.py')
        target=copy.deepcopy(prior['target']);target['original']=velero.volume(io,'backup-probe');target.pop('restored',None)
        h.require(not velero.lab_inventory(io,'backup-probe-restored'),'Unexpected recreated restored sample cannot be silently adopted.')
        proof={'previous_lifecycle_receipt':copy.deepcopy(previous['receipt']),'prior_restore_proof':copy.deepcopy(prior['restore_proof'])}
    h.require(target.get('account')==context['account'] and target.get('region')==context['backend']['region'],'Synthetic snapshot account/region differs.')
    idx=index_objects(objects);delete=[];uids=[]
    for field,ns in (('original','backup-probe'),('restored','backup-probe-restored')):
        if field not in target:continue
        volume=target[field]
        for kind,name,part in (('Pod','writer','pod'),('PersistentVolumeClaim','data','pvc')):
            item=idx.get((kind,ns,name));h.require(item is not None and incident.identity(item['object'])==volume[part],'Synthetic workload identity differs from restore proof.')
            row=core.resource_row(item);row['resource_version']=item['object']['metadata']['resourceVersion'];delete.append(row);uids.append(row['uid'])
        pv=idx.get(('PersistentVolume','',volume['pv']['name']));h.require(pv is not None and incident.identity(pv['object'])==volume['pv'],'Synthetic PV identity changed.')
        spec=pv['object']['spec'];h.require(spec['persistentVolumeReclaimPolicy']=='Delete' and spec['claimRef']['uid']==volume['pvc']['uid'] and spec['csi']['driver']=='ebs.csi.aws.com' and spec['csi']['volumeHandle']==volume['volume_id'],'Synthetic PVC/PV/CSI reclaim chain differs.')
        uids.append(volume['pv']['uid']);volume['pv_row']=core.resource_row(pv)
        aws=s.aws_list(context,'ec2','describe-volumes','Volumes','--volume-ids',volume['volume_id'])
        h.require(len(aws)==1 and aws[0]['VolumeId']==volume['volume_id'],'Synthetic EBS unavailable.')
        volume['aws_identity']={k:aws[0].get(k) for k in ('VolumeId','CreateTime','AvailabilityZone','Size','VolumeType','Encrypted','KmsKeyId','SnapshotId')}
    # No other sample data may hide behind a namespace or Application exemption.
    for item in objects:
        obj=item['object'];kind=obj['kind'];md=obj['metadata']
        if md.get('namespace') in ('backup-probe','backup-probe-restored') and kind in ('Pod','PersistentVolumeClaim'):
            h.require(md['uid'] in uids,'Unknown synthetic-namespace workload/data blocks retirement.')
        h.require(kind not in ('VolumeSnapshot','VolumeSnapshotContent','DeleteBackupRequest'),'Unexpected CSI/deletion-request path; the course uses exact AWS plugin snapshots.')
    retained=[]
    for item in objects:
        obj=item['object'];kind=obj['kind'];md=obj['metadata']
        if kind not in META_KINDS:continue
        h.require(md.get('namespace')=='velero' and obj.get('apiVersion')=='velero.io/v1' and item['base']=='/apis/velero.io/v1' and item['resource'] in META_RESOURCES,'Velero metadata outside the exact API group/namespace.')
        if kind in ('Backup','Restore'):
            h.require(md['name']=='platform-storage-probe','Unknown Velero data object.')
            if not continuation:h.require(obj.get('status',{}).get('phase')=='Completed','Initial backup/restore exercise is incomplete.')
            else:
                prior_rows=[x['before'] for x in previous['original']['metadata'] if x['before']['kind']==kind]
                h.require(len(prior_rows)==1 and core.object_digest(obj)==prior_rows[0]['spec_sha256'],'Recreated backup metadata spec differs from retained course proof.')
        elif kind=='Schedule':h.require(md['name']=='platform-daily' and obj.get('spec',{}).get('paused') is True,'Unpaused or unknown Schedule can create unreviewed data.')
        else:h.require(md['name']=='default' and obj.get('spec',{}).get('provider')=='aws','Unknown backup/snapshot location.')
        if kind=='BackupStorageLocation':
            bucket=obj['spec'].get('objectStorage',{}).get('bucket');prefix=obj['spec'].get('objectStorage',{}).get('prefix')
            h.require(prefix=='backups' and isinstance(bucket,str) and bucket,'Actual course backup bucket/prefix is missing.')
        old=core.resource_row(item);after=core.resource_row(dict(item,object=retained_metadata(obj)))
        retained.append({'before':old,'after':after,'resource_version':md['resourceVersion'],'before_annotations':md.get('annotations',{}),'after_annotations':retained_metadata(obj)['metadata']['annotations']})
    h.require(({x['before']['kind'] for x in retained}==META_KINDS) if not continuation else {'Schedule','BackupStorageLocation','VolumeSnapshotLocation'}<={x['before']['kind'] for x in retained},'Complete Velero metadata inventory is required.')
    protection=source_retention(config,core.ops)
    buckets=[x['object']['spec']['objectStorage']['bucket'] for x in objects if x['object']['kind']=='BackupStorageLocation']
    resource=protection['object_policy']['Resource'];resources=[resource] if isinstance(resource,str) else resource
    h.require(resources==['arn:aws:s3:::'+buckets[0]+'/backups/backups/platform-storage-probe/*'],'Retained object policy protects another storage location.')
    snapshot={'schema':1,'checkpoint_generation':context['generation'],'source_sha':context['snapshot_sha'],'environment':context['environment'],
              'cluster_arn':config['cluster_arn'],'cluster_created_at':config['cluster_created_at'],'restore_proof':proof,'target':target,
              'delete':delete,'synthetic_uids':uids,'metadata':retained,'protection':protection,'continuation':continuation,
              'effect':'delete only two verified synthetic Pod/PVC pairs; retain remote backup and snapshot; retain metadata until EKS deletion'}
    verify_snapshot_cloud(snapshot,context)
    return snapshot


def verify_snapshot_cloud(snapshot,context):
    expected=snapshot['target']['snapshot']
    rows=s.aws_list(context,'ec2','describe-snapshots','Snapshots','--snapshot-ids',expected['SnapshotId'])
    h.require(len(rows)==1 and all(rows[0].get(k)==v for k,v in expected.items()) and rows[0].get('State')=='completed','Exact retained course EC2 snapshot is unavailable/changed.')
    tags={x['Key']:x['Value'] for x in rows[0].get('Tags',[])}
    h.require(tags.get('velero.io/backup')=='platform-storage-probe','Retained snapshot no longer has exact protected course tag.')
    return {'snapshot_id':expected['SnapshotId'],'status':'retained','age_limit':None}


def verify_live(snapshot,objects,core,completed=(),patched=()):
    idx={(x['resource'],x['object']['metadata'].get('namespace',''),x['object']['metadata']['name']):x for x in objects}
    for row in snapshot['delete']:
        item=idx.get((row['resource'],row['namespace'],row['name']))
        if row['uid'] in completed:
            h.require(item is None,'Deleted synthetic identity was replaced/recreated.');continue
        h.require(item is not None and core.resource_row(item)=={k:v for k,v in row.items() if k!='resource_version'},'Synthetic cleanup target identity/spec/metadata changed.')
    for pair in snapshot['metadata']:
        row=pair['after'] if pair['before']['uid'] in patched else pair['before']
        item=idx.get((row['resource'],row['namespace'],row['name']))
        h.require(item is not None and core.resource_row(item)==row,'Retained Velero metadata changed.')


def verify_content(snapshot,done):
    _,incident=provider();io=incident.fixture_io();velero=load('cleanup_velero_content',gitops_dir()/'operations/velero_ops.py')
    for field,namespace in (('original','backup-probe'),('restored','backup-probe-restored')):
        if field not in snapshot['target'] or snapshot['target'][field]['pod']['uid'] in done:continue
        if snapshot.get('continuation'):
            files=velero.disposable_files(io,namespace)
            if 'probe.txt' in files:velero.synthetic_files(io,namespace,snapshot['target']['expected_sha256'])
        else:velero.synthetic_files(io,namespace,snapshot['target']['expected_sha256'])


def apply_cleanup(snapshot,context,core,progress,completed=(),patched=(),expected_versions=None):
    done=list(completed);safe=list(patched)
    verify_content(snapshot,done)
    verify_snapshot_cloud(snapshot,context);verify_live(snapshot,core.api_inventory(),core,done,safe)
    for pair in snapshot['metadata']:
        row=pair['before']
        if row['uid'] in safe:continue
        obj=json.loads(core.ops.run(['kubectl','-n',row['namespace'],'get',row['resource']+'.velero.io',row['name'],'-o','json']))
        if expected_versions is not None:h.require(obj['metadata']['resourceVersion']==expected_versions[row['uid']],'Velero metadata resource version changed after action review.')
        h.require(obj['metadata']['uid']==row['uid'] and core.object_digest(obj)==row['spec_sha256'] and obj['metadata'].get('annotations',{})==pair['before_annotations'],'Velero metadata was replaced before retention patch.')
        patch=[{'op':'test','path':'/metadata/uid','value':row['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},
               {'op':'test','path':'/metadata','value':obj['metadata']},
               {'op':'add','path':'/metadata/annotations','value':pair['after_annotations']}]
        core.ops.run(['kubectl','-n',row['namespace'],'patch',row['resource']+'.velero.io',row['name'],'--type=json','-p',json.dumps(patch)])
        safe.append(row['uid']);progress(done,safe)
    # Delete both writers before either claim; then CSI owns volume deletion.
    for row in sorted(snapshot['delete'],key=lambda x:0 if x['kind']=='Pod' else 1):
        if row['uid'] in done:continue
        verify_live(snapshot,core.api_inventory(),core,done,safe);verify_snapshot_cloud(snapshot,context)
        obj=json.loads(core.ops.run(['kubectl','-n',row['namespace'],'get',row['resource'],row['name'],'-o','json']))
        h.require(obj['metadata']['uid']==row['uid'],'Synthetic object replaced before exact delete.')
        if expected_versions is not None:h.require(obj['metadata']['resourceVersion']==expected_versions[row['uid']],'Synthetic resource version changed after action review.')
        options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':row['uid'],'resourceVersion':obj['metadata']['resourceVersion']}}
        path=row['base']+'/namespaces/'+row['namespace']+'/'+row['resource']+'/'+row['name']
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'delete.json';file.write_bytes(h.canonical(options));core.ops.run(['kubectl','delete','--raw',path,'-f',str(file)])
        for _ in range(120):
            raw=core.ops.run(['kubectl','-n',row['namespace'],'get',row['resource'],row['name'],'--ignore-not-found','-o','json'])
            if not raw.strip():break
            h.require(json.loads(raw)['metadata']['uid']==row['uid'],'Synthetic replacement appeared during cleanup.');time.sleep(3)
        else:raise h.SafeError('Synthetic foreground cleanup timed out; exact checkpoint retained.')
        done.append(row['uid']);progress(done,safe)
    volume_ids=[snapshot['target'][k]['volume_id'] for k in volume_scopes(snapshot)]
    for _ in range(120):
        live=s.aws_list(context,'ec2','describe-volumes','Volumes','--filters','Name=volume-id,Values='+','.join(volume_ids))
        if not live:
            remaining=core.api_inventory()
            pv_ids={snapshot['target'][k]['pv']['uid'] for k in volume_scopes(snapshot)}
            if not any(x['object']['kind']=='PersistentVolume' and x['object']['metadata']['uid'] in pv_ids for x in remaining):break
        known={snapshot['target'][k]['volume_id']:snapshot['target'][k]['aws_identity'] for k in volume_scopes(snapshot)}
        h.require(all(x['VolumeId'] in known and all(x.get(k)==v for k,v in known[x['VolumeId']].items()) for x in live),'Synthetic volume identity changed during CSI reclaim.');time.sleep(5)
    else:raise h.SafeError('CSI volume absence not established; do not delete EKS/controllers.')
    retained=verify_snapshot_cloud(snapshot,context)
    return {'deleted_pod_pvc_uids':done,'deleted_volume_ids':volume_ids,'retained_snapshot':retained,
            'approved_residuals':[{k:pair['after'][k] for k in ('resource','namespace','name','uid','spec_sha256','metadata_policy_sha256')} for pair in snapshot['metadata']],
            'up_semantics':'restore original sample declaration; do not replay completed backup/restore exercise'}


@contextlib.contextmanager
def session(store,context):
    adapter,incident=provider();ops=adapter.ops
    cfg=json.loads((gitops_dir()/'operations.json').read_text());h.require(cfg.get('enabled') is True,'GitOps registration is inactive.')
    config=copy.deepcopy(cfg['environments'][context['environment']]);config['operator_image']=cfg['operator_image'];config['environment']=context['environment']
    effective,binding=adapter.live_binding(config,store)
    effective['environment']=context['environment']
    proof=load('velero_access',HERE/'operations-access.py').verify_bootstrap_receipt(effective,store,config_sha256=config['operations_access_config_sha256'])
    binding['operations_access']={k:proof[k] for k in ('key','version','sha256')}
    private=load('velero_private',HERE/'private-api-session.py')
    with tempfile.TemporaryDirectory() as directory:
        with private.private_api(effective['cluster'],effective['relay'],effective['region'],Path(directory)/'kubeconfig') as (env,cluster):
            old=os.environ.get('KUBECONFIG');os.environ['KUBECONFIG']=env['KUBECONFIG']
            try:yield effective,binding,incident,adapter.hooks
            finally:
                if old is None:os.environ.pop('KUBECONFIG',None)
                else:os.environ['KUBECONFIG']=old



def for_gitops(config, objects, require_complete=False):
    """Read only the current owned checkpoint; never trust a caller UID allowlist."""
    if os.environ.get('OPERATION') != 'down':return {'skip_uids': [], 'residuals': [], 'rows': []}
    relevant=[x for x in objects if x['object']['kind'] in META_KINDS or
              (x['object']['metadata'].get('namespace') in ('backup-probe','backup-probe-restored') and x['object']['kind'] in ('Pod','PersistentVolumeClaim'))]
    if not relevant:return {'skip_uids': [], 'residuals': [], 'rows': []}
    env=config.get('environment',config.get('_environment'))
    h.require(env in ('dev','prod'),'Velero handoff environment missing.')
    repo=h.required('GITHUB_REPOSITORY_ID');store=h.Store(config['state_bucket'],config['account_id'])
    record,_=c.read_json(store,f'ci-lifecycle/{repo}/{env}/hook-velero-backup-restore.json')
    h.require(isinstance(record,dict) and record.get('step_id')==STEP and record.get('operation')=='down' and
              record.get('generation')==h.required('LIFECYCLE_GENERATION') and record.get('snapshot_sha')==h.required('LIFECYCLE_SNAPSHOT_SHA'),
              'Exact Velero checkpoint must precede GitOps cleanup planning.')
    snapshot=record['original']
    h.require(snapshot['cluster_arn']==config['cluster_arn'] and snapshot['cluster_created_at']==config['cluster_created_at'], 'Velero checkpoint cluster incarnation differs.')
    if require_complete:
        barrier=load('velero_authenticated_barriers',HERE/'lifecycle-barriers.py')
        context={'repository_id':repo,'account':config['account_id'],'environment':env,'root':'terraform/environments/'+env+'/eks',
                 'backend':{'bucket':config['state_bucket'],'region':config['region']},'operation':'down',
                 'generation':record['generation'],'source_sha':record['snapshot_sha'],'lifecycle_registry_sha256':h.required('LIFECYCLE_CONFIG_SHA256')}
        result=barrier.for_consumer(store,context,json.loads(h.required('LIFECYCLE_BARRIER_RECEIPTS')),step=STEP)
        validate_result(STEP,'down',snapshot,result,record['generation'])
    core=provider()[0].hooks
    completed=record.get('completed',[]);patched=record.get('patched',[])
    verify_live(snapshot,objects,core,completed,patched)
    if require_complete:h.require(set(completed)=={x['uid'] for x in snapshot['delete']},'Synthetic retirement prefix is incomplete.')
    rows=[x['after'] for x in snapshot['metadata']]
    return {'skip_uids':snapshot['synthetic_uids']+[x['uid'] for x in rows], 'rows':rows,
            'residuals':[{k:x[k] for k in ('resource','namespace','name','uid','spec_sha256','metadata_policy_sha256')} for x in rows]}

def validate_result(step,operation,snapshot,result,generation,context=None,binding=None):
    h.require(step==STEP and result.get('checkpoint_generation')==generation and result.get('retained_snapshot',{}).get('snapshot_id')==snapshot['target']['snapshot']['SnapshotId'] and result.get('retained_snapshot',{}).get('status')=='retained','Velero completion snapshot/generation differs.')
    if operation=='down':
        h.require(set(result.get('deleted_pod_pvc_uids',[]))=={x['uid'] for x in snapshot['delete']} and result.get('deleted_volume_ids')==[snapshot['target'][k]['volume_id'] for k in volume_scopes(snapshot)],'Velero exact synthetic deletion/CSI absence incomplete.')
        expected=[{k:x['after'][k] for k in ('resource','namespace','name','uid','spec_sha256','metadata_policy_sha256')} for x in snapshot['metadata']]
        h.require(result.get('approved_residuals')==expected,'Retained Velero metadata identity differs.')
    else:h.require(result.get('backup_exercise_replayed') is False,'Up must not rerun completed backup exercise.')



def recover_claim(record, context, objects=None, core=None):
    if not record.get('apply_claim'):return
    claim=record['apply_claim']
    previous=json.loads(h.execute(['gh','api','repos/'+h.required('GITHUB_REPOSITORY')+'/actions/runs/'+claim['run_id']]))
    h.require(str(previous.get('repository',{}).get('id'))==context['repository_id'] and str(previous.get('id'))==claim['run_id'] and previous.get('status')=='completed','Previous Velero mutation owner is active or unknown.')
    if objects is not None:
        idx={(x['resource'],x['object']['metadata'].get('namespace',''),x['object']['metadata']['name']):x for x in objects}
        for row in record['original']['delete']:
            item=idx.get((row['resource'],row['namespace'],row['name']))
            if item is None:
                if row['uid'] not in record['completed']:record['completed'].append(row['uid'])
            else:h.require(core.resource_row(item)=={k:v for k,v in row.items() if k!='resource_version'},'Unknown synthetic replacement during recovery.')
        for pair in record['original']['metadata']:
            row=pair['before'];item=idx.get((row['resource'],row['namespace'],row['name']))
            h.require(item is not None,'Retained metadata disappeared during recovery.')
            actual=core.resource_row(item)
            h.require(actual in (pair['before'],pair['after']),'Retained metadata changed outside exact plan during recovery.')
            if actual==pair['after'] and row['uid'] not in record['patched']:record['patched'].append(row['uid'])
    record.pop('apply_claim')

def run(stage):
    h.require(stage in ('start','plan','verify','apply'),'Unknown Velero lifecycle stage.')
    s.HOOKS=s.HOOKS|{STEP}
    store,key,context,course=s.settings(stage);h.require(context['step_id']==STEP,'Wrong Velero semantic hook.')
    context['registration_sha256']=h.digest(h.canonical({'provider_sha256':h.digest(Path(__file__).read_bytes()),'gitops_registration_sha256':h.digest((gitops_dir()/'operations.json').read_bytes())}))
    record,control=c.read_json(store,key);operation=context['operation']
    if stage=='start' and operation=='up':
        h.require(record and record.get('phase')=='paused','No retained Velero Down checkpoint.')
        h.require(all(record.get(k)==context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')),'Velero retained source identity changed.')
        recover_claim(record,context)
        record.update(request_context=context,operation=operation);c.update(store,key,record,control);h.emit({'snapshot_sha':context['snapshot_sha']});return
    # Up only verifies retained remote snapshot; owner Application restores sample.
    manager=session(store,context) if operation=='down' else contextlib.nullcontext((None,{},None,None))
    with manager as (config,binding,incident,core):
        if stage=='start':
            if record is None or record.get('phase')=='active':
                snapshot=build_snapshot(config,context,store,core.api_inventory(),incident,core,previous=record if record and record.get('phase')=='active' else None)
                record={'schema':1,**{k:context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')},'original':snapshot,'phase':'paused','completed':[],'patched':[]}
            h.require(all(record[k]==context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')),'Velero checkpoint changed.')
            recover_claim(record,context,core.api_inventory(),core)
            record.update(request_context=context,operation=operation);c.update(store,key,record,control);h.emit({'snapshot_sha':context['snapshot_sha']});return
        h.require(record and record.get('request_context')==context and record.get('phase')=='paused','Velero action ownership changed.')
        h.require(all(record.get(k)==context[k] for k in ('step_id','generation','snapshot_sha','registration_sha256')),'Velero retained source identity changed.')
        snapshot=record['original'];verify_snapshot_cloud(snapshot,context)
        expected_versions={}
        if operation=='down':
            objects=core.api_inventory();verify_live(snapshot,objects,core,record['completed'],record['patched'])
            targets={x['uid'] for x in snapshot['delete']}|{x['before']['uid'] for x in snapshot['metadata']}
            expected_versions={i['object']['metadata']['uid']:i['object']['metadata']['resourceVersion'] for i in objects if i['object']['metadata']['uid'] in targets}
        payload={'step_id':STEP,'operation':operation,'snapshot':snapshot,'completed':record['completed'],'patched':record['patched'],'resource_versions':expected_versions};prefix=context['prefix']
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory)
            if stage=='plan':
                now=time.time();file=temp/'actions.json';file.write_bytes(h.canonical(payload));action=store.put(prefix+'actions.json',file)
                review=temp/'review.json';review.write_bytes(h.canonical({'effect':snapshot['effect'],'retained_metadata_patch':'exact Delete=false annotation only; UID/resourceVersion test','retention':'all existing S3 and named EC2 snapshot retained; no account-wide absence claim'}))
                manifest={'schema':1,'kind':'gitops-lifecycle','context':context,'control':control,'binding':binding,'created_at':now,'expires_at':now+h.TTL_SECONDS,'plan':action,'review':store.put(prefix+'review.json',review)}
                file=temp/'manifest.json';file.write_bytes(h.canonical(manifest));d=store.put(prefix+'manifest.json',file)
                h.emit({'manifest_key':d['key'],'manifest_version':d['version'],'manifest_sha':d['sha256'],'plan_sha':action['sha256']});return
            desc={'key':h.required('MANIFEST_KEY'),'version':h.required('MANIFEST_VERSION'),'sha256':h.required('EXPECTED_MANIFEST_SHA')};h.require(desc['key']==prefix+'manifest.json','Wrong Velero manifest namespace.')
            manifest=s.read(store,desc)
            h.require(manifest.get('context')==context and manifest.get('control')==control and manifest.get('binding')==binding and manifest['created_at']<=time.time()<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==h.TTL_SECONDS,'Velero reviewed scope/control/TTL changed.')
            h.require(manifest['plan']['key']==prefix+'actions.json' and manifest['plan']['sha256']==h.required('EXPECTED_PLAN_SHA') and s.read(store,manifest['plan'])==payload,'Velero action bytes differ.')
            if stage=='verify':return
            h.ensure_current_main(context);current,info=c.read_json(store,key);h.require(current==record and info==control,'Velero control changed before cleanup.')
            h.require(not record.get('apply_claim'),'Prior Velero mutation claim needs owner-aware reconciliation, never blind replay.')
            record['apply_claim']={k:context[k] for k in ('run_id','run_attempt','sha')};control=c.update(store,key,record,control)
            def progress(completed,patched):
                nonlocal control
                record.update(completed=completed,patched=patched);control=c.update(store,key,record,control)
            if operation=='down':result=apply_cleanup(snapshot,context,core,progress,record['completed'],record['patched'],expected_versions)
            else:result={'retained_snapshot':verify_snapshot_cloud(snapshot,context),'backup_exercise_replayed':False,'up_semantics':'sample Application is restored by platform-operations; historical backup remains retained'}
            result['checkpoint_generation']=context['generation'];validate_result(STEP,operation,snapshot,result,context['generation'])
            completed=time.time();h.require(completed<manifest['expires_at'],'Velero cleanup exceeded approved TTL.')
            file=temp/'receipt.json';file.write_bytes(h.canonical({'schema':1,'kind':'gitops-lifecycle-completion','context':context,'plan_sha':manifest['plan']['sha256'],'completed_at':completed,'result':result}))
            rd=store.put(prefix.replace('ci-up-plans/','ci-logs/',1).replace('ci-plans/','ci-logs/',1)+'apply/receipt.json',file)
            record.update(last_result=operation+'-complete',receipt=rd,phase='active' if operation=='up' else 'paused');record.pop('apply_claim',None)
            c.update(store,key,record,control);h.emit({'receipt_key':rd['key'],'receipt_version':rd['version'],'receipt_sha':rd['sha256']})

if __name__=='__main__':
    try:run(sys.argv[1])
    except Exception:raise SystemExit('Exact Velero lifecycle stopped; retain private ownership checkpoint and never force deletion.')
