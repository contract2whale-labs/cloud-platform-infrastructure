"""Exact disposable Velero storage probe; no production dataset or namespace deletion."""
import copy, datetime as dt, hashlib, json, pathlib, re, tempfile, time, uuid
import platform_probe_ops as probe
IDS=('velero-lab-backup','velero-lab-restore','velero-lab-cleanup')
PROD_IDS=IDS
BASE=pathlib.Path(__file__).resolve().parent

def ident(io,obj):return io.identity(obj)
def volume(io,namespace):
    pod=io.kube('pods',namespace,'writer');pvc=io.kube('persistentvolumeclaims',namespace,'data')
    io.require(any(x.get('persistentVolumeClaim',{}).get('claimName')=='data' for x in pod['spec'].get('volumes',[])),'Writer does not mount exact lab PVC.')
    io.require(pvc.get('status',{}).get('phase')=='Bound','Lab PVC must be Bound.')
    pv=io.kube('persistentvolumes','',pvc['spec']['volumeName'])
    io.require(pv['spec']['claimRef']['uid']==pvc['metadata']['uid'] and pv['spec']['claimRef']['namespace']==namespace,'PV claim UID mismatch.')
    csi=pv['spec'].get('csi',{});io.require(csi.get('driver')=='ebs.csi.aws.com' and re.fullmatch(r'vol-[0-9a-f]+',csi.get('volumeHandle','')),'Only exact EBS lab volume is registered.')
    return {'pod':ident(io,pod),'pvc':ident(io,pvc),'pv':ident(io,pv),'volume_id':csi['volumeHandle'],'reclaim_policy':pv['spec']['persistentVolumeReclaimPolicy']}

def hash_file(io,namespace):
    out=io.ops.run(['kubectl','-n',namespace,'exec','writer','--','sha256sum','/data/probe.txt'])
    if isinstance(out,bytes):out=out.decode()
    value=out.split()[0];io.require(re.fullmatch('[0-9a-f]{64}',value),'Lab file hash missing.')
    return value

def source(io,action,r,environment="prod"):
    io.require(environment in ("dev","prod"),"Unknown Velero environment.")
    import yaml
    path='gitops/platform/velero-resources/overlays/'+environment+'/'+action+'-request.yaml'
    raw=io.ops.run(['git','show',r['source_sha']+':'+path]);obj=yaml.safe_load(raw)
    expected={'apiVersion':'velero.io/v1','kind':action.title(),'metadata':{'name':'platform-storage-probe','namespace':'velero','annotations':{'argocd.argoproj.io/sync-options':'Prune=confirm,Delete=confirm'}},'spec':({'includedNamespaces':['backup-probe'],'includedResources':['pods','persistentvolumeclaims','persistentvolumes'],'snapshotVolumes':True,'ttl':'24h'} if action=='backup' else {'backupName':'platform-storage-probe','namespaceMapping':{'backup-probe':'backup-probe-restored'},'restorePVs':True})}
    io.require(obj==expected,'Velero lab source differs from exact reviewed course asset.')
    return obj,{'path':path,'source_sha':r['source_sha'],'sha256':hashlib.sha256(raw.encode() if isinstance(raw,str) else raw).hexdigest()}

def lab_inventory(io,namespace):
    io.require(namespace in ('backup-probe','backup-probe-restored'),'Unregistered disposable lab namespace.')
    rows=[]
    # The fixed Backup includes only Pod/PVC/PV. Never read arbitrary Secrets or discover APIs.
    for resource,name in (('pods','writer'),('persistentvolumeclaims','data')):
        listing=json.loads(io.ops.run(['kubectl','-n',namespace,'get',resource,'-o','json']))
        io.require(not listing.get('metadata',{}).get('continue'),'Incomplete lab resource inventory.')
        for obj in listing['items']:
            io.require(obj['metadata']['name']==name,'Foreign Pod/PVC in disposable backup lab.')
            rows.append({'resource':resource,'identity':ident(io,obj)})
    return sorted(rows,key=lambda x:x['resource'])

def receipt(io,r,c,store,operation):
    d=r.get('creation_receipt');io.require(d and store,'Exact private versioned prior operation receipt required.')
    io.require(d['key'].startswith('ci-logs/'+io.h.required('GITHUB_REPOSITORY_ID')+'/') and '/'+c['environment']+'/incidents/'+operation+'/apply/receipt.json' in d['key'],'Wrong Velero creation receipt.')
    with tempfile.TemporaryDirectory() as tmp:
        p=pathlib.Path(tmp)/'receipt';store.get(d,p);v=json.loads(p.read_bytes())
    io.require(v['kind']=='incident-completion' and v['success'] is True and v['context']['account']==c['account_id'] and v['context']['environment']==c['environment'] and v['context']['repository_id']==io.h.required('GITHUB_REPOSITORY_ID') and v['context']['region']==c['region'],'Velero receipt identity/outcome mismatch.')
    return v['result']['velero_target']

def snapshot(io,operation,r,c,marker,store=None):
    io.require(operation in IDS and c['environment'] in ('dev','prod'),'Velero lab requires a protected Dev or Prod environment.')
    io.require(r['data_decision']==('delete-exact-disposable-restored-pvc-and-volume' if operation.endswith('cleanup') else 'lab-probe-overwrite-and-24h-backup'),'Explicit lab data/retention decision required.')
    if operation=='velero-lab-backup':
        run=str(uuid.UUID(r['experiment_id']));obj,src=source(io,'backup',r,c['environment'])
        io.require(io.kube('backups.velero.io','velero','platform-storage-probe',True) is None,'Backup exists; do not adopt/rewrite it.')
        io.require(not lab_inventory(io,'backup-probe-restored'),'Restored lab Pod/PVC must be absent before backup.')
        original=volume(io,'backup-probe');inventory=lab_inventory(io,'backup-probe')
        restored_namespace=ident(io,io.kube('namespaces','','backup-probe-restored'))
        pod=io.kube('pods','backup-probe','writer');io.require(all(io.ops.DIGEST.fullmatch(x['image']) for x in pod['spec']['containers']),'Lab writer image must be an approved immutable digest.');pvc=io.kube('persistentvolumeclaims','backup-probe','data')
        io.require(all(x['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id','').startswith('platform-backup-probe-'+c['environment']+':') for x in (pod,pvc)),'Original lab resources are not tracked by exact platform-backup-probe-prod Application.')
        return {'manifest':obj,'source':src,'original':original,'inventory':inventory,'run':run,'expected_sha256':hashlib.sha256((run+'\n').encode()).hexdigest(),'created':[],'restored_namespace':restored_namespace,'region':c['region'],'account':c['account_id']}
    recovering=bool(operation=='velero-lab-cleanup' and marker and marker.get('operation')=='velero-lab-cleanup' and marker.get('target',{}).get('cleanup_authorized'))
    if operation=='velero-lab-cleanup' and marker and marker.get('owner')=='kubernetes-fixed-operations' and marker.get('operation') in ('velero-lab-restore','velero-lab-cleanup'):
        target=copy.deepcopy(marker['target'])
        io.require(target.get('restored') and target.get('restore'),'Incomplete restore ownership evidence; recovery review required.')
    else:target=receipt(io,r,c,store,'velero-lab-backup' if operation=='velero-lab-restore' else 'velero-lab-restore')
    if operation=='velero-lab-restore':
        io.require(volume(io,'backup-probe')==target['original'],'Original lab PV/PVC/Pod replaced or changed.')
    backup=io.kube('backups.velero.io','velero','platform-storage-probe')
    io.require(ident(io,backup)==target['backup'] and backup.get('status',{}).get('phase')=='Completed' and not backup['status'].get('errors',0),'Exact original completed Backup required.')
    if operation=='velero-lab-restore':
        io.require(io.kube('restores.velero.io','velero','platform-storage-probe',True) is None and not lab_inventory(io,'backup-probe-restored'),'Restore destination Pod/PVC or CR exists; never merge/adopt.')
        io.require(ident(io,io.kube('namespaces','','backup-probe-restored'))==target['restored_namespace'],'Restored namespace changed.')
        target['manifest'],target['source']=source(io,'restore',r,c['environment'])
        snapshots=json.loads(io.ops.run(['aws','ec2','describe-snapshots','--owner-ids','self','--filters','Name=tag:velero.io/backup,Values=platform-storage-probe','--region',c['region']]))['Snapshots']
        matches=[s for s in snapshots if s['VolumeId']==target['original']['volume_id'] and s['State']=='completed' and s['OwnerId']==c['account_id']]
        io.require(len(matches)==1 and dt.datetime.fromisoformat(matches[0]['StartTime'].replace('Z','+00:00'))>=dt.datetime.fromisoformat(backup['status']['startTimestamp'].replace('Z','+00:00')),'One completed original-volume snapshot from this backup is required.')
        target['snapshot']={k:matches[0][k] for k in ('SnapshotId','VolumeId','OwnerId','VolumeSize','StartTime')}
    else:
        if recovering:
            for kind,name,key in (('pods','writer','pod'),('persistentvolumeclaims','data','pvc')):
                live=io.kube(kind,'backup-probe-restored',name,True)
                if live is not None:io.require(ident(io,live)==target['restored'][key],'Restored cleanup object replaced/changed.')
        else:io.require(volume(io,'backup-probe-restored')==target['restored'],'Restored UID/spec changed; do not delete.')
        io.require(target['restored']['volume_id']!=target['original']['volume_id'] and target['restored']['reclaim_policy']=='Delete','Disposable restored EBS volume must be separate with explicit Delete policy.')
        restore=io.kube('restores.velero.io','velero','platform-storage-probe');io.require(ident(io,restore)==target['restore'],'Restore CR changed/replaced.')
        apps=json.loads(io.ops.run(['kubectl','-n','argocd','get','applications.argoproj.io','-o','json']))['items']
        for app in apps:
            io.require(not any(x.get('namespace')=='backup-probe-restored' and x.get('name') in ('writer','data') for x in app.get('status',{}).get('resources',[])),'Restored object is currently tracked by an Argo Application; retire approved Git desired first.')
        target['cleanup_inventory']=lab_inventory(io,'backup-probe-restored')
        target['restored_namespace']=ident(io,io.kube('namespaces','','backup-probe-restored'))
    return target

def wait_complete(io,resource,uid):
    for _ in range(240):
        obj=io.kube(resource,'velero','platform-storage-probe');io.require(obj['metadata']['uid']==uid,'Velero CR replaced during operation.')
        phase=obj.get('status',{}).get('phase')
        if phase=='Completed':
            io.require(not obj['status'].get('errors',0) and not obj['status'].get('warnings',0),'Velero errors/warnings require review before proceeding.');return obj
        io.require(phase not in ('Failed','PartiallyFailed','FailedValidation'),'Velero lab operation failed.')
        time.sleep(5)
    raise io.h.SafeError('Velero timeout; original data and recovery marker retained.')

def apply(io,operation,target,r,mark):
    mark('active',target)
    try:
        if operation=='velero-lab-cleanup':
            if io.kube('pods','backup-probe-restored','writer',True) is not None:
                synthetic_files(io,'backup-probe-restored',target['expected_sha256'])
            target['cleanup_authorized']=True;mark('active',target)
            io.require(lab_inventory(io,'backup-probe-restored')==target['cleanup_inventory'],'Restored lab inventory changed after review.')
            io.require(ident(io,io.kube('namespaces','','backup-probe-restored'))==target['restored_namespace'],'Restored namespace changed.')
            for kind,name,key in (('pods','writer','pod'),('persistentvolumeclaims','data','pvc')):
                original=target['restored'][key]
                probe.delete_owned(io,{'resource':kind,'namespace':'backup-probe-restored','name':name,'identity':original,'api_path':'/api/v1/namespaces/backup-probe-restored/'+kind+'/'+name})
            for _ in range(120):
                pv=io.kube('persistentvolumes','',target['restored']['pv']['name'],True)
                volumes=json.loads(io.ops.run(['aws','ec2','describe-volumes','--filters','Name=volume-id,Values='+target['restored']['volume_id'],'--region',target['region']]))['Volumes']
                if pv is None and not volumes:break
                if pv is not None:io.require(pv['metadata']['uid']==target['restored']['pv']['uid'],'Restored PV replaced during cleanup.')
                time.sleep(5)
            else:raise io.h.SafeError('Restored PV/EBS deletion incomplete; do not remove finalizers or delete by guessed ID.')
            # Leave namespace, Backup, Restore and snapshots retained. No broad deletion.
            mark('idle',target);return {'velero_target':target,'restored_pod_pvc_deleted':True,'backup_retained':True}
        if operation=='velero-lab-restore':
            synthetic_files(io,'backup-probe',target['expected_sha256'])
        if operation=='velero-lab-backup':
            disposable_files(io,'backup-probe')
            io.require(volume(io,'backup-probe')==target['original'] and lab_inventory(io,'backup-probe')==target['inventory'],'Original lab changed since review.')
            io.ops.run(['kubectl','-n','backup-probe','exec','writer','--','sh','-ec','printf "%s\\n" "$1" > /data/probe.txt; sync','sh',target['run']])
            io.require(hash_file(io,'backup-probe')==target['expected_sha256'],'Synthetic lab file write/hash verification failed.')
        created=json.loads(io.ops.run(['kubectl','create','--field-manager=course-velero-lab','-f','-','-o','json'],content=io.h.canonical(target['manifest'])))
        key='backup' if operation=='velero-lab-backup' else 'restore';resource=key+'s.velero.io';target[key]=ident(io,created);mark('active',target)
        completed=wait_complete(io,resource,created['metadata']['uid']);target[key]=ident(io,completed)
        if key=='backup':
            io.require(completed['status'].get('volumeSnapshotsAttempted')==1 and completed['status'].get('volumeSnapshotsCompleted')==1,'Backup must complete exactly the one lab volume snapshot.')
        if key=='restore':
            io.ops.run(['kubectl','-n','backup-probe-restored','wait','pod/writer','--for=condition=Ready','--timeout=300s'])
            target['restored']=volume(io,'backup-probe-restored');io.require(target['restored']['volume_id']!=target['original']['volume_id'],'Restore reused original EBS volume.')
            volumes=json.loads(io.ops.run(['aws','ec2','describe-volumes','--volume-ids',target['original']['volume_id'],target['restored']['volume_id'],'--region',target['region']]))['Volumes']
            byid={v['VolumeId']:v for v in volumes};old=byid[target['original']['volume_id']];new=byid[target['restored']['volume_id']]
            io.require(new['SnapshotId']==target['snapshot']['SnapshotId'] and new['Size']==old['Size'] and new['AvailabilityZone']==old['AvailabilityZone'],'Restored volume does not match original snapshot/size/AZ.')
            for kind,name in (('pods','writer'),('persistentvolumeclaims','data')):
                labels=io.kube(kind,'backup-probe-restored',name)['metadata'].get('labels',{})
                io.require(labels.get('velero.io/backup-name')=='platform-storage-probe' and labels.get('velero.io/restore-name')=='platform-storage-probe','Restored objects lack exact Velero ownership labels.')
            io.require(hash_file(io,'backup-probe-restored')==target['expected_sha256'],'Restored data hash mismatch.')
        mark('idle',target);return {'velero_target':target,'completed':True,'raw_data_published':False}
    except Exception:
        mark('recovery-required',target);raise


def disposable_files(io, namespace):
    """Fixed apply-only content inventory before any lab write."""
    names=io.ops.run(['kubectl','-n',namespace,'exec','writer','--','ls','-A','/data'])
    if isinstance(names,bytes):names=names.decode()
    io.require(set(names.splitlines()) <= {'probe.txt','lost+found'},'Unregistered files on disposable probe volume.')
    for name,expected_type in (('probe.txt','regular file'),('lost+found','directory')):
        if name in names.splitlines():
            kind=io.ops.run(['kubectl','-n',namespace,'exec','writer','--','stat','-c','%F','/data/'+name])
            if isinstance(kind,bytes):kind=kind.decode()
            io.require(kind.strip()==expected_type,'Symlink or unexpected file type in disposable volume.')
    if 'lost+found' in names.splitlines():
        recovered=io.ops.run(['kubectl','-n',namespace,'exec','writer','--','ls','-A','/data/lost+found'])
        io.require(not recovered.strip(),'Recovered files exist on disposable probe volume.')
    return set(names.splitlines())


def synthetic_files(io, namespace, expected):
    """Approved apply-only fixed commands prove exact synthetic file contents."""
    io.require('probe.txt' in disposable_files(io,namespace),'Synthetic probe file is missing.')
    kind=io.ops.run(['kubectl','-n',namespace,'exec','writer','--','stat','-c','%F','/data/probe.txt'])
    if isinstance(kind,bytes):kind=kind.decode()
    io.require(kind.strip()=='regular file' and hash_file(io,namespace)==expected,'Synthetic probe must be an exact regular file with saved hash.')


def retained_restore(io, proof, check_files=True):
    """The exact verified restored copy, Backup, Restore and snapshot stay retained."""
    for resource,key in (('backups.velero.io','backup'),('restores.velero.io','restore')):
        obj=io.kube(resource,'velero','platform-storage-probe')
        if key=='backup':
            io.require(obj['spec'].get('includedNamespaces')==['backup-probe'] and obj['spec'].get('includedResources')==['pods','persistentvolumeclaims','persistentvolumes'],
                       'Backup must be explicitly restricted to the fixed lab resource kinds.')
        io.require(ident(io,obj)==proof[key] and obj.get('status',{}).get('phase')=='Completed' and not obj.get('status',{}).get('errors',0),
                   'Verified synthetic Backup/Restore changed, expired or failed.')
    io.require(volume(io,'backup-probe-restored')==proof['restored'],'Retained restored Pod/PVC/PV identity changed.')
    io.require(lab_inventory(io,'backup-probe-restored')==proof['restored_inventory'],'Retained restored lab inventory changed.')
    if check_files:synthetic_files(io,'backup-probe-restored',proof['expected_sha256'])
    snapshots=json.loads(io.ops.run(['aws','ec2','describe-snapshots','--snapshot-ids',proof['snapshot']['SnapshotId'],'--region',proof['region']]))['Snapshots']
    io.require(len(snapshots)==1 and snapshots[0]['OwnerId']==proof['account'] and snapshots[0]['State']=='completed'
               and all(snapshots[0].get(k)==v for k,v in proof['snapshot'].items()),'Retained original-volume snapshot changed or unavailable.')


def original_retirement_proof(io,r,c,store,previous=None):
    """Prove only original synthetic writer/data retirement from a successful restore receipt."""
    io.require(c['environment'] in ('dev','prod') and r['data_decision']=='delete-exact-original-disposable-probe-pod-pvc-and-volume',
               'Explicit original synthetic Pod/PVC/EBS data decision required.')
    experiment=str(uuid.UUID(r['experiment_id']))
    if previous:
        proof=copy.deepcopy(previous['storage_proof'])
        io.require(proof['creation_receipt']==r['creation_receipt'] and proof['run']==experiment
                   and proof['account']==c['account_id'] and proof['region']==c['region'],'Original synthetic proof/request identity changed.')
        completed=list(previous.get('completed',[]))
        pending=previous.get('pending_delete')
        for resource,key in (('pods','/Pod/backup-probe/writer'),('persistentvolumeclaims','/PersistentVolumeClaim/backup-probe/data')):
            if pending==key and io.kube(resource,'backup-probe','writer' if resource=='pods' else 'data',True) is None:
                completed.append(key)
        verify_original_retirement(io,proof,completed,check_files=False)
        return proof
    prior=receipt(io,r,c,store,'velero-lab-restore')
    io.require(prior['run']==experiment and prior['account']==c['account_id'] and prior['region']==c['region']
               and prior['expected_sha256']==hashlib.sha256((experiment+'\n').encode()).hexdigest(),
               'Successful exact synthetic experiment restore receipt required.')
    original=volume(io,'backup-probe')
    io.require(original==prior['original'] and original['reclaim_policy']=='Delete','Original PVC/PV ownership changed or reclaim policy is not Delete.')
    io.require(original['volume_id']!=prior['restored']['volume_id'],'Original and retained restore must be distinct volumes.')
    for key,namespace,name in (('pod','backup-probe','writer'),('pvc','backup-probe','data')):
        io.require(original[key]['namespace']==namespace and original[key]['name']==name,'Original proof points outside exact source lab.')
    inventory=lab_inventory(io,'backup-probe')
    io.require(len(inventory)==2,'Exact original Pod/PVC inventory required.')
    volumes=json.loads(io.ops.run(['aws','ec2','describe-volumes','--volume-ids',original['volume_id'],'--region',c['region']]))['Volumes']
    io.require(len(volumes)==1 and volumes[0]['VolumeId']==original['volume_id'],'Original EBS volume unavailable.')
    volume_identity={k:volumes[0][k] for k in ('VolumeId','CreateTime','Size','AvailabilityZone','VolumeType','Encrypted')}
    proof={k:copy.deepcopy(prior[k]) for k in ('run','expected_sha256','original','restored','backup','restore','snapshot','account','region')}
    proof.update(creation_receipt=copy.deepcopy(r['creation_receipt']),original_inventory=inventory,
                 restored_inventory=lab_inventory(io,'backup-probe-restored'),original_volume=volume_identity)
    retained_restore(io,proof,check_files=False)
    return proof


def verify_original_retirement(io,proof,completed,check_files=True):
    """Before each exact deletion, prove retained copy and no replacement/new consumers."""
    retained_restore(io,proof,check_files=check_files)
    pod_key='/Pod/backup-probe/writer';pvc_key='/PersistentVolumeClaim/backup-probe/data'
    inventory=lab_inventory(io,'backup-probe')
    expected=[x for x in proof['original_inventory'] if (pod_key if x['resource']=='pods' else pvc_key) not in completed]
    io.require(inventory==expected,'Original remaining Pod/PVC inventory changed.')
    if pod_key not in completed:
        io.require(volume(io,'backup-probe')==proof['original'],'Original live volume binding changed.')
        if check_files:synthetic_files(io,'backup-probe',proof['expected_sha256'])
    if pvc_key not in completed:
        pvc=io.kube('persistentvolumeclaims','backup-probe','data')
        pv=io.kube('persistentvolumes','',proof['original']['pv']['name'])
        io.require(ident(io,pvc)==proof['original']['pvc'] and ident(io,pv)==proof['original']['pv'],
                   'Original PVC/PV replaced or changed before retirement.')
        volumes=json.loads(io.ops.run(['aws','ec2','describe-volumes','--volume-ids',proof['original']['volume_id'],'--region',proof['region']]))['Volumes']
        io.require(len(volumes)==1 and all(volumes[0].get(k)==v for k,v in proof['original_volume'].items()),'Original EBS identity changed.')


def verify_original_volume_absent(io,proof):
    """Observe the exact CSI reclaim; never issue an AWS delete or remove finalizers."""
    for _ in range(120):
        pv=io.kube('persistentvolumes','',proof['original']['pv']['name'],True)
        volumes=json.loads(io.ops.run(['aws','ec2','describe-volumes','--filters','Name=volume-id,Values='+proof['original']['volume_id'],'--region',proof['region']]))['Volumes']
        if pv is None and not volumes:
            retained_restore(io,proof)
            return
        if pv is not None:
            io.require(pv['metadata']['uid']==proof['original']['pv']['uid'],'Original PV replacement appeared during reclaim.')
        io.require(not volumes or (len(volumes)==1 and all(volumes[0].get(k)==v for k,v in proof['original_volume'].items())),
                   'Unexpected original volume identity during reclaim.')
        time.sleep(5)
    raise io.h.SafeError('Original synthetic PV/EBS reclaim incomplete; preserve marker, no forced deletion.')
