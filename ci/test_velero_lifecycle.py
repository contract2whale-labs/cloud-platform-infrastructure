import copy
import importlib.util
import json
from pathlib import Path
import re
import types
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('velero_semantic_test',Path(__file__).with_name('velero-lifecycle.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    objects=[]
    def item(kind,resource,namespace,name,uid):
        obj={'apiVersion':'velero.io/v1' if kind=='Backup' else 'v1','kind':kind,'metadata':{'namespace':namespace,'name':name,'uid':uid,'resourceVersion':'1','annotations':{'existing':'yes'}},'spec':{'safe':True}}
        result={'resource':resource,'base':'/apis/velero.io/v1' if kind=='Backup' else '/api/v1','namespaced':bool(namespace),'gvr':'v1/'+resource,'object':obj}
        objects.append(result);return result
    def digest(x):return m.h.digest(m.h.canonical(x))
    def row(i):
        obj=i['object'];md=obj['metadata']
        return {k:i[k] for k in ('resource','base','namespaced','gvr')}|{'kind':obj['kind'],'namespace':md.get('namespace',''),'name':md['name'],'uid':md['uid'],'spec_sha256':digest({k:v for k,v in obj.items() if k not in ('metadata','status')}),'metadata_policy_sha256':digest({k:md.get(k) for k in ('labels','annotations','finalizers','ownerReferences')})}
    original=item('Pod','pods','backup-probe','writer','pod1');pvc1=item('PersistentVolumeClaim','persistentvolumeclaims','backup-probe','data','pvc1')
    restored=item('Pod','pods','backup-probe-restored','writer','pod2');pvc2=item('PersistentVolumeClaim','persistentvolumeclaims','backup-probe-restored','data','pvc2')
    metadata=item('Backup','backups','velero','platform-storage-probe','backup')
    after=row(dict(metadata,object=m.retained_metadata(metadata['object'])))
    snap={'SnapshotId':'snap-123','VolumeId':'vol-1','OwnerId':'123456789012','VolumeSize':1,'StartTime':'2026-10-01T00:00:00Z'}
    snapshot={'delete':[row(i)|{'resource_version':'1'} for i in (original,pvc1,restored,pvc2)],
              'metadata':[{'before':row(metadata),'after':after,'resource_version':'1','before_annotations':{'existing':'yes'},'after_annotations':{'existing':'yes','argocd.argoproj.io/sync-options':'Delete=false'}}],
              'target':{'snapshot':snap,'original':{'volume_id':'vol-1','pv':{'uid':'pv1'}},'restored':{'volume_id':'vol-2','pv':{'uid':'pv2'}}}}
    context={'account':'123456789012','backend':{'region':'ap-northeast-2'}}
    calls=[]
    def run(args):
        calls.append(args)
        if 'patch' in args:
            obj=next(x['object'] for x in objects if x['object']['kind']=='Backup')
            operations=json.loads(args[-1]);obj['metadata']['annotations']=operations[-1]['value'];obj['metadata']['resourceVersion']='2';return b'{}'
        if args[1]=='delete':
            path=args[3];idx=next(n for n,x in enumerate(objects) if path.endswith('/'+x['resource']+'/'+x['object']['metadata']['name']) and '/namespaces/'+x['object']['metadata']['namespace']+'/' in path)
            objects.pop(idx);return b'{}'
        ns=args[2];resource=args[4].removesuffix('.velero.io');name=args[5]
        found=next((x['object'] for x in objects if x['resource']==resource and x['object']['metadata']['namespace']==ns and x['object']['metadata']['name']==name),None)
        return json.dumps(found).encode() if found else b''
    core=types.SimpleNamespace(resource_row=row,api_inventory=lambda:copy.deepcopy(objects),object_digest=lambda obj:digest({k:v for k,v in obj.items() if k not in ('metadata','status')}),ops=types.SimpleNamespace(run=run))
    def aws(context,service,operation,field,*args):
        if field=='Snapshots':return [snap|{'State':'completed','Tags':[{'Key':'velero.io/backup','Value':'platform-storage-probe'}]}]
        if field=='Volumes':return []
        raise AssertionError((service,operation))
    return snapshot,context,core,calls,objects,aws


class VeleroLifecycleTests(unittest.TestCase):
    def setUp(self):
        patcher=patch.object(m,"verify_content");patcher.start();self.addCleanup(patcher.stop)
    def test_retention_patch_preserves_unrelated_annotations(self):
        obj={'metadata':{'annotations':{'foo':'bar','argocd.argoproj.io/sync-options':'Prune=confirm,Delete=confirm,ServerSideApply=true'}}}
        after=m.retained_metadata(obj)
        self.assertEqual(after['metadata']['annotations']['foo'],'bar')
        self.assertEqual(after['metadata']['annotations']['argocd.argoproj.io/sync-options'],'Prune=confirm,ServerSideApply=true,Delete=false')
        self.assertIn('Delete=confirm',obj['metadata']['annotations']['argocd.argoproj.io/sync-options'])
    def test_old_snapshot_is_retained_without_replaying_backup(self):
        snapshot,ctx,core,calls,objects,aws=fixture()
        with patch.object(m.s,'aws_list',side_effect=aws):result=m.verify_snapshot_cloud(snapshot,ctx)
        self.assertIsNone(result['age_limit']);self.assertEqual(result['snapshot_id'],'snap-123');self.assertEqual(calls,[])
    def test_missing_snapshot_tag_blocks(self):
        snapshot,ctx,*_=fixture()
        live=snapshot['target']['snapshot']|{'State':'completed','Tags':[]}
        with patch.object(m.s,'aws_list',return_value=[live]):
            with self.assertRaises(m.h.SafeError):m.verify_snapshot_cloud(snapshot,ctx)
    def test_snapshot_identity_replacement_blocks(self):
        snapshot,ctx,core,calls,objects,aws=fixture()
        live=snapshot['target']['snapshot']|{'State':'completed','VolumeId':'foreign'}
        with patch.object(m.s,'aws_list',return_value=[live]):
            with self.assertRaises(m.h.SafeError):m.verify_snapshot_cloud(snapshot,ctx)
    def test_exact_cleanup_metadata_then_both_pods_then_claims(self):
        snapshot,ctx,core,calls,objects,aws=fixture();progress=[]
        with patch.object(m.s,'aws_list',side_effect=aws),patch.object(m.time,'sleep',side_effect=AssertionError('no waits expected')):
            result=m.apply_cleanup(snapshot,ctx,core,lambda a,b:progress.append((list(a),list(b))))
        deletes=[x for x in calls if x[:2]==['kubectl','delete']]
        self.assertEqual(len(deletes),4)
        self.assertTrue(all('/pods/' in x[3] for x in deletes[:2]))
        self.assertTrue(all('/persistentvolumeclaims/' in x[3] for x in deletes[2:]))
        self.assertEqual(result['deleted_volume_ids'],['vol-1','vol-2'])
        self.assertEqual(result['approved_residuals'][0]['uid'],'backup')
        self.assertFalse(any('delete-snapshot' in x or 'delete-object' in x for x in calls))
        self.assertEqual(len(objects),1)
        self.assertEqual(set(progress[-1][0]),{'pod1','pod2','pvc1','pvc2'})
    def test_changed_synthetic_target_blocks_before_any_patch(self):
        snapshot,ctx,core,calls,objects,aws=fixture();objects[0]['object']['metadata']['uid']='replacement'
        with patch.object(m.s,'aws_list',side_effect=aws):
            with self.assertRaises(m.h.SafeError):m.apply_cleanup(snapshot,ctx,core,lambda a,b:None)
        self.assertEqual(calls,[])
    def test_unknown_metadata_change_blocks(self):
        snapshot,ctx,core,calls,objects,aws=fixture();objects[-1]['object']['metadata']['annotations']['foreign']='yes'
        with self.assertRaises(m.h.SafeError):m.verify_live(snapshot,objects,core)
    def test_up_never_claims_exercise_replay(self):
        snapshot,ctx,*_=fixture()
        result={'checkpoint_generation':'3-1','retained_snapshot':{'snapshot_id':'snap-123','status':'retained'},'backup_exercise_replayed':False}
        m.validate_result(m.STEP,'up',snapshot,result,'3-1')
        result['backup_exercise_replayed']=True
        with self.assertRaises(m.h.SafeError):m.validate_result(m.STEP,'up',snapshot,result,'3-1')
    def test_incomplete_volume_cleanup_cannot_complete(self):
        snapshot,ctx,*_=fixture()
        result={'checkpoint_generation':'3-1','retained_snapshot':{'snapshot_id':'snap-123','status':'retained'},'deleted_pod_pvc_uids':['pod1','pod2','pvc1','pvc2'],'deleted_volume_ids':['vol-1']}
        with self.assertRaises(m.h.SafeError):m.validate_result(m.STEP,'down',snapshot,result,'3-1')
    def test_recovery_requires_previous_owner_completed(self):
        record={'apply_claim':{'run_id':'2'},'original':{},'completed':[],'patched':[]}
        with patch.object(m.h,'required',return_value='owner/repo'),patch.object(m.h,'execute',return_value=b'{"id":2,"repository":{"id":7},"status":"in_progress"}'):
            with self.assertRaises(m.h.SafeError):m.recover_claim(record,{'repository_id':'7'})
        self.assertIn('apply_claim',record)

if __name__=='__main__':unittest.main()

class VeleroPlanningTests(unittest.TestCase):
    def fixture(self):
        snap,ctx,core,calls,objects,aws=fixture()
        ctx.update(environment='dev',generation='4-1',snapshot_sha='a'*40,repository_id='7')
        def ident(obj):return {'uid':obj['metadata']['uid'],'name':obj['metadata']['name'],'namespace':obj['metadata'].get('namespace','')}
        target={'account':ctx['account'],'region':'ap-northeast-2','snapshot':snap['target']['snapshot'],'expected_sha256':'f'*64}
        for field,ns,number in (('original','backup-probe',1),('restored','backup-probe-restored',2)):
            pod=next(x['object'] for x in objects if x['object']['kind']=='Pod' and x['object']['metadata']['namespace']==ns)
            pvc=next(x['object'] for x in objects if x['object']['kind']=='PersistentVolumeClaim' and x['object']['metadata']['namespace']==ns)
            pv={'apiVersion':'v1','kind':'PersistentVolume','metadata':{'name':'pv'+str(number),'uid':'pv'+str(number),'resourceVersion':'1'},
                'spec':{'persistentVolumeReclaimPolicy':'Delete','claimRef':{'uid':pvc['metadata']['uid']},'csi':{'driver':'ebs.csi.aws.com','volumeHandle':'vol-'+str(number)}}}
            objects.append({'resource':'persistentvolumes','base':'/api/v1','namespaced':False,'gvr':'v1/persistentvolumes','object':pv})
            target[field]={'pod':ident(pod),'pvc':ident(pvc),'pv':ident(pv),'volume_id':'vol-'+str(number)}
        objects[4]['object']['status']={'phase':'Completed'}
        target['backup']=ident(objects[4]['object'])
        for kind,resource,name,spec in [('Restore','restores','platform-storage-probe',{'backupName':'platform-storage-probe'}),
          ('Schedule','schedules','platform-daily',{'paused':True}),
          ('BackupStorageLocation','backupstoragelocations','default',{'provider':'aws','objectStorage':{'bucket':'course-backup','prefix':'backups'}}),
          ('VolumeSnapshotLocation','volumesnapshotlocations','default',{'provider':'aws'})]:
            obj={'apiVersion':'velero.io/v1','kind':kind,'metadata':{'name':name,'namespace':'velero','uid':kind,'resourceVersion':'1','annotations':{}},'spec':spec,'status':{'phase':'Completed'}}
            objects.append({'resource':resource,'base':'/apis/velero.io/v1','namespaced':True,'gvr':'velero.io/v1/'+resource,'object':obj})
            if kind=='Restore':target['restore']=ident(obj)
        config={'cluster_arn':'arn:eks','cluster_created_at':'2026-10-01T00:00:00Z'}
        proof={'receipt':{'result':{'velero_target':target}}}
        def api(context,service,operation,field,*args):
            if field=='Volumes':return [{'VolumeId':args[-1],'CreateTime':'2026-10-01T00:00:00Z','AvailabilityZone':'ap-northeast-2a','Size':1,'VolumeType':'gp3','Encrypted':True,'KmsKeyId':'key','SnapshotId':''}]
            return aws(context,service,operation,field,*args)
        protection={'object_policy':{'Resource':'arn:aws:s3:::course-backup/backups/backups/platform-storage-probe/*'}}
        return config,ctx,objects,types.SimpleNamespace(identity=ident),core,proof,api,protection
    def test_initial_plan_captures_exact_two_pairs_and_five_metadata_kinds(self):
        config,ctx,objects,incident,core,proof,api,protection=self.fixture()
        with patch.object(m,'restore_receipt',return_value=proof),patch.object(m,'source_retention',return_value=protection),patch.object(m.s,'aws_list',side_effect=api):
            snapshot=m.build_snapshot(config,ctx,None,objects,incident,core)
        self.assertEqual(len(snapshot['delete']),4)
        self.assertEqual({x['before']['kind'] for x in snapshot['metadata']},m.META_KINDS)
        self.assertFalse(snapshot['continuation'])
        self.assertNotIn('aws_identity',proof['receipt']['result']['velero_target']['original'])
    def test_active_schedule_blocks_snapshot_before_any_deletion(self):
        config,ctx,objects,incident,core,proof,api,protection=self.fixture()
        next(x['object'] for x in objects if x['object']['kind']=='Schedule')['spec']['paused']=False
        with patch.object(m,'restore_receipt',return_value=proof),patch.object(m,'source_retention',return_value=protection),patch.object(m.s,'aws_list',side_effect=api):
            with self.assertRaisesRegex(m.h.SafeError,'Unpaused'):m.build_snapshot(config,ctx,None,objects,incident,core)
    def test_unknown_csi_snapshot_path_blocks(self):
        config,ctx,objects,incident,core,proof,api,protection=self.fixture()
        objects.append({'object':{'kind':'VolumeSnapshotContent','metadata':{'uid':'foreign','name':'foreign'}}})
        with patch.object(m,'restore_receipt',return_value=proof),patch.object(m,'source_retention',return_value=protection),patch.object(m.s,'aws_list',side_effect=api):
            with self.assertRaisesRegex(m.h.SafeError,'CSI'):m.build_snapshot(config,ctx,None,objects,incident,core)
    def test_wrong_retained_bucket_policy_blocks(self):
        config,ctx,objects,incident,core,proof,api,protection=self.fixture();protection['object_policy']['Resource']='arn:aws:s3:::other/backups/backups/platform-storage-probe/*'
        with patch.object(m,'restore_receipt',return_value=proof),patch.object(m,'source_retention',return_value=protection),patch.object(m.s,'aws_list',side_effect=api):
            with self.assertRaisesRegex(m.h.SafeError,'another storage'):m.build_snapshot(config,ctx,None,objects,incident,core)
    def test_second_down_reuses_old_proof_and_only_fresh_original_pair(self):
        config,ctx,objects,incident,core,proof,api,protection=self.fixture()
        with patch.object(m,'restore_receipt',return_value=proof),patch.object(m,'source_retention',return_value=protection),patch.object(m.s,'aws_list',side_effect=api):
            first=m.build_snapshot(config,ctx,None,objects,incident,core)
        previous={'original':first,'receipt':{'key':'old','version':'v1','sha256':'b'*64},'request_context':{'old':'owner'},'operation':'up','last_result':'up-complete','generation':'4-1'}
        receipt={'kind':'gitops-lifecycle-completion','context':previous['request_context'],'result':{'checkpoint_generation':'4-1','retained_snapshot':{'snapshot_id':'snap-123','status':'retained'},'backup_exercise_replayed':False}}
        objects[:]=[x for x in objects if x['object']['metadata'].get('namespace')!='backup-probe-restored' and x['object']['metadata']['uid']!='pv2' and x['object']['kind']!='Restore']
        current=copy.deepcopy(first['target']['original']);current.pop('aws_identity',None);current.pop('pv_row',None)
        incident.fixture_io=lambda:None
        adapter=types.SimpleNamespace(volume=lambda *a:current,lab_inventory=lambda *a:[])
        core.ops.run=lambda *a:b''
        with patch.object(m.s,'read',return_value=receipt),patch.object(m,'load',return_value=adapter),patch.object(m,'source_retention',return_value=protection),patch.object(m.s,'aws_list',side_effect=api):
            second=m.build_snapshot(config,ctx,None,objects,incident,core,previous)
        self.assertTrue(second['continuation']);self.assertEqual(len(second['delete']),2);self.assertNotIn('restored',second['target'])
