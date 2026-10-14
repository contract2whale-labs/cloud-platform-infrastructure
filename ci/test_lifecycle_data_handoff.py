import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('handoff',Path(__file__).with_name('lifecycle-data-handoff.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class DataHandoffTests(unittest.TestCase):
    def setUp(self):
        self.owner='hook:platform-observability';self.current='hook:platform-core'
        self.context={'repository_id':'7','environment':'dev','account':'123456789012','generation':'2-1','source_sha':'a'*40,'lifecycle_registry_sha256':'b'*64,'backend':{'region':'ap-northeast-2'}}
        self.pvc={'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':'grafana','namespace':'monitoring','uid':'pvc'},'spec':{'volumeName':'pv'}}
        self.pv={'apiVersion':'v1','kind':'PersistentVolume','metadata':{'name':'pv','uid':'pv'},'spec':{'persistentVolumeReclaimPolicy':'Delete','claimRef':{'uid':'pvc','name':'grafana','namespace':'monitoring'},'csi':{'driver':'ebs.csi.aws.com','volumeHandle':'vol-abc'}}}
        self.objects=[{'object':self.pvc},{'object':self.pv}]
        self.volume={'contract':{'approved_reset':True,'source_sha':'a'*40,'restore_mode':'git-provisioned-grafana','namespace':'monitoring','pvc':'grafana','volume_id':'vol-abc'},'pvc_uid':'pvc','pv_uid':'pv','pv_name':'pv','pvc_spec_sha256':m.body_hash(self.pvc),'pv_spec_sha256':m.body_hash(self.pv),'volume_identity':{'VolumeId':'vol-abc','Encrypted':True},'tags':{'pvc':'grafana'}}
        self.snapshot={'disposable_volumes':[self.volume],'registry_sha256':'c'*64,'checkpoint_generation':'2-1','account_id':self.context['account'],'environment':'dev','cluster_arn':'arn:eks'}
        self.marker={'schema':1,'step_id':self.owner,'operation':'down','generation':'2-1','snapshot_sha':'a'*40,'registration_sha256':'c'*64,'original':self.snapshot,
          'request_context':{'repository_id':'7','account':self.context['account'],'environment':'dev','step_id':self.owner,'operation':'down','snapshot_sha':'a'*40,'generation':'2-1','registry_sha256':'b'*64}}
        self.live=[{'VolumeId':'vol-abc','Encrypted':True,'Tags':[{'Key':'pvc','Value':'grafana'}]}]
    def test_exact_source_owned_volume_is_provisional(self):
        with patch.object(m,'volume_response',return_value=self.live):
            self.assertEqual(m.match_live(self.snapshot,self.objects,self.context,self.owner),{'pvc','pv'})
    def test_pvc_same_name_replacement_is_rejected(self):
        self.pvc['metadata']['uid']='replacement'
        with patch.object(m,'volume_response',return_value=self.live):
            with self.assertRaises(m.h.SafeError):m.match_live(self.snapshot,self.objects,self.context,self.owner)
    def test_pv_claim_or_reclaim_change_is_rejected(self):
        self.pv['spec']['persistentVolumeReclaimPolicy']='Retain'
        with patch.object(m,'volume_response',return_value=self.live):
            with self.assertRaises(m.h.SafeError):m.match_live(self.snapshot,self.objects,self.context,self.owner)
    def test_ebs_incarnation_change_is_rejected(self):
        self.live[0]['VolumeId']='vol-foreign'
        with patch.object(m,'volume_response',return_value=self.live):
            with self.assertRaises(m.h.SafeError):m.match_live(self.snapshot,self.objects,self.context,self.owner)
    def test_foreign_generation_or_registration_marker_rejected(self):
        for field,value in [('generation','9-1'),('registration_sha256','d'*64)]:
            marker=copy.deepcopy(self.marker);marker[field]=value
            with self.assertRaises(m.h.SafeError):m.validate_owner(marker,self.context,self.owner)
    def run_approved(self,stage,completed=(),selected=True,objects=None):
        config={'environment':'dev','account_id':self.context['account'],'state_bucket':'state','region':'ap-northeast-2','cluster_arn':'arn:eks'}
        course={'phase':'paused','operation':'down','generation':'2-1','snapshot_sha':'a'*40,'registry_sha256':'b'*64,'steps':[self.current]+([self.owner] if selected else []),'completed':list(completed)}
        required={'GITHUB_REPOSITORY_ID':'7','LIFECYCLE_GENERATION':'2-1','LIFECYCLE_SNAPSHOT_SHA':'a'*40,'LIFECYCLE_CONFIG_SHA256':'b'*64,'LIFECYCLE_STEP_ID':self.current}
        read=lambda store,key:(course if key.endswith('/course.json') else self.marker,{'version':'v1'})
        with patch.object(m.h,'required',side_effect=lambda key:required[key]),patch.object(m.h,'Store'),patch.object(m.c,'read_json',side_effect=read),patch.object(m.c,'validate_course'),patch.object(m,'volume_response',return_value=self.live):
            return m.approved(config,self.objects if objects is None else objects,stage)
    def test_unselected_owner_grants_no_data_exception(self):
        self.assertEqual(self.run_approved('start',selected=False),[])
    def test_start_needs_only_owned_selected_checkpoint(self):
        self.assertEqual(self.run_approved('start'),['pv','pvc'])
    def test_plan_requires_exact_saved_owner_descriptor(self):
        with self.assertRaises(Exception):self.run_approved('plan')
    def test_core_apply_never_accepts_provisional_marker(self):
        with self.assertRaisesRegex(m.h.SafeError,'completion'):self.run_approved('apply')
    def test_completed_owner_needs_authenticated_receipt_and_live_absence(self):
        self.live=[]
        with patch.object(m.b,'for_consumer',return_value={'volumes':{'deleted_volume_ids':['vol-abc']}}) as check:
            self.assertEqual(self.run_approved('apply',completed=[self.owner],objects=[]),[])
            self.assertEqual(check.call_args.kwargs['step'],self.owner)
        self.live=[{'VolumeId':'vol-abc'}]
        with patch.object(m.b,'for_consumer',return_value={}):
            with self.assertRaisesRegex(m.h.SafeError,'EBS'):self.run_approved('apply',completed=[self.owner],objects=[])

if __name__=='__main__':unittest.main()
