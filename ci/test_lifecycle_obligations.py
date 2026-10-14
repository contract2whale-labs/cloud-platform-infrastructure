import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('obligations', Path(__file__).with_name('lifecycle-obligations.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def context(step='hook:out-of-state-pitr-inventory', operation='down', environment='dev'):
    return {'repository_id':'7','account':'123456789012','environment':environment,
            'backend':{'bucket':'state','region':'ap-northeast-2'}, 'step_id':step,'operation':operation,
            'generation':'3-1','snapshot_sha':'a'*40,'registry_sha256':'b'*64,'root':f'terraform/environments/{environment}/eks'}


class Store:
    bucket='state'
    def __init__(self, pages=()): self.pages=list(pages); self.calls=[]
    def call(self,*args): self.calls.append(args); return self.pages.pop(0)


class ObligationsTests(unittest.TestCase):
    def test_complete_paginated_inventory(self):
        s=Store([{'Contents':[{'Key':'prefix/a'}],'IsTruncated':True,'NextContinuationToken':'token'},
                 {'Contents':[{'Key':'prefix/b'}],'IsTruncated':False}])
        self.assertEqual(len(m.listing(s,'prefix/')),2)
        self.assertIn('--continuation-token',s.calls[1])

    def test_missing_completeness_fails(self):
        with self.assertRaises(m.h.SafeError):m.listing(Store([{'Contents':[]}]),'prefix/')

    def test_history_delete_marker_fails(self):
        with self.assertRaises(m.h.SafeError):m.listing(Store([{'Versions':[],'IsTruncated':False,'DeleteMarkers':[{}]}]),'prefix/',True)

    def test_repeated_page_token_fails(self):
        s=Store([{'IsTruncated':True,'NextContinuationToken':'same'},{'IsTruncated':True,'NextContinuationToken':'same'}])
        with self.assertRaises(m.h.SafeError):m.listing(s,'prefix/')

    def test_disabled_consumer_requires_empty_actual_state(self):
        ctx=context('hook:external-log-consumer-drain');root='terraform/environments/dev/account-integrations'
        course={'inputs':{root:{'enable_external_log_consumer':False}}}
        empty=lambda key:{'state':{'version':4,'resources':[]},'fingerprint':{'version':'s1'}}
        self.assertEqual(m.external_consumer(Store(),ctx,course,empty)['external_resources'],[])
        with patch.object(m.v,'managed_resources',return_value=[{'type':'aws_sqs_queue','name':'logs'}]):
            with self.assertRaises(m.h.SafeError):m.external_consumer(Store(),ctx,course,empty)

    def test_enabled_consumer_never_uses_empty_queue_as_drain(self):
        root='terraform/environments/dev/account-integrations'
        with self.assertRaisesRegex(m.h.SafeError,'Enabled external'):
            m.external_consumer(Store(),context(),{'inputs':{root:{'enable_external_log_consumer':True}}},lambda key:self.fail('no read may turn enabled into disabled'))

    def test_prod_pitr_is_explicit_source_scope(self):
        proof=m.pitr_inventory(Store(),context(environment='prod'))
        self.assertEqual(proof['clones'],[]);self.assertIn('Dev-only',proof['scope'])

    @patch.object(m, 'load', return_value=type('Retention', (), {'check_retention': staticmethod(lambda *a: None)})())
    def test_no_pitr_history_still_reads_and_rejects_unknown_tagged_clone(self, _):
        ctx=context();s=Store([{'Versions':[],'IsTruncated':False}])
        def aws(c,service,operation,field,*args):
            return [{'DBInstanceArn':'arn:clone'}] if field=='DBInstances' else [{'Key':'Purpose','Value':'incident-pitr-drill'}]
        with patch.object(m,'aws_list',side_effect=aws):
            with self.assertRaisesRegex(m.h.SafeError,'unaccounted'):m.pitr_inventory(s,ctx)

    @patch.object(m, 'load', return_value=type('Retention', (), {'check_retention': staticmethod(lambda *a: None)})())
    def test_pitr_accepted_only_marker_blocks(self, _):
        ctx=context();key='ci-lifecycle/7/dev/incident-aws-'+'0'*36+'.json'
        marker={'schema':1,'phase':'accepted-pending-observation','context':{'repository_id':'7','account':ctx['account'],'incident_run':'0'*36}}
        with patch.object(m,'listing',return_value=[{'Key':key,'VersionId':'v1','IsLatest':True}]),patch.object(m,'version_json',return_value=(marker,{})):
            with self.assertRaisesRegex(m.h.SafeError,'pending/uncertain'):m.pitr_inventory(Store(),ctx)

    @patch.object(m, 'load', return_value=type('Retention', (), {'check_retention': staticmethod(lambda *a: None)})())
    def test_pitr_old_create_cannot_be_hidden_by_latest_scram_marker(self, _):
        ctx=context();key='ci-lifecycle/7/dev/incident-aws-'+'0'*36+'.json'
        desc={'key':'ci-logs/7/1/1/'+'a'*40+'/dev/incident/rds-pitr-create/apply/receipt.json','version':'proof','sha256':'c'*64}
        base={'schema':1,'phase':'idle','context':{'repository_id':'7','account':ctx['account'],'incident_run':'0'*36}}
        old=copy.deepcopy(base);old['context']['operation']='rds-pitr-create';old['completion']=desc
        latest=copy.deepcopy(base);latest['context']['operation']='scram-admin-disassociate'
        receipt={'request':{'target_db_identifier':'clone'},'result':{'DBInstance':{'DBInstanceIdentifier':'clone','DBInstanceArn':'arn:clone','DbiResourceId':'db-1'}},'observations':{'status':'available'}}
        with patch.object(m,'listing',return_value=[{'Key':key,'VersionId':'v2','IsLatest':True},{'Key':key,'VersionId':'v1','IsLatest':False}]),patch.object(m,'version_json',side_effect=[(latest,{}),(old,{})]),patch.object(m,'fixed_receipt',return_value=(receipt,{})),patch.object(m,'aws_list',return_value=[]):
            with self.assertRaisesRegex(m.h.SafeError,'cleanup receipt'):m.pitr_inventory(Store(),ctx)

    def test_audit_never_claims_account_absence(self):
        ctx=context('hook:service-absence-audit','up')
        proof=m.aggregate(Store(),ctx,{'steps':['terraform/environments/dev/data'],'retained_roots':['terraform/environments/dev/retained/data']})
        self.assertFalse(proof['account_wide_absence']);self.assertEqual(proof['completed_roots'],[])

    def test_down_audit_requires_every_root_completed(self):
        course={'steps':['terraform/environments/dev/data'],'completed':[]}
        with self.assertRaises(m.h.SafeError):m.aggregate(Store(),context(operation='down'),course)

    def test_completion_cannot_promote_deferred_or_fake_all_absence(self):
        ctx=context();result={'checkpoint_generation':'3-1','semantic_contract':{},'no_cloud_mutation':True,'account_wide_absence':False,
                            'observation':{'incident':{'phase':'idle'},'details':{'deferred':True}}}
        with self.assertRaises(m.h.SafeError):m.validate_result(ctx['step_id'],'down',{},result,'3-1')
        result['observation']['details']={'clones':[],'unknown_tagged_clones':[]}
        m.validate_result(ctx['step_id'],'down',{},result,'3-1')
        result['account_wide_absence']=True
        with self.assertRaises(m.h.SafeError):m.validate_result(ctx['step_id'],'down',{},result,'3-1')

    def test_aliases_name_providers_not_shell_commands(self):
        self.assertEqual(m.ALIASES['minimum-argo-bootstrap']['provider_hooks'],['platform-core'])
        self.assertEqual(m.ALIASES['app-auth-provision-and-securitypolicy']['retained_roots'],['platform/app-auth'])
        self.assertFalse(any('command' in v for v in m.ALIASES.values()))

if __name__=='__main__':unittest.main()

class SemanticStagesTests(unittest.TestCase):
    def setUp(self):
        self.context={**context('hook:incident-quiescence-and-baseline'), 'sha':'c'*40,
                      'registration_sha256':'d'*64,'run_id':'4','run_attempt':'1','completed_chapter':'BU16',
                      'prefix':'ci-plans/7/4/1/'+'c'*40+'/dev/hooks/incident-quiescence-and-baseline/lifecycle-down/'}
        self.course={'roots':[],'retained_roots':[],'steps':[self.context['step_id']], 'inputs':{}}
        self.record=None;self.version=0;self.artifacts={};self.emissions=[]
        outer=self
        class MemoryStore:
            bucket='state'
            def put(self,key,path):
                if key in outer.artifacts:raise m.h.SafeError('immutable overwrite')
                raw=path.read_bytes();outer.artifacts[key]=raw
                return {'key':key,'version':'v1','sha256':m.h.digest(raw)}
            def get(self,d,path):
                raw=outer.artifacts[d['key']]
                m.h.require(m.h.digest(raw)==d['sha256'] and d['version']=='v1','artifact changed')
                path.write_bytes(raw)
        self.store=MemoryStore()
        self.patches=[patch.object(m,'settings',return_value=(self.store,'key',self.context,self.course)),
                      patch.object(m.c,'read_json',side_effect=lambda *a:(copy.deepcopy(self.record),self.info())),
                      patch.object(m.c,'update',side_effect=self.update),patch.object(m,'course_record',return_value=self.course),
                      patch.object(m,'observation',return_value={'incident':{'phase':'idle'},'details':{'scope':'fixed-owner'}}),
                      patch.object(m.h,'ensure_current_main'),patch.object(m.h,'emit',side_effect=self.emissions.append)]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])
    def info(self):return {'exists':bool(self.version),'version':str(self.version),'etag':str(self.version)}
    def update(self,store,key,record,previous):
        m.h.require(previous==self.info(),'CAS mismatch');self.record=copy.deepcopy(record);self.version+=1
        return self.info()
    def plan(self):
        m.run('start');m.run('plan');d=self.emissions[-1]
        env={'MANIFEST_KEY':d['manifest_key'],'MANIFEST_VERSION':d['manifest_version'],'EXPECTED_MANIFEST_SHA':d['manifest_sha'],'EXPECTED_PLAN_SHA':d['plan_sha']}
        return env
    def test_plan_verify_apply_receipt_and_no_replay(self):
        env=self.plan()
        with patch.dict(m.os.environ,env):
            version=self.version;m.run('verify');self.assertEqual(self.version,version)
            m.run('apply');self.assertEqual(self.record['last_result'],'down-complete')
            self.assertIn('receipt_key',self.emissions[-1])
            with self.assertRaises(m.h.SafeError):m.run('apply')
    def test_changed_plan_bytes_rejected(self):
        env=self.plan();key=self.context['prefix']+'actions.json';self.artifacts[key]=b'{}'
        with patch.dict(m.os.environ,env):
            with self.assertRaises(m.h.SafeError):m.run('apply')
        self.assertNotIn('last_result',self.record)
    def test_cas_change_between_plan_and_verify_blocks(self):
        env=self.plan();self.version+=1
        with patch.dict(m.os.environ,env):
            with self.assertRaises(m.h.SafeError):m.run('verify')
    def test_apply_failed_read_keeps_claimed_pause(self):
        env=self.plan()
        with patch.dict(m.os.environ,env),patch.object(m,'observation',side_effect=[{'incident':{'phase':'idle'},'details':{}},m.h.SafeError('AccessDenied')]):
            with self.assertRaises(m.h.SafeError):m.run('apply')
        self.assertEqual(self.record['last_result'],'down-applying');self.assertEqual(self.record['phase'],'paused')
        self.assertNotIn('receipt',self.record)
