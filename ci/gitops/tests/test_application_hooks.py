import importlib.util, pathlib, sys, unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import application_hooks as a

def item(kind,name,uid,owner=None,tracking=None,spec=None):
    md={'name':name,'uid':uid,'namespace':'monitoring'}
    if owner:md['ownerReferences']=[{'uid':owner,'name':'parent','kind':'Deployment'}]
    if tracking:md['annotations']={'argocd.argoproj.io/tracking-id':tracking+':'+kind+':monitoring/'+name}
    return {'gvr':'v1/items','resource':'items','base':'/api/v1','namespaced':True,'object':{'apiVersion':'v1','kind':kind,'metadata':md,'spec':spec or {}}}
class Tests(unittest.TestCase):
    def test_static_names(self):
        self.assertEqual(a.name_id('commerce-api-prod','prod'),'commerce-api')
        self.assertEqual(a.name_id('platform-monitoring-dev','dev'),'monitoring')
        with self.assertRaises(Exception):a.name_id('custom-admin-dev','dev')
    def test_owner_closure(self):
        x=[item('Deployment','d','1',tracking='platform-monitoring-dev'),item('ReplicaSet','r','2',owner='1'),item('Pod','p','3',owner='2')]
        self.assertEqual(len(a.ownership_closure('platform-monitoring-dev',x)),3)
    def test_data_never_boolean_bypass(self):
        x=[item('PersistentVolumeClaim','p','1',tracking='platform-monitoring-dev')]
        with self.assertRaises(Exception):a.child_rows('platform-monitoring-dev',x)
        self.assertEqual(len(a.child_rows('platform-monitoring-dev',x,volume_uids=['1'])),1)
    def test_namespace_requires_retention(self):
        x=[item('Namespace','app','1',tracking='platform-tenant-baseline-dev')]
        with self.assertRaises(Exception):a.child_rows('platform-tenant-baseline-dev',x)
        self.assertEqual(len(a.child_rows('platform-tenant-baseline-dev',x,True)),1)
    def test_external_secret_retains(self):
        x=[item('ExternalSecret','e','1',tracking='a',spec={'target':{'deletionPolicy':'Delete'}})]
        with self.assertRaises(Exception):a.child_rows('a',x)
    def test_real_prod_volume_reset_blocked(self):
        with self.assertRaises(Exception):a.volume_plan({'disposable_volumes':[{}],'environment_class':'production'},[])
    def test_job_command_and_completion(self):
        c={'completion':{'namespace':'app','application_image':'app@sha256:'+'a'*64}}
        job={'metadata':{'uid':'u'},'spec':{'template':{'spec':{'serviceAccountName':'delivery-migration','containers':[{'image':c['completion']['application_image'],'command':['./node_modules/.bin/medusa','db:migrate','--execute-safe-links']}]}}},'status':{'conditions':[{'type':'Complete','status':'True'}]}}
        with patch.object(a,'get',return_value=job):self.assertEqual(a.migration_complete(c)['job_uid'],'u')
        job['spec']['template']['spec']['containers'][0]['command']=['sh','-c','arbitrary']
        with patch.object(a,'get',return_value=job),self.assertRaises(Exception):a.migration_complete(c)
    def test_functional_db_seed_required(self):
        c={'completion':{'namespace':'app','seed_product_ids':['prod_1']}}
        with patch.object(a.ops,'run',side_effect=[b'OK',b'{"products":[{"id":"prod_1"}]}']):self.assertEqual(a.functional(c)['seed_product_ids'],['prod_1'])
        with patch.object(a.ops,'run',side_effect=[b'OK',b'{"products":[]}']),self.assertRaises(Exception):a.functional(c)
    def test_ebs_absence_requires_successful_empty(self):
        rows=[{'contract':{'volume_id':'vol-ab'}}]
        with patch.object(a.ops,'run',return_value=b'{"Volumes":[]}'):self.assertEqual(a.verify_volume_absence({'region':'x'},rows)['deleted_volume_ids'],['vol-ab'])
        with patch('time.sleep'),patch.object(a.ops,'run',return_value=b'{"Volumes":[{}]}'),self.assertRaises(Exception):a.verify_volume_absence({'region':'x'},rows)
class RetainedTests(unittest.TestCase):
    def config(self):
        record={'arn':'arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:AmazonMSK_demo-abc','version_id':'a'*64}
        return {'region':'ap-northeast-2','account_id':'123456789012','retained_credentials':{'queue-credentials-provision':{'reader':record,'writer':record}}}
    def test_current_metadata_only(self):
        c=self.config();r=c['retained_credentials']['queue-credentials-provision']['reader']
        response={'ARN':r['arn'],'Name':'AmazonMSK_demo','KmsKeyId':'arn:key','VersionIdsToStages':{r['version_id']:['AWSCURRENT']}}
        import json
        with patch.object(a.ops,'run',return_value=json.dumps(response).encode()) as run:
            self.assertTrue(a.retained_checks.credentials(c,'queue-credentials-provision',a)['reader']['current'])
            self.assertTrue(all(call.args[0][2]=='describe-secret' for call in run.call_args_list))
    def test_rotated_version_rejected(self):
        c=self.config();r=c['retained_credentials']['queue-credentials-provision']['reader']
        import json
        response={'ARN':r['arn'],'Name':'AmazonMSK_demo','KmsKeyId':'arn:key','VersionIdsToStages':{r['version_id']:['AWSPREVIOUS']}}
        with patch.object(a.ops,'run',return_value=json.dumps(response).encode()),self.assertRaises(Exception):a.retained_checks.credentials(c,'queue-credentials-provision',a)

class QueueTests(unittest.TestCase):
    def test_offsets_complete(self):
        self.assertEqual(a.queue.offsets(b't:0:3\nt:1:4\nt:2:5', 't', a),{0:3,1:4,2:5})
    def test_offsets_partial(self):
        with self.assertRaises(Exception):a.queue.offsets(b't:0:3\nt:1:4','t',a)
    def test_offsets_duplicate(self):
        with self.assertRaises(Exception):a.queue.offsets(b't:0:3\nt:0:4\nt:2:5','t',a)
    def test_lag_complete(self):
        data=b'GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG\nblock-builder t 0 2 2 0\nblock-builder t 1 3 3 0\nblock-builder t 2 4 4 0'
        self.assertEqual(a.queue.lag(data,'t','block-builder',a),{0:2,1:3,2:4})
    def test_lag_nonzero(self):
        data=b'GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG\nblock-builder t 0 2 3 1'
        with self.assertRaises(Exception):a.queue.lag(data,'t','block-builder',a)
    def test_lag_unknown(self):
        data=b'GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG\nblock-builder t 0 - 3 -'
        with self.assertRaises(Exception):a.queue.lag(data,'t','block-builder',a)
    def test_retirement_groups_disjoint(self):
        seen=set()
        for name,group in a.GROUPS.items():
            if name in a.OBSERVATIONS:continue
            self.assertFalse(seen & set(group),name)
            seen.update(group)
    def test_up_start_before_cluster(self):
        source=(ROOT/'application-lifecycle.py').read_text()
        self.assertLess(source.index("if stage=='start' and operation=='up':"),source.index('effective,fingerprints=live_binding'))
    def test_mutation_claim_before_hook(self):
        source=(ROOT/'application-lifecycle.py').read_text()
        self.assertLess(source.index("record['apply_claim']={k:context[k]"),source.index("result=hooks.down"))

if __name__=='__main__':unittest.main()
