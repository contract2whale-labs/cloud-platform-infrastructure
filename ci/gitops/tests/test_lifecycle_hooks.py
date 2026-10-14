import copy, datetime as dt, importlib.util, json, pathlib, sys, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import lifecycle_hooks as m
class Tests(unittest.TestCase):
    def test_known_names_only(self):
        with self.assertRaises(m.HookBlocked):m.name_id('anything-dev','dev')
        self.assertEqual(m.name_id('platform-cert-manager-dev','dev'),'cert-manager')
    def test_dependency_order(self):
        c={'applications':[{'metadata':{'name':'platform-istiod-dev'}},{'metadata':{'name':'platform-istio-base-dev'}}]}
        with self.assertRaises(m.HookBlocked):m.inventory(c,'dev')
    def test_data_resource_block(self):
        for kind in ('PersistentVolumeClaim','Backup','Bucket','Kafka'):
            with self.assertRaises(m.HookBlocked):m.check_resources({'status':{'resources':[{'kind':kind}]}})
    def test_unknown_kind_block(self):
        with self.assertRaises(m.HookBlocked):m.check_resources({'status':{'resources':[{'kind':'CustomStorageDestroyer'}]}})
    def test_secret_digest_binds_data(self):
        a={'kind':'Secret','metadata':{'name':'x'},'data':{'x':'a'}};b=copy.deepcopy(a);b['data']['x']='b'
        self.assertNotEqual(m.object_digest(a),m.object_digest(b))
    def test_uid_bound_delete(self):
        row={'name':'platform-cert-manager-dev','uid':'original','spec':{'project':'platform'}}
        live={'metadata':{'uid':'original','resourceVersion':'3'},'spec':row['spec']}
        calls=[]
        with patch.object(m,'get_app',side_effect=[live,None]),patch.object(m.ops,'run',side_effect=lambda args,**k:calls.append(args) or b''):
            m.cascade(row)
        patch_payload=json.loads(calls[0][-1]);self.assertEqual(patch_payload[0],{'op':'test','path':'/metadata/uid','value':'original'})
        self.assertIn('--raw',calls[1]);self.assertFalse(any('--force' in x for x in calls))
    def test_replaced_app_no_delete(self):
        with patch.object(m,'get_app',return_value={'metadata':{'uid':'new'},'spec':{}}),patch.object(m.ops,'run') as call:
            with self.assertRaises(m.HookBlocked):m.cascade({'name':'platform-cert-manager-dev','uid':'old','spec':{}})
            call.assert_not_called()
    def test_foreign_finalizer_no_delete(self):
        row={'name':'platform-cert-manager-dev','uid':'uid','spec':{}}
        with patch.object(m,'get_app',return_value={'metadata':{'uid':'uid','resourceVersion':'3','finalizers':['unknown']},'spec':{}}),patch.object(m.ops,'run') as call:
            with self.assertRaises(m.HookBlocked):m.cascade(row)
            call.assert_not_called()
    def test_lb_wait_new_lb_blocks(self):
        with patch.object(m,'lbs',return_value=[{'arn':'new'}]):
            with self.assertRaises(m.HookBlocked):m.wait_lbs_absent({}, {'load_balancers':[{'arn':'old'}]})
    def test_lb_wait_empty(self):
        with patch.object(m,'lbs',return_value=[]):m.wait_lbs_absent({}, {'load_balancers':[]})
    def test_controller_cleanup_order(self):
        names=['platform-aws-load-balancer-controller-dev','platform-envoy-gateway-dev','platform-gateway-dev'];calls=[]
        snapshot={'applications':[{'name':n,'retained_until_cluster_deletion':False} for n in names]}
        with patch.object(m,'verify'),patch.object(m,'cascade',side_effect=lambda r:calls.append('delete:'+r['name'])),patch.object(m,'wait_lbs_absent',side_effect=lambda *a:calls.append('lb-empty')):
            m.down({},'dev',snapshot,'generation',lambda n:None)
        self.assertEqual(calls,['delete:platform-gateway-dev','lb-empty','delete:platform-envoy-gateway-dev','lb-empty','delete:platform-aws-load-balancer-controller-dev','lb-empty'])
    def test_resume_does_not_repeat_delete(self):
        snapshot={'applications':[{'name':'platform-cert-manager-dev','retained_until_cluster_deletion':False}]}
        with patch.object(m,'verify'),patch.object(m,'cascade') as delete,patch.object(m,'wait_lbs_absent'):
            m.down({},'dev',snapshot,'generation',lambda n:None,['platform-cert-manager-dev'])
            delete.assert_not_called()
if __name__=='__main__':unittest.main()
