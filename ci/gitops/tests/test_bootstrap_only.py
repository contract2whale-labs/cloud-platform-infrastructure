import copy,json,os,pathlib,tempfile,unittest
from unittest.mock import patch
import gitops_ops as ops
import lifecycle_hooks as hooks

class BootstrapOnlyGitOps(unittest.TestCase):
    def config(self):
        return {'enabled':True,'operator_image':'example@sha256:'+'a'*64,'environments':{'dev':{'bootstrap_only':True,'role_arn':'arn:aws:iam::111111111111:role/cp-dev-gitops-apply','bootstrap_role_arn':'arn:aws:iam::111111111111:role/cp-dev-gitops-bootstrap','account_id':'111111111111','cluster':'owned','relay':'i-abc','applications':[],'authority_applications':[],'authority_children':{},'projects':[],'repository':'git@example'}}}
    def test_bootstrap_loads_without_future_apps_or_images(self):
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory);(base/'operations.json').write_text(json.dumps(self.config()))
            with patch.object(ops,'BASE',base):
                c=ops.load('dev','bootstrap');self.assertEqual(c['applications'],[])
                for operation in ('reconcile','verify'):
                    with self.assertRaises(ops.Blocked):ops.load('dev',operation)
            with self.assertRaises(ops.Blocked):ops.validate_authorities(c,'dev')
            self.assertEqual(ops.validate_authorities(c,'dev',allow_bootstrap_only=True),[])
    def test_empty_normal_or_populated_bootstrap_is_rejected(self):
        for change in ({'bootstrap_only':False},{'bootstrap_only':'true'},{'applications':[{}]},{'authority_applications':[{}]},{'authority_children':{'root':['future']}},{'projects':[{}]},{'rbac_applications':[{}]}):
            cfg=self.config();cfg['environments']['dev'].update(change)
            with tempfile.TemporaryDirectory() as directory:
                base=pathlib.Path(directory);(base/'operations.json').write_text(json.dumps(cfg))
                with patch.object(ops,'BASE',base),self.assertRaises(ops.Blocked):ops.load('dev','bootstrap')
    def test_core_retains_only_exact_bootstrap_chart_row(self):
        obj={'apiVersion':'v1','kind':'Secret','metadata':{'namespace':'argocd','name':'chart-secret','uid':'owned','labels':{'app.kubernetes.io/instance':'argocd'}},'data':{'key':'private'}}
        item={'gvr':'v1/secrets','resource':'secrets','base':'/api/v1','namespaced':True,'object':obj}
        config={'applications':[],'cluster_arn':'arn','cluster_created_at':'now','_bootstrap_residual_resources':[hooks.resource_row(item)]}
        with patch.dict(os.environ,{'LIFECYCLE_SNAPSHOT_SHA':'a'*40,'OPERATION':'down'}),patch.object(hooks,'velero_handoff',return_value={'residuals':[]}):
            result=hooks.residual_contract(config,[item],'1-1');self.assertEqual(result['approved_residuals'][0]['metadata_policy_sha256'],config['_bootstrap_residual_resources'][0]['metadata_policy_sha256'])
            foreign=copy.deepcopy(item);foreign['object']['metadata']['uid']='replaced'
            with self.assertRaises(hooks.HookBlocked):hooks.residual_contract(config,[foreign],'1-1')
            config['_bootstrap_residual_resources']=[]
            self.assertEqual(hooks.residual_contract(config,[item],'1-1')['approved_residuals'],[])

if __name__=='__main__':unittest.main()
