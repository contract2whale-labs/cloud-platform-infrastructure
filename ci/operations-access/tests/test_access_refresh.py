import copy,contextlib,hashlib,importlib.util,json,os,pathlib,tempfile,types,unittest
from unittest.mock import Mock,patch
BASE=pathlib.Path(__file__).resolve().parents[1]
ROOT=BASE.parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
m=load('protected_access_refresh',BASE/'install-rbac.py')
import lifecycle_hooks as hooks
import gitops_ops as ops
fixture=load('refresh_private_store',(ROOT/'test_vpc_lifecycle.py' if (ROOT/'test_vpc_lifecycle.py').is_file() else ROOT/'ci/test_vpc_lifecycle.py'))

@contextlib.contextmanager
def private(*args,**kwargs):yield {'KUBECONFIG':'private-test'}, {'arn':'arn','createdAt':'time'}

def obj(kind,name,namespace='argocd'):
    api='rbac.authorization.k8s.io/v1' if kind=='Role' else 'v1'
    return {'apiVersion':api,'kind':kind,'metadata':{'name':name,'namespace':namespace,'uid':name+'-uid','resourceVersion':'1'},**({'rules':[]} if kind=='Role' else {'data':{'policy.csv':'','policy.default':'','scopes':'[groups]','unrelated':'preserve'}})}

def row(value):
    resource={'Role':'roles','ConfigMap':'configmaps','Secret':'secrets','AppProject':'appprojects'}[value['kind']];gv=value['apiVersion']
    return hooks.resource_row({'gvr':gv+'/'+resource,'resource':resource,'base':'/api/v1' if gv=='v1' else '/apis/'+gv,'namespaced':True,'object':value})

class AccessRefresh(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=pathlib.Path(self.temp.name)
        self.role=obj('Role','generated-role');self.cm=obj('ConfigMap','argocd-rbac-cm');self.secret=obj('Secret','argocd-secret')
        (self.base/'admission.json').write_text(json.dumps({'items':[]}));(self.base/'rbac.json').write_text(json.dumps({'items':[self.role]}))
        self.c={'environment':'dev','account_id':'111111111111','cluster_arn':'arn','cluster_created_at':'time','bootstrap_chart_sha256':'chart','operator_image':'image','tool_sha256':{'kubectl':'hash'},'state_bucket':'private','region':'ap-northeast-2','cluster':'owned','relay':'i-abc','applications':[],'authority_applications':[],'projects':[]}
        toolhash=hashlib.sha256(json.dumps({'operator_image':self.c['operator_image'],'tool_sha256':self.c['tool_sha256']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.prior={'schema_version':1,'complete':True,'environment':'dev','account_id':self.c['account_id'],'cluster_arn':'arn','cluster_created_at':'time','chart_sha256':'chart','toolchain_sha256':toolhash,'access_config_sha256':'old','installer_residual_resources':[row(self.role)],'bootstrap_residual_resources':[row(x) for x in (self.role,self.cm,self.secret)]}
        self.store=fixture.Store();self.key=m.key_for('dev','arn','time');path=self.base/'old-proof';path.write_bytes(fixture.v.h.canonical(self.prior));self.descriptor=self.store.put(self.key,path)
        self.args=types.SimpleNamespace(previous_receipt_version=self.descriptor['version'],previous_receipt_sha256=self.descriptor['sha256'],expected_bundle_sha256='b'*64)
        self.fingerprints={'eks':'pinned','relay':'pinned'};self.adapter=types.SimpleNamespace(state=fixture.c,h=fixture.v.h,live_binding=Mock(return_value=(self.c,self.fingerprints)))
        self.operations=Mock();self.helper=types.SimpleNamespace(private_api=private)
        self.env={'GITHUB_REPOSITORY_ID':'1','GITHUB_RUN_ID':'2','GITHUB_SHA':'a'*40}
    def invoke(self):
        return m.refresh_access(self.args,self.base,{'config_sha256':'new'},self.c,self.store,self.adapter,'course',{'exists':False},None,self.fingerprints,self.helper,self.operations)
    def test_refresh_preserves_chart_and_credentials_advances_exact_receipt(self):
        updated_role=copy.deepcopy(self.role);updated_role['rules']=[{'apiGroups':[''],'resources':['pods'],'verbs':['get']}]
        updated_cm=copy.deepcopy(self.cm);updated_cm['data']['policy.csv']='new reviewed policy'
        with patch.dict(os.environ,self.env,clear=True),patch.object(hooks,'verify_resource_rows'),patch.object(m,'capture_installer_rows',return_value=[row(updated_role)]),patch.object(m,'refresh_argo_access',return_value={m.row_identity(row(updated_cm)):row(updated_cm)}),patch.object(m,'apply_generated_refresh') as generated,patch.object(m,'run') as command,patch('builtins.print'):
            self.invoke()
        generated.assert_called_once();command.assert_not_called();self.operations.bootstrap.assert_not_called()
        receipt=json.loads(self.store.objects[self.key][0]);self.assertEqual(receipt['previous_receipt'],self.descriptor);self.assertEqual(receipt['access_config_sha256'],'new')
        rows={m.row_identity(r):r for r in receipt['bootstrap_residual_resources']};self.assertEqual(rows[m.row_identity(row(self.secret))],row(self.secret));self.assertEqual(rows[m.row_identity(row(updated_cm))],row(updated_cm))
        marker=json.loads(self.store.objects[self.key.replace('/complete.json','/access-refresh.json')][0]);self.assertEqual(marker['phase'],'complete');self.assertEqual(marker['receipt']['version'],self.store.state(self.key)['version'])
        with patch.object(m,'run') as command,self.assertRaisesRegex(RuntimeError,'no longer current'):self.invoke()
        command.assert_not_called()
    def test_interrupted_refresh_cannot_retry_even_before_receipt(self):
        with patch.dict(os.environ,self.env,clear=True),patch.object(hooks,'verify_resource_rows'),patch.object(m,'apply_generated_refresh',side_effect=RuntimeError('interrupted')):
            with self.assertRaisesRegex(RuntimeError,'interrupted'):self.invoke()
        marker=json.loads(self.store.objects[self.key.replace('/complete.json','/access-refresh.json')][0]);self.assertEqual(marker['phase'],'refreshing')
        self.assertEqual(self.store.state(self.key)['version'],self.descriptor['version'])
        with patch.dict(os.environ,self.env,clear=True),patch.object(m,'run') as command,self.assertRaisesRegex(RuntimeError,'interrupted'):self.invoke()
        command.assert_not_called()
    def test_changed_old_object_blocks_before_marker_or_mutation(self):
        with patch.dict(os.environ,self.env,clear=True),patch.object(hooks,'verify_resource_rows',side_effect=RuntimeError('changed old row')),patch.object(m,'run') as command:
            with self.assertRaisesRegex(RuntimeError,'changed old row'):self.invoke()
            command.assert_not_called()
        self.assertFalse(self.store.state(self.key.replace('/complete.json','/access-refresh.json'))['exists'])
    def test_chart_cluster_toolchain_or_removed_existing_declaration_rejected(self):
        for key,value in [('cluster_arn','other'),('cluster_created_at','other'),('chart_sha256','new-chart'),('toolchain_sha256','new-toolchain')]:
            prior=copy.deepcopy(self.prior);prior[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):m.validate_refresh_scope(prior,self.c,self.base)
        (self.base/'rbac.json').write_text(json.dumps({'items':[]}))
        with self.assertRaisesRegex(RuntimeError,'only expands'):m.validate_refresh_scope(self.prior,self.c,self.base)
    def test_only_policy_csv_is_patched_with_uid_resourceversion_tests(self):
        updated=copy.deepcopy(self.cm);updated['data']['policy.csv']='';updated['metadata']['resourceVersion']='2'
        old={m.row_identity(row(self.cm)):row(self.cm)}
        with patch.object(m,'run',side_effect=[json.dumps(self.cm).encode(),b'{}',json.dumps(updated).encode()]) as command,patch.object(ops,'registered_projects',return_value=[]):
            changed=m.refresh_argo_access(self.c,old,{},hooks,ops)
        patch_ops=json.loads(command.call_args_list[1].args[0][-1])
        self.assertEqual([x['path'] for x in patch_ops],['/metadata/uid','/metadata/resourceVersion','/data/policy.csv'])
        self.assertEqual(changed[m.row_identity(row(self.cm))],row(updated))
    def test_unrelated_configmap_field_change_blocks_completion(self):
        changed=copy.deepcopy(self.cm);changed['data']['unrelated']='changed'
        with patch.object(m,'run',side_effect=[json.dumps(self.cm).encode(),b'{}',json.dumps(changed).encode()]),self.assertRaisesRegex(RuntimeError,'unrelated ConfigMap fields'):m.refresh_argo_access(self.c,{m.row_identity(row(self.cm)):row(self.cm)},{},hooks,ops)

    def test_generated_refresh_uses_uid_resourceversion_and_never_takes_over(self):
        import yaml
        prior={m.row_identity(row(self.role)):row(self.role)}
        with patch.object(m,'run',return_value=json.dumps(self.role).encode()):
            m.apply_generated_refresh(self.base,prior,{},hooks,self.operations)
        args=self.operations.run.call_args.args[0];body=yaml.safe_load(self.operations.run.call_args.kwargs['content'])
        self.assertEqual(args,['kubectl','apply','--server-side','--field-manager=course-operation-access','-f','-'])
        self.assertEqual(body['metadata']['uid'],self.role['metadata']['uid']);self.assertEqual(body['metadata']['resourceVersion'],'1')
        self.operations.reset_mock()
        changed=copy.deepcopy(self.role);changed['metadata']['uid']='foreign'
        with patch.object(m,'run',return_value=json.dumps(changed).encode()),self.assertRaisesRegex(RuntimeError,'another owner'):m.apply_generated_refresh(self.base,prior,{},hooks,self.operations)
        self.operations.run.assert_not_called()
        with patch.object(m,'run',return_value=b''),self.assertRaisesRegex(RuntimeError,'vanished'):m.apply_generated_refresh(self.base,prior,{},hooks,self.operations)
        self.operations.run.assert_not_called()
        with patch.object(m,'run',return_value=b''):m.apply_generated_refresh(self.base,{}, {},hooks,self.operations)
        self.assertEqual(self.operations.run.call_args.args[0],['kubectl','create','--field-manager=course-operation-access','-f','-'])
    def test_new_project_is_created_once_and_existing_unknown_project_blocked(self):
        project={'apiVersion':'argoproj.io/v1alpha1','kind':'AppProject','metadata':{'namespace':'argocd','name':'platform'},'spec':{'sourceRepos':['git@example'],'destinations':[{'server':'https://kubernetes.default.svc','namespace':'*'}]}}
        live=copy.deepcopy(project);live['metadata'].update(uid='new-project',resourceVersion='1')
        prior={m.row_identity(row(self.cm)):row(self.cm)};updated=copy.deepcopy(self.cm)
        with patch.object(m,'run',side_effect=[json.dumps(self.cm).encode(),b'{}',json.dumps(updated).encode(),b'',json.dumps(live).encode()]),patch.object(self.operations,'registered_projects',return_value=[project]):
            changed=m.refresh_argo_access(self.c,prior,{},hooks,self.operations)
        self.assertIn(('appprojects','argocd','platform'),changed);self.assertEqual(self.operations.run.call_args.args[0],['kubectl','create','-f','-'])
        self.operations.reset_mock()
        with patch.object(m,'run',side_effect=[json.dumps(self.cm).encode(),b'{}',json.dumps(updated).encode(),json.dumps(live).encode()]),patch.object(self.operations,'registered_projects',return_value=[project]),self.assertRaisesRegex(RuntimeError,'cannot be taken over'):m.refresh_argo_access(self.c,prior,{},hooks,self.operations)
        self.operations.run.assert_not_called()

if __name__=='__main__':unittest.main()
