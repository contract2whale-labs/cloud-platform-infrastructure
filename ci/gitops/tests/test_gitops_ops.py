import copy, contextlib, importlib.util, json, os, pathlib, tempfile, types, unittest
from unittest.mock import patch
p = pathlib.Path(__file__).resolve().parents[1] / 'gitops_ops.py'
spec = importlib.util.spec_from_file_location('gitops_ops', p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
REPO='git@github.com:example/cloud-platform-infrastructure.git'
def app():
    return {'apiVersion':'argoproj.io/v1alpha1','kind':'Application','metadata':{'name':'platform-cert-manager-dev','namespace':'argocd'},'spec':{'project':'platform','destination':{'server':'https://kubernetes.default.svc','namespace':'cert-manager'},'source':{'repoURL':REPO,'targetRevision':'a'*40,'path':'gitops/vendor/cert-manager'}}}
class Tests(unittest.TestCase):
    def test_registered(self): m.validate_app(app(),'dev',REPO)
    def test_mutable_revision(self):
        a=app();a['spec']['source']['targetRevision']='main'
        with self.assertRaises(m.Blocked):m.validate_app(a,'dev',REPO)
    def test_mutable_chart(self):
        a=app();a['spec']['source']['chart']='cert-manager'
        with self.assertRaises(m.Blocked):m.validate_app(a,'dev',REPO)
    def test_foreign_repository(self):
        with self.assertRaises(m.Blocked):m.validate_app(app(),'dev','https://evil.test/repo')
    def test_auto_sync(self):
        a=app();a['spec']['syncPolicy']={'automated':{}}
        with self.assertRaises(m.Blocked):m.validate_app(a,'dev',REPO)
    def test_finalizer(self):
        a=app();a['metadata']['finalizers']=['resources-finalizer.argocd.argoproj.io']
        with self.assertRaises(m.Blocked):m.validate_app(a,'dev',REPO)
    def test_no_arbitrary_app(self):
        a=app();a['metadata']['name']='shell-command'
        with self.assertRaises(m.Blocked):m.validate_app(a,'dev',REPO)
    def test_multisource_positions(self):
        a=app();src=a['spec'].pop('source');a['spec']['sources']=[src,dict(src,targetRevision='b'*40,ref='values')]
        self.assertEqual(m.revision_args(a),['--revisions','a'*40,'--source-positions','1','--revisions','b'*40,'--source-positions','2'])
    def test_image(self):
        m.validate_images({'spec':{'containers':[{'image':'repo/image@sha256:'+'b'*64}]}})
        with self.assertRaises(m.Blocked):m.validate_images({'spec':{'initContainers':[{'image':'repo/image:latest'}]}})
    def test_receipt_wrong_revision(self):
        a=app();live=copy.deepcopy(a);live['status']={'health':{'status':'Healthy'},'sync':{'status':'Synced'},'operationState':{'phase':'Succeeded','syncResult':{'revision':'b'*40}}}
        with self.assertRaises(m.Blocked):m.validate_receipt(live,a)
    def test_receipt_success(self):
        a=app();live=copy.deepcopy(a);live['status']={'health':{'status':'Healthy'},'sync':{'status':'Synced'},'operationState':{'phase':'Succeeded','syncResult':{'revision':'a'*40}}};m.validate_receipt(live,a)
    def test_disabled_before_subprocess(self):
        with patch.object(m.subprocess,'run') as call:
            with self.assertRaises(m.Blocked):m.load('dev','reconcile')
            call.assert_not_called()
    def test_terraform_addon_ownership(self):
        with self.assertRaises(m.Blocked):m.validate_ownership([{'kind':'DaemonSet','metadata':{'namespace':'kube-system','name':'aws-node'}}])
    def test_nested_app_authority(self):
        with self.assertRaises(m.Blocked):m.validate_ownership([{'kind':'AppProject','metadata':{'name':'unreviewed'}}])
    def test_actual_reconcile_sequence(self):
        a=app(); live=copy.deepcopy(a); live['status']={'health':{'status':'Healthy'},'sync':{'status':'Synced'},'operationState':{'phase':'Succeeded','syncResult':{'revision':'a'*40}}}
        c={'cluster':'cluster','relay':'i-123','region':'ap-northeast-2','applications':[a],'evidence_bucket':'private-bucket','evidence_kms_arn':'arn:aws:kms:region:account:key/id'}
        calls=[]
        def fake_run(args, **kwargs):
            calls.append(args)
            if args[:3]==['argocd','app','get']:return json.dumps(live).encode()
            if args[:3]==['argocd','app','manifests']:return b'kind: ConfigMap\nmetadata: {name: safe}\n'
            return b''
        @contextlib.contextmanager
        def private(*args):yield ({'KUBECONFIG':'/tmp/mock-kubeconfig'}, {})
        @contextlib.contextmanager
        def argo(*args):yield ['argocd']
        module=types.SimpleNamespace(private_api=private)
        fake_spec=types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda x:None))
        with tempfile.TemporaryDirectory() as d, patch.object(m,'verify_access'), patch.object(m,'validate_authorities',return_value=[]), patch.object(m,'own'), patch.object(m,'state_binding',return_value=(c,{})), patch.object(m,'normal_allowed'), patch.object(m,'current_main'), patch.object(m,'run',side_effect=fake_run), patch.object(m,'argo_connection',argo), patch.object(m.importlib.util,'spec_from_file_location',return_value=fake_spec), patch.object(m.importlib.util,'module_from_spec',return_value=module), patch.dict(os.environ,{'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'12','GITHUB_RUN_ATTEMPT':'1'}):
            m.execute(c,'dev','reconcile',pathlib.Path(d))
            self.assertTrue((pathlib.Path(d)/'receipt.json').exists())
        verbs=[x[2] for x in calls if x[:2]==['argocd','app']]
        self.assertEqual(verbs,['get','manifests','diff','sync','wait','get'])
        self.assertFalse(any('--prune' in x or '--resource' in x for x in calls))
    def test_no_shell(self):
        with patch.object(m.subprocess,'run') as call:
            call.return_value.returncode=0;call.return_value.stdout=b'';m.run(['argocd','app','get','fixed'])
            self.assertNotIn('shell',call.call_args.kwargs)
if __name__=='__main__':unittest.main()

class Authorities(unittest.TestCase):
    def config(self):
        leaf=app();root=copy.deepcopy(leaf);root['metadata']['name']='platform-root-dev';root['spec']['source']['path']='gitops/clusters/dev/platform-applications'
        return {'repository':REPO,'applications':[leaf],'authority_applications':[root],'authority_children':{'platform-root-dev':[leaf['metadata']['name']]}}
    def test_exact_root_child(self):
        c=self.config();self.assertEqual(len(m.validate_authorities(c,'dev')),1);m.validate_authority_render(c,c['authority_applications'][0],c['applications'])
    def test_unknown_child_rejected(self):
        c=self.config();foreign=copy.deepcopy(c['applications'][0]);foreign['metadata']['name']='foreign'
        with self.assertRaises(m.Blocked):m.validate_authority_render(c,c['authority_applications'][0],[foreign])
    def test_child_revision_drift_rejected(self):
        c=self.config();foreign=copy.deepcopy(c['applications'][0]);foreign['spec']['source']['targetRevision']='b'*40
        with self.assertRaises(m.Blocked):m.validate_authority_render(c,c['authority_applications'][0],[foreign])
    def test_cycle_rejected(self):
        c=self.config();c['authority_children']['platform-root-dev'].append('platform-root-dev')
        with self.assertRaises(m.Blocked):m.validate_authorities(c,'dev')
    def test_orphan_leaf_rejected(self):
        c=self.config();c['authority_children']['platform-root-dev']=[]
        with self.assertRaises(m.Blocked):m.validate_authorities(c,'dev')
