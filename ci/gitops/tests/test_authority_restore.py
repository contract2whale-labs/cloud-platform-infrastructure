import contextlib,copy,importlib.util,json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
BASE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
import lifecycle_hooks as h,gitops_ops as o
REPO='git@github.com:example/infra.git'
def app(name):return {'apiVersion':'argoproj.io/v1alpha1','kind':'Application','metadata':{'name':name,'namespace':'argocd'},'spec':{'project':'platform','source':{'repoURL':REPO,'targetRevision':'a'*40,'path':'gitops/fixed'},'destination':{'server':'https://kubernetes.default.svc','namespace':'argocd'}}}
class Restore(unittest.TestCase):
 def fixture(self):
  root=app('platform-root-dev');leaf=app('platform-cert-manager-dev')
  snap={'authorities':[{'name':root['metadata']['name'],'uid':'old-root','spec':root['spec'],'desired':root}],'authority_children':{'platform-root-dev':['platform-cert-manager-dev']},'registered_applications':[leaf]}
  c={'repository':REPO,'applications':[leaf],'authority_applications':[root],'authority_children':snap['authority_children']};return c,snap,root,leaf
 def test_only_root_syncs_no_leaf_apply(self):
  c,snap,root,leaf=self.fixture();live={x['metadata']['name']:copy.deepcopy(x) for x in (root,leaf)}
  for x in live.values():x['metadata']['uid']='new-'+x['metadata']['name']
  done=copy.deepcopy(root);done['status']={'sync':{'status':'Synced'},'operationState':{'phase':'Succeeded','syncResult':{'revision':'a'*40}}}
  calls=[]
  def run(argv,**kw):
   calls.append(argv)
   if 'manifests' in argv:return json.dumps(leaf).encode()
   if argv[:3]==['argocd','app','get']:return json.dumps(done).encode()
   return b''
  @contextlib.contextmanager
  def argo(*a):yield ['argocd']
  with tempfile.TemporaryDirectory() as d,patch.object(h,'get_app',side_effect=lambda name:live.get(name)),patch.object(o,'run',side_effect=run),patch.object(o,'argo_connection',argo):h.restore_authorities(c,'dev',snap,pathlib.Path(d))
  self.assertEqual([x[3] for x in calls if x[:3]==['argocd','app','sync']],['platform-root-dev']);self.assertFalse(any(x[:2]==['kubectl','apply'] for x in calls));self.assertFalse(any('--prune' in x for x in calls))
 def test_automated_leaf_blocks_before_mutation(self):
  c,snap,root,leaf=self.fixture();leaf['spec']['syncPolicy']={'automated':{}}
  with patch.object(o,'run') as run:
   with self.assertRaises(o.Blocked):h.restore_authorities(c,'dev',snap,pathlib.Path('/tmp'))
   run.assert_not_called()
 def test_changed_retained_root_blocks_down(self):
  c,snap,root,leaf=self.fixture();live=copy.deepcopy(root);live['metadata']['uid']='replacement'
  with patch.object(h,'get_app',return_value=live):
   with self.assertRaises(h.HookBlocked):h.verify_authorities(snap)
