import importlib.util,json,pathlib,sys,types,unittest
P=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(P))
import velero_ops as m
class VeleroTests(unittest.TestCase):
 def io(self,raw):
  def require(value,message):
   if not value:raise ValueError(message)
  return types.SimpleNamespace(require=require,ops=types.SimpleNamespace(run=lambda *a,**k:json.dumps(raw)))
 def backup(self):return {'apiVersion':'velero.io/v1','kind':'Backup','metadata':{'name':'platform-storage-probe','namespace':'velero','annotations':{'argocd.argoproj.io/sync-options':'Prune=confirm,Delete=confirm'}},'spec':{'includedNamespaces':['backup-probe'],'includedResources':['pods','persistentvolumeclaims','persistentvolumes'],'snapshotVolumes':True,'ttl':'24h'}}
 def test_exact_lab_backup(self):
  v,src=m.source(self.io(self.backup()),'backup',{'source_sha':'a'*40});self.assertEqual(v['spec']['includedNamespaces'],['backup-probe']);self.assertEqual(len(src['sha256']),64)
 def test_refuses_business_namespace(self):
  v=self.backup();v['spec']['includedNamespaces']=['contract2whale-demo']
  with self.assertRaisesRegex(ValueError,'differs'):m.source(self.io(v),'backup',{'source_sha':'a'*40})
 def test_refuses_full_cluster_backup(self):
  v=self.backup();v['spec'].pop('includedNamespaces')
  with self.assertRaises(ValueError):m.source(self.io(v),'backup',{'source_sha':'a'*40})
 def test_no_arbitrary_restore_mapping(self):
  v={'kind':'Restore','spec':{'namespaceMapping':{'backup-probe':'production'}}}
  with self.assertRaises(ValueError):m.source(self.io(v),'restore',{'source_sha':'a'*40})
 def test_bounded_ids(self):self.assertEqual(m.IDS,m.PROD_IDS);self.assertEqual(len(m.IDS),3)
if __name__=='__main__':unittest.main()
