import copy, importlib.util, json, pathlib, types, unittest
from unittest.mock import patch
P=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('platform_probe_ops',P/'platform_probe_ops.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ProbeTests(unittest.TestCase):
 def test_ids_are_finite_and_environment_scoped(self):
  self.assertEqual(len(m.IDS),13);self.assertNotIn('mesh-probes-create',m.PROD_IDS)
 def test_source_commands_not_normalized(self):
  a=m.template('seed-dev');b=copy.deepcopy(a);b[0]['spec']['template']['spec']['containers'][0]['command']=['rm','-rf','/']
  self.assertNotEqual(m.normalized(a),m.normalized(b))
 def test_only_reviewed_image_is_variable(self):
  a=m.template('mesh');b=copy.deepcopy(a);b[0]['spec']['template']['spec']['containers'][0]['image']='other@sha256:'+'a'*64
  self.assertEqual(m.normalized(a),m.normalized(b))
 def test_metadata_owner_not_normalized(self):
  a=m.template('seed-prod');b=copy.deepcopy(a);b[0]['metadata']['ownerReferences']=[{'uid':'foreign'}]
  self.assertNotEqual(m.normalized(a),m.normalized(b))
 def test_source_preserves_seed_readonly_and_exact_sql(self):
  for env in ('dev','prod'):
   c=m.template('seed-'+env)[0]['spec']['template']['spec']['containers'][0]
   self.assertIn('default_transaction_read_only=on',str(c['env']))
   self.assertIn('select count(*) from product',(' '.join(c['command'])))
   self.assertIn("type = 'publishable'",(' '.join(c['command'])))
 def test_source_true_resource_kinds(self):
  self.assertEqual(m.template('collection')[0]['kind'],'Deployment')
  self.assertEqual(m.template('notification')[0]['kind'],'PrometheusRule')
 def test_mesh_snapshot_uses_source_and_digest(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  docs=m.template('mesh');calls=[]
  def run(args,**kw):calls.append(args);return '\n---\n'.join(json.dumps(x) for x in docs)
  def kube(kind,ns,name,optional=False):
   if kind=='namespaces':return {'metadata':{'uid':'namespace-'+name,'name':name}}
   return None
  io=types.SimpleNamespace(require=require,ops=types.SimpleNamespace(run=run,DIGEST=__import__('re').compile(r'.+@sha256:[0-9a-f]{64}')),kube=kube,identity=lambda o:o['metadata'])
  request={'source_sha':'a'*40,'experiment_id':'00000000-0000-4000-8000-000000000001'}
  config={'environment':'dev','platform_probe_image':'python@sha256:'+'b'*64}
  target=m.snapshot(io,'mesh-probes-create',request,config,None)
  self.assertEqual(len(target['manifests']),4)
  self.assertTrue(all(x['spec']['template']['spec']['containers'][0]['image']==config['platform_probe_image'] for x in target['manifests']))
  self.assertEqual(calls[0],['git','show','a'*40+':tests/e2e/mesh/checks/mesh-probes.yaml'])
 def test_mesh_rejects_prod_before_reads(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  with self.assertRaisesRegex(ValueError,'environment'):m.snapshot(types.SimpleNamespace(require=require),'mesh-probes-create',{}, {'environment':'prod'},None)
 def test_delete_refuses_replacement(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  calls=[];io=types.SimpleNamespace(kube=lambda *a:{'metadata':{'uid':'replacement'}},identity=lambda o:o['metadata'],require=require,ops=types.SimpleNamespace(run=lambda *a,**kw:calls.append(a)))
  item={'resource':'pods','namespace':'observability','name':'x','identity':{'uid':'created'}}
  with self.assertRaisesRegex(ValueError,'replaced'):m.delete_owned(io,item)
  self.assertEqual(calls,[])
 def test_delete_uses_uid_and_rv_preconditions(self):
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  live={'metadata':{'uid':'created','resourceVersion':'9'}};calls=[]
  def run(args,**kw):
   calls.append((args,json.loads(pathlib.Path(args[-1]).read_text())))
  sequence=iter([live,None]);io=types.SimpleNamespace(kube=lambda *a:next(sequence),identity=lambda o:{'uid':o['metadata']['uid']},require=require,ops=types.SimpleNamespace(run=run),h=types.SimpleNamespace(canonical=lambda o:json.dumps(o).encode()))
  item={'resource':'pods','namespace':'observability','name':'x','identity':{'uid':'created'},'api_path':'/api/v1/namespaces/observability/pods/x'}
  m.delete_owned(io,item);self.assertEqual(calls[0][1]['preconditions'],{'uid':'created','resourceVersion':'9'});self.assertEqual(calls[0][1]['propagationPolicy'],'Foreground')
if __name__=='__main__':unittest.main()
