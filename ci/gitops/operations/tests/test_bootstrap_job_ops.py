import copy,hashlib,importlib.util,json,pathlib,types,unittest
from unittest.mock import patch
PATH=pathlib.Path(__file__).resolve().parents[1]/'bootstrap_job_ops.py'
spec=importlib.util.spec_from_file_location('bootstrap',PATH);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def io(self,fail=False):
  events=[];objects={}
  def require(ok,msg):
   if not ok:raise ValueError(msg)
  def run(args,content=None):
   if args[0]=='aws':return json.dumps({'DBInstances':[{'DBInstanceIdentifier':'db','DBInstanceArn':'arn','DbiResourceId':'id','DBInstanceStatus':'available'}]}).encode()
   obj=json.loads(content);events.append(obj['kind'])
   if fail:raise RuntimeError('uncertain API response')
   obj['metadata']['uid']='uid-'+obj['kind']
   kind='jobs.batch' if obj['kind']=='Job' else 'configmaps'
   if kind=='jobs.batch':obj['status']={'succeeded':1}
   objects[(kind,obj['metadata']['name'])]=obj
   return json.dumps(obj).encode()
  def kube(kind,ns,name,optional=False):
   return copy.deepcopy(objects.get((kind,name)))
  io=types.SimpleNamespace(require=require,ops=types.SimpleNamespace(run=run),h=types.SimpleNamespace(canonical=lambda x:json.dumps(x).encode(),SafeError=ValueError,digest=lambda x:hashlib.sha256(x).hexdigest()),identity=lambda x:{'name':x['metadata']['name'],'uid':x['metadata']['uid']},kube=kube)
  return io,events
 def target(self):
  return {'job':{'kind':'Job','metadata':{'name':'database-bootstrap-run'}},'configmap':{'kind':'ConfigMap','metadata':{'name':'database-bootstrap-run'}},'bootstrap_run_id':'run','source_sha':'a'*40,'region':'ap-northeast-2','db_identifier':'db','db':{'arn':'arn','resource_id':'id'}}
 def test_saved_exact_objects_create_once(self):
  io,events=self.io();marks=[]
  result=m.apply(io,'database-bootstrap',self.target(),{'source_sha':'a'*40,'bootstrap_run_id':'run'},lambda phase,t:marks.append((phase,t)))
  self.assertEqual(events,['ConfigMap','Job']);self.assertEqual(marks[0][0],'active');self.assertEqual(marks[-1][0],'idle');self.assertTrue(result['complete']);self.assertFalse(result['raw_job_logs_published'])
 def test_uncertain_write_keeps_active_marker(self):
  io,events=self.io(True);marks=[]
  with self.assertRaises(RuntimeError):m.apply(io,'database-bootstrap',self.target(),{'source_sha':'a'*40,'bootstrap_run_id':'run'},lambda phase,t:marks.append(phase))
  self.assertEqual(marks,['active']);self.assertEqual(events,['ConfigMap'])
 def test_fixed_template_no_retry_no_shell_input(self):
  job=json.loads((PATH.parent/'templates/database-bootstrap-job.json').read_text());container=job['spec']['template']['spec']['containers'][0]
  self.assertEqual(container['command'],['bash','/opt/contract2whale/operator/bootstrap.sh']);self.assertEqual(job['spec']['backoffLimit'],0);self.assertEqual(job['spec']['activeDeadlineSeconds'],600)
 def test_wrong_operation_cannot_mutate(self):
  io,events=self.io()
  with self.assertRaises(ValueError):m.apply(io,'arbitrary-job',self.target(),{'source_sha':'a'*40,'bootstrap_run_id':'run'},lambda *x:None)
  self.assertEqual(events,[])
if __name__=='__main__':unittest.main()
