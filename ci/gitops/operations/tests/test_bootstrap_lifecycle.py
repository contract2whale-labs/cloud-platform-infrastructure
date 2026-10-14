"""Offline fresh-target and exact-object bootstrap lifecycle regressions."""
import copy, hashlib, importlib.util, json, pathlib, types, unittest

PATH=pathlib.Path(__file__).resolve().parents[1]/'bootstrap_job_ops.py'
spec=importlib.util.spec_from_file_location('lifecycle_bootstrap',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ROOT=PATH.parents[2]
spec=importlib.util.spec_from_file_location('bootstrap_state_fixture',(ROOT/'vpc-lifecycle-guard.py' if (ROOT/'vpc-lifecycle-guard.py').is_file() else ROOT/'ci/vpc-lifecycle-guard.py'))
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
SHA='a'*40
RUN='d4e524ec-6e60-48e1-8f44-286a47311453'

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value):return hashlib.sha256(value).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def identity(obj):
    return {'name':obj['metadata']['name'],'namespace':obj['metadata']['namespace'],'uid':obj['metadata']['uid'],'body_sha256':digest(canonical({key:value for key,value in obj.items() if key not in ('metadata','status')})),'metadata_sha256':digest(canonical({key:obj['metadata'].get(key) for key in ('labels','annotations','ownerReferences')}))}
def resource(kind,name,**values):
    return {'mode':'managed','type':kind,'name':name,'instances':[{'attributes':values}]}

class Fixture:
    def __init__(self):
        self.calls=[];self.objects={};self.fail_create=False
        self.c={'state_bucket':'states','account_id':'111111111111','region':'ap-northeast-2','cluster':'demo','environment':'dev','completion':{'bootstrap_data_decision':'bootstrap-reviewed-database-roles-and-secret-stages'},'source_sha':SHA}
        self.repo='111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/operator'
        self.db_arn='arn:aws:rds:ap-northeast-2:111111111111:db:demo-db'
        self.role='arn:aws:iam::111111111111:role/platform/operator'
        self.desc={'key':'operator-publication/dev/release/operator-publication.json','version':'pub-version','sha256':'e'*64}
        self.c['retained_operator_images']=[{'image':self.repo+'@sha256:'+'b'*64,'source_sha':'c'*40,'signing_key_arn':'arn:aws:kms:ap-northeast-2:111111111111:key/a-b','publication_receipt':self.desc}]
        self.cred={key:'arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:'+key for key in ('master_secret_arn','migration_secret_arn','runtime_secret_arn','app_secret_arn')}
        self.data={'account_id':self.c['account_id'],'environment':'dev','region':self.c['region'],'cluster_name':'demo','namespace':m.NS,'database':{'identifier':'demo-db','address':'db.example','port':5432,'name':'commerce','schema':'public','engine_version_actual':'17.6'},'credentials':self.cred,'service_accounts':{'operator':'database-operator'},'redis':{'address':'redis.example','port':6379},'operator':{'repository_url':self.repo}}
        self.states={
            'data/terraform.tfstate':{'state':{'version':4,'outputs':{'data_contract':{'value':self.data}},'resources':[resource('aws_db_instance','data',identifier='demo-db',arn=self.db_arn,resource_id='db-original')]},'fingerprint':{'exists':True,'version':'data-version'}},
            'identity/terraform.tfstate':{'state':{'version':4,'resources':[resource('aws_eks_pod_identity_association','operator',cluster_name='demo',namespace=m.NS,service_account='database-operator',association_id='a-original',role_arn=self.role),resource('aws_iam_role','operator',arn=self.role)]},'fingerprint':{'exists':True,'version':'identity-version'}}}
        self.live={'DBInstanceIdentifier':'demo-db','DBInstanceArn':self.db_arn,'DbiResourceId':'db-original','Endpoint':{'Address':'db.example'},'DBInstanceStatus':'available','Engine':'postgres','MasterUserSecret':{'SecretArn':self.cred['master_secret_arn']}}
        self.assoc={'associationId':'a-original','clusterName':'demo','namespace':m.NS,'serviceAccount':'database-operator','roleArn':self.role}
        self.associations=[{'associationId':'a-original'}]
        self.publication={'signature_verified':True,'spdx_attestation_verified':True,'account_id':self.c['account_id'],'region':self.c['region'],'environment':'dev','source_revision':'c'*40,'repository':self.repo,'operator_image_digest':'sha256:'+'b'*64}
        self.sa={'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'database-operator','namespace':m.NS,'uid':'sa-original'}}
        self.io=types.SimpleNamespace(require=require,identity=identity,kube=self.kube,ops=types.SimpleNamespace(run=self.run,shared_file=lambda _:None,load_module=lambda *args:types.SimpleNamespace(VersionedStateReader=lambda *args:self.read_state,managed_resources=guard.managed_resources)),h=types.SimpleNamespace(canonical=canonical,digest=digest,SafeError=ValueError,Store=lambda *args:self,required=lambda name:'123'))
    def read_state(self,key):
        self.calls.append(('state',key));return copy.deepcopy(self.states[key])
    def check(self):pass
    def get(self,descriptor,path):
        self.calls.append(('receipt',descriptor['key']));path.write_bytes(canonical(self.publication if descriptor==self.desc else self.receipt))
    def kube(self,kind,ns,name,optional=False):
        self.calls.append(('kube',kind,ns,name))
        if kind=='serviceaccounts':return copy.deepcopy(self.sa)
        obj=self.objects.get((kind,name))
        if obj is None and not optional:raise ValueError('Missing object')
        return copy.deepcopy(obj)
    def run(self,args,content=None):
        self.calls.append(tuple(args))
        if args[0]=='aws':
            service,action=args[1:3]
            if (service,action)==('rds','describe-db-instances'):return canonical({'DBInstances':[self.live]})
            if (service,action)==('eks','list-pod-identity-associations'):return canonical({'associations':self.associations})
            if (service,action)==('eks','describe-pod-identity-association'):return canonical({'association':self.assoc})
            if (service,action)==('secretsmanager','describe-secret'):return canonical({'ARN':args[args.index('--secret-id')+1],'VersionIdsToStages':{'current':['AWSCURRENT']}})
            raise AssertionError('Unexpected AWS call '+repr(args))
        if 'create' in args:
            if self.fail_create:raise RuntimeError('uncertain API response')
            obj=json.loads(content);obj['metadata'].update(uid='uid-'+obj['kind'],resourceVersion='1')
            if obj['kind']=='Job':obj['status']={'succeeded':1}
            kind='jobs.batch' if obj['kind']=='Job' else 'configmaps'
            self.objects[(kind,obj['metadata']['name'])]=obj
            return canonical(obj)
        if 'delete' in args:
            path=args[args.index('--raw')+1];kind='jobs.batch' if '/jobs/' in path else 'configmaps'
            options=json.loads(pathlib.Path(args[-1]).read_text())
            require(self.objects[(kind,path.split('/')[-1])]['metadata']['uid']==options['preconditions']['uid'],'Wrong UID precondition')
            del self.objects[(kind,path.split('/')[-1])];return b'{}'
        if 'pods,deployments,statefulsets,cronjobs' in args:return canonical({'items':[]})
        raise AssertionError('Unexpected call '+repr(args))
    def request(self):return m.lifecycle_request(self.io,self.c,SHA,RUN)
    def snapshot(self):return m.snapshot(self.io,'database-bootstrap',self.request(),self.c,self)
    def complete(self):
        request=self.request();target=m.snapshot(self.io,'database-bootstrap',request,self.c,self);marks=[]
        result=m.apply(self.io,'database-bootstrap',target,request,lambda phase,value:marks.append((phase,copy.deepcopy(value))))
        return target,marks[-1][1],result,marks
    def cleanup_receipt(self,result):
        self.receipt={'kind':'gitops-lifecycle-completion','context':{'operation':'up','step_id':'hook:database-bootstrap','account':self.c['account_id'],'environment':'dev','repository_id':'123','snapshot_sha':SHA},'result':{'database_bootstrap':result}}
        return {'key':'ci-logs/123/1/1/'+SHA+'/dev/hooks/database-bootstrap/lifecycle-up/apply/receipt.json','version':'receipt-version','sha256':'d'*64}

class FreshTargetTests(unittest.TestCase):
    def test_request_snapshot_bind_state_live_source_and_provenance(self):
        f=Fixture();request=f.request();target=m.snapshot(f.io,'database-bootstrap',request,f.c,f)
        self.assertEqual(request['db_resource_id'],'db-original');self.assertEqual(target['source_sha'],SHA)
        self.assertEqual(target['state'],f.states['data/terraform.tfstate']['fingerprint'])
        self.assertEqual(target['identity_state'],f.states['identity/terraform.tfstate']['fingerprint'])
        self.assertEqual(target['serviceaccount']['uid'],'sa-original')
        self.assertNotIn('get-secret-value',json.dumps(f.calls));self.assertNotIn('SecretString',json.dumps(target))
    def test_request_requires_exact_approval(self):
        f=Fixture();f.c['completion']['bootstrap_data_decision']='other'
        with self.assertRaises(ValueError):f.request()
        self.assertEqual(f.calls,[])
    def test_replaced_db_same_name_and_arn_rejected(self):
        f=Fixture();f.live['DbiResourceId']='db-replacement'
        with self.assertRaises(ValueError):f.request()
    def test_snapshot_rejects_request_and_live_when_state_is_old(self):
        f=Fixture();request=f.request();f.live['DbiResourceId']='db-replacement';request['db_resource_id']='db-replacement'
        with self.assertRaises(ValueError):m.snapshot(f.io,'database-bootstrap',request,f.c,f)
    def test_duplicate_managed_database_rejected(self):
        f=Fixture();f.states['data/terraform.tfstate']['state']['resources'].append(resource('aws_db_instance','other',identifier='demo-db',arn=f.db_arn,resource_id='db-original'))
        with self.assertRaises(ValueError):f.request()
    def test_duplicate_live_database_rejected(self):
        f=Fixture();original=f.io.ops.run
        f.io.ops.run=lambda args,content=None:canonical({'DBInstances':[f.live,f.live]}) if args[:3]==['aws','rds','describe-db-instances'] else original(args,content)
        with self.assertRaises(ValueError):f.request()
    def test_deposed_database_rejected(self):
        f=Fixture();f.states['data/terraform.tfstate']['state']['resources'][0]['instances'][0]['deposed']='old'
        with self.assertRaises(Exception):f.request()
    def test_retained_publication_must_match_exactly_once(self):
        for records in ([],[Fixture().c['retained_operator_images'][0]]*2):
            f=Fixture();f.c['retained_operator_images']=records
            with self.assertRaises(ValueError):f.request()
    def test_operator_state_role_and_live_association_are_bound(self):
        for mutate in (lambda f:f.assoc.update(roleArn=f.role+'-other'),lambda f:f.assoc.update(associationId='a-other'),lambda f:f.associations.append({'associationId':'a-other'}),lambda f:f.states['identity/terraform.tfstate']['state']['resources'].pop()):
            f=Fixture();mutate(f)
            with self.assertRaises(ValueError):f.request()
    def test_snapshot_rejects_replaced_serviceaccount(self):
        f=Fixture();request=f.request();f.sa['metadata']['uid']='replacement'
        with self.assertRaises(ValueError):m.snapshot(f.io,'database-bootstrap',request,f.c,f)
    def test_verify_database_rejects_changed_version_source_or_incarnation(self):
        for change in ('state','source','live'):
            f=Fixture();target=f.snapshot()
            if change=='state':f.states['data/terraform.tfstate']['fingerprint']['version']='new'
            elif change=='source':f.c['source_sha']='d'*40
            else:f.live['DbiResourceId']='db-replaced'
            with self.assertRaises(ValueError):m.verify_database(f.io,f.c,target)
    def test_verify_database_does_not_require_absent_bootstrap_objects(self):
        f=Fixture();_,target,_,_=f.complete();self.assertEqual(m.verify_database(f.io,f.c,target),target['db'])

class CompletionTests(unittest.TestCase):
    def test_apply_verifies_original_objects_and_preserves_target_digest(self):
        f=Fixture();original,target,result,marks=f.complete()
        self.assertEqual([phase for phase,_ in marks],['active','active','active','idle'])
        self.assertNotIn('created_job',marks[0][1]);self.assertNotIn('created_configmap',marks[0][1])
        self.assertEqual(result['source_sha'],SHA);self.assertEqual(result['target_sha256'],m.target_sha256(f.io,original))
        self.assertEqual(m.verify_completion(f.io,target,result),result)
    def test_failed_or_active_job_cannot_complete_or_observe(self):
        for status in ({'succeeded':1,'failed':1},{'succeeded':1,'active':1},{'succeeded':1,'conditions':[{'type':'Failed','status':'True'}]}):
            f=Fixture();_,target,result,_=f.complete();f.objects[('jobs.batch',target['created_job']['name'])]['status']=status
            with self.assertRaises(ValueError):m.verify_completion(f.io,target,result)
            marks=[]
            with self.assertRaises(ValueError):m.observe(f.io,target,lambda *args:marks.append(args))
            self.assertEqual(marks,[])
    def test_altered_completion_or_created_identity_rejected(self):
        for field,value in (('source_sha','e'*40),('target_sha256','0'*64),('database',{'arn':'other','resource_id':'other'}),('created_job',{'uid':'other','name':'other'})):
            f=Fixture();_,target,result,_=f.complete();result[field]=value
            with self.assertRaises(ValueError):m.verify_completion(f.io,target,result)
    def test_live_object_replacement_rejected(self):
        for kind,field in (('jobs.batch','created_job'),('configmaps','created_configmap')):
            f=Fixture();_,target,result,_=f.complete();f.objects[(kind,target[field]['name'])]['metadata']['uid']='other'
            with self.assertRaises(ValueError):m.verify_completion(f.io,target,result)
    def test_completion_rechecks_database_incarnation(self):
        f=Fixture();_,target,result,_=f.complete();f.live['DbiResourceId']='new'
        with self.assertRaises(ValueError):m.verify_completion(f.io,target,result)
    def test_observe_is_read_only_and_uses_original_source(self):
        f=Fixture();_,target,_,_=f.complete();f.calls=[]
        captured=m.observe_snapshot(f.io,{'source_sha':SHA,'bootstrap_run_id':RUN},{'operation':'database-bootstrap','phase':'active','target':target})
        result=m.observe(f.io,captured,lambda *args:None)
        self.assertFalse(result['replayed']);self.assertFalse(any('create' in call or 'delete' in call for call in f.calls))
        with self.assertRaises(ValueError):m.observe_snapshot(f.io,{'source_sha':'f'*40,'bootstrap_run_id':RUN},{'operation':'database-bootstrap','phase':'active','target':target})
    def test_uncertain_create_retains_marker_without_adoption(self):
        f=Fixture();request=f.request();target=m.snapshot(f.io,'database-bootstrap',request,f.c,f);f.fail_create=True;marks=[]
        with self.assertRaises(RuntimeError):m.apply(f.io,'database-bootstrap',target,request,lambda phase,value:marks.append((phase,value)))
        self.assertEqual([p for p,_ in marks],['active'])
        with self.assertRaises(ValueError):m.observe_snapshot(f.io,{'source_sha':SHA,'bootstrap_run_id':RUN},{'operation':'database-bootstrap','phase':'active','target':marks[0][1]})

class LifecycleCleanupTests(unittest.TestCase):
    def test_legacy_incident_cleanup_ignores_completed_prior_marker(self):
        f=Fixture();_,_,result,_=f.complete()
        descriptor={'key':'ci-logs/123/1/1/'+SHA+'/dev/incidents/database-bootstrap/apply/receipt.json','version':'receipt-version','sha256':'d'*64}
        f.receipt={'kind':'incident-completion','success':True,'context':{'account':f.c['account_id'],'environment':'dev','repository_id':'123'},'result':result}
        request={'bootstrap_run_id':RUN,'data_decision':'remove-completed-bootstrap-job-and-configmap','creation_receipt':descriptor}
        target=m.cleanup_snapshot(f.io,request,f.c,f,{'phase':'idle','operation':'database-bootstrap','target':{}})
        self.assertEqual(target['created_job'],result['created_job'])
        m.cleanup(f.io,target,lambda *args:None)
        self.assertEqual(f.objects,{})
    def test_cleanup_rejects_failed_job_before_any_delete(self):
        f=Fixture();_,_,result,_=f.complete();descriptor=f.cleanup_receipt(result)
        f.objects[('jobs.batch',result['created_job']['name'])]['status'].update(failed=1)
        with self.assertRaises(ValueError):m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
        self.assertFalse(any('delete' in call for call in f.calls))
    def test_prior_cycle_receipt_cleans_exact_objects_without_database_read(self):
        f=Fixture();_,_,result,_=f.complete();descriptor=f.cleanup_receipt(result);f.c['source_sha']='f'*40;f.calls=[]
        target=m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
        refreshed=m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor,{'phase':'planned','target':target})
        self.assertEqual(target,refreshed)
        deleted=m.cleanup(f.io,target,lambda *args:None)
        self.assertEqual(set(deleted['deleted_uids']),{'uid-Job','uid-ConfigMap'})
        self.assertFalse(any(call[0] in ('state','aws') for call in f.calls))
    def test_forged_receipt_context_or_source_rejected(self):
        for field,value in (('operation','down'),('step_id','hook:other'),('repository_id','999'),('snapshot_sha','e'*40),('account','999999999999')):
            f=Fixture();_,_,result,_=f.complete();descriptor=f.cleanup_receipt(result);f.receipt['context'][field]=value
            with self.assertRaises(ValueError):m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
    def test_unversioned_receipt_rejected_before_read(self):
        f=Fixture();_,_,result,_=f.complete();descriptor=f.cleanup_receipt(result);descriptor['version']='null';f.calls=[]
        with self.assertRaises(ValueError):m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
        self.assertEqual(f.calls,[])
    def test_missing_target_only_recoverable_after_exact_delete_attempt(self):
        f=Fixture();_,_,result,_=f.complete();descriptor=f.cleanup_receipt(result);target=m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
        del f.objects[('jobs.batch',target['created_job']['name'])]
        with self.assertRaises(ValueError):m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
        target['delete_attempted_uids']=[target['created_job']['uid']]
        recovered=m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor,{'phase':'active','target':target})
        self.assertEqual(recovered,target)
        result=m.cleanup(f.io,recovered,lambda *args:None);self.assertEqual(len(result['deleted_uids']),2)
    def test_replaced_job_is_never_deleted(self):
        f=Fixture();_,_,result,_=f.complete();descriptor=f.cleanup_receipt(result);target=m.lifecycle_cleanup_snapshot(f.io,f.c,f,descriptor)
        f.objects[('jobs.batch',target['created_job']['name'])]['metadata']['uid']='replacement';f.calls=[]
        with self.assertRaises(ValueError):m.cleanup(f.io,target,lambda *args:None)
        self.assertFalse(any('delete' in call for call in f.calls))

if __name__=='__main__':unittest.main()
