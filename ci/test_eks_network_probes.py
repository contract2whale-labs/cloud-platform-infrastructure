import copy,importlib.util,json,os,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('p',HERE/'eks-network-probes.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
s=importlib.util.spec_from_file_location('g',HERE/'eks-lifecycle-guard.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)
s=importlib.util.spec_from_file_location('baseline',HERE/'test_eks_guard.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.scope={'account':'111111111111','vpc':'vpc-123','query':'unique.invalid','started_at':1000,'finished_probes_at':1100,'pod_ip':'10.0.1.7','endpoint':{'ips':['10.0.2.3'],'eni_ids':['eni-123']}}
    def test_image_accounts(self):
        images={k:'111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/course-bu07-'+n+'@sha256:'+'a'*64 for k,n in [('probe_image','python'),('pause_image','pause')]}
        p.validate_inputs(images,'ap-northeast-2','111111111111')
        with self.assertRaises(p.p.GuardError):p.validate_inputs(images,'ap-northeast-2','222222222222')
        images['probe_image']=images['probe_image'].split('@')[0]+':latest'
        with self.assertRaises(p.p.GuardError):p.validate_inputs(images,'ap-northeast-2','111111111111')
    def test_negative_not_any_error(self):
        for kind,result in [('imdsv1',{'status':403}),('imdsv2',{'status':401}),('imdsv2',{'result':'transport-error'}),('nxdomain',{'result':'dns-error'})]:
            with self.assertRaises(p.p.GuardError):p.validate_probe(kind,{'kind':kind,**result},[])
        p.validate_probe('imdsv1',{'kind':'imdsv1','status':401},[])
        p.validate_probe('imdsv2',{'kind':'imdsv2','result':'timeout'},[])
    def test_dns_exact_owned_addresses(self):
        p.validate_probe('dns',{'kind':'dns','addresses':['10.0.2.3']},['10.0.2.3'])
        for addresses in ([],['1.1.1.1'],['10.0.2.3','1.1.1.1']):
            with self.assertRaises(p.p.GuardError):p.validate_probe('dns',{'kind':'dns','addresses':addresses},['10.0.2.3'])
    def test_dns_log_account_vpc_run_time(self):
        value={'account_id':'111111111111','vpc_id':'vpc-123','query_name':'unique.invalid.','rcode':'NXDOMAIN','query_timestamp':'1970-01-01T00:17:00Z'}
        self.assertTrue(p.dns_match(json.dumps(value),self.scope))
        for key,new in [('account_id','222222222222'),('vpc_id','vpc-other'),('query_name','older.invalid'),('rcode','NOERROR'),('query_timestamp','1970-01-01T00:00:00Z')]:
            self.assertFalse(p.dns_match(json.dumps({**value,key:new}),self.scope))
    def test_flow_log_full_correlation(self):
        header='account-id interface-id srcaddr dstaddr dstport start end action log-status'
        row='111111111111 eni-123 10.0.1.7 10.0.2.3 443 1000 1050 ACCEPT OK'
        self.assertTrue(p.flow_match(header+'\n'+row,self.scope))
        for old,new in [('eni-123','eni-other'),('10.0.1.7','10.0.1.8'),('443','80'),('ACCEPT','REJECT'),('1000 1050','0 900'),('111111111111','222222222222')]:self.assertFalse(p.flow_match(header+'\n'+row.replace(old,new),self.scope))
    def test_cleanup_has_atomic_uid_precondition(self):
        calls=[]
        with patch.object(p,'get',return_value={'metadata':{'uid':'owned'}}),patch.object(p,'command',side_effect=lambda args,env,body=None: calls.append((args,body)) or b''):
            p.delete_owned_namespace({},'nodes-probe-a','owned')
        self.assertEqual(calls[0][1]['preconditions'],{'uid':'owned'})
        self.assertIn('--raw',calls[0][0])
    def test_cleanup_foreign_uid_never_deletes(self):
        with patch.object(p,'get',return_value={'metadata':{'uid':'foreign'}}),patch.object(p,'command') as cmd:
            with self.assertRaises(p.p.GuardError):p.delete_owned_namespace({},'nodes-probe-a','owned')
            cmd.assert_not_called()
    def test_endpoint_wrong_account(self):
        row={'VpcId':'vpc-123','OwnerId':'222222222222','State':'available','PrivateDnsEnabled':True}
        with patch.object(p.p,'aws',return_value={'VpcEndpoints':[row]}):
            with self.assertRaises(p.p.GuardError):p.endpoint_targets('ap-northeast-2','vpc-123','111111111111')
    def test_no_local_probe_mutation(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),patch.object(p.p,'aws') as aws:
            with self.assertRaises(p.p.GuardError):p.run({},'c','i','v','b',{})
            aws.assert_not_called()
    def test_residual_uid_spec_binding(self):
        inv=b.baseline();obj={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'argocd','uid':'abc'},'spec':{}}
        inv['namespaces'].append(obj)
        context={'source_sha':'a'*40,'generation':'1-1'};live={'arn':'arn:cluster','createdAt':'today'}
        contract={'schema_version':1,'cluster_arn':'arn:cluster','cluster_created_at':'today',**context,'approved_residuals':[{'resource':'namespaces','namespace':'','name':'argocd','uid':'abc','spec_sha256':g.residual_spec_hash(obj)}]}
        self.assertTrue(g.validate_residual_inventory(inv,contract,context,live))
        obj['metadata']['uid']='other'
        with self.assertRaises(g.SafeError):g.validate_residual_inventory(inv,contract,context,live)
if __name__=='__main__':unittest.main()
