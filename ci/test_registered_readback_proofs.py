"""Pure fixtures for bounded SSM session and Prod edge publication readbacks."""
import copy,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(name,file):
 s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
s=load('dev_sessions_tests','dev-app-session-proof.py');e=load('edge_publication_tests','edge-publication-proof.py')
ACCOUNT='123456789012';REGION='ap-northeast-2'
def row(address,ty,values):return {'address':address,'type':ty,'values':values,'mode':'managed'}
class DevSessions(unittest.TestCase):
 def setUp(self):
  self.c={'root':s.ROOT,'environment':'dev','account':ACCOUNT,'backend':{'region':REGION},'operation':'down'}
  self.rows=[row('aws_ssm_document.dev_app_https','aws_ssm_document',{'id':s.DOCUMENT}),row('aws_iam_role.dev_app_session','aws_iam_role',{'id':s.ROLE})]
  self.relay=[row('aws_instance.relay','aws_instance',{'id':'i-0123456789abcdef0'})]
  self.target=s.capture(self.c,self.rows,self.relay)
  self.sessions=[];self.calls=[]
 def aws(self,*args):
  self.calls.append(args)
  return {'Account':ACCOUNT} if args[:2]==('sts','get-caller-identity') else {'Sessions':self.sessions}
 def session(self,doc=s.DOCUMENT,status='Connected'):
  return {'SessionId':'reviewed-session','Target':self.target['instance_id'],'DocumentName':doc,'Status':status}
 def test_exact_empty_inventory_read_only(self):
  proof=s.verify(self.target,self.aws);self.assertEqual(proof['active_owned_sessions'],0)
  self.assertEqual([c[:2] for c in self.calls],[('sts','get-caller-identity'),('ssm','describe-sessions')]);self.assertIn('Active',self.calls[1])
 def test_connected_disconnected_and_terminating_block(self):
  for status in ('Connected','Connecting','Disconnected','Terminating'):
   self.sessions=[self.session(status=status)]
   with self.assertRaisesRegex(ValueError,'remains'):s.verify(self.target,self.aws)
 def test_private_api_other_document_is_not_terminated(self):
  self.sessions=[self.session(doc='AWS-StartPortForwardingSession')]
  self.assertEqual(s.verify(self.target,self.aws)['active_owned_sessions'],0)
 def test_unknown_document_pagination_and_target_block(self):
  self.sessions=[self.session()];self.sessions[0].pop('DocumentName')
  with self.assertRaises(ValueError):s.verify(self.target,self.aws)
  self.sessions=[{**self.session(),'Target':'i-00000000000000000'}]
  with self.assertRaises(ValueError):s.verify(self.target,self.aws)
  def paged(*args):return {'Account':ACCOUNT} if args[0]=='sts' else {'Sessions':[],'NextToken':'more'}
  with self.assertRaises(ValueError):s.verify(self.target,paged)
 def test_empty_state_is_not_disabled_but_can_use_original_exact_ids(self):
  with self.assertRaises(ValueError):s.capture(self.c,[],self.relay)
  before=[{'address':r['address'],'type':r['type'],'id':r['values']['id']} for r in self.rows]
  self.assertEqual(s.capture(self.c,[],self.relay,before),self.target)
  before[0]['id']='OtherDocument'
  with self.assertRaises(ValueError):s.capture(self.c,[],self.relay,before)
 def test_cross_account_and_prod_rejected(self):
  with self.assertRaises(ValueError):s.capture({**self.c,'environment':'prod'},self.rows,self.relay)
  with self.assertRaises(ValueError):s.verify(self.target,lambda *a:{'Account':'999999999999'})
 def test_policy_must_bind_exact_state_relay(self):
  statements=[{'Sid':sid,'Effect':'Allow','Action':['ssm:StartSession'],'Resource':[resource]} for sid,resource in [('StartFixedSessionOnRelay',f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0'),('UseFixedDocumentOnly',f'arn:aws:ssm:{REGION}:{ACCOUNT}:document/{s.DOCUMENT}')]]
  statements.append({'Sid':'ManageOwnSessions'})
  r=row('aws_iam_role_policy.dev_app_session','aws_iam_role_policy',{'role':s.ROLE,'policy':json.dumps({'Statement':statements})});s.capture(self.c,self.rows+[r],self.relay)
  statements[0]['Resource']=['*'];r['values']['policy']=json.dumps({'Statement':statements})
  with self.assertRaises(ValueError):s.capture(self.c,self.rows+[r],self.relay)

class EdgePublication(unittest.TestCase):
 def setUp(self):
  self.c={'root':e.ROOT,'environment':'prod','account':ACCOUNT,'backend':{'region':REGION},'operation':'up'}
  self.did='E123456789';self.oid='vo-reviewed';self.domain='d123.cloudfront.net';self.hostname='app.example.com';self.zone='ZCLOUD'
  self.darn=f'arn:aws:cloudfront::{ACCOUNT}:distribution/{self.did}';self.oarn=f'arn:aws:cloudfront::{ACCOUNT}:vpcorigin/{self.oid}'
  self.cert=f'arn:aws:acm:us-east-1:{ACCOUNT}:certificate/1234-abcd';self.waf=f'arn:aws:wafv2:us-east-1:{ACCOUNT}:global/webacl/course-edge/1234-abcd'
  self.nlb=f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/net/owned-nlb/1234abcd';self.ndns='owned-nlb.elb.ap-northeast-2.amazonaws.com'
  self.rows=[row(e.PREFIX+'aws_cloudfront_distribution.app[0]','aws_cloudfront_distribution',{'id':self.did,'arn':self.darn,'aliases':[self.hostname],'domain_name':self.domain,'hosted_zone_id':self.zone}),row(e.PREFIX+'aws_cloudfront_vpc_origin.gateway[0]','aws_cloudfront_vpc_origin',{'id':self.oid,'arn':self.oarn,'vpc_origin_endpoint_config':[{'arn':self.nlb,'name':'course-gateway'}]}),row(e.PREFIX+'aws_acm_certificate.viewer[0]','aws_acm_certificate',{'arn':self.cert}),row(e.PREFIX+'aws_wafv2_web_acl.edge[0]','aws_wafv2_web_acl',{'arn':self.waf,'name':'course-edge','id':'1234-abcd','scope':'CLOUDFRONT'})]
  for resource,ty in [('app_ipv4','A'),('app_ipv6','AAAA')]:self.rows.append(row(e.PREFIX+f'aws_route53_record.{resource}["{self.hostname}"]','aws_route53_record',{'name':self.hostname,'type':ty,'zone_id':'ZPUBLIC','alias':[{'name':self.domain,'zone_id':self.zone}]}))
  self.responses={
   ('sts','get-caller-identity'):{'Account':ACCOUNT},
   ('cloudfront','get-distribution'):{'Distribution':{'Id':self.did,'ARN':self.darn,'Status':'Deployed','DomainName':self.domain,'DistributionConfig':{'Enabled':True,'Aliases':{'Quantity':1,'Items':[self.hostname]},'WebACLId':self.waf,'ViewerCertificate':{'ACMCertificateArn':self.cert},'Origins':{'Quantity':1,'Items':[{'Id':'gateway','DomainName':self.ndns,'VpcOriginConfig':{'VpcOriginId':self.oid}}]}}}},
   ('cloudfront','get-vpc-origin'):{'VpcOrigin':{'Id':self.oid,'Arn':self.oarn,'Status':'Deployed','VpcOriginEndpointConfig':{'Arn':self.nlb,'Name':'course-gateway','HTTPSPort':443,'OriginProtocolPolicy':'https-only','OriginSslProtocols':{'Items':['TLSv1.2']}}}},
   ('elbv2','describe-load-balancers'):{'LoadBalancers':[{'LoadBalancerArn':self.nlb,'Scheme':'internal','Type':'network','State':{'Code':'active'},'DNSName':self.ndns}]},
   ('acm','describe-certificate'):{'Certificate':{'CertificateArn':self.cert,'Status':'ISSUED','SubjectAlternativeNames':[self.hostname],'InUseBy':[self.darn]}},
   ('wafv2','get-web-acl'):{'WebACL':{'ARN':self.waf,'Name':'course-edge','Id':'1234-abcd'}}}
  self.rows[3]['values']['rule']=[{'name':'request-rate','statement':[{'rate_based_statement':[{'limit':2000}]}]}]
  acl=self.responses[('wafv2','get-web-acl')]['WebACL'];acl['DefaultAction']={'Allow':{}}
  acl['Rules']=[{'Name':name,'Priority':priority,'OverrideAction':{'None':{}},'Statement':{'ManagedRuleGroupStatement':{'Name':name,'VendorName':'AWS'}}} for name,priority in [('AWSManagedRulesCommonRuleSet',10),('AWSManagedRulesKnownBadInputsRuleSet',20),('AWSManagedRulesSQLiRuleSet',30)]]
  acl['Rules'].append({'Name':'request-rate','Priority':40,'Action':{'Block':{}},'Statement':{'RateBasedStatement':{'Limit':2000,'AggregateKeyType':'IP','EvaluationWindowSec':300}}})
  self.calls=[];self.http_calls=[]
 def aws(self,*args):
  self.calls.append(args)
  if args[0]=='route53':return {'ResourceRecordSets':[{'Name':self.hostname+'.','Type':args[args.index('--start-record-type')+1],'AliasTarget':{'DNSName':self.domain+'.','HostedZoneId':self.zone,'EvaluateTargetHealth':False}}]}
  return copy.deepcopy(self.responses[args[:2]])
 def http(self,name,path):
  self.http_calls.append((name,path));status={'/':200,'/metrics':404,'/store/products?limit=1':400}[path]
  body=b'{"type":"invalid_data","message":"A publishable API key is required"}' if path.startswith('/store/') else b'reviewed response'
  return dict(hostname=name,path=path,status=status,body=body,tls_version='TLSv1.3',certificate_verified=True)
 def verify(self):return e.verify(self.c,self.rows,self.aws,http_read=self.http)
 def test_exact_deployed_readback_and_three_tls_routes(self):
  proof=self.verify();self.assertEqual(proof['dns_records'],2);self.assertEqual(len(proof['https_probes']),3);self.assertTrue(proof['read_only'])
  self.assertNotIn('body',proof['https_probes'][0]);self.assertFalse(proof['application_data_integrity_proven'])
  self.assertTrue(all(a[1].startswith(('get-','describe-','list-')) for a in self.calls))
 def test_state_missing_wrong_account_and_dev_fail_before_reads(self):
  self.rows.pop()
  with self.assertRaises(ValueError):self.verify()
  self.setUp();self.c['environment']='dev'
  with self.assertRaises(ValueError):self.verify()
  self.assertEqual(self.calls,[])
  self.setUp();self.rows[0]['values']['arn']=self.darn.replace(ACCOUNT,'999999999999')
  with self.assertRaises(ValueError):self.verify()
  self.assertEqual(self.calls,[])
 def test_not_deployed_wrong_origin_waf_or_certificate_blocks(self):
  for field,value in [('Status','InProgress'),('ARN',self.darn+'other')]:
   self.setUp();self.responses[('cloudfront','get-distribution')]['Distribution'][field]=value
   with self.assertRaises(ValueError):self.verify()
  for field,value in [('WebACLId','wrong'),('ViewerCertificate',{'ACMCertificateArn':'wrong'}),('Enabled',False)]:
   self.setUp();self.responses[('cloudfront','get-distribution')]['Distribution']['DistributionConfig'][field]=value
   with self.assertRaises(ValueError):self.verify()
 def test_origin_tls_nlb_certificate_and_waf_drift_block(self):
  cases=[(('cloudfront','get-vpc-origin'),lambda r:r['VpcOrigin'].update(Status='InProgress')),(('cloudfront','get-vpc-origin'),lambda r:r['VpcOrigin']['VpcOriginEndpointConfig'].update(OriginProtocolPolicy='http-only')),(('elbv2','describe-load-balancers'),lambda r:r['LoadBalancers'][0].update(Scheme='internet-facing')),(('acm','describe-certificate'),lambda r:r['Certificate'].update(Status='PENDING_VALIDATION')),(('wafv2','get-web-acl'),lambda r:r['WebACL'].update(ARN='other')),(('wafv2','get-web-acl'),lambda r:r['WebACL'].update(Rules=[])),(('wafv2','get-web-acl'),lambda r:r['WebACL']['Rules'][0].update(OverrideAction={'Count':{}}))]
  for key,mutate in cases:
   self.setUp();mutate(self.responses[key])
   with self.assertRaises(ValueError):self.verify()
   self.assertEqual(self.http_calls,[])
 def test_dns_mismatch_refuses_http(self):
  def aws(*args):
   result=self.aws(*args)
   if args[0]=='route53':result['ResourceRecordSets'][0]['AliasTarget']['DNSName']='other.cloudfront.net'
   return result
  with self.assertRaises(ValueError):e.verify(self.c,self.rows,aws,http_read=self.http)
  self.assertEqual(self.http_calls,[])
 def test_status_only_store_error_is_not_proof(self):
  def http(name,path):
   result=self.http(name,path)
   if path.startswith('/store/'):result['body']=b'{"type":"other","message":"Bad request"}'
   return result
  with self.assertRaises(ValueError):e.verify(self.c,self.rows,self.aws,http_read=http)
 def test_tls_and_metrics_exposure_fail(self):
  for mutation in ({'certificate_verified':False},{'tls_version':'TLSv1.1'},{'status':200}):
   def http(name,path):
    value=self.http(name,path)
    if path=='/metrics':value.update(mutation)
    return value
   with self.assertRaises(ValueError):e.verify(self.c,self.rows,self.aws,http_read=http)
 def test_private_dns_never_opens_a_connection(self):
  with patch.object(e.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]),patch.object(e.socket,'create_connection',side_effect=AssertionError('Private connection forbidden')),self.assertRaises(ValueError):e.https_read('app.example.com','/')
 def test_hostname_does_not_accept_url_ip_or_shell(self):
  for name in ('127.0.0.1','https://app.example.com','app.example.com;sh','APP.example.com','localhost'):
   with self.assertRaises(ValueError):e.host(name)
if __name__=='__main__':unittest.main()
