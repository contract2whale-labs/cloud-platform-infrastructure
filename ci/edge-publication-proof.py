#!/usr/bin/env python3
"""Read-only Prod edge publication from exact approved Terraform State identities.
No target discovery by tags and no CloudFront/WAF/DNS/certificate mutation.
"""
import hashlib,http.client,ipaddress,json,re,socket,ssl
ROOT='terraform/environments/prod/platform/edge'
PREFIX='module.component.'

def need(value,message):
 if not value:raise ValueError(message)
def one(rows,address,ty):
 found=[r['values'] for r in rows if r.get('address')==PREFIX+address and r.get('type')==ty]
 need(len(found)==1,'Exact edge State identity is missing: '+address)
 return found[0]
def singleton(value,description):
 need(isinstance(value,list) and len(value)==1 and isinstance(value[0],dict),'Ambiguous '+description+'.')
 return value[0]
def host(value):
 need(isinstance(value,str) and len(value)<=253 and value==value.lower() and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',value),'Unreviewed public edge hostname.')
 return value

def https_read(hostname,path):
 """Fixed public GETs only, validated TLS, no redirects/cookies/credentials."""
 host(hostname);need(path in ('/','/store/products?limit=1','/metrics'),'Unreviewed publication path.')
 answers=socket.getaddrinfo(hostname,443,type=socket.SOCK_STREAM)
 addresses=sorted({answer[4][0] for answer in answers})
 need(addresses and all(ipaddress.ip_address(a).is_global for a in addresses),'Publication DNS must resolve only to public addresses.')
 context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
 with socket.create_connection((addresses[0],443),timeout=15) as raw:
  with context.wrap_socket(raw,server_hostname=hostname) as connection:
   connection.settimeout(20)
   connection.sendall(f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: course-lifecycle-publication/1\r\nConnection: close\r\n\r\n'.encode('ascii'))
   response=http.client.HTTPResponse(connection);response.begin();body=response.read(1048577)
   need(len(body)<=1048576,'Publication response exceeds its bounded read limit.')
   return {'hostname':hostname,'path':path,'status':response.status,'body':body,'tls_version':connection.version(),'certificate_sha256':hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest(),'certificate_verified':True}

def verify(context,rows,aws,*,http_read=None):
 need(context.get('root')==ROOT and context.get('environment')=='prod' and context.get('operation')=='up','Edge publication is bound to exact Prod Up.')
 account=context.get('account');region=context.get('backend',{}).get('region')
 need(isinstance(account,str) and re.fullmatch('[0-9]{12}',account) and region=='ap-northeast-2','Exact Prod publication account/region is required.')
 d=one(rows,'aws_cloudfront_distribution.app[0]','aws_cloudfront_distribution');o=one(rows,'aws_cloudfront_vpc_origin.gateway[0]','aws_cloudfront_vpc_origin')
 cert=one(rows,'aws_acm_certificate.viewer[0]','aws_acm_certificate');waf=one(rows,'aws_wafv2_web_acl.edge[0]','aws_wafv2_web_acl')
 did=d.get('id');oid=o.get('id');certificate=cert.get('arn');wafarn=waf.get('arn')
 need(isinstance(did,str) and re.fullmatch('[A-Z0-9]+',did) and d.get('arn')==f'arn:aws:cloudfront::{account}:distribution/{did}','Unreviewed distribution account/identity.')
 need(isinstance(oid,str) and re.fullmatch('[A-Za-z0-9_-]+',oid) and o.get('arn')==f'arn:aws:cloudfront::{account}:vpcorigin/{oid}','Unreviewed VPC origin account/identity.')
 need(isinstance(certificate,str) and re.fullmatch(f'arn:aws:acm:us-east-1:{account}:certificate/[0-9a-fA-F-]+',certificate),'Unreviewed viewer certificate account/region.')
 need(isinstance(wafarn,str) and re.fullmatch(f'arn:aws:wafv2:us-east-1:{account}:global/webacl/[A-Za-z0-9_-]+/[0-9a-fA-F-]+',wafarn) and waf.get('scope')=='CLOUDFRONT','Unreviewed global WAF account/scope.')
 aliases=d.get('aliases');need(isinstance(aliases,list) and aliases and len(aliases)==len(set(aliases)),'Distribution aliases are missing or duplicated.')
 aliases=sorted(host(name) for name in aliases)
 endpoint=singleton(o.get('vpc_origin_endpoint_config'),'State VPC origin endpoint');lbarn=endpoint.get('arn')
 need(isinstance(lbarn,str) and re.fullmatch(f'arn:aws:elasticloadbalancing:{region}:{account}:loadbalancer/net/[A-Za-z0-9-]+/[0-9a-f]+',lbarn),'Origin NLB account/region/identity is invalid.')
 need(aws('sts','get-caller-identity').get('Account')==account,'Publication caller account differs.')
 live=aws('cloudfront','get-distribution','--id',did).get('Distribution')
 need(isinstance(live,dict) and live.get('Id')==did and live.get('ARN')==d['arn'] and live.get('Status')=='Deployed' and live.get('DomainName')==d.get('domain_name'),'Exact CloudFront distribution is not deployed.')
 config=live.get('DistributionConfig',{});need(config.get('Enabled') is True and config.get('Aliases',{}).get('Quantity')==len(aliases) and sorted(config.get('Aliases',{}).get('Items',[]))==aliases,'Live distribution enablement/aliases changed.')
 need(config.get('WebACLId')==wafarn and config.get('ViewerCertificate',{}).get('ACMCertificateArn')==certificate,'Live distribution WAF/certificate differs from approved State.')
 liveorigin=singleton(config.get('Origins',{}).get('Items'),'CloudFront origin')
 need(config.get('Origins',{}).get('Quantity')==1 and liveorigin.get('Id')=='gateway' and liveorigin.get('VpcOriginConfig',{}).get('VpcOriginId')==oid,'CloudFront is not using the exact approved VPC origin.')
 origin=aws('cloudfront','get-vpc-origin','--id',oid).get('VpcOrigin')
 need(isinstance(origin,dict) and origin.get('Id')==oid and origin.get('Arn')==o['arn'] and origin.get('Status')=='Deployed','Exact VPC origin is not deployed.')
 actual=origin.get('VpcOriginEndpointConfig',{})
 need(actual.get('Arn')==lbarn and actual.get('Name')==endpoint.get('name') and actual.get('HTTPSPort')==443 and actual.get('OriginProtocolPolicy')=='https-only' and actual.get('OriginSslProtocols',{}).get('Items')==['TLSv1.2'],'Live VPC origin endpoint/TLS differs.')
 lbs=aws('elbv2','describe-load-balancers','--load-balancer-arns',lbarn,'--region',region).get('LoadBalancers')
 lb=singleton(lbs,'origin NLB')
 need(lb.get('LoadBalancerArn')==lbarn and lb.get('Scheme')=='internal' and lb.get('Type')=='network' and lb.get('State',{}).get('Code')=='active' and lb.get('DNSName')==liveorigin.get('DomainName'),'Approved internal NLB is not active or linked to this distribution.')
 issued=aws('acm','describe-certificate','--certificate-arn',certificate,'--region','us-east-1').get('Certificate')
 need(isinstance(issued,dict) and issued.get('CertificateArn')==certificate and issued.get('Status')=='ISSUED' and set(issued.get('SubjectAlternativeNames',[]))==set(aliases) and d['arn'] in issued.get('InUseBy',[]),'Viewer certificate is not issued for the exact aliases/distribution.')
 observed=aws('wafv2','get-web-acl','--name',waf.get('name',''),'--id',waf.get('id',''),'--scope','CLOUDFRONT','--region','us-east-1').get('WebACL')
 need(isinstance(observed,dict) and observed.get('ARN')==wafarn and observed.get('Id')==waf.get('id') and observed.get('Name')==waf.get('name'),'Exact WAF ACL readback failed.')
 need(observed.get('DefaultAction')=={'Allow':{}},'WAF default action differs from the exact source.')
 rules=observed.get('Rules');need(isinstance(rules,list) and len(rules)==4,'The reviewed WAF rule set is incomplete.')
 indexed={r.get('Name'):r for r in rules if isinstance(r,dict)}
 groups={'AWSManagedRulesCommonRuleSet':10,'AWSManagedRulesKnownBadInputsRuleSet':20,'AWSManagedRulesSQLiRuleSet':30}
 need(set(indexed)==set(groups)|{'request-rate'},'WAF has missing or unrelated rules.')
 for name,priority in groups.items():
  rule=indexed[name];statement=rule.get('Statement',{}).get('ManagedRuleGroupStatement',{})
  need(rule.get('Priority')==priority and rule.get('OverrideAction')=={'None':{}} and statement.get('VendorName')=='AWS' and statement.get('Name')==name and not statement.get('ExcludedRules') and not statement.get('RuleActionOverrides') and not statement.get('ScopeDownStatement'),'WAF managed rule enforcement differs from the source.')
 rate=indexed['request-rate'];live_rate=rate.get('Statement',{}).get('RateBasedStatement',{})
 state_rate=singleton([r for r in waf.get('rule',[]) if r.get('name')=='request-rate'],'State WAF rate rule')
 state_statement=singleton(state_rate.get('statement'),'State WAF rate statement');expected_rate=singleton(state_statement.get('rate_based_statement'),'State WAF rate settings')
 need(rate.get('Priority')==40 and rate.get('Action')=={'Block':{}} and live_rate.get('AggregateKeyType')=='IP' and live_rate.get('EvaluationWindowSec')==300 and live_rate.get('Limit')==expected_rate.get('limit') and type(live_rate.get('Limit')) is int and not live_rate.get('ScopeDownStatement'),'WAF rate-limit enforcement differs from approved State.')
 records=[r for r in rows if r.get('type')=='aws_route53_record' and r.get('address','').startswith((PREFIX+'aws_route53_record.app_ipv4[',PREFIX+'aws_route53_record.app_ipv6['))]
 need(len(records)==2*len(aliases),'Exact public A/AAAA State inventory is missing.')
 matched=set()
 for record in records:
  v=record['values'];name=v.get('name','').rstrip('.');ty=v.get('type');zone=v.get('zone_id');alias=singleton(v.get('alias'),'State Route53 alias')
  need(name in aliases and ty in ('A','AAAA') and (name,ty) not in matched and isinstance(zone,str) and re.fullmatch('Z[A-Z0-9]+',zone),'Unreviewed public record identity.')
  need(alias.get('name','').rstrip('.')==d.get('domain_name') and alias.get('zone_id')==d.get('hosted_zone_id'),'State DNS alias does not target the approved distribution.')
  response=aws('route53','list-resource-record-sets','--hosted-zone-id',zone,'--start-record-name',name,'--start-record-type',ty,'--max-items','1')
  rr=singleton(response.get('ResourceRecordSets'),'exact public Route53 record');target=rr.get('AliasTarget',{})
  need(rr.get('Name','').rstrip('.')==name and rr.get('Type')==ty and target.get('DNSName','').rstrip('.')==d.get('domain_name') and target.get('HostedZoneId')==d.get('hosted_zone_id') and target.get('EvaluateTargetHealth') is False,'Live public DNS alias differs from approved State.')
  matched.add((name,ty))
 need(matched=={(name,ty) for name in aliases for ty in ('A','AAAA')},'Public DNS alias coverage is incomplete.')
 read=http_read or https_read;probes=[]
 for name in aliases:
  for path,status in [('/',200),('/store/products?limit=1',400),('/metrics',404)]:
   response=read(name,path)
   need(isinstance(response,dict) and response.get('hostname')==name and response.get('path')==path and response.get('certificate_verified') is True and response.get('tls_version') in ('TLSv1.2','TLSv1.3') and response.get('status')==status,'Published TLS/HTTP route readback failed; no redirect is followed.')
   body=response.get('body');need(isinstance(body,bytes) and len(body)<=1048576,'Publication body proof is missing or oversized.')
   if path.startswith('/store/'):
    try:error=json.loads(body)
    except (ValueError,TypeError):raise ValueError('Store-key rejection is not a reviewed JSON error.') from None
    need(isinstance(error,dict) and isinstance(error.get('type'),str) and error['type'] and isinstance(error.get('message'),str) and all(word in error['message'].lower() for word in ('publishable','key')),'Store route rejection does not establish its publishable-key boundary.')
   probes.append({k:response[k] for k in ('hostname','path','status','tls_version','certificate_verified') }|{'body_sha256':hashlib.sha256(body).hexdigest()})
 return {'scope':'exact-prod-edge-publication','read_only':True,'distribution_id':did,'vpc_origin_id':oid,'certificate_arn':certificate,'waf_arn':wafarn,'dns_records':len(matched),'https_probes':probes,'application_data_integrity_proven':False}
