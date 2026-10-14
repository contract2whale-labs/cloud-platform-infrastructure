"""BU10B exact S3 Gateway endpoint policy recovery from reviewed committed JSON."""
import importlib.util,json,re,time
IDS=('s3-endpoint-policy-recover',)
POLICY='operations/requests/s3-endpoint-recovery-policy.json'
def describe(io,c,endpoint):
 rows=json.loads(io.ops.run(['aws','ec2','describe-vpc-endpoints','--region',c['region'],'--vpc-endpoint-ids',endpoint]))['VpcEndpoints']
 io.require(len(rows)==1,'Ambiguous endpoint observation');return rows[0]
def snapshot(io,operation,r,c,store):
 io.require(operation in IDS and c['environment']=='dev','Only the registered Dev S3 Gateway recovery is supported')
 io.require(set(r)<={'source_sha','expires_at','change_request','data_decision','endpoint_id','vpc_id','policy_sha256','policy_expansion_approved','reconcile_source_change'},'Unknown recovery fields')
 io.require(r['data_decision']=='restore-reviewed-s3-gateway-endpoint-policy' and r.get('reconcile_source_change'),'Explicit recovery and subsequent Terraform source reconciliation required')
 spec=importlib.util.spec_from_file_location('endpoint_state',io.ops.shared_file('vpc-lifecycle-guard.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
 reader=v.VersionedStateReader(c['state_bucket'],c['account_id'],c['region']);network=reader('network/vpc/terraform.tfstate');owner=reader('platform/observability/terraform.tfstate')
 endpoints=[row['values'] for row in v.managed_resources(network['state']) if row['type']=='aws_vpc_endpoint' and row['values'].get('service_name')=='com.amazonaws.'+c['region']+'.s3']
 io.require(len(endpoints)==1 and endpoints[0]['id']==r['endpoint_id'] and endpoints[0]['vpc_id']==r['vpc_id'],'Endpoint differs from exact source State')
 policies=[row['values'] for row in v.managed_resources(owner['state']) if row['type']=='aws_vpc_endpoint_policy']
 io.require(any(row.get('vpc_endpoint_id')==r['endpoint_id'] for row in policies),'Observability policy ownership not verified')
 live=describe(io,c,r['endpoint_id']);io.require(live['OwnerId']==c['account_id'] and live['VpcId']==r['vpc_id'] and live['VpcEndpointType']=='Gateway' and live['ServiceName']=='com.amazonaws.'+c['region']+'.s3' and live['State']=='available','Live S3 endpoint identity/state differs')
 body=io.ops.run(['git','show',r['source_sha']+':'+POLICY]);io.require(io.h.digest(body)==r['policy_sha256'],'Reviewed previous policy bytes differ');policy=json.loads(body)
 io.require(isinstance(policy,dict) and policy.get('Version')=='2012-10-17' and isinstance(policy.get('Statement'),list) and policy['Statement'],'Invalid reviewed policy document')
 for stmt in policy['Statement']:
  io.require(isinstance(stmt,dict) and stmt.get('Effect') in ('Allow','Deny') and 'Action' in stmt and 'NotAction' not in stmt and 'NotResource' not in stmt and 'NotPrincipal' not in stmt,'Unsupported inverse/ambiguous policy statement')
  actions=stmt['Action'] if isinstance(stmt['Action'],list) else [stmt['Action']]
  io.require(actions and all(isinstance(a,str) and (a.startswith('s3:') or a=='*') for a in actions),'Only S3 endpoint policy actions supported')
 if '*' in json.dumps(policy):io.require(r.get('policy_expansion_approved') is True,'Wildcard/full-access recovery requires explicit expansion approval')
 return {'endpoint_id':r['endpoint_id'],'vpc_id':r['vpc_id'],'account':c['account_id'],'region':c['region'],'network_state':network['fingerprint'],'policy_owner_state':owner['fingerprint'],'old_policy':json.loads(live['PolicyDocument']),'desired_policy':policy,'policy_source':{'path':POLICY,'source_sha':r['source_sha'],'sha256':r['policy_sha256']},'route_table_ids':sorted(live.get('RouteTableIds',[])),'reconcile_source_change':r['reconcile_source_change']}
def apply(io,operation,target,r,mark):
 io.require(operation in IDS,'Unknown policy operation');c={'region':target['region']};live=describe(io,c,target['endpoint_id'])
 io.require(live['OwnerId']==target['account'] and live['VpcId']==target['vpc_id'] and json.loads(live['PolicyDocument'])==target['old_policy'] and sorted(live.get('RouteTableIds',[]))==target['route_table_ids'],'Endpoint or policy changed after review')
 mark('active',target)
 result=json.loads(io.ops.run(['aws','ec2','modify-vpc-endpoint','--region',target['region'],'--vpc-endpoint-id',target['endpoint_id'],'--policy-document',json.dumps(target['desired_policy'],separators=(',',':'))]))
 io.require(result.get('Return') is True,'Endpoint policy change not acknowledged')
 for _ in range(30):
  live=describe(io,c,target['endpoint_id']);io.require(live['OwnerId']==target['account'] and live['VpcId']==target['vpc_id'],'Endpoint identity changed')
  if json.loads(live['PolicyDocument'])==target['desired_policy']:
   receipt={'endpoint_id':target['endpoint_id'],'policy_sha256':io.h.digest(io.h.canonical(target['desired_policy'])),'policy_source':target['policy_source'],'reconcile_source_change':target['reconcile_source_change'],'verified':True};mark('idle',dict(target,result=receipt));return receipt
  time.sleep(2)
 raise io.h.SafeError('Policy observation timeout; retain exact target marker, do not replay blindly')
