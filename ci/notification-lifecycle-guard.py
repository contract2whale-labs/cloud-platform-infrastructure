#!/usr/bin/env python3
"""Read-only ownership fence around exact Terraform S3 notification plans.
Terraform owns the entire notification document. Never clear mixed ownership.
No S3 bucket, object, encryption, policy, lifecycle or access mutation is allowed.
The backlog discard decision is lab-only. Ordinary production data needs its
approved preservation/recovery process before any reset.
"""
import json,re
ADDRESS='module.component.aws_s3_bucket_notification.network_logs[0]'
ROOTS={f'terraform/environments/{e}/account-integrations' for e in ('dev','prod')}
def need(value,message):
 if not value:raise ValueError(message)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def normalize(document):
 need(isinstance(document,dict),'Missing live bucket notification document.')
 # Empty arrays are serialization differences; EventBridge={} is ENABLED and
 # must never be normalized away.
 return {k:sorted(v,key=canonical) if isinstance(v,list) else v for k,v in document.items() if v!=[]}
def owned(values,account,region):
 need(isinstance(values,dict) and isinstance(values.get('bucket'),str),'Exact retained notification bucket is required.')
 need(not values.get('eventbridge') and not values.get('topic') and not values.get('lambda_function'),'Mixed notification ownership is unsupported.')
 queues=values.get('queue');need(isinstance(queues,list) and len(queues)==2,'Expected two source-owned notification queues.')
 result=[];arns=set()
 for item in queues:
  name=item.get('id');prefix={'flow-logs':'flow/','dns-logs':'dns/'}.get(name)
  need(prefix is not None and item.get('filter_prefix')==prefix and item.get('filter_suffix') in (None,'') and item.get('events')==['s3:ObjectCreated:*'],'Notification differs from the exact source contract.')
  arn=item.get('queue_arn');need(isinstance(arn,str) and re.fullmatch(r'arn:aws:sqs:'+re.escape(region)+':'+account+r':[A-Za-z0-9_-]+-network-log-events',arn),'Notification queue is outside the reviewed account/region/name boundary.')
  arns.add(arn);result.append({'Id':name,'QueueArn':arn,'Events':['s3:ObjectCreated:*'],'Filter':{'Key':{'FilterRules':[{'Name':'prefix','Value':prefix}]}}})
 need(len(arns)==1 and {r['Id'] for r in result}=={'flow-logs','dns-logs'},'Notification queue identity or IDs are ambiguous.')
 return values['bucket'],normalize({'QueueConfigurations':result})
def changes(context,plan):
 if context.get('root') not in ROOTS:return []
 need(isinstance(context.get('account'),str) and re.fullmatch('[0-9]{12}',context['account']),'Exact 12-digit account required.')
 need(context.get('backend',{}).get('region')=='ap-northeast-2','Only the reviewed course region is allowed.')
 result=[]
 for row in plan.get('resource_changes',[]):
  if row.get('type')!='aws_s3_bucket_notification' or row.get('mode')!='managed':continue
  need(row.get('address')==ADDRESS,'Unreviewed S3 notification address.')
  change=row.get('change',{});actions=change.get('actions')
  need(actions in (['create'],['delete'],['no-op']), 'Notification update/replacement requires separate ownership review.')
  decision=plan.get('variables',{}).get('lifecycle_notification_backlog_mode',{}).get('value')
  need(decision=='discard-notifications-retain-source-objects','Optional log consumer needs protected lifecycle_notification_backlog_mode=discard-notifications-retain-source-objects; no backlog replay hook exists.')
  # Source: BU03 network-log-storage/main.tf fixes this stable naming rule.
  # It is a boundary assertion, not evidence that a bucket exists.
  values=change.get('before') if actions!=['create'] else change.get('after')
  env=context['root'].split('/')[2]
  expected=f"cp-{env}-network-logs-{context['account']}-{context['backend']['region']}"
  need(isinstance(values,dict) and values.get('bucket')==expected,'Notification must target the exact source-named retained network log bucket.')
  result.append((actions,change))
 need(len(result)<=1,'Duplicate notification resource.')
 return result

def verify(context,plan,aws):
 """Call at plan, verify, and immediately before saved-plan apply."""
 proofs=[]
 for actions,change in changes(context,plan):
  if actions==['create']:
   after=change.get('after') or {};bucket=after.get('bucket')
   need(isinstance(bucket,str) and bucket,'Up notification bucket must be known before approval.')
   expected={}
  else:bucket,expected=owned(change.get('before'),context['account'],context['backend']['region'])
  live=normalize(aws('s3api','get-bucket-notification-configuration','--bucket',bucket,'--expected-bucket-owner',context['account']))
  need(live==expected,'Bucket notification contains unrelated entries or drift; refuse whole-document Terraform mutation.')
  proofs.append({'bucket':bucket,'owned_before':expected,'operation':context['operation']})
 return proofs

def completion(context,plan,state_rows,aws):
 """Run after apply; scope is notification ownership, not bucket/object absence."""
 receipts=[]
 for actions,change in changes(context,plan):
  if actions==['delete']:bucket,unused=owned(change['before'],context['account'],context['backend']['region']);expected={}
  else:
   rows=[r for r in state_rows if r.get('address')==ADDRESS]
   need(len(rows)==1,'Restored notification State identity is missing.')
   bucket,expected=owned(rows[0]['values'],context['account'],context['backend']['region'])
  live=normalize(aws('s3api','get-bucket-notification-configuration','--bucket',bucket,'--expected-bucket-owner',context['account']))
  need(live==expected,'Notification detach/restore was not observed.')
  receipts.append({'bucket':bucket,'notification_configuration':expected,'retained_object_mutations_requested':False})
 return receipts
