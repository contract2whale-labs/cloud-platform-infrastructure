#!/usr/bin/env python3
"""Read-only proof that the exact source-owned Dev SSM document has no sessions.
Never terminates sessions, changes access, or treats tags as deletion authority.
"""
import json,re
ROOT='terraform/environments/dev/platform/dev-app-access'
DOCUMENT='CommerceDevelopmentAppHttps'
ROLE='CommerceDevelopmentAppSession'

def need(value,message):
 if not value:raise ValueError(message)
def capture(context,rows,upstream_rows,original=()):
 need(context.get('root')==ROOT and context.get('environment')=='dev','Dev session proof cannot cross the root/environment boundary.')
 account=context.get('account');region=context.get('backend',{}).get('region')
 need(isinstance(account,str) and re.fullmatch('[0-9]{12}',account) and region=='ap-northeast-2','Exact Dev session account/region is required.')
 owned={r['address']:r for r in rows};before={r['address']:r for r in (original or ())}
 for address,ty,identity in [('aws_ssm_document.dev_app_https','aws_ssm_document',DOCUMENT),('aws_iam_role.dev_app_session','aws_iam_role',ROLE)]:
  present=owned.get(address)
  if present:need(present['type']==ty and present['values'].get('id')==identity,'Dev session State has an unreviewed document/role identity.')
  else:need(before.get(address)=={'address':address,'type':ty,'id':identity},'No approved original Dev session identity remains; absence is not a disabled-source proof.')
 instances=[r['values'].get('id') for r in upstream_rows if r['type']=='aws_instance' and r['address']=='aws_instance.relay']
 need(len(instances)==1 and isinstance(instances[0],str) and re.fullmatch(r'i-[0-9a-f]{8,17}',instances[0]),'Exact source-owned private API relay State is required.')
 instance=instances[0];policy=owned.get('aws_iam_role_policy.dev_app_session')
 if policy:
  value=policy['values'];need(value.get('role')==ROLE,'Session policy owner differs from the approved role.')
  try:body=json.loads(value['policy'])
  except (ValueError,TypeError,KeyError):raise ValueError('Session IAM policy is unreadable.') from None
  statements=body.get('Statement');need(isinstance(statements,list),'Session policy statements are missing.')
  indexed={s.get('Sid'):s for s in statements if isinstance(s,dict)}
  need(len(indexed)==len(statements)==3 and set(indexed)=={'StartFixedSessionOnRelay','UseFixedDocumentOnly','ManageOwnSessions'},'Unreviewed Dev session policy statements.')
  for sid,resource in [('StartFixedSessionOnRelay',f'arn:aws:ec2:{region}:{account}:instance/{instance}'),('UseFixedDocumentOnly',f'arn:aws:ssm:{region}:{account}:document/{DOCUMENT}')]:
   stmt=indexed[sid];need(stmt.get('Effect')=='Allow' and stmt.get('Action')==['ssm:StartSession'] and stmt.get('Resource')==[resource],'Dev session policy points to another target/document.')
 return {'root':ROOT,'environment':'dev','account':account,'region':region,'instance_id':instance,'document_name':DOCUMENT,'role_name':ROLE}

def verify(target,aws):
 need(isinstance(target,dict) and target.get('root')==ROOT and target.get('environment')=='dev' and target.get('document_name')==DOCUMENT and target.get('role_name')==ROLE,'Unreviewed Dev session readback target.')
 need(isinstance(target.get('account'),str) and re.fullmatch('[0-9]{12}',target['account']) and target.get('region')=='ap-northeast-2' and isinstance(target.get('instance_id'),str) and re.fullmatch(r'i-[0-9a-f]{8,17}',target['instance_id']),'Invalid Dev session target boundary.')
 need(aws('sts','get-caller-identity').get('Account')==target['account'],'Dev session caller is in another account.')
 # DocumentName is not a supported SessionFilter. Filter by the exact State
 # instance, then inspect the document locally. Active includes disconnected.
 response=aws('ssm','describe-sessions','--state','Active','--filters',json.dumps([{'key':'Target','value':target['instance_id']}]),'--region',target['region'])
 need(isinstance(response,dict) and not response.get('NextToken') and isinstance(response.get('Sessions'),list),'Dev session inventory is incomplete.')
 seen=set()
 for session in response['Sessions']:
  need(isinstance(session,dict) and session.get('Target')==target['instance_id'] and isinstance(session.get('SessionId'),str) and session['SessionId'] and session['SessionId'] not in seen,'Session inventory has an ambiguous target or identity.')
  seen.add(session['SessionId'])
  need(isinstance(session.get('DocumentName'),str) and re.fullmatch(r'[a-zA-Z0-9_\-.]{3,128}',session['DocumentName']),'Session document is missing; cannot prove the Dev app session is closed.')
  need(session.get('Status') in ('Connected','Connecting','Disconnected','Terminating','Terminated','Failed'),'Unknown SSM session status.')
  need(session['DocumentName']!=DOCUMENT or session['Status'] in ('Terminated','Failed'),'An approved Dev app SSM session remains active or disconnected. Close it through its owner before creating a fresh Down plan.')
 return {'scope':'exact-dev-app-document-on-approved-relay','target':target,'active_owned_sessions':0,'read_only':True}
