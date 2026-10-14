#!/usr/bin/env python3
"""Project non-secret retained-root inputs from the installed, reviewed chapter source.
No AWS, Terraform State, process execution, or credential retrieval is performed.
"""
import argparse,json,re
from pathlib import Path
ROOTS={'data':'data','delivery':'delivery','operations':'platform/operations','observability-foundation':'platform/observability','queue-managed':'platform/queue','account-integrations':'account-integrations'}
def need(value,message):
 if not value:raise ValueError(message)
# A deliberately restricted literal reader, not an HCL evaluator. Expressions,
# function calls and interpolation are never executed or guessed.
TOKEN=re.compile(r'\s+|\#[^\n]*|//[^\n]*|"(?:\\.|[^"\\])*"|-?[0-9]+(?:\.[0-9]+)?|[A-Za-z_][\w-]*|[{}\[\]=,:]')
def literal(text):
 tokens=[];end=0
 for m in TOKEN.finditer(text):
  need(not text[end:m.start()].strip(),'Non-literal default needs an explicit protected input.')
  end=m.end();s=m.group()
  if s.isspace() or s.startswith(('#','//')):continue
  tokens.append(s)
 # Parse only the first value: validation blocks after defaults are not inputs.
 def take(i):
  t=tokens[i]
  if t in ('{','['):
   out={} if t=='{' else [];close='}' if t=='{' else ']';i+=1
   while tokens[i]!=close:
    if tokens[i]==',':i+=1;continue
    if t=='{':
     k=tokens[i];k=json.loads(k) if k.startswith('"') else k;i+=1
     need(tokens[i] in ('=',':'),'Invalid literal object.');v,i=take(i+1)
     need(k not in out,'Duplicate literal object key.');out[k]=v
    else:v,i=take(i);out.append(v)
   return out,i+1
  if t.startswith('"'):
   v=json.loads(t);need('${' not in v and '%{' not in v,'Interpolated default needs explicit protected input.');return v,i+1
  if t in ('true','false','null'):return json.loads(t),i+1
  need(re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?',t),'Expression default needs explicit protected input.')
  return json.loads(t),i+1
 # Trim at end of first syntactically balanced literal before lexing source tails.
 return take(0)[0]
def variables(directory):
 result={}
 for p in sorted(directory.glob('*.tf')):
  text=p.read_text()
  for m in re.finditer(r'^variable\s+"([^"]+)"\s*\{(.*?)^\}',text,re.M|re.S):
   body=m[2];default=re.search(r'^\s*default\s*=\s*(.*)',body,re.M)
   # Retain only through the next top-level variable attribute; defaults can span lines.
   if default:
    value=body[default.start(1):]
    value=re.split(r'\n  (?:nullable|sensitive|validation|description|type)\s*[={]',value)[0]
    result[m[1]]=literal(value)
   else:result[m[1]]=MISSING
 return result
MISSING=object()
def project(repo,environment,module,runtime,eks,metadata,account,region):
 need(environment in ('dev','prod') and module in ROOTS,'Unknown environment or retained module.')
 need(re.fullmatch('[0-9]{12}',account) and region=='ap-northeast-2','Exact protected account and course region required.')
 for label,values in [('runtime',runtime),('eks',eks)]:
  need(isinstance(values,dict),label+' inputs must be an object.')
  for k,wanted in [('expected_account_id',account),('environment',environment),('region',region)]:
   need(k not in values or values[k]==wanted,label+' input boundary mismatch: '+k)
 need(isinstance(metadata,dict) and set(metadata)<= {'github_oidc_provider_arn'},'Only public GitHub OIDC provider ARN metadata is accepted.')
 base=repo/'terraform/environments'/environment
 rt=base/ROOTS[module];ret=base/'retained'/module
 need(rt.is_dir() and ret.is_dir(),'Install the chapter source layout before projecting inputs.')
 defaults=variables(rt);rv=variables(ret)
 result={k:v for k,v in [('environment',environment),('region',region),('expected_account_id',account),('provider_region',region),('provider_expected_account_id',account)]}
 def root_value(name):
  value=runtime.get(name,defaults.get(name,MISSING));need(value is not MISSING,'Missing protected '+ROOTS[module]+' input: '+name);return value
 for name,default in rv.items():
  if name in result or name in ('cluster_contract','operations_contract','application','database','github_oidc_provider_arn'):continue
  need(name not in runtime or name in defaults,'Unexposed runtime input needs source review: '+name)
  value=runtime.get(name,defaults.get(name,default))
  need(value is not MISSING,'Missing protected '+ROOTS[module]+' input: '+name)
  # Omit module-only defaults: Terraform evaluates the exact reviewed source.
  if name in runtime or name in defaults:result[name]=value
 if 'cluster_contract' in rv or 'operations_contract' in rv:
  name=eks.get('cluster_name');need(isinstance(name,str) and bool(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,99}',name)),'Missing explicit protected eks.cluster_name; do not copy a disposable cluster ARN.')
  if 'cluster_contract' in rv:result['cluster_contract']={'name':name}
  if 'operations_contract' in rv:result['operations_contract']={'cluster_name':name}
 if module=='data':
  db=root_value('database');need(isinstance(db,dict) and isinstance(db.get('name'),str),'data.database.name is required.');result['database']={'name':db['name']}
  delivery=variables(repo/'modules/runtime-delivery');sa=root_value('service_accounts')
  need(isinstance(sa,dict) and set(sa)=={'runtime','operator'},'Exact data.service_accounts naming contract required.')
  workloads=delivery.get('application_workloads',MISSING);namespace=delivery.get('application_namespace',MISSING)
  need(workloads is not MISSING and namespace is not MISSING,'Reviewed delivery application defaults missing.')
  # Current delivery root does not expose these as root inputs. Refuse a future
  # root rewrite rather than silently ignoring its explicit naming overrides.
  main=(base/'delivery/main.tf').read_text()
  need(not re.search(r'^\s*(application_namespace|application_workloads)\s*=',main,re.M),'Delivery naming override needs projection review.')
  result['application']={'namespace':namespace,'deployment':workloads['api']['deployment'],'runtime_service_account':sa['runtime'],'operator_service_account':sa['operator'],'migration_service_account':workloads['api']['migration_service_account']}
 if module=='delivery':
  arn=metadata.get('github_oidc_provider_arn');need(arn==f'arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com','Supply the existing account-baseline public github_oidc_provider_arn output; do not invent a provider.')
  repos=result.get('github_app_repositories')
  need(isinstance(repos,dict) and isinstance(repos.get('owner_id'),str),'Existing delivery GitHub numeric owner ID is required.')
  safe={'owner_id':repos['owner_id']}
  for kind in ('web','api'):
   row=repos.get(kind)
   need(isinstance(row,dict) and all(isinstance(row.get(k),str) for k in ('name','id')),'Existing delivery '+kind+' repository name and numeric ID required.')
   safe[kind]={k:row[k] for k in ('name','id')}
  result['github_app_repositories']=safe
  result['github_oidc_provider_arn']=arn
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--repo',type=Path,required=True);p.add_argument('--environment',choices=['dev','prod'],required=True);p.add_argument('--module',choices=sorted(ROOTS),required=True)
 p.add_argument('--runtime-inputs',type=Path,required=True);p.add_argument('--eks-inputs',type=Path,required=True);p.add_argument('--public-metadata',type=Path)
 p.add_argument('--account',required=True);p.add_argument('--region',default='ap-northeast-2');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();read=lambda x:json.loads(x.read_text())
 value=project(a.repo,a.environment,a.module,read(a.runtime_inputs),read(a.eks_inputs),read(a.public_metadata) if a.public_metadata else {},a.account,a.region)
 import os
 fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2);f.write('\n')
 print('Prepared '+str(a.output)+'; review and register for retained/'+a.module+'. No remote operation was performed.')
if __name__=='__main__':main()
