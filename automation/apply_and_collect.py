#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply the exact reviewed saved plan and collect a non-secret receipt.

Run in the protected apply environment, not in a pull-request validation job.
State is read transiently only for lineage/serial, never logged or exported.
"""
import argparse, hashlib, json, os, subprocess, uuid
from pathlib import Path
from collect_platform_inputs import collect

ROOT_PATHS={'network':'network/vpc','core':'platform/core','gateway':'platform/gateway','operations':'platform/operations','observability':'platform/observability','queue-managed':'platform/queue','delivery':'delivery','data':'data','identity':'identity','app-auth':'platform/app-auth','alerting':'platform/alerting'}

def run(command,**kw):return subprocess.run(command,check=True,**kw)

def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--root',choices=ROOT_PATHS,required=True);p.add_argument('--environment',choices=['dev','prod'],required=True);p.add_argument('--profile',required=True);p.add_argument('--state-profile');p.add_argument('--expect-account',required=True);p.add_argument('--expect-revision',required=True);p.add_argument('--state-bucket',required=True);p.add_argument('--plan',type=Path,required=True);p.add_argument('--reviewed-plan-sha256',required=True);p.add_argument('--receipt',type=Path,required=True);a=p.parse_args()
 repo=a.repo.resolve();tfroot=repo/'terraform/environments'/a.environment/ROOT_PATHS[a.root]
 if a.receipt.exists() or a.receipt.is_symlink():raise FileExistsError('receipt path already exists; preserve the previous attempt and choose a new approved path')
 if hashlib.sha256(a.plan.read_bytes()).hexdigest()!=a.reviewed_plan_sha256:raise ValueError('saved plan differs from reviewed plan bytes')
 backend=json.loads((tfroot/'.terraform/terraform.tfstate').read_text())['backend']
 key=ROOT_PATHS[a.root]+'/terraform.tfstate'
 if backend['type']!='s3' or backend['config'].get('bucket')!=a.state_bucket or backend['config'].get('key')!=key:
  raise ValueError('initialized backend differs from selected root/bucket/key')
 head=run(['git','-C',str(repo),'rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()
 if head!=a.expect_revision:raise ValueError('checked out revision differs from approved revision')
 run(['git','-C',str(repo),'diff','--exit-code']);run(['git','-C',str(repo),'diff','--cached','--exit-code'])
 aws=['aws','--profile',a.profile,'--region','ap-northeast-2']
 account=run(aws+['sts','get-caller-identity','--query','Account','--output','text'],capture_output=True,text=True).stdout.strip()
 if account!=a.expect_account:raise ValueError('AWS apply identity differs from expected account')
 env=dict(os.environ);env['AWS_PROFILE']=a.profile;env.pop('TF_LOG',None);env.pop('TF_LOG_PATH',None)
 run(['terraform','-chdir='+str(tfroot),'apply','-input=false','-lock-timeout=5m',str(a.plan.resolve())],env=env)
 state_aws=['aws','--profile',a.state_profile or a.profile,'--region','ap-northeast-2']
 state_result=run(state_aws+['s3','cp','s3://'+a.state_bucket+'/'+key,'-','--expected-bucket-owner',a.expect_account,'--only-show-errors'],capture_output=True,text=True)
 state=json.loads(state_result.stdout);lineage=str(uuid.UUID(state['lineage']));serial=state['serial']
 if type(serial) is not int or serial<0:raise ValueError('invalid backend state serial')
 del state,state_result
 metadata={'schema_version':1,'environment':a.environment,'account_id':a.expect_account,'region':'ap-northeast-2','root':a.root,'apply_revision':head,'base_revision':head,'state_lineage':lineage,'state_serial':serial}
 previous=os.environ.get('AWS_PROFILE');os.environ['AWS_PROFILE']=a.profile
 try:receipt=collect(repo,tfroot,metadata)
 finally:
  if previous is None:os.environ.pop('AWS_PROFILE',None)
  else:os.environ['AWS_PROFILE']=previous
 a.receipt.parent.mkdir(parents=True,exist_ok=True)
 receipt_fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(receipt_fd,'w') as receipt_file:receipt_file.write(json.dumps(receipt,indent=2)+'\n')
 print('Reviewed saved plan applied. Allowlisted non-secret receipt collected; raw State and raw output were not saved.')

if __name__=='__main__':main()
