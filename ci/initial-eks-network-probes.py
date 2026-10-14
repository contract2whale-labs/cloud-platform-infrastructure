#!/usr/bin/env python3
"""Initial BU07 CI diagnostics without lifecycle Down/Up or course-pause writes."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
h=load('initial_probe_saved_plan','saved-plan.py')
c=load('initial_probe_course','lifecycle-state.py')
g=load('initial_probe_guard','eks-lifecycle-guard.py')
p=load('initial_probe_run','eks-network-probes.py')

def settings():
    h.require(h.required('GITHUB_ACTIONS')=='true' and h.required('GITHUB_EVENT_NAME')=='workflow_dispatch' and h.required('GITHUB_REF')=='refs/heads/main','Initial BU07 probes require trusted main CI dispatch.')
    h.require(h.required('PROBE_ENVIRONMENT')=='dev' and h.required('PROBE_APPLY_ENVIRONMENT')=='infra-dev-apply','Initial BU07 probe requires ordinary Dev apply gate.')
    image=h.required('LIFECYCLE_TOOLCHAIN_IMAGE')
    h.require(re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}',image),'Diagnostic runner toolchain image must be digest-pinned.')
    workspace=Path(h.required('GITHUB_WORKSPACE')).resolve()
    context={k:h.required(v) for k,v in {'repository_id':'GITHUB_REPOSITORY_ID','run_id':'GITHUB_RUN_ID','run_attempt':'GITHUB_RUN_ATTEMPT','sha':'GITHUB_SHA','account':'EXPECTED_ACCOUNT_ID'}.items()}
    h.require(all(context[k].isdigit() for k in ('repository_id','run_id','run_attempt')) and re.fullmatch('[0-9a-f]{40}',context['sha']) and re.fullmatch(r'\d{12}',context['account']),'Invalid initial probe run/account identity.')
    region=h.required('AWS_REGION');h.require(region=='ap-northeast-2','Initial probe region mismatch.')
    role=f"arn:aws:iam::{context['account']}:role/gha-infra-dev-apply"
    h.require(h.required('AWS_ROLE_ARN')==role,'Initial probe requires ordinary Dev apply role.')
    h.check_identity(context['account'],role)
    h.require(h.execute(['git','rev-parse','HEAD'],cwd=workspace).decode().strip()==context['sha'],'Initial probe source checkout mismatch.')
    h.execute(['git','diff','--exit-code','HEAD','--','terraform','modules','ci'],cwd=workspace)
    h.ensure_current_main(context)
    context.update(environment='dev',root='terraform/environments/dev/eks',backend={'bucket':h.required('STATE_BUCKET'),'region':region},source_sha=context['sha'],operation='initial-probe',generation=None,
                   probe_inputs=p.validate_inputs({'probe_image':h.required('EKS_PROBE_IMAGE'),'pause_image':h.required('EKS_PAUSE_IMAGE')},region,context['account']))
    capability=g.source_capability(workspace,context,'BU07')
    h.require(capability.get('operations_access') is True,'Initial BU07 probe requires reviewed access bootstrap source and receipt.')
    context['source_capability']=capability
    store=h.Store(context['backend']['bucket'],context['account']);store.check()
    c.assert_normal_allowed(store,context,workspace)
    for suffix,root in (('eks',context['root']),('platform-private-api','terraform/environments/dev/platform/private-api')):
        record,_=c.read_json(store,f"ci-lifecycle/{context['repository_id']}/dev/{suffix}.json")
        if record is not None:
            h.require(record.get('root')==root and record.get('account')==context['account'] and record.get('bucket')==store.bucket and record.get('region')==region and record.get('phase')=='active','EKS/relay lifecycle is paused or has an invalid checkpoint; use the common Up workflow.')
    return workspace,context,store

def run():
    os.umask(0o077);workspace,context,store=settings()
    config=p.registration(workspace,'dev')
    prefix=f"ci-logs/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/dev/eks/initial-network-probes/"
    with tempfile.TemporaryDirectory(prefix='initial-node-probes-') as directory:
        temp=Path(directory)
        try:
            result=p.run_probe_completion(context,store,config,evidence_file=temp/'progress.json')
            c.assert_normal_allowed(store,context,workspace);h.ensure_current_main(context)
            proof=temp/'completion.json';proof.write_bytes(h.canonical(result));receipt=store.put(prefix+'completion.json',proof)
            h.emit({'receipt_key':receipt['key'],'receipt_version':receipt['version'],'receipt_sha':receipt['sha256']})
            with open(h.required('GITHUB_STEP_SUMMARY'),'a') as out:
                out.write('\nBU07 initial network probes completed. The bounded Pods were removed by exact UID; namespace/RBAC remain.\n')
                out.write('\nPrivate evidence key: '+receipt['key']+'\nVersion: '+receipt['version']+'\nSHA-256: '+receipt['sha256']+'\n')
        finally:
            progress=temp/'progress.json'
            if progress.is_file():store.put(prefix+'progress.json',progress)

if __name__=='__main__':
    try:run()
    except Exception:raise SystemExit('Initial BU07 network probes stopped safely. Inspect private evidence; no lifecycle Down/Up was performed.')
