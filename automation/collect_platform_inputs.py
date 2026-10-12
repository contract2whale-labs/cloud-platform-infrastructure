#!/usr/bin/env python3
"""Collect only allowlisted non-sensitive Terraform outputs in the apply job.

Call after the approved saved plan applies successfully. Metadata comes from
that protected job. This is not a standalone proof of a successful AWS apply.
"""
import argparse, json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from platform_input_registry import active_entries

def pointer(value,path):
    for key in path.lstrip('/').split('/') if path else []:
        key=key.replace('~1','/').replace('~0','~')
        value=value[int(key)] if isinstance(value,list) else value[key]
    return value

def collect(repo,terraform_root,metadata):
    entries=active_entries(json.loads((repo/'automation/platform-input-mappings.json').read_text()),metadata['root'],metadata['environment'])
    if not entries:raise ValueError('root has no explicit publishable fields')
    # Terraform JSON includes sensitive flags. Keep the raw result only in memory.
    env=dict(os.environ);env.pop('TF_LOG',None);env.pop('TF_LOG_PATH',None)
    result=subprocess.run(['terraform','-chdir='+str(terraform_root),'output','-json'],env=env,capture_output=True,text=True,check=True)
    outputs=json.loads(result.stdout);values={}
    for entry in entries:
        source=entry['source']
        if source.get('metadata'):
            if source['metadata'] not in ['region','account_id','environment']:raise ValueError('unsupported metadata field')
            values[entry['field']]=metadata[source['metadata']];continue
        output=outputs[source['output']]
        if output.get('sensitive') is not False:raise ValueError('sensitive or unknown sensitivity output: '+source['output'])
        values[entry['field']]=pointer(output['value'],source.get('pointer',''))
    del outputs,result
    return {**metadata,'values':values}

def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,default=Path('.'));p.add_argument('--terraform-root',type=Path,required=True);p.add_argument('--metadata',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        if a.output.exists() or a.output.is_symlink():
            raise FileExistsError("receipt path already exists; preserve the previous attempt and choose a new approved path")
        request=collect(a.repo,a.terraform_root,json.loads(a.metadata.read_text()))
        a.output.parent.mkdir(parents=True,exist_ok=True)
        receipt_fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(receipt_fd,'w') as receipt_file:
            receipt_file.write(json.dumps(request,indent=2)+'\n')
        print('Non-sensitive allowlisted receipt prepared; raw output was not persisted.')
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as e:p.exit(2,'input collection stopped: '+str(e)+'\n')

if __name__=='__main__':main()
