#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate allowlisted non-secret inputs and update reviewed native YAML fields.

This program has no AWS/cluster/GitHub write permissions. The apply workflow is
responsible for the successful-apply receipt; JSON alone is not an attestation.
"""
import argparse, copy, hashlib, io, ipaddress, json, os, re, subprocess, sys, tempfile
from pathlib import Path
from urllib.parse import urlsplit
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from ruamel.yaml import YAML
sys.path.insert(0,str(Path(__file__).resolve().parent))
from update_objstore_revision import DESTINATIONS,KEY
from platform_input_registry import active_entries

SENSITIVE = re.compile(r'(password|private.?key|access.?key|secret.?key|secret.?value|secret.?string|client.?secret|token|credential)',re.I)
SHA = re.compile(r'^[0-9a-f]{40}$')
ROOTS = {'network','core','gateway','operations','observability','queue-managed','delivery','data','identity','app-auth','alerting'}

def contained(repo, relative):
    repo=repo.resolve()
    p=Path(relative)
    if p.is_absolute() or '..' in p.parts: raise ValueError('invalid destination path')
    target=repo/p
    if target.is_symlink() or any(x.is_symlink() for x in target.parents if x.is_relative_to(repo)):
        raise ValueError('symlink destination is forbidden')
    if not target.resolve().is_relative_to(repo.resolve()): raise ValueError('destination leaves repository')
    return target

def validate_value(name,value,kind,request):
    if SENSITIVE.search(name): raise ValueError('credential field is forbidden: '+name)
    if kind=='boolean':
        if type(value) is not bool:raise ValueError('boolean required: '+name)
        return
    if kind=='integer':
        if type(value) is not int or value<0:raise ValueError('nonnegative integer required: '+name)
        return
    if not isinstance(value,str) or not value.strip() or '\n' in value or len(value)>1024:
        raise ValueError('bounded single-line string required: '+name)
    if any(x in value.lower() for x in ['-----begin','replace_me','example.invalid','example.com','<replace']):
        raise ValueError('unresolved example or credential text: '+name)
    if kind=='bucket' and not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',value):
        raise ValueError('invalid bucket: '+name)
    if kind=='arn':
        parts=value.split(':',5)
        if len(parts)!=6 or parts[:2]!=['arn','aws'] or parts[4]!=request['account_id']:
            raise ValueError('ARN account differs from expected account: '+name)
    if kind=='image':
        expected=re.escape(request['account_id']+'.dkr.ecr.'+request['region']+'.amazonaws.com/')
        if not re.fullmatch(expected+r'[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}',value) or value.endswith('0'*64):
            raise ValueError('image must be an immutable digest in the expected account/region: '+name)
    if kind=='region' and value!=request['region']:raise ValueError('region mismatch: '+name)
    if kind=='prefix' and (not value.startswith(request['environment']+'/') or '..' in value.split('/')):
        raise ValueError('prefix environment mismatch: '+name)
    if kind=='cidr':ipaddress.ip_network(value,strict=True)
    if kind=='endpoint':
        for endpoint in value.split(','):
            if not endpoint or endpoint!=endpoint.strip():raise ValueError('invalid endpoint list: '+name)
            parsed=urlsplit(endpoint if '://' in endpoint else '//'+endpoint)
            if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError('endpoint must contain no credentials/query: '+name)
            if parsed.port is not None and not 1<=parsed.port<=65535:raise ValueError('invalid endpoint port: '+name)

def set_pointer(document,pointer,value):
    if not pointer.startswith('/'):raise ValueError('JSON pointer must be absolute')
    parts=[x.replace('~1','/').replace('~0','~') for x in pointer[1:].split('/')]
    obj=document
    for part in parts[:-1]:obj=obj[int(part)] if isinstance(obj,list) else obj[part]
    key=int(parts[-1]) if isinstance(obj,list) else parts[-1]
    if isinstance(obj,dict) and key not in obj:raise ValueError('target field must already exist: '+pointer)
    obj[key]=value

def run(request,repo,environment,account,base):
    schema=json.loads((repo/'schemas/platform-inputs.schema.json').read_text())
    try:Draft202012Validator(schema,format_checker=FormatChecker()).validate(request)
    except ValidationError as e:raise ValueError('invalid receipt field: '+'.'.join(str(x) for x in e.path)) from None
    if request['environment']!=environment or request['account_id']!=account or request['base_revision']!=base:
        raise ValueError('receipt environment/account/base differs from trusted workflow inputs')
    if request['apply_revision']!=base:
        raise ValueError('successful-apply source differs from the approved publish base')
    if request['region']!='ap-northeast-2' or request['root'] not in ROOTS:
        raise ValueError('unsupported environment root or region')
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    if actual!=base:raise ValueError('repository HEAD changed since approved apply base')
    entries=active_entries(json.loads((repo/'automation/platform-input-mappings.json').read_text()),request['root'],environment)
    if not entries or len({x['field'] for x in entries})!=len(entries):raise ValueError('invalid/missing root allowlist')
    if set(request['values'])!={x['field'] for x in entries}:raise ValueError('missing or unknown fields for selected root')
    for entry in entries:validate_value(entry['field'],request['values'][entry['field']],entry['type'],request)
    receipt_path=contained(repo,'gitops/inputs/'+environment+'/'+request['root']+'.receipt.json')
    if receipt_path.exists():
        previous=json.loads(receipt_path.read_text())
        if any(previous.get(name)!=request[name] for name in ['environment','account_id','region','root']):
            raise ValueError('previous receipt belongs to a different environment/account/region/root')
        if previous['state_lineage']!=request['state_lineage']:raise ValueError('state lineage changed; explicit migration review required')
        if request['state_serial']<previous['state_serial']:raise ValueError('stale apply serial')
        if request['state_serial']==previous['state_serial'] and previous['values_sha256']!=hashlib.sha256(json.dumps(request['values'],sort_keys=True).encode()).hexdigest():
            prior_values=previous.get('published_values')
            if not isinstance(prior_values,dict) or not prior_values:
                raise ValueError('same serial expansion requires the previous verified field values; legacy receipt cannot prove them')
            if hashlib.sha256(json.dumps(prior_values,sort_keys=True).encode()).hexdigest()!=previous['values_sha256']:
                raise ValueError('previous published values do not match their receipt hash')
            if not set(prior_values)<set(request['values']) or any(request['values'][name]!=value for name,value in prior_values.items()):
                raise ValueError('same serial has conflicting values')
            if previous['apply_revision']==request['apply_revision'] or previous['base_revision']==base:
                raise ValueError('allowlist expansion requires a newly approved source and fresh successful-apply receipt')
    yaml=YAML();yaml.preserve_quotes=True
    documents={};sources={}
    for entry in entries:
        for dest in entry['targets']:
            relative=dest['file'].replace('{environment}',environment)
            parts=Path(relative).parts
            overlay=any(parts[i]=='overlays' and parts[i+1] in {environment,environment+'-e2',environment+'-e3'} for i in range(len(parts)-1))
            values=any(parts[i]=='values' and re.fullmatch(r'(?:(?:argo-cd|argo-rollouts|kyverno)-)?'+re.escape(environment)+r'(?:-[a-z0-9-]+)?\.yaml',parts[i+1]) for i in range(len(parts)-1))
            request_job=relative.startswith('gitops/platform/database-operations/requests/'+environment+'/') and bool(re.fullmatch(r'(?:job-database-bootstrap-[a-z0-9]+|operator-check-job)\.yaml',parts[-1]))
            if request_job and (entry['type']!='image' or dest['pointer']!='/spec/template/spec/containers/0/image'):
                raise ValueError('reviewed database request permits only its immutable operator image field')
            if not relative.startswith(('gitops/platform/','gitops/apps/')) or not (overlay or values or request_job):
                raise ValueError('mapping target is not selected environment native source')
            p=contained(repo,relative)
            if p not in documents:
                sources[p]=p.read_text();documents[p]=list(yaml.load_all(sources[p]))
            stream=documents[p];selector=dest.get('document_selector')
            if selector:
                if set(selector)!={'kind','name'}:raise ValueError('document selector must specify kind/name only')
                matches=[d for d in stream if isinstance(d,dict) and d.get('kind')==selector['kind'] and d.get('metadata',{}).get('name')==selector['name']]
                if len(matches)!=1:raise ValueError('document selector must match exactly one native object')
                document=matches[0]
            elif len(stream)==1:document=stream[0]
            else:raise ValueError('multiple YAML documents require an explicit selector')
            if request_job and (document.get('kind')!='Job' or not document.get('spec',{}).get('activeDeadlineSeconds') or not document['spec'].get('ttlSecondsAfterFinished')):
                raise ValueError('database request must be a bounded one-time native Job')
            if dest.get('embedded_pointer'):
                if dest['pointer']!='/configs/cm/oidc.config' or dest['embedded_pointer'] not in ['/issuer','/clientID']:raise ValueError('unsupported embedded scalar field')
                embedded=yaml.load(document['configs']['cm']['oidc.config'])
                secret=embedded.get('clientSecret')
                if secret!='$argocd-oidc-cognito:clientSecret':raise ValueError('OIDC credential must remain the fixed external Secret reference')
                set_pointer(embedded,dest['embedded_pointer'],request['values'][entry['field']])
                out=io.StringIO();yaml.dump(embedded,out);set_pointer(document,dest['pointer'],out.getvalue())
            else:set_pointer(document,dest['pointer'],request['values'][entry['field']])
    writes={}
    for p,d in documents.items():
        stream=io.StringIO()
        if len(d)==1:yaml.dump(d[0],stream)
        else:yaml.dump_all(d,stream)
        if stream.getvalue()!=sources[p]:writes[p]=stream.getvalue()
    if request['root']=='observability':
        config_path=contained(repo,'gitops/platform/monitoring/overlays/'+environment+'/objstore.yml')
        if config_path.exists():
            config_text=writes.get(config_path,config_path.read_text());config=yaml.load(config_text)['config']
            if config.get('aws_sdk_auth') is not True or any(k in config for k in ['access_key','secret_key','session_token']):raise ValueError('object store source must contain no credentials')
            digest=hashlib.sha256(config_text.encode()).hexdigest()
            for relative,keys in DESTINATIONS.values():
                target=contained(repo,relative.format(environment=environment))
                if not target.exists():continue # This consumer has not been authored/registered at this course stage.
                text=writes.get(target,target.read_text());data=yaml.load(text);current=data
                for key in keys:current=current.setdefault(key,{})
                current[KEY]=digest;stream=io.StringIO();yaml.dump(data,stream)
                if stream.getvalue()!=target.read_text():writes[target]=stream.getvalue()
    receipt={k:request[k] for k in ['schema_version','environment','account_id','region','root','apply_revision','base_revision','state_lineage','state_serial']}
    receipt['values_sha256']=hashlib.sha256(json.dumps(request['values'],sort_keys=True).encode()).hexdigest()
    receipt['published_values']=copy.deepcopy(request['values']) # Only fields already validated as non-sensitive and active for this root/environment.
    receipt_text=json.dumps(receipt,indent=2)+'\n'
    if not receipt_path.exists() or receipt_path.read_text()!=receipt_text:writes[receipt_path]=receipt_text
    if not writes:return []
    # Validate the full batch before a write; callers work on an isolated clean PR branch.
    originals={p:p.read_bytes() if p.exists() else None for p in writes}
    try:
        for p,content in writes.items():
            p.parent.mkdir(parents=True,exist_ok=True)
            with tempfile.NamedTemporaryFile('w',dir=p.parent,delete=False,encoding='utf-8') as f:
                f.write(content);tmp=Path(f.name)
            tmp.replace(p)
    except OSError:
        for p,original in originals.items():
            if original is None:p.unlink(missing_ok=True)
            else:p.write_bytes(original)
        raise
    return [str(p.relative_to(repo)) for p in writes]

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--repo',type=Path,required=True)
    p.add_argument('--expect-environment',choices=['dev','prod'],required=True);p.add_argument('--expect-account',required=True);p.add_argument('--expect-base-revision',required=True)
    a=p.parse_args()
    try:
        changed=run(json.loads(a.input.read_text()),a.repo.resolve(),a.expect_environment,a.expect_account,a.expect_base_revision)
        print(json.dumps({'changed_files':changed,'result':'updated' if changed else 'no-op'}))
    except (ValueError,KeyError,TypeError,OSError,subprocess.CalledProcessError) as e:
        p.exit(2,'platform input validation failed: '+str(e)+'\n')

if __name__=='__main__':main()
