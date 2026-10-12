#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Render registered platform Applications and check source/ownership contracts.

This is a cluster-free test. Rendered CRD structural schemas are checked.
Built-in API schemas, CEL, admission and actual functionality require separate
checks; success is not evidence that a controller or service works.
"""
import argparse, json, shutil, subprocess, tempfile
from pathlib import Path
import yaml
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from jsonschema import Draft7Validator

def parser():
    result=YAML(typ='safe');result.version=(1,2)
    result.constructor.add_constructor('tag:yaml.org,2002:value',lambda loader,node: loader.construct_scalar(node))
    return result
def load_all(text):return list(parser().load_all(text))
def load(text):return parser().load(text)

def kubernetes_load_all(text):
    # Kubernetes' YAML-to-JSON decoder accepts YAML 1.1 integers (e.g. 0755).
    # Validate exact native stdout before any 1.2 parse/dump round trip.
    result=parser();result.version=(1,1)
    return [x for x in result.load_all(text) if x]

BUILTIN_GROUPS={'','apps','batch','policy','rbac.authorization.k8s.io',
    'networking.k8s.io','storage.k8s.io','autoscaling','apiextensions.k8s.io',
    'apiregistration.k8s.io','admissionregistration.k8s.io','scheduling.k8s.io',
    'coordination.k8s.io','discovery.k8s.io'}

def unknown_fields(value,schema,path=''):
    if schema.get('x-kubernetes-preserve-unknown-fields'):return []
    if isinstance(value,dict):
        props=schema.get('properties',{});extra=schema.get('additionalProperties');issues=[]
        for key,child in value.items():
            if key in props:issues+=unknown_fields(child,props[key],path+'/'+key)
            elif isinstance(extra,dict):issues+=unknown_fields(child,extra,path+'/'+key)
            elif extra is True:continue
            elif path=='' and key in ('apiVersion','kind','metadata'):continue
            elif path=='/metadata':continue
            elif schema.get('type')=='object' or props:issues.append(path+'/'+key)
        return issues
    if isinstance(value,list) and isinstance(schema.get('items'),dict):
        return [issue for i,child in enumerate(value) for issue in unknown_fields(child,schema['items'],path+'/'+str(i))]
    return []

def json_schema(schema):
    # OpenAPI nullable is not a Draft 7 keyword; preserve its Kubernetes meaning.
    if isinstance(schema,list):return [json_schema(x) for x in schema]
    if not isinstance(schema,dict):return schema
    converted={key:json_schema(value) for key,value in schema.items()}
    if schema.get('nullable') and isinstance(schema.get('type'),str):
        converted['type']=[schema['type'],'null']
    return converted

def check_crd_schemas(objects):
    schemas={}
    for obj in objects:
        if obj.get('kind')!='CustomResourceDefinition':continue
        for version in obj['spec']['versions']:
            if not version.get('served'):continue
            key=(obj['spec']['group'],obj['spec']['names']['kind'],version['name'])
            schema=version.get('schema',{}).get('openAPIV3Schema')
            if not isinstance(schema,dict):raise ValueError('served CRD has no structural schema: '+repr(key))
            if key in schemas and schemas[key]!=schema:raise ValueError('conflicting served CRD schemas: '+repr(key))
            schemas[key]=schema
    checked=0;builtin=0
    for obj in objects:
        api=obj['apiVersion'];group,version=api.split('/',1) if '/' in api else ('',api)
        if group in BUILTIN_GROUPS:
            builtin+=1;continue
        key=(group,obj['kind'],version);schema=schemas.get(key)
        if schema is None:raise ValueError('rendered custom API has no matching served CRD schema: '+repr(key))
        errors=list(Draft7Validator(json_schema(schema)).iter_errors(obj))
        unknown=unknown_fields(obj,schema)
        if errors or unknown:
            detail=[('/'+ '/'.join(map(str,e.absolute_path)))+': '+e.message for e in errors]
            detail+=['unknown field '+field for field in unknown]
            raise ValueError('CRD schema failed for '+repr(key)+'/'+obj['metadata']['name']+': '+'; '.join(detail))
        checked+=1
    return {'crd_objects_checked':checked,'builtin_objects_not_schema_checked':builtin}


CLUSTER_KINDS={'Namespace','CustomResourceDefinition','ClusterRole','ClusterRoleBinding','StorageClass','PriorityClass','ClusterIssuer','GatewayClass','MutatingWebhookConfiguration','ValidatingWebhookConfiguration','ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding','CSIDriver','ClusterPolicy','ClusterSecretStore','CiliumClusterwideNetworkPolicy','APIService'}

def safe_file(repo,name):
    p=Path(name)
    if p.is_absolute() or '..' in p.parts:raise ValueError('source path leaves repository')
    target=(repo/p).resolve()
    if not target.is_relative_to(repo.resolve()) or not target.exists():raise ValueError('missing source: '+name)
    return target

def render(repo,application,raw_outputs=None):
    spec=application['spec'];sources=spec.get('sources') or [spec['source']]
    rendered=[]
    def capture(raw):
        if raw_outputs is not None:raw_outputs.append(raw)
        return load_all(raw)
    for source in sources:
        if source.get('ref') and not source.get('path') and not source.get('chart'):continue
        if 'chart' in source:
            helm=source.get('helm',{});chart=source['chart'];url=source['repoURL'];version=source['targetRevision']
            if version in ['HEAD','main','latest','*'] or '*' in version:raise ValueError('chart version must be exact')
            cmd=['helm','template',helm.get('releaseName',application['metadata']['name']),('oci://'+url.rstrip('/')+'/'+chart if not url.startswith('https://') else chart),'--version',version,'--namespace',spec['destination']['namespace'],'--kube-version','1.36.0']
            if url.startswith('https://'):cmd+=['--repo',url]
            if not helm.get('skipCrds',False):cmd+=['--include-crds']
            for value in helm.get('valueFiles',[]):
                if value.startswith('$'):
                    alias,relative=value[1:].split('/',1)
                    matches=[s for s in sources if s.get('ref')==alias]
                    if len(matches)!=1:raise ValueError('unresolved values reference: '+alias)
                    path=safe_file(repo,relative)
                else:path=safe_file(repo,str(Path(source.get('path',''))/value))
                cmd+=['--values',str(path)]
            with tempfile.TemporaryDirectory() as work:
                inline=helm.get('valuesObject')
                if inline is not None:
                    p=Path(work)/'inline.yaml';p.write_text(yaml.safe_dump(inline));cmd+=['--values',str(p)]
                if helm.get('values'):
                    p=Path(work)/'inline-string.yaml';p.write_text(helm['values']);cmd+=['--values',str(p)]
                rendered+=capture(subprocess.check_output(cmd,text=True))
        else:
            path=safe_file(repo,source['path'])
            if (path/'kustomization.yaml').exists() or (path/'kustomization.yml').exists():
                cmd=['kustomize','build','--enable-helm',str(path)]
                rendered+=capture(subprocess.check_output(cmd,text=True))
            else:
                for p in sorted(path.rglob('*.yaml')):rendered+=capture(p.read_text())
    return [x for x in rendered if x]

def check(repo,env):
    if not (repo/'gitops').exists():return _check(repo,env)
    if any(path.is_symlink() for path in (repo/'gitops').rglob('*')):raise ValueError('native source tree must contain no symlinks')
    # Kustomize's Helm integration downloads charts beside the source. Render
    # in a temporary source copy so checks cannot contaminate an input PR.
    with tempfile.TemporaryDirectory(prefix='native-source-check-') as directory:
        work=Path(directory)
        shutil.copytree(repo/'gitops',work/'gitops',ignore=shutil.ignore_patterns('charts','__pycache__'))
        return _check(work,env)

def _check(repo,env):
    cluster=repo/'gitops/clusters'/env
    indexes=[cluster/'platform-applications',cluster/'apps']
    if not any(x.exists() for x in indexes):return {'environment':env,'applications':0,'resources':0,'scope':'no platform Applications registered yet'}
    owners={};count=0;apps=0;raw_outputs=[]
    for p in sorted(path for index in indexes for path in index.glob('*.yaml')):
        for app in load_all(p.read_text()):
            if not app or app.get('kind')!='Application':continue
            name=app['metadata']['name'];apps+=1
            for obj in render(repo,app,raw_outputs):
                if not all(k in obj for k in ['apiVersion','kind','metadata']):raise ValueError('incomplete rendered resource in '+name)
                meta=obj['metadata'];kind=obj['kind']
                ns='' if kind in CLUSTER_KINDS else meta.get('namespace',app['spec']['destination'].get('namespace','default'))
                key=(obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else '',kind,ns,meta.get('name',''))
                if not key[-1]:raise ValueError('rendered resource has no name in '+name)
                if key in owners:raise ValueError('duplicate desired owner: '+repr(key)+' in '+owners[key]+' and '+name)
                owners[key]=name;count+=1
                if kind=='Secret' and meta.get('name')=='thanos-objstore':
                    raw=(obj.get('stringData') or {}).get('objstore.yml')
                    if raw is None:
                        import base64
                        encoded=obj.get('data',{}).get('objstore.yml','')
                        # Kustomize emits valid folded base64 lines; reject non-base64 bytes after normalizing ASCII whitespace.
                        raw=base64.b64decode(''.join(encoded.split()),validate=True).decode()
                    config=load(raw)
                    if not config or config['config'].get('aws_sdk_auth') is not True:raise ValueError('Thanos must use AWS SDK identity')
                    if any(k in config['config'] for k in ['access_key','secret_key','session_token']):raise ValueError('Thanos config must contain no credentials')
    schema_result=check_crd_schemas(kubernetes_load_all('\n---\n'.join(raw_outputs)))
    return {'environment':env,'applications':apps,'resources':count,**schema_result,
            'scope':'native render, single desired owner and served CRD structural schema; built-in/CEL/admission/live unverified'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--environment',choices=['dev','prod']);a=p.parse_args()
    try:print(json.dumps([check(a.repo.resolve(),e) for e in ([a.environment] if a.environment else ['dev','prod'])],ensure_ascii=False))
    except (ValueError,KeyError,subprocess.CalledProcessError,YAMLError,yaml.YAMLError) as e:p.exit(2,'platform source check failed: '+str(e)+'\n')

if __name__=='__main__':main()
