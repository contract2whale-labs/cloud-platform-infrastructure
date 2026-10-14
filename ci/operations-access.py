#!/usr/bin/env python3
"""Incarnation-bound private bootstrap proof used by installer and Up adapters."""
import hashlib, importlib.util, json, pathlib, tempfile
BASE=pathlib.Path(__file__).resolve().parent

def key_for(environment,cluster_arn,created_at):
    if environment not in ('dev','prod'):raise ValueError('Unknown environment')
    incarnation=hashlib.sha256((cluster_arn+'|'+created_at).encode()).hexdigest()
    return 'operation-access/'+environment+'/'+incarnation+'/complete.json'

def verify_bootstrap_receipt(c,store, *, generation=None, config_sha256=None):
    """Latest exact version is validated privately, never assume an old cluster proof.

    c must come from fresh version-pinned EKS and relay State, not workflow input.
    An initial non-lifecycle bootstrap has generation null; lifecycle handoffs must
    pass the active generation and bundle digest for exact checkpoint continuity.
    """
    key=key_for(c['environment'],c['cluster_arn'],c['cluster_created_at'])
    info=store.state(key)
    if not info.get('exists'):raise RuntimeError('Fresh-cluster protected GitOps bootstrap handoff required before Up hooks.')
    if not isinstance(info.get('version'),str) or info['version'] in ('','null'):raise RuntimeError('Bootstrap proof is not versioned')
    with tempfile.TemporaryDirectory(prefix='private-bootstrap-proof-') as d:
        file=pathlib.Path(d)/'proof.json'
        result=store.call('get-object','--key',key,'--version-id',info['version'],str(file))
        if result.get('VersionId')!=info['version'] or result.get('ServerSideEncryption') not in ('AES256','aws:kms','aws:kms:dsse'):raise RuntimeError('Bootstrap proof version/encryption changed')
        raw=file.read_bytes();receipt=json.loads(raw)
    expected={'schema_version':1,'environment':c['environment'],'account_id':c['account_id'],'cluster_arn':c['cluster_arn'],'cluster_created_at':c['cluster_created_at'],'complete':True}
    if any(receipt.get(k)!=v for k,v in expected.items()):raise RuntimeError('Bootstrap proof does not match current cluster incarnation')
    if generation is not None and receipt.get('lifecycle_generation')!=generation:raise RuntimeError('Bootstrap proof belongs to another retained checkpoint')
    expected_config=config_sha256 or c.get('operations_access_config_sha256')
    if not expected_config or receipt.get('access_config_sha256')!=expected_config:raise RuntimeError('Reviewed access registration differs from bootstrap proof')
    if receipt.get('toolchain_sha256')!=hashlib.sha256(json.dumps({'operator_image':c['operator_image'],'tool_sha256':c['tool_sha256']},sort_keys=True,separators=(',',':')).encode()).hexdigest():raise RuntimeError('Bootstrap toolchain differs from reviewed registry')
    if c.get('lifecycle_snapshot_sha') is not None and receipt.get('snapshot_sha')!=c['lifecycle_snapshot_sha']:raise RuntimeError('Bootstrap proof belongs to another source checkpoint')
    if receipt.get('chart_sha256')!=c['bootstrap_chart_sha256']:raise RuntimeError('Bootstrap chart differs from reviewed registry')
    return {'key':key,'version':info['version'],'sha256':hashlib.sha256(raw).hexdigest(),'receipt':receipt}


def collect_bootstrap_residuals(c, rendered, installed, fetch, helm_status, resource_row, before_secret_uids=()):
    """Hash-only exact rows for a fresh, pinned chart and this installer's outputs.

    fetch receives a fixed API path and returns one live object, or None only for
    a chart hook with an explicit hook-succeeded deletion policy. Labels alone
    never establish ownership and secret bodies never enter the returned proof.
    """
    import yaml
    resources={
        'Namespace':('v1','namespaces',False),
        'ServiceAccount':('v1','serviceaccounts',True),
        'ConfigMap':('v1','configmaps',True),
        'Secret':('v1','secrets',True),
        'Service':('v1','services',True),
        'Deployment':('apps/v1','deployments',True),
        'StatefulSet':('apps/v1','statefulsets',True),
        'Role':('rbac.authorization.k8s.io/v1','roles',True),
        'RoleBinding':('rbac.authorization.k8s.io/v1','rolebindings',True),
        'ClusterRole':('rbac.authorization.k8s.io/v1','clusterroles',False),
        'ClusterRoleBinding':('rbac.authorization.k8s.io/v1','clusterrolebindings',False),
        'CustomResourceDefinition':('apiextensions.k8s.io/v1','customresourcedefinitions',False),
        'AppProject':('argoproj.io/v1alpha1','appprojects',True),
        'NetworkPolicy':('networking.k8s.io/v1','networkpolicies',True),
        'PodDisruptionBudget':('policy/v1','poddisruptionbudgets',True),
        'Job':('batch/v1','jobs',True),
        'Pod':('v1','pods',True),
    }
    def check(ok,why):
        if not ok:raise RuntimeError(why)
    check(helm_status.get('name')=='argocd' and helm_status.get('namespace')=='argocd' and helm_status.get('version')==1 and helm_status.get('info',{}).get('status')=='deployed','Bootstrap requires a fresh, deployed, exact Helm revision one')
    rows={}
    fields={'gvr','resource','base','namespaced','kind','namespace','name','uid','spec_sha256','metadata_policy_sha256'}
    def add(row):
        check(isinstance(row,dict) and set(row)==fields,'Installer residual row schema mismatch')
        key=(row['resource'],row['namespace'],row['name'])
        check(key not in rows or rows[key]==row,'Bootstrap residual sources disagree on an exact identity')
        rows[key]=row
    for row in installed:add(row)
    documents=[x for x in yaml.safe_load_all(rendered) if x]
    check(documents,'Pinned bootstrap chart rendered no objects')
    # These declarations are created directly by ops.bootstrap, not label-selected.
    projects=c.get('projects',[c.get('project')])
    check(all(isinstance(x,dict) and x.get('kind')=='AppProject' for x in projects),'Reviewed bootstrap projects missing')
    documents+=projects+[
        {'apiVersion':'v1','kind':'Secret','metadata':{'namespace':'argocd','name':'argocd-repo-gitops'}},
        {'apiVersion':'v1','kind':'Secret','metadata':{'namespace':'argocd','name':'sh.helm.release.v1.argocd.v1'}},
    ]
    for desired in documents:
        kind=desired['kind'];md=desired['metadata'];annotations=md.get('annotations',{})
        check(kind in resources,'Chart kind lacks a reviewed exact residual adapter: '+kind)
        gv,resource,namespaced=resources[kind]
        check(desired['apiVersion']==gv,'Unreviewed chart API version')
        namespace=md.get('namespace','argocd') if namespaced else ''
        check(not namespaced or namespace=='argocd','Chart object escapes the Argo namespace')
        check(kind!='Namespace' or md['name']=='argocd','Unreviewed chart namespace')
        base='/api/v1' if gv=='v1' else '/apis/'+gv
        hook=bool(annotations.get('helm.sh/hook'))
        deletable=hook and 'hook-succeeded' in annotations.get('helm.sh/hook-delete-policy','').split(',')
        obj=fetch(base+('/namespaces/'+namespace if namespaced else '')+'/'+resource+'/'+md['name'],allow_missing=deletable)
        if obj is None:
            check(deletable,'Unconfirmed missing bootstrap resource')
            continue
        check(isinstance(obj,dict) and obj.get('apiVersion')==gv and obj.get('kind')==kind and obj.get('metadata',{}).get('name')==md['name'] and obj['metadata'].get('namespace','')==namespace and obj['metadata'].get('uid'),'Bootstrap live resource differs from exact installed declaration')
        if kind in ('Job','Pod'):
            check(hook and obj['metadata'].get('annotations',{}).get('helm.sh/hook')==annotations['helm.sh/hook'],'Only exact declared Argo install hooks can be retained')
            if kind=='Job':check(not obj.get('status',{}).get('active') and not obj.get('status',{}).get('failed') and any(x.get('type')=='Complete' and x.get('status')=='True' for x in obj.get('status',{}).get('conditions',[])),'Chart install Job is incomplete or failed')
            else:check(obj.get('status',{}).get('phase')=='Succeeded','Chart install Pod is incomplete or failed')
        if md['name']=='sh.helm.release.v1.argocd.v1':
            labels=obj['metadata'].get('labels',{})
            check(obj.get('type')=='helm.sh/release.v1' and all(labels.get(k)==v for k,v in {'owner':'helm','name':'argocd','status':'deployed','version':'1'}.items()),'Exact Helm revision secret identity differs')
        add(resource_row({'gvr':gv+'/'+resource,'resource':resource,'base':base,'namespaced':namespaced,'object':obj}))
    # Argo may create its built-in default project when the pinned server starts.
    # It is an explicit bootstrap output, never a later names-only allowlist.
    # Capture its exact live identity/hash if present; every later consumer must
    # authenticate this row just like a manifest-owned AppProject.
    default_project=fetch('/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/default',allow_missing=True)
    if default_project is not None:
        md=default_project.get('metadata',{})
        check(default_project.get('apiVersion')=='argoproj.io/v1alpha1' and default_project.get('kind')=='AppProject' and md.get('namespace')=='argocd' and md.get('name')=='default' and md.get('uid'),'Invalid generated default AppProject identity')
        add(resource_row({'gvr':'argoproj.io/v1alpha1/appprojects','resource':'appprojects','base':'/apis/argoproj.io/v1alpha1','namespaced':True,'object':default_project}))
    # A generated Redis credential is not necessarily a manifest Secret. Only
    # exact Secret references in this pinned chart may add a newly-created row;
    # neither a label scan nor an arbitrary well-known Secret name is accepted.
    referenced=set()
    def references(value):
        if isinstance(value,list):
            for item in value:references(item)
        elif isinstance(value,dict):
            for key,item in value.items():
                if key in ('secretKeyRef','secretRef') and isinstance(item,dict) and isinstance(item.get('name'),str):referenced.add(item['name'])
                elif key=='secret' and isinstance(item,dict) and isinstance(item.get('secretName'),str):referenced.add(item['secretName'])
                references(item)
    for desired in documents:
        if desired.get('kind') in ('Deployment','StatefulSet','Job','Pod'):references(desired.get('spec',{}))
    for name in sorted(referenced):
        key=('secrets','argocd',name)
        if key in rows:continue
        import re
        check(re.fullmatch(r'[a-z0-9]([-a-z0-9.]*[a-z0-9])?',name),'Invalid chart Secret reference')
        obj=fetch('/api/v1/namespaces/argocd/secrets/'+name)
        check(isinstance(obj,dict) and obj.get('apiVersion')=='v1' and obj.get('kind')=='Secret' and obj.get('metadata',{}).get('namespace')=='argocd' and obj['metadata'].get('name')==name and obj['metadata'].get('uid') and obj['metadata']['uid'] not in before_secret_uids,'Referenced generated Secret must be new to this exact bootstrap')
        add(resource_row({'gvr':'v1/secrets','resource':'secrets','base':'/api/v1','namespaced':True,'object':obj}))
    return sorted(rows.values(),key=lambda row:(row['gvr'],row['namespace'],row['name']))
