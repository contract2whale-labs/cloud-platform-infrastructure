#!/usr/bin/env python3
"""Protected fresh-cluster bootstrap and reviewed same-incarnation access refresh.

The bootstrap principal has persistent Terraform-owned EKS admin access, but OIDC
is admitted ONLY through gitops-<env>-bootstrap. A started marker forbids blind
retry. No ordinary principal may assume the relay's instance authority.
"""
import argparse, hashlib, importlib.util, json, os, pathlib, subprocess, sys, tempfile, time
BASE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(BASE));sys.path.insert(0,str(BASE.parent/'gitops'))
from bootstrap_receipt import key_for, collect_bootstrap_residuals

def require(ok,message):
    if not ok:raise RuntimeError(message)
def run(args,env=None):
    p=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
    require(p.returncode==0,'Private access installation command failed; inspect protected logs.');return p.stdout

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

PLURAL={'Namespace':'namespaces','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','ValidatingAdmissionPolicy':'validatingadmissionpolicies','ValidatingAdmissionPolicyBinding':'validatingadmissionpolicybindings'}

def generated_declarations(bundle):
    return [item for source in ('admission.json','rbac.json') for item in json.loads((bundle/source).read_text())['items']]

def capture_installer_rows(bundle,env,hooks):
    rows=[]
    for desired in generated_declarations(bundle):
        md=desired['metadata'];gv=desired['apiVersion'];resource=PLURAL[desired['kind']];base='/api/v1' if gv=='v1' else '/apis/'+gv;ns=md.get('namespace')
        obj=json.loads(run(['kubectl','get','--raw',base+('/namespaces/'+ns if ns else '')+'/'+resource+'/'+md['name']],env))
        rows.append(hooks.resource_row({'gvr':gv+'/'+resource,'resource':resource,'base':base,'namespaced':bool(ns),'object':obj}))
    namespaces=[x['metadata']['name'] for x in generated_declarations(bundle) if x['kind']=='Namespace']
    for ns in namespaces:
        for resource,name in (('serviceaccounts','default'),('configmaps','kube-root-ca.crt')):
            obj=None
            for _ in range(60):
                raw=run(['kubectl','-n',ns,'get',resource,name,'--ignore-not-found','-o','json'],env)
                if raw.strip():obj=json.loads(raw);break
                time.sleep(1)
            require(obj is not None,'Namespace controller defaults not ready; preserve the access marker')
            rows.append(hooks.resource_row({'gvr':'v1/'+resource,'resource':resource,'base':'/api/v1','namespaced':True,'object':obj}))
    return sorted(rows,key=lambda row:(row['gvr'],row['namespace'],row['name']))

def row_identity(row):return row['resource'],row['namespace'],row['name']

def validate_refresh_scope(prior,c,bundle):
    require(prior.get('complete') is True and prior.get('schema_version')==1,'Prior access proof is incomplete')
    require(all(prior.get(k)==c[v] for k,v in [('environment','environment'),('account_id','account_id'),('cluster_arn','cluster_arn'),('cluster_created_at','cluster_created_at'),('chart_sha256','bootstrap_chart_sha256')]),'Access refresh cannot change cluster incarnation or chart')
    toolchain=hashlib.sha256(json.dumps({'operator_image':c['operator_image'],'tool_sha256':c['tool_sha256']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    require(prior.get('toolchain_sha256')==toolchain,'Access refresh cannot change bootstrap toolchain')
    installed=prior.get('installer_residual_resources');boot=prior.get('bootstrap_residual_resources')
    require(isinstance(installed,list) and installed and isinstance(boot,list) and boot,'Prior exact bootstrap resource proof is missing')
    old={row_identity(row):row for row in boot}
    require(len(old)==len(boot) and all(old.get(row_identity(row))==row for row in installed),'Prior installer and chart identity inventories disagree')
    declared={(PLURAL[x['kind']],x['metadata'].get('namespace',''),x['metadata']['name']) for x in generated_declarations(bundle)}
    require({row_identity(row) for row in installed if row['kind'] in PLURAL}<=declared,'Access refresh only expands existing generated declarations; removal requires separate reviewed revocation')
    require(('configmaps','argocd','argocd-rbac-cm') in old,'Prior exact Argo RBAC ConfigMap identity is missing')
    return old

def apply_generated_refresh(bundle,prior_rows,env,hooks,ops):
    """Per-object optimistic concurrency; no takeover through server-side apply."""
    import copy,yaml
    for desired in generated_declarations(bundle):
        md=desired['metadata'];gv=desired['apiVersion'];resource=PLURAL[desired['kind']];ns=md.get('namespace','')
        identity=(resource,ns,md['name']);base='/api/v1' if gv=='v1' else '/apis/'+gv
        qualified=resource if gv=='v1' else resource+'.'+gv.split('/')[0]
        args=['kubectl','get',qualified,md['name']]+(['-n',ns] if ns else [])+['--ignore-not-found','-o','json']
        raw=run(args,env);live=json.loads(raw) if raw.strip() else None
        declaration=copy.deepcopy(desired)
        if live is None:
            require(identity not in prior_rows,'Previously owned generated access object vanished')
            ops.run(['kubectl','create','--field-manager=course-operation-access','-f','-'],content=yaml.safe_dump(declaration).encode())
        else:
            actual=hooks.resource_row({'gvr':gv+'/'+resource,'resource':resource,'base':base,'namespaced':bool(ns),'object':live})
            require(identity in prior_rows and actual==prior_rows[identity],'Generated access object changed or belongs to another owner')
            declaration['metadata'].update(uid=live['metadata']['uid'],resourceVersion=live['metadata']['resourceVersion'])
            ops.run(['kubectl','apply','--server-side','--field-manager=course-operation-access','-f','-'],content=yaml.safe_dump(declaration).encode())

def refresh_argo_access(c,prior_rows,env,hooks,ops):
    """Only reviewed Projects and policy.csv; no Helm or credential operation."""
    import copy,yaml
    changed={}
    cm=json.loads(run(['kubectl','-n','argocd','get','configmap','argocd-rbac-cm','-o','json'],env))
    item={'gvr':'v1/configmaps','resource':'configmaps','base':'/api/v1','namespaced':True,'object':cm}
    require(hooks.resource_row(item)==prior_rows[('configmaps','argocd','argocd-rbac-cm')],'Argo access ConfigMap changed before refresh')
    require(cm.get('data',{}).get('policy.default','')=='','Unexpected Argo default authorization policy')
    policy='\n'.join(f'p, ci, applications, {action}, {a["spec"]["project"]}/{a["metadata"]["name"]}, allow' for a in c.get('rbac_applications',c['applications']+c.get('authority_applications',[])) for action in ('get','sync'))
    patch=[{'op':'test','path':'/metadata/uid','value':cm['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':cm['metadata']['resourceVersion']},{'op':'add','path':'/data/policy.csv','value':policy}]
    run(['kubectl','-n','argocd','patch','configmap','argocd-rbac-cm','--type=json','-p',json.dumps(patch)],env)
    current=json.loads(run(['kubectl','-n','argocd','get','configmap','argocd-rbac-cm','-o','json'],env))
    expected=copy.deepcopy(cm);expected['data']['policy.csv']=policy
    require(current['metadata']['uid']==cm['metadata']['uid'] and {k:v for k,v in current.items() if k not in ('metadata','status')}=={k:v for k,v in expected.items() if k not in ('metadata','status')},'Argo access refresh changed unrelated ConfigMap fields')
    require(all(current['metadata'].get(k)==cm['metadata'].get(k) for k in ('labels','annotations','finalizers','ownerReferences')),'Argo access refresh changed unrelated ConfigMap ownership')
    changed[('configmaps','argocd','argocd-rbac-cm')]=hooks.resource_row(dict(item,object=current))
    for desired in ops.registered_projects(c):
        name=desired['metadata']['name'];identity=('appprojects','argocd',name)
        raw=run(['kubectl','-n','argocd','get','appproject',name,'--ignore-not-found','-o','json'],env)
        live=json.loads(raw) if raw.strip() else None
        declared=copy.deepcopy(desired)
        if live is not None:
            item={'gvr':'argoproj.io/v1alpha1/appprojects','resource':'appprojects','base':'/apis/argoproj.io/v1alpha1','namespaced':True,'object':live}
            require(identity in prior_rows and hooks.resource_row(item)==prior_rows[identity],'Unowned or changed Argo Project cannot be taken over by access refresh')
            declared['metadata'].update(uid=live['metadata']['uid'],resourceVersion=live['metadata']['resourceVersion'])
            ops.run(['kubectl','apply','--server-side','--field-manager=platform-bootstrap','-f','-'],content=yaml.safe_dump(declared).encode())
        else:
            require(identity not in prior_rows,'Previously owned Argo Project vanished')
            ops.run(['kubectl','create','-f','-'],content=yaml.safe_dump(declared).encode())
        current=json.loads(run(['kubectl','-n','argocd','get','appproject',name,'-o','json'],env))
        require(current.get('spec')==desired['spec'] and (live is None or current['metadata']['uid']==live['metadata']['uid']),'Argo Project differs from reviewed declaration')
        changed[identity]=hooks.resource_row({'gvr':'argoproj.io/v1alpha1/appprojects','resource':'appprojects','base':'/apis/argoproj.io/v1alpha1','namespaced':True,'object':current})
    return changed

def refresh_access(a,bundle,m,c,store,adapter,checkpoint_key,checkpoint,control,fingerprints,helper,ops):
    """Protected same-incarnation expansion. A claimed refresh is never retried blind."""
    from bootstrap_receipt import verify_bootstrap_receipt
    import copy,lifecycle_hooks as hooks
    key=key_for(c['environment'],c['cluster_arn'],c['cluster_created_at'])
    require(a.previous_receipt_version and a.previous_receipt_sha256,'Access refresh requires exact prior receipt version and hash')
    previous={'key':key,'version':a.previous_receipt_version,'sha256':a.previous_receipt_sha256}
    current=store.state(key);require(current.get('exists') and current['version']==previous['version'],'Prior receipt is no longer current')
    with tempfile.TemporaryDirectory(prefix='private-access-refresh-') as directory:
        temp=pathlib.Path(directory);path=temp/'previous.json';store.get(previous,path);prior=json.loads(path.read_bytes())
        old_config=dict(c,operations_access_config_sha256=prior.get('access_config_sha256'))
        old_config.pop('lifecycle_snapshot_sha',None)
        proof=verify_bootstrap_receipt(old_config,store,config_sha256=prior.get('access_config_sha256'))
        require({k:proof[k] for k in ('key','version','sha256')}==previous,'Prior bootstrap authentication changed')
        old_rows=validate_refresh_scope(prior,c,bundle)
        require(prior['access_config_sha256']!=m['config_sha256'],'Access registration is already installed; no refresh needed')
        refresh_key=key.replace('/complete.json','/access-refresh.json')
        marker,marker_info=adapter.state.read_json(store,refresh_key)
        if marker is not None:
            require(marker.get('phase')=='complete' and marker.get('receipt')==previous,'An access refresh was interrupted or its proof changed; explicit recovery review required')
        with helper.private_api(c['cluster'],c['relay'],c['region'],temp/'kubeconfig') as (env,info):
            require(info['arn']==c['cluster_arn'] and info['createdAt']==c['cluster_created_at'],'Refresh cluster incarnation changed')
            os.environ['KUBECONFIG']=env['KUBECONFIG']
            hooks.verify_resource_rows(prior['bootstrap_residual_resources'])
            require(store.state(key)==current and store.state(checkpoint_key)==checkpoint,'Access receipt/course checkpoint changed before refresh')
            _,latest=adapter.live_binding(c,store);require(latest==fingerprints,'EKS/relay State changed before access refresh')
            ops.current_main()
            marker={'schema_version':1,'phase':'refreshing','environment':c['environment'],'cluster_arn':c['cluster_arn'],'cluster_created_at':c['cluster_created_at'],'previous_receipt':previous,'bundle_sha256':a.expected_bundle_sha256,'source_sha':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID']}
            marker_info=adapter.state.update(store,refresh_key,marker,marker_info)
            apply_generated_refresh(bundle,old_rows,env,hooks,ops)
            rows=capture_installer_rows(bundle,env,hooks)
            replacements={row_identity(row):row for row in rows}
            replacements.update(refresh_argo_access(c,old_rows,env,hooks,ops))
            updated=copy.deepcopy(old_rows);updated.update(replacements)
            # Recheck all exact old survivors and refreshed rows before receipt CAS.
            hooks.verify_resource_rows(list(updated.values()))
            require(store.state(checkpoint_key)==checkpoint and store.state(key)==current,'Course/access proof changed during refresh')
            _,latest=adapter.live_binding(c,store);require(latest==fingerprints,'EKS/relay State changed during access refresh')
            adapter.state.assert_incident_clear(store,{'root':'terraform/environments/'+c['environment']+'/eks','repository_id':os.environ['GITHUB_REPOSITORY_ID'],'account':c['account_id'],'backend':{'bucket':c['state_bucket'],'region':c['region']}})
            ops.current_main()
            receipt=copy.deepcopy(prior)
            receipt.update(access_config_sha256=m['config_sha256'],installer_residual_resources=rows,bootstrap_residual_resources=sorted(updated.values(),key=lambda row:(row['gvr'],row['namespace'],row['name'])),state_bindings=fingerprints,previous_receipt=previous,refresh_bundle_sha256=a.expected_bundle_sha256,refresh_source_sha=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'])
            if control is not None:receipt.update(lifecycle_generation=control['generation'],snapshot_sha=control['snapshot_sha'])
            info=adapter.state.update(store,key,receipt,current)
            descriptor={'key':key,'version':info['version'],'sha256':adapter.h.digest(adapter.h.canonical(receipt))}
            marker.update(phase='complete',receipt=descriptor)
            adapter.state.update(store,refresh_key,marker,marker_info)
            print(json.dumps(descriptor,sort_keys=True))

def main():
    p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);p.add_argument('--expected-bundle-sha256',required=True)
    p.add_argument('--checkpoint-version');p.add_argument('--checkpoint-sha256');p.add_argument('--generation')
    p.add_argument('--mode',choices=('initial','access-refresh'),default='initial');p.add_argument('--previous-receipt-version');p.add_argument('--previous-receipt-sha256');a=p.parse_args()
    require(a.mode=='access-refresh' or not (a.previous_receipt_version or a.previous_receipt_sha256),'Prior receipt inputs are access-refresh-only')
    bundle=pathlib.Path(a.bundle);raw=(bundle/'access-manifest.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==a.expected_bundle_sha256,'Reviewed access bundle digest mismatch')
    m=json.loads(raw);e=m['environment'];account=m['account_id'];registration=json.loads((bundle/'registration.json').read_text())
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REF')=='refs/heads/main' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','Protected main dispatch required')
    require(os.environ.get('ACCESS_INSTALL_ENVIRONMENT')=='gitops-'+e+'-bootstrap','Exact protected bootstrap Environment required')
    require(os.environ.get('GITHUB_REPOSITORY_ID')==registration['repository_id'],'Wrong repository identity')
    for name,wanted in m['files'].items():
        path=bundle/name;require(path.resolve().is_relative_to(bundle.resolve()),'Invalid bundle path')
        require(hashlib.sha256(path.read_bytes()).hexdigest()==wanted,'Access bundle file changed')
    import gitops_ops as ops
    ops.current_main();c=ops.load(e,'bootstrap');ops.preflight(c,require_argo_token=a.mode=='initial')
    require(set(registration['application_names'])=={x['metadata']['name'] for x in c['applications']+c.get('authority_applications',[])},'Access and GitOps Application inventories differ')
    require(c['bootstrap_chart_sha256']==registration['bootstrap_chart_sha256'],'Access bootstrap chart fingerprint differs from registered chart')
    run(['git','merge-base','--is-ancestor',registration['reviewed_source_sha'],os.environ['GITHUB_SHA']])
    require(c.get('operations_access_config_sha256')==m['config_sha256'],'Access registration differs from protected GitOps registry')
    require(c['account_id']==account and c['state_bucket']==registration['state_bucket'] and c['region']==registration['region'],'Bootstrap and access registration differ')
    principal='arn:aws:iam::'+account+':role/cp-'+e+'-gitops-bootstrap'
    require(c['bootstrap_role_arn']==principal and os.environ.get('AWS_ROLE_ARN')==principal,'Wrong registered bootstrap principal')
    caller=json.loads(run(['aws','sts','get-caller-identity']))
    require(caller['Account']==account and caller['Arn'].startswith('arn:aws:sts::'+account+':assumed-role/cp-'+e+'-gitops-bootstrap/'),'Wrong bootstrap identity')
    adapter=module('access_state_binding',BASE.parent/'gitops'/'gitops-lifecycle.py')
    store=adapter.h.Store(c['state_bucket'],account);store.check();c,fingerprints=adapter.live_binding(c,store)
    require(c['cluster']==m['cluster_name'],'Different EKS cluster')
    # Relay may have been recreated. Runtime target is ONLY the versioned State ID;
    # IAM limits StartSession to the immutable four-tag private relay role.
    associated=json.loads(run(['aws','eks','list-associated-access-policies','--cluster-name',c['cluster'],'--principal-arn',principal,'--region',c['region']]))['associatedAccessPolicies']
    require(any(x['policyArn']=='arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy' and x['accessScope']['type']=='cluster' for x in associated),'Terraform bootstrap association missing')
    checkpoint_key='ci-lifecycle/'+registration['repository_id']+'/'+e+'/course.json';checkpoint=store.state(checkpoint_key)
    control=None
    if checkpoint.get('exists'):
        require(a.checkpoint_version and a.checkpoint_sha256 and a.generation,'Existing lifecycle checkpoint needs exact private version/hash/generation')
        require(checkpoint['version']==a.checkpoint_version,'Lifecycle checkpoint advanced')
        with tempfile.TemporaryDirectory() as d:
            f=pathlib.Path(d)/'checkpoint';store.get({'key':checkpoint_key,'version':a.checkpoint_version,'sha256':a.checkpoint_sha256},f);control=json.loads(f.read_bytes())
        require(control.get('generation')==a.generation and control.get('environment',e)==e,'Wrong lifecycle generation')
        adapter.state.validate_course(control,registration['repository_id'],account,c['state_bucket'],c['region'],e)
        if control['phase']=='paused':
            require(control.get('operation')=='up' and 'eks' in control.get('completed',[]),'Paused bootstrap requires Up with the exact EKS root already completed')
            if a.mode=='access-refresh':require(control['completed']==control['steps'][:control['steps'].index('eks')+1],'Paused access refresh is permitted only at the exact post-EKS pre-hook Up handoff')
    else:require(not any((a.checkpoint_version,a.checkpoint_sha256,a.generation)),'No checkpoint exists for supplied binding')
    adapter.state.assert_incident_clear(store,{'root':'terraform/environments/'+e+'/eks','repository_id':registration['repository_id'],'account':account,'backend':{'bucket':c['state_bucket'],'region':c['region']}})
    helper=module('private_session',BASE.parent/'private-api-session.py')
    if a.mode=='access-refresh':
        refresh_access(a,bundle,m,c,store,adapter,checkpoint_key,checkpoint,control,fingerprints,helper,ops)
        return
    key=key_for(e,c['cluster_arn'],c['cluster_created_at']);started=key.replace('/complete.json','/started.json')
    require(not store.state(key).get('exists'),'This cluster incarnation was already bootstrapped; ordinary operations must use scoped role')
    require(not store.state(started).get('exists'),'Bootstrap was interrupted; preserve marker and request explicit recovery review, never blindly retry')
    helper=module('private_session',BASE.parent/'private-api-session.py')
    with tempfile.TemporaryDirectory(prefix='private-access-install-') as d:
        temp=pathlib.Path(d)
        marker={'environment':e,'cluster_arn':c['cluster_arn'],'cluster_created_at':c['cluster_created_at'],'bundle_sha256':a.expected_bundle_sha256,'lifecycle_generation':a.generation,'snapshot_sha':control.get('snapshot_sha') if control else None,'run_id':os.environ['GITHUB_RUN_ID']}
        f=temp/'started.json';f.write_text(json.dumps(marker))
        with helper.private_api(c['cluster'],c['relay'],c['region'],temp/'kubeconfig') as (env,info):
            require(info['arn']==c['cluster_arn'] and info['createdAt']==c['cluster_created_at'],'Cluster incarnation changed')
            os.environ['KUBECONFIG']=env['KUBECONFIG']
            nodes=json.loads(run(['kubectl','get','nodes','-o','json'],env))['items']
            require(nodes and all(any(x.get('type')=='Ready' and x.get('status')=='True' for x in n.get('status',{}).get('conditions',[])) for n in nodes),'Bootstrap requires created Ready worker nodes; resume infrastructure Up first')
            chart=ops.BASE/'vendor'/'argo-cd-10.9.0.tgz'
            require(chart.is_file() and hashlib.sha256(chart.read_bytes()).hexdigest()==c['bootstrap_chart_sha256'],'Pinned bootstrap chart is not packaged')
            # Do not reserve an unrecoverable started marker for missing prerequisites.
            started_descriptor=store.put(started,f)
            # Native admission first. No operational RBAC before name constraints.
            for name in ('admission.json','rbac.json'):run(['kubectl','apply','--server-side','--field-manager=course-operation-access','-f',str(bundle/name)],env)
            before_secrets=json.loads(run(['kubectl','-n','argocd','get','secrets','-o','json'],env))
            require(not before_secrets.get('metadata',{}).get('continue'),'Incomplete pre-bootstrap secret identity inventory')
            before_secret_uids={x['metadata']['uid'] for x in before_secrets['items']}
            c['_hook']='platform-core' # Chart/CRDs/Projects only; retained authority restore belongs to Up.
            ops.bootstrap(c,temp)
            receipt={**marker,'schema_version':1,'account_id':account,'complete':True,'access_config_sha256':m['config_sha256'],'chart_sha256':c['bootstrap_chart_sha256'],'toolchain_sha256':hashlib.sha256(json.dumps({'operator_image':c['operator_image'],'tool_sha256':c['tool_sha256']},sort_keys=True,separators=(',',':')).encode()).hexdigest(),'state_bindings':fingerprints,'started':started_descriptor,'fixture_namespace_uids':{}}
            import lifecycle_hooks as hooks
            receipt['installer_residual_resources']=capture_installer_rows(bundle,env,hooks)
            # Chart identity comes only from this pinned archive and the exact
            # effective values used above, never from a cluster-wide name filter.
            rendered=run(['helm','template','argocd',str(chart),'--namespace','argocd','--include-crds','--values',str(temp/'bootstrap-values.yaml')],env)
            status=json.loads(run(['helm','status','argocd','--namespace','argocd','--output','json'],env))
            def fetch(path,allow_missing=False):
                args=['kubectl','get','--raw',path]
                if allow_missing:
                    response=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
                    if response.returncode:
                        # kubectl may only suppress an exact NotFound; deny/transport
                        # errors remain failures rather than empty inventories.
                        error=response.stderr.decode(errors='replace')
                        require('Error from server (NotFound)' in error,'Hook lookup failed without authenticated NotFound')
                        return None
                    return json.loads(response.stdout)
                return json.loads(run(args,env))
            receipt['bootstrap_residual_resources']=collect_bootstrap_residuals(c,rendered,receipt['installer_residual_resources'],fetch,status,hooks.resource_row,before_secret_uids)
            probe_ns=json.loads(run(['kubectl','get','namespace','course-node-probes','-o','json'],env));receipt['node_probe_namespace_uid']=probe_ns['metadata']['uid']
            for case in (('t3','t4','t5','t6') if e=='dev' else []):
                ns=json.loads(run(['kubectl','get','namespace','incident-fixture-'+case,'-o','json'],env));receipt['fixture_namespace_uids'][case]=ns['metadata']['uid']
            require(store.state(checkpoint_key)==checkpoint,'Course checkpoint changed during bootstrap; do not issue completion proof')
            _,current_bindings=adapter.live_binding(c,store)
            require(current_bindings==fingerprints,'EKS or relay State changed during bootstrap')
            f=temp/'complete.json';f.write_text(json.dumps(receipt,sort_keys=True,separators=(',',':')));descriptor=store.put(key,f)
            # Only version/hash descriptor is printable. Receipt and inventory stay private.
            print(json.dumps(descriptor,sort_keys=True))
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Private bootstrap/access refresh blocked; original marker is preserved. No automatic interrupted retry, chart reinstall, or alternate identity.')
