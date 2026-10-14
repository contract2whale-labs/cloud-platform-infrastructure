#!/usr/bin/env python3
"""Bounded CI-only GitOps operations; every subprocess is captured privately."""
import argparse, contextlib, hashlib, importlib.util, json, os, pathlib, re, subprocess, sys, tempfile, time
BASE = pathlib.Path(__file__).resolve().parent
OPERATIONS = ('bootstrap', 'reconcile', 'verify')
ORDER = ('namespaces', 'cert-manager', 'admission-policy', 'network-policy', 'istio-base', 'istio-cni', 'istiod', 'ztunnel', 'mesh-policy', 'platform-crds', 'aws-load-balancer-controller', 'envoy-gateway', 'external-dns', 'gateway', 'gateway-auth')
# Exact leaf applications present in the supplied BU09–BU15 source. Root/AppSet
# authorities remain excluded; CI owns reviewed leaf declarations directly.
ORDER += ('storage','external-secrets','loki','thanos','fluent-bit','collection-agent','collection-policy','collection-gateway','collection-gateway-resources','monitoring-config','queue-network','queue-secrets','strimzi','kafka','queue-admin','tempo-identities','tempo','tempo-e2','tempo-e3','tempo-active-query','metrics-server','cluster-autoscaler','grafana-secret','monitoring','monitoring-resources','velero','backup-probe','velero-resources','tenant-baseline','database-operations','kyverno','argo-rollouts','reloader','platform-policies','commerce-api','commerce-web')
def app_name(key,env):
    return key if key in ('kyverno','argo-rollouts','reloader','platform-policies') else key+'-'+env if key.startswith('commerce-') else 'platform-'+key+'-'+env

SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^.+@sha256:[0-9a-f]{64}$')
class Blocked(Exception): pass

def require(condition, message):
    if not condition: raise Blocked(message)

def shared_file(filename):
    require(filename in ('saved-plan.py','lifecycle-state.py','private-api-session.py','eks-lifecycle-guard.py','vpc-lifecycle-guard.py','runtime-lifecycle-guard.py','operations-access.py'),'Unregistered shared helper')
    candidates=(BASE/filename,BASE.parent/'ci'/filename,BASE.parents[1]/'ci'/filename,BASE.parent/'eks-adapter-proposal'/filename)
    if filename=='operations-access.py':candidates+=(BASE.parent/'operations-access-proposal/bootstrap_receipt.py',)
    for path in candidates:
        if path.is_file():return path
    raise Blocked('Required packaged helper is missing')

def run(args, allowed=(0,), content=None):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, input=content, timeout=1200)
    require(p.returncode in allowed, 'Private command failed; no output disclosed')
    return p.stdout

def sources(spec):
    require(not ('source' in spec and 'sources' in spec), 'Ambiguous source')
    return spec.get('sources', [spec.get('source', {})])

def validate_app(app, env, repository, authority=False):
    require(set(app) == {'apiVersion', 'kind', 'metadata', 'spec'}, 'Unexpected Application fields')
    require(set(app['metadata']) <= {'name','namespace','annotations','labels'}, 'Unsafe metadata')
    name = app['metadata']['name']
    require(name in ([f'platform-root-{env}',f'delivery-root-{env}',f'platform-{env}'] if authority else [app_name(x,env) for x in ORDER]), 'Unregistered app')
    require(app['kind'] == 'Application' and app['apiVersion'] == 'argoproj.io/v1alpha1', 'Not Application')
    require(app['metadata'].get('namespace') == 'argocd', 'Wrong namespace')
    spec = app['spec']
    require(spec['project'] == ('delivery' if name.startswith('commerce-') else 'platform'), 'Wrong project')
    require(spec['destination']['server'] == 'https://kubernetes.default.svc', 'Foreign cluster')
    require('automated' not in spec.get('syncPolicy', {}), 'Automatic sync bypasses approval')
    for option in spec.get('syncPolicy', {}).get('syncOptions', []):
        require(option not in ('Replace=true', 'Force=true', 'Prune=true'), 'Unsafe sync option')
    for src in sources(spec):
        require(src.get('repoURL') == repository and SHA.fullmatch(src.get('targetRevision', '')), 'Source must be registered Git URL and full SHA')
        require('chart' not in src and 'plugin' not in src, 'Vendor charts at immutable Git SHA; plugins not supported')
        require(bool(src.get('path') or src.get('ref')), 'Missing Git source path/ref')
        require(not src.get('path', '').startswith('/') and '..' not in src.get('path', '').split('/'), 'Unsafe source path')
    return app

def validate_authorities(c,env,*,allow_bootstrap_only=False):
    authorities=c.get('authority_applications',[])
    if allow_bootstrap_only and c.get('bootstrap_only') is True:
        require(c.get('applications')==[] and authorities==[] and c.get('authority_children')=={} and c.get('deferred_applications',[])==[],'Bootstrap-only registration cannot carry application authorities')
        return []
    require(authorities,'Register source app-of-apps authority declarations; no competing direct leaf owner')
    for app in authorities:validate_app(app,env,c['repository'],authority=True)
    names=[a['metadata']['name'] for a in authorities];leaves={a['metadata']['name'] for a in c['applications']}
    require(len(names)==len(set(names)) and not set(names)&leaves,'Duplicate authority/leaf names')
    children=c['authority_children'];require(set(children)==set(names),'Exact root child inventory required')
    owners={}
    for parent,targets in children.items():
        require(targets and len(targets)==len(set(targets)),'Empty/duplicate child set')
        for child in targets:
            require(child in set(names)|leaves and child not in owners,'Unknown or multiply-owned child')
            if child in names:require(names.index(parent)<names.index(child),'Authority DAG must be parent-first, without cycles')
            owners[child]=parent
    require(leaves<=set(owners),'Every leaf needs exactly one registered authority owner')
    return [a for a in authorities if a['metadata']['name'] not in owners]

def validate_authority_render(c,app,objects):
    expected={x['metadata']['name']:x for x in c['applications']+c['authority_applications']}
    wanted=set(c['authority_children'][app['metadata']['name']]);seen=set()
    for obj in objects:
        if not obj:continue
        require(obj.get('kind')=='Application' and obj.get('apiVersion')=='argoproj.io/v1alpha1','Root may render only reviewed child Applications')
        name=obj['metadata']['name'];require(name in wanted and name not in seen,'Unreviewed/duplicate root child')
        require(obj==expected[name],'Rendered child spec/metadata differs from exact reviewed declaration')
        seen.add(name)
    require(seen==wanted,'Root child set differs from reviewed registration')

def revision_args(app):
    src = sources(app['spec'])
    if len(src) == 1: return ['--revision', src[0]['targetRevision']]
    return [v for i, s in enumerate(src, 1) for v in ('--revisions', s['targetRevision'], '--source-positions', str(i))]

def validate_receipt(live, app, require_health=True):
    require(live['spec'] == app['spec'], 'Application changed during operation')
    status = live.get('status', {})
    op = status.get('operationState', {})
    require(op.get('phase') == 'Succeeded' and (not require_health or status.get('health', {}).get('status') == 'Healthy'), 'Operation not healthy/succeeded')
    result = op.get('syncResult', {})
    actual = result.get('revisions') or [result.get('revision')]
    require(actual == [s['targetRevision'] for s in sources(app['spec'])], 'Operation revision mismatch')
    require(status.get('sync', {}).get('status') == 'Synced', 'Pending drift')

def validate_images(objects):
    # Check nested workloads and hook pod specs without printing manifests/Secrets.
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ('containers', 'initContainers', 'ephemeralContainers'):
                    for c in value: require(DIGEST.fullmatch(c.get('image', '')), 'Rendered workload has mutable image')
                walk(value)
        elif isinstance(node, list):
            for value in node: walk(value)
    walk(objects)

def validate_ownership(objects):
    for obj in objects:
        if not obj: continue
        md=obj.get('metadata', {})
        require(obj.get('kind') not in ('Application','ApplicationSet','AppProject'), 'Nested Argo authority not permitted')
        require(not (md.get('namespace')=='kube-system' and md.get('name') in ('aws-node','coredns','kube-proxy','eks-pod-identity-agent')), 'Terraform add-on ownership collision')

def current_main():
    import urllib.request
    repo=os.environ['GITHUB_REPOSITORY']
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo), 'Invalid workflow repository')
    request=urllib.request.Request('https://api.github.com/repos/'+repo+'/git/ref/heads/main', headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response: live=json.load(response)
    require(live['object']['sha']==os.environ['GITHUB_SHA'], 'Stale main workflow; use newer reviewed run')

def load(env, operation):
    cfg = json.loads((BASE / 'operations.json').read_text())
    require(cfg.get('enabled') is True, 'GitOps activation prerequisites missing')
    require(env in ('dev', 'prod') and operation in OPERATIONS, 'Unsupported operation')
    c = dict(cfg['environments'][env])
    c['operator_image']=cfg['operator_image']
    c['environment']=env
    if operation == 'bootstrap': c['role_arn'] = c['bootstrap_role_arn']
    require(re.fullmatch(r'\d{12}', c['account_id']), 'Invalid account')
    require(c['role_arn'].startswith(f"arn:aws:iam::{c['account_id']}:role/"), 'Role account mismatch')
    require(re.fullmatch(r'[a-zA-Z0-9_-]+', c['cluster']), 'Invalid cluster')
    require(re.fullmatch(r'i-[a-f0-9]+', c['relay']), 'Invalid relay')
    require(type(c.get('bootstrap_only',False)) is bool,'Invalid bootstrap-only registration flag')
    bootstrap_only=c.get('bootstrap_only') is True
    require(not bootstrap_only or operation=='bootstrap','Bootstrap-only registration cannot run ordinary GitOps operations')
    require(isinstance(c.get('applications'),list) and (bool(c['applications']) or bootstrap_only),'No registered applications')
    if bootstrap_only:require(c['applications']==[] and c.get('rbac_applications',[])==[] and c.get('projects')==[],'Early bootstrap registration must contain no future application/project declarations')
    apps = [validate_app(x, env, c['repository']) for x in c['applications']]
    require(len({x['metadata']['name'] for x in apps}) == len(apps), 'Duplicate applications')
    indices = [[app_name(key,env) for key in ORDER].index(x['metadata']['name']) for x in apps]
    require(indices == sorted(indices), 'Dependency order mismatch')
    deferred=c.get('deferred_applications',[])
    require(isinstance(deferred,list) and len(deferred)==len(set(deferred)) and set(deferred)<={'platform-policies'} and set(deferred)<={a['metadata']['name'] for a in apps},'Only reviewed platform-policies selective phase may defer full sync')
    validate_authorities(c,env,allow_bootstrap_only=operation=='bootstrap')
    return c

def check_tools(c):
    for tool in ('aws', 'kubectl', 'argocd', 'helm', 'session-manager-plugin', 'gh', 'cosign'):
        import shutil
        path = shutil.which(tool)
        require(path and hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == c['tool_sha256'][tool], 'Toolchain fingerprint mismatch')

def preflight(c,*,require_argo_token=True):
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Trusted main required')
    require(SHA.fullmatch(os.environ.get('GITHUB_SHA', '')), 'Immutable workflow SHA required')
    check_tools(c)
    if require_argo_token:require(os.environ.get('ARGOCD_AUTH_TOKEN'), 'Scoped Argo token missing')
    require(c['repository']=='git@github.com:'+os.environ['GITHUB_REPOSITORY']+'.git', 'Source must match protected workflow repository')
    for app in c['applications']+c.get('authority_applications',[]):
        for source in sources(app['spec']):
            run(['git','merge-base','--is-ancestor',source['targetRevision'],os.environ['GITHUB_SHA']])

def own(c):
    caller = json.loads(run(['aws', 'sts', 'get-caller-identity']))
    require(caller['Account'] == c['account_id'], 'AWS account mismatch')
    role = c['role_arn'].split(':role/')[1].split('/')[-1]
    require(caller['Arn'].startswith(f"arn:aws:sts::{c['account_id']}:assumed-role/{role}/"), 'Unexpected OIDC role')
    cluster = json.loads(run(['aws', 'eks', 'describe-cluster', '--name', c['cluster'], '--region', c['region']]))['cluster']
    require(cluster['arn'] == c['cluster_arn'] and cluster.get('tags', {}).get('CourseOwner') == c['owner'], 'EKS ownership mismatch')
    require(cluster['resourcesVpcConfig']['endpointPrivateAccess'] and not cluster['resourcesVpcConfig']['endpointPublicAccess'], 'Private-only endpoint required')
    relay = json.loads(run(['aws', 'ec2', 'describe-instances', '--instance-ids', c['relay'], '--region', c['region']]))['Reservations'][0]['Instances'][0]
    tags = {x['Key']: x['Value'] for x in relay.get('Tags', [])}
    require(relay['VpcId'] == cluster['resourcesVpcConfig']['vpcId'] and tags.get('CourseOwner') == c['owner'], 'SSM relay ownership mismatch')

@contextlib.contextmanager
def argo_connection(c, temp):
    # Source bootstrap uses ClusterIP HTTP. Loopback-only forwarding travels inside
    # authenticated EKS TLS and SSM; never expose this listener or use --insecure.
    p = subprocess.Popen(['kubectl', '-n', 'argocd', 'port-forward', 'service/argocd-server', '18443:80', '--address', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        import socket
        for _ in range(60):
            require(p.poll() is None, 'Argo port-forward exited')
            try:
                with socket.create_connection(('127.0.0.1', 18443), timeout=1): break
            except OSError: time.sleep(1)
        else: raise Blocked('Argo port-forward timeout')
        yield ['argocd', '--server', '127.0.0.1:18443', '--plaintext', '--config', str(temp / 'argocd-config')]
    finally:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait()


def registered_projects(c):
    projects=c['projects'] if 'projects' in c else [c['project']]
    require({x['metadata']['name'] for x in projects}=={x['spec']['project'] for x in c.get('rbac_applications',c['applications'])},'Exact registered AppProject set required')
    for project in projects:
        require(project['kind']=='AppProject' and project['metadata'] in ({'name':'platform','namespace':'argocd'},{'name':'delivery','namespace':'argocd'}), 'Unexpected project')
        require(project['spec']['sourceRepos']==[c['repository']], 'Unexpected project repositories')
        require(all(d['server']=='https://kubernetes.default.svc' for d in project['spec']['destinations']), 'Foreign project destination')
    return projects

def bootstrap(c, temp):
    """Adapted from supplied tooling bootstrap, never used for normal updates."""
    import base64, hmac, yaml
    run(['kubectl','wait','node','--all','--for=condition=Ready','--timeout=300s'])
    for workload in ('deployment/coredns','daemonset/eks-pod-identity-agent'):
        run(['kubectl','-n','kube-system','rollout','status',workload,'--timeout=300s'])
    chart = BASE / 'vendor' / 'argo-cd-10.9.0.tgz'
    require(chart.exists() and hashlib.sha256(chart.read_bytes()).hexdigest() == c['bootstrap_chart_sha256'], 'Reviewed Argo chart archive absent/mismatch')
    require(not run(['kubectl', '-n', 'argocd', 'get', 'secret', 'argocd-repo-gitops', '--ignore-not-found', '-o', 'name']).strip(), 'Existing bootstrap requires separate takeover review')
    # Preprovisioned protected secrets, not arbitrary caller parameters. Never persist
    # credentials to Actions output/artifacts or generate a new standing credential.
    token = os.environ['ARGOCD_AUTH_TOKEN']
    signing = os.environ['ARGOCD_SERVER_SECRETKEY']
    head, body, sig = token.split('.')
    decode = lambda x: base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
    require(json.loads(decode(head)).get('alg') == 'HS256', 'Unsupported token algorithm')
    require(hmac.compare_digest(decode(sig), hmac.digest(signing.encode(), (head+'.'+body).encode(), 'sha256')), 'Preprovisioned token signature mismatch')
    claims = json.loads(decode(body))
    require(claims.get('sub') == 'ci:apiKey' and claims.get('iss') == 'argocd' and claims.get('exp', 0) > time.time(), 'Invalid CI token scope/expiry')
    require(claims.get('jti') and isinstance(claims.get('iat'), int), 'Missing token registration')
    values = yaml.safe_load((BASE/'bootstrap-values.yaml').read_text())
    values['configs']['cm'].update({'admin.enabled': False, 'accounts.ci': 'apiKey'})
    values['configs']['ssh'] = {'knownHosts': (BASE/'github-known-hosts').read_text()}
    require(DIGEST.fullmatch(c['operator_image']), 'Immutable renderer toolchain required')
    values['repoServer'].update({'initContainers':[{'name':'pinned-renderers','image':c['operator_image'],'command':['sh','-c','cp /usr/local/bin/helm /usr/local/bin/kustomize /custom-tools/'],'volumeMounts':[{'name':'custom-tools','mountPath':'/custom-tools'}]}], 'volumes':[{'name':'custom-tools','emptyDir':{}}], 'volumeMounts':[{'name':'custom-tools','mountPath':'/usr/local/bin/helm','subPath':'helm'},{'name':'custom-tools','mountPath':'/usr/local/bin/kustomize','subPath':'kustomize'}]})
    values['configs']['rbac'] = {'policy.default': '', 'policy.csv': '\n'.join(f'p, ci, applications, {action}, {a["spec"]["project"]}/{a["metadata"]["name"]}, allow' for a in c.get('rbac_applications',c['applications']+c.get('authority_applications',[])) for action in ('get', 'sync'))}
    values['configs']['secret'] = {'extra': {'server.secretkey': signing, 'accounts.ci.tokens': json.dumps([{'id': claims['jti'], 'iat': claims['iat'], 'exp': claims['exp']}])}}
    # Image overrides must be reviewed in operations.json and all rendered workloads
    # (including hooks/init containers) must actually use image digests.
    for component, override in c['bootstrap_image_values'].items():
        require(component in ('global','controller','repoServer','server','redis','applicationSet','dex','notifications'), 'Unknown image component')
        values.setdefault(component, {})['image'] = override
    f = temp/'bootstrap-values.yaml'; f.write_text(yaml.safe_dump(values))
    rendered = run(['helm', 'template', 'argocd', str(chart), '--namespace', 'argocd', '--include-crds', '--values', str(f)])
    validate_images(list(yaml.safe_load_all(rendered)))
    run(['helm', 'upgrade', '--install', 'argocd', str(chart), '--namespace', 'argocd', '--create-namespace', '--values', str(f), '--wait', '--timeout', '15m'])
    key = os.environ['GITOPS_REPO_SSH_KEY']
    secret = {'apiVersion':'v1','kind':'Secret','metadata':{'name':'argocd-repo-gitops','namespace':'argocd','labels':{'argocd.argoproj.io/secret-type':'repository'}},'stringData':{'type':'git','url':c['repository'],'sshPrivateKey':key}}
    # Project is a reviewed document in the immutable operation registry, not free
    # workflow input. Review clusterResourceWhitelist for each chapter explicitly.
    projects=registered_projects(c)
    run(['kubectl','apply','--server-side','--field-manager=platform-bootstrap','-f','-'], content=yaml.safe_dump_all([secret]+projects+([] if c.get('_hook') else validate_authorities(c,c['environment'],allow_bootstrap_only=True))).encode())

def normal_allowed(c, env):
    ci=shared_file('saved-plan.py').parent
    def module(name,path):
        spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
    helper=module('normal_gitops_store',ci/'saved-plan.py');state=module('normal_gitops_control',ci/'lifecycle-state.py')
    store=helper.Store(c['state_bucket'],c['account_id']);store.check()
    repo=os.environ['GITHUB_REPOSITORY_ID']
    incident,_=state.read_json(store,f'ci-incidents/{repo}/{env}/active.json')
    if incident is not None:
        require(incident.get('schema')==1 and incident.get('owner') in ('kubernetes-fixed-operations','aws-fixed-operations') and incident.get('repository_id')==repo and incident.get('environment')==env and incident.get('account')==c['account_id'] and incident.get('bucket')==c['state_bucket'] and incident.get('region')==c['region'] and incident.get('phase')=='idle','Unresolved/invalid incident marker blocks ordinary GitOps')
    record,_=state.read_json(store,state.course_marker_key(repo,env))
    if record is not None:
        state.validate_course(record,repo,c['account_id'],c['state_bucket'],c['region'],env)
        require(record['phase']=='active','Course is lifecycle-paused; ordinary GitOps changes blocked')

def state_binding(c):
    spec=importlib.util.spec_from_file_location('normal_gitops_binding',BASE/'gitops-lifecycle.py');binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)
    store=binding.h.Store(c['state_bucket'],c['account_id']);store.check()
    c,fingerprints=binding.live_binding(c,store)
    return c,fingerprints

def bootstrap_proof(c,store):
    require(re.fullmatch('[0-9a-f]{64}',c.get('operations_access_config_sha256','')),'Actual compiled operations-access registration digest required')
    spec=importlib.util.spec_from_file_location('ops_access_receipt',shared_file('operations-access.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.verify_bootstrap_receipt(c,store,config_sha256=c['operations_access_config_sha256'])

def verify_access(c):
    spec=importlib.util.spec_from_file_location('ops_proof_store',shared_file('saved-plan.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return bootstrap_proof(c,module.Store(c['state_bucket'],c['account_id']))

def execute(c, env, operation, temp):
    require(operation!='bootstrap','Use protected gitops-access-bootstrap.yml for the fresh one-time access/Argo installation receipt')
    current_main()
    if operation!='verify':normal_allowed(c,env)
    c,fingerprints=state_binding(c)
    verify_access(c)
    helper = shared_file('private-api-session.py')
    require(helper.exists(), 'Private API adapter not packaged')
    spec = importlib.util.spec_from_file_location('private_api_session', helper)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    with module.private_api(c['cluster'], c['relay'], c['region'], temp / 'kubeconfig') as (session_env, cluster):
        os.environ['KUBECONFIG'] = session_env['KUBECONFIG']
        if operation == 'bootstrap':
            bootstrap(c, temp)
        if operation == 'reconcile':
            import yaml
            run(['kubectl','apply','--server-side','--field-manager=gitops-ci','-f','-'], content=yaml.safe_dump_all(validate_authorities(c,env)).encode())
        with argo_connection(c, temp) as argo:
            for app in c.get('authority_applications',[])+c['applications']:
                name = app['metadata']['name']
                live = json.loads(run(argo + ['app', 'get', name, '--refresh', '-o', 'json']))
                require(live['spec'] == app['spec'], 'Live Application differs from reviewed declaration; bootstrap handoff required')
                # Argo renderer result is YAML. PyYAML belongs in the pinned operator image.
                import yaml
                rendered = list(yaml.safe_load_all(run(argo + ['app', 'manifests', name] + revision_args(app))))
                validate_images(rendered)
                if app in c.get('authority_applications',[]):validate_authority_render(c,app,rendered)
                else:validate_ownership(rendered)
                run(argo + ['app', 'diff', name] + revision_args(app), allowed=(0, 1))
                if name in c.get('deferred_applications',[]):continue # registered root-owned leaf; explicit selective phase, not deployed
                if operation in ('reconcile', 'bootstrap'):
                    current_main()
                    normal_allowed(c,env)
                    run(argo + ['app', 'sync', name] + revision_args(app))
                is_authority=app in c.get('authority_applications',[])
                run(argo + ['app', 'wait', name, '--operation', '--sync', '--timeout', '900']+([] if is_authority else ['--health']))
                validate_receipt(json.loads(run(argo + ['app', 'get', name, '-o', 'json'])), app, require_health=not is_authority)
    receipt = {'schema_version': 1, 'workflow_sha': os.environ['GITHUB_SHA'], 'run_id': os.environ['GITHUB_RUN_ID'], 'operation': operation, 'environment': env, 'applications': [{'name':x['metadata']['name'],'revisions':[s['targetRevision'] for s in sources(x['spec'])]} for x in c['applications']], 'registry_sha256':hashlib.sha256((BASE/'operations.json').read_bytes()).hexdigest(), 'verified': True, 'deferred_full_sync':c.get('deferred_applications',[])}
    (temp / 'receipt.json').write_text(json.dumps(receipt))
    # No stdout output, no Actions artifact. Exact private SSE-KMS destination only.
    require(re.fullmatch(r'[a-z0-9.-]+', c['evidence_bucket']), 'Invalid private evidence bucket')
    run(['aws', 's3', 'cp', str(temp / 'receipt.json'), f"s3://{c['evidence_bucket']}/gitops/{env}/{os.environ['GITHUB_RUN_ID']}/{os.environ['GITHUB_RUN_ATTEMPT']}/receipt.json", '--sse', 'aws:kms', '--sse-kms-key-id', c['evidence_kms_arn'], '--only-show-errors'])

def main():
    p = argparse.ArgumentParser(); p.add_argument('--environment', choices=('dev','prod'), required=True); p.add_argument('--operation', choices=OPERATIONS, required=True); p.add_argument('--check', action='store_true'); a=p.parse_args()
    try:
        c=load(a.environment,a.operation)
        if a.check: return
        preflight(c)
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix='gitops-private-') as d: execute(c,a.environment,a.operation,pathlib.Path(d))
    except Exception:
        print('GitOps stopped safely. Check activation contract and private access configuration; no command output published.', file=sys.stderr)
        sys.exit(1)
if __name__ == '__main__': main()
