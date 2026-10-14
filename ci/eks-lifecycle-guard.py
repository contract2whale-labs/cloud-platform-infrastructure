#!/usr/bin/env python3
"""Exact Dev/Prod EKS/relay ownership and bounded readiness guards."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
CI = HERE if (HERE/'saved-plan.py').exists() else HERE.parent/'ci'
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
v=load('eks_state_tools',CI/'vpc-lifecycle-guard.py')
p=load('eks_private_api',HERE/'private-api-session.py')
SafeError,require=v.SafeError,v.require
normalize_resources,managed_resources,VersionedStateReader=v.normalize_resources,v.managed_resources,v.VersionedStateReader
EKS='terraform/environments/dev/eks'
RELAY='terraform/environments/dev/platform/private-api'
VPC='terraform/environments/dev/network/vpc'
# Exact module/resource names from BU06/BU07, not an IAM resource-type bypass.
EKS_NAMES={
 'aws_eks_cluster':{'this'},'aws_cloudwatch_log_group':{'cluster'},
 'aws_iam_role':{'cluster','nodes','cni','ebs'},'aws_iam_role_policy_attachment':{'cluster','nodes','cni','ebs'},
 'aws_iam_openid_connect_provider':{'cluster'},'aws_security_group':{'api_clients','nodes'},
 'aws_vpc_security_group_ingress_rule':{'api_client_sg','api_client_cidr','nodes_self','nodes_from_control_plane','nodes_https_from_control_plane','control_plane_from_nodes'},
 'aws_vpc_security_group_egress_rule':{'nodes'},'aws_eks_access_entry':{'admin','operations','lifecycle','aws_fixed'},'aws_eks_access_policy_association':{'admin','operations_bootstrap'},
 'aws_launch_template':{'nodes'},'aws_eks_node_group':{'groups'},'aws_eks_addon':{'cni','network','pod_identity','ebs'},
 'terraform_data':{'environment_boundary'}}
RELAY_NAMES={'aws_iam_role':{'relay'},'aws_iam_role_policy_attachment':{'relay_ssm'},'aws_iam_instance_profile':{'relay'},'aws_security_group':{'relay'},'aws_vpc_security_group_egress_rule':{'relay_https'},'aws_instance':{'relay'}}
BASELINE_CRDS={'eniconfigs.crd.k8s.amazonaws.com','securitygrouppolicies.vpcresources.k8s.aws','policyendpoints.networking.k8s.aws'}
ADDONS={'vpc-cni','coredns','kube-proxy','eks-pod-identity-agent','aws-ebs-csi-driver'}
INSTALLER_RESIDUAL_READS={'serviceaccounts':True,'roles':True,'rolebindings':True,'clusterroles':False,'clusterrolebindings':False,'validatingadmissionpolicies':False,'validatingadmissionpolicybindings':False,'poddisruptionbudgets':True}

# Only these explicit Velero metadata CRs can survive a verified core handoff.
VELERO_RESIDUAL_READS={name:name+'.velero.io' for name in ('backups','restores','schedules','backupstoragelocations','volumesnapshotlocations')}
INSTALLER_RESIDUAL_READS.update({name:True for name in VELERO_RESIDUAL_READS})

OPERATIONS=('gitops-bootstrap','gitops-apply','incident-plan','incident-apply')
LIFECYCLE={'plan':'plan','apply':'apply','destroy':'lifecycle-destroy'}

def roots(context):
    root=context['root'];parts=root.split('/')
    require(len(parts)>=4 and parts[:2]==['terraform','environments'] and parts[2] in ('dev','prod'),'Unregistered EKS environment.')
    env=parts[2];base='terraform/environments/'+env+'/'
    require(root in (base+'eks',base+'platform/private-api'),'Unregistered EKS root.')
    require(context.get('environment',env)==env,'EKS environment/root mismatch.')
    return env,base+'eks',base+'platform/private-api',base+'network/vpc'

def allowed_types(root):
    _,eks,_,_=roots({'root':root});return set(EKS_NAMES if root==eks else RELAY_NAMES)

def access_identities(context):
    env,_,_,_=roots(context);account=context['account']
    require(re.fullmatch(r'\d{12}',account) is not None,'Invalid EKS account.')
    operations={k:('arn:aws:iam::'+account+':role/cp-'+env+'-'+k,'cp:'+env+':'+k) for k in OPERATIONS}
    lifecycle={k:('arn:aws:iam::'+account+':role/gha-infra-'+env+'-'+v,'cp:'+env+':lifecycle-'+k) for k,v in LIFECYCLE.items()}
    result={'operations':operations,'lifecycle':lifecycle}
    if env=='dev':result['aws_fixed']={mode:('arn:aws:iam::'+account+':role/gha-aws-ops-dev-'+mode,'cp:dev:aws-fixed-'+mode) for mode in ('plan','apply')}
    return result

def source_capability(workspace,context,chapter):
    """Later chapters need the exact reviewed access source, never a loose label."""
    env,eks,relay,_=roots(context)
    require(re.fullmatch(r'BU(?:0[6-9]|1[0-6])[ABC]?',chapter) is not None,'Unreviewed EKS completed chapter.')
    require(env=='dev' or chapter in ('BU15','BU16'),'Prod EKS begins at BU15.')
    base=Path(workspace).resolve();root=base/context['root']
    require(root.is_dir() and root.resolve().is_relative_to(base),'EKS retained source missing.')
    if context['root']==relay:return {'schema':1,'kind':'private-api','environment':env}
    source='\n'.join(path.read_text() for path in sorted(root.glob('*.tf')))
    require(re.search(r'module\s+"component"\s*\{\s*source\s*=\s*"../../../../modules/eks"',source) is not None,'Only the reviewed local modules/eks component is supported.')
    module=base/'modules/eks'
    # The root-relative source resolves outside terraform/, to repository modules/.
    require(module.is_dir(),'Owned EKS module source is missing.')
    contract=CI/'eks-operations-access.tf'
    require(contract.is_file(),'Reviewed EKS access capability source is missing from support package.')
    expected=contract.read_bytes();files=list(module.glob('*.tf'))
    matches=[path for path in files if path.read_bytes()==expected]
    modern=chapter not in ('BU06','BU07') or env=='prod'
    require(not modern or len(matches)==1,'Merge the exact reviewed eks-access.tf into modules/eks and complete its source tests before this chapter lifecycle.')
    return {'schema':1,'kind':'eks','environment':env,'operations_access':len(matches)==1,
            'operations_source_sha256':hashlib.sha256(expected).hexdigest() if matches else None}

def key(root):return '/'.join(root.split('/')[3:])+'/terraform.tfstate'
def read_upstreams(workspace,context,*,load_state=None):
    root=context['root'];_,eks,relay,vpc=roots(context)
    reader=load_state or VersionedStateReader(context['backend']['bucket'],context['account'],context['backend']['region'])
    return {r:reader(key(r)) for r in ([vpc,relay] if root==eks else [vpc])}
def upstream_fingerprints(workspace,context,*,load_state=None):
    return {k:v['fingerprint'] for k,v in read_upstreams(workspace,context,load_state=load_state).items()}
def state(item):return item.get('state') if item else None

def validate_rows(context, rows):
    root=context['root'];env,eks,relay,vpc=roots(context); names=EKS_NAMES if root==eks else RELAY_NAMES
    clusters=[r['values'] for r in rows if r['type']=='aws_eks_cluster']
    cluster=clusters[0] if clusters else None
    require(len(clusters)<=1,'Multiple clusters are unsupported.')
    for row in rows:
        t,name,a=row['type'],row['name'],row['values']
        require(isinstance(a.get('id'),str) and bool(a['id']),'Owned State resource ID missing.')
        require(t in names and name in names[t],'Unknown managed resource; S3/KMS/persistent identity cannot be removed.')
        prefix='module.component.' if root==eks and t!='terraform_data' else ''
        require(re.fullmatch(re.escape(prefix+t+'.'+name)+r'(\[(?:"[^"\\]*"|\d+)\])?',row['address']) is not None,'Unexpected resource owner/address.')
        arn=a.get('arn')
        if arn and t!='aws_iam_openid_connect_provider':
            require(arn.startswith('arn:aws:') and arn.split(':')[4]==context['account'],'Cross-account resource owner.')
        if t=='aws_eks_cluster':
            require(a.get('deletion_protection') is False,'Cluster deletion protection must already be reviewed false.')
            require(a.get('vpc_config') and a['vpc_config'][0].get('endpoint_public_access') is False,'Public EKS endpoint unsupported.')
        if t=='aws_iam_openid_connect_provider':
            require(cluster is not None,'IRSA OIDC requires exact owned cluster.')
            issuer=cluster['identity'][0]['oidc'][0]['issuer']
            require(a.get('url') in (issuer,issuer.removeprefix('https://')) and 'oidc.eks.' in issuer,'Only current cluster-bound OIDC can be destroyed; GitHub OIDC retained.')
            require(a.get('arn')=='arn:aws:iam::'+context['account']+':oidc-provider/'+issuer.removeprefix('https://'),'OIDC ARN differs from cluster issuer.')
        if t=='aws_iam_role':
            expected=('cp-'+env+'-private-api-relay' if root==relay else cluster['name']+{'cluster':'-cluster','nodes':'-nodes','cni':'-vpc-cni','ebs':'-ebs-csi'}[name]) if cluster or root==relay else None
            require(expected is not None and a.get('name')==expected,'Unexpected IAM role identity.')
        if t=='aws_iam_role_policy_attachment':
            owned_roles={r['values'].get('name') for r in rows if r['type']=='aws_iam_role'}
            require(a.get('role') in owned_roles,'Policy attachment targets an external/persistent IAM role.')
            require(isinstance(a.get('policy_arn'),str) and a['policy_arn'].startswith('arn:aws:iam::aws:policy/'),'Only course AWS-managed policy attachments are supported.')
        if t=='aws_iam_instance_profile':
            require(a.get('name')=='cp-'+env+'-private-api-relay' and a.get('role')=='cp-'+env+'-private-api-relay','Unexpected instance profile ownership.')
        if t=='aws_cloudwatch_log_group':
            require(cluster and a.get('name')=='/aws/eks/'+cluster['name']+'/cluster','Unknown log group owner.')
        if t in ('aws_vpc_security_group_ingress_rule','aws_vpc_security_group_egress_rule'):
            owned_groups={r['values'].get('id') for r in rows if r['type']=='aws_security_group'}
            if cluster:owned_groups.add(cluster['vpc_config'][0].get('cluster_security_group_id'))
            require(a.get('security_group_id') in owned_groups and a.get('security_group_id') is not None,'Security group rule targets unowned group.')
        if t in ('aws_eks_access_entry','aws_eks_access_policy_association'):
            validate_access_row(context,row,cluster)
        if t=='aws_eks_addon':require(a.get('addon_name') in ADDONS and cluster and a.get('cluster_name')==cluster['name'],'Unknown add-on owner.')
        if t=='aws_eks_node_group':require(cluster and a.get('cluster_name')==cluster['name'],'Unknown node group owner.')
    return rows

def validate_state(context,raw,expected_resources=None,upstream_states=None):
    rows=validate_rows(context,managed_resources(raw))
    if expected_resources is not None:
        original={r['address']:r for r in expected_resources}
        require(all(original.get(r['address'])==r for r in normalize_resources(raw)),'State gained/changed original owned resource identities.')
    return rows

def validate_access_row(context,row,cluster,*,planned=False):
    t,name,a=row['type'],row['name'],row['values'];identities=access_identities(context)
    require(cluster is not None,'EKS access resource has no owned cluster.')
    require(a.get('cluster_name')==cluster.get('name') and isinstance(a.get('cluster_name'),str),'EKS access cluster differs from owned cluster.')
    principal=a.get('principal_arn');all_principals={x[0] for values in identities.values() for x in values.values()}
    if t=='aws_eks_access_entry' and name in identities:
        match=re.fullmatch(r'module\.component\.aws_eks_access_entry\.'+name+r'\["([^"\\]+)"\]',row['address'])
        require(match is not None and match[1] in identities[name],'Unexpected operations/lifecycle access index.')
        expected,group=identities[name][match[1]]
        require(principal==expected and a.get('type')=='STANDARD' and a.get('kubernetes_groups')==[group],'Operations/lifecycle principal or Kubernetes group differs from exact contract.')
    elif t=='aws_eks_access_policy_association' and name=='operations_bootstrap':
        require(row['address']=='module.component.aws_eks_access_policy_association.operations_bootstrap','Bootstrap association must be singular.')
        require(principal==identities['operations']['gitops-bootstrap'][0],'Only the protected GitOps bootstrap principal may receive bootstrap ClusterAdmin.')
        require(a.get('policy_arn')=='arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy','Unexpected bootstrap EKS access policy.')
        scope=a.get('access_scope')
        require(isinstance(scope,list) and len(scope)==1 and scope[0].get('type')=='cluster' and not scope[0].get('namespaces'),'Bootstrap EKS access scope differs from reviewed cluster scope.')
    else:
        require(name=='admin' and isinstance(principal,str) and re.fullmatch(r'arn:aws:iam::'+context['account']+r':role/[A-Za-z0-9_+=,.@/-]+',principal) and principal not in all_principals,'Instructor access cannot impersonate operational/lifecycle roles.')
        if t=='aws_eks_access_entry':require(a.get('type')=='STANDARD' and not a.get('kubernetes_groups'),'Unexpected instructor group or entry type.')
        else:
            require(a.get('policy_arn')=='arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy','Unknown instructor EKS policy.')
            scope=a.get('access_scope');require(isinstance(scope,list) and len(scope)==1 and scope[0].get('type')=='cluster' and not scope[0].get('namespaces'),'Unknown instructor EKS access scope.')

def plan_rows(plan):
    rows=[]
    def visit(module):
        for row in module.get('resources',[]):
            if row.get('mode')=='managed':rows.append(row)
        for child in module.get('child_modules',[]):visit(child)
    visit(plan.get('planned_values',{}).get('root_module',{}))
    return rows

def validate_plan_contracts(context,plan,upstream):
    _,eks,relay,vpc=roots(context);names=EKS_NAMES if context['root']==eks else RELAY_NAMES
    changes=[r for r in plan.get('resource_changes',[]) if r.get('mode')!='data']
    rows=plan_rows(plan)
    # Destroy planned_values is empty, so authenticate known before identities.
    if not rows:rows=[{**r,'values':r.get('change',{}).get('before') or {}} for r in changes]
    clusters=[r.get('values',{}) for r in rows if r.get('type')=='aws_eks_cluster']
    require(len(clusters)<=1,'Multiple planned EKS clusters.')
    for row in [*changes,*rows]:
        require(row.get('type') in names and row.get('name') in names[row['type']],'Unknown planned owner/type.')
    for row in rows:
        t=row['type'];prefix='module.component.' if context['root']==eks and t!='terraform_data' else ''
        require(re.fullmatch(re.escape(prefix+t+'.'+row['name'])+r'(\[(?:"[^"\\]*"|\d+)\])?',row.get('address','')) is not None,'Unexpected planned resource owner/address.')
        if t in ('aws_eks_access_entry','aws_eks_access_policy_association'):
            validate_access_row(context,row,clusters[0] if clusters else None,planned=bool(plan_rows(plan)))
    capability=context.get('source_capability',{})
    if context['root']==eks and capability.get('operations_access') and plan_rows(plan):
        actual={r['address'] for r in rows if r['type'] in ('aws_eks_access_entry','aws_eks_access_policy_association')}
        expected={'module.component.aws_eks_access_entry.'+kind+'["'+index+'"]' for kind,values in access_identities(context).items() if kind!='aws_fixed' for index in values}
        fixed={name for name in actual if name.startswith('module.component.aws_eks_access_entry.aws_fixed[')}
        fixed_expected={'module.component.aws_eks_access_entry.aws_fixed["'+mode+'"]' for mode in ('plan','apply')}
        require(not fixed or fixed==fixed_expected,'Optional AWS fixed-operation access must be the complete exact Dev pair.')
        expected.add('module.component.aws_eks_access_policy_association.operations_bootstrap')
        require(expected<=actual,'Reviewed operations/lifecycle access source did not evaluate to its complete exact capability.')
    require(state(upstream.get(vpc)) is not None,'VPC State missing.')

def validate_inventory(inv):
    """Strict baseline only. Missing reads are errors, not an empty inventory."""
    required={'namespaces','services','pods','deployments','daemonsets','replicasets','statefulsets','jobs','cronjobs','persistentvolumes','persistentvolumeclaims','ingresses','volumeattachments','customresourcedefinitions','secrets','configmaps','networkpolicies','mutatingwebhookconfigurations','validatingwebhookconfigurations'}
    require(set(inv)==required,'Incomplete cluster inventory.')
    for rows in inv.values():require(isinstance(rows,list),'Malformed inventory.')
    require({x['metadata']['name'] for x in inv['namespaces']} <= {'default','kube-system','kube-public','kube-node-lease'},'Unknown namespace: complete workload cleanup before EKS deletion.')
    for kind in ('statefulsets','jobs','cronjobs','persistentvolumes','persistentvolumeclaims','ingresses','volumeattachments','secrets','networkpolicies','mutatingwebhookconfigurations','validatingwebhookconfigurations'):
        require(not inv[kind],f'{kind} remains: explicit owner-aware cleanup/retention required.')
    for x in inv['configmaps']:
        m=x['metadata']
        require(m['name']=='kube-root-ca.crt' or (m.get('namespace')=='kube-system' and m['name'] in {'coredns','kube-proxy','kube-proxy-config','amazon-vpc-cni','extension-apiserver-authentication'}),'Unknown ConfigMap data must be preserved/reviewed before teardown.')
    require({x['metadata']['name'] for x in inv['customresourcedefinitions']} <= BASELINE_CRDS,'Unknown CRD: later platform consumers are unsupported.')
    allowed={'deployments':{'coredns','ebs-csi-controller'},'daemonsets':{'aws-node','kube-proxy','eks-pod-identity-agent','ebs-csi-node','ebs-csi-node-windows'}}
    owners={}
    for kind,names in allowed.items():
        for x in inv[kind]:
            m=x['metadata'];require(m.get('namespace')=='kube-system' and m['name'] in names,'Unknown Kubernetes controller.')
            owners[m['uid']]=m['name']
    for x in inv['replicasets']:
        m=x['metadata']; refs=m.get('ownerReferences',[])
        require(m.get('namespace')=='kube-system' and len(refs)==1 and refs[0]['uid'] in owners and refs[0]['kind']=='Deployment','Unknown ReplicaSet owner.')
        owners[m['uid']]=m['name']
    for x in inv['pods']:
        m=x['metadata'];refs=m.get('ownerReferences',[])
        require(m.get('namespace')=='kube-system' and len(refs)==1 and refs[0]['uid'] in owners,'Unknown/unowned pod remains.')
    for x in inv['services']:
        m=x['metadata'];spec=x['spec']
        require((m.get('namespace'),m['name']) in {('default','kubernetes'),('kube-system','kube-dns')} and spec.get('type')=='ClusterIP' and not spec.get('externalIPs') and not x.get('status',{}).get('loadBalancer',{}).get('ingress'),'Unknown service/LB remains.')
    return {'baseline_only':True,'resource_counts':{k:len(v) for k,v in inv.items()}}

def residual_spec_hash(obj):
    body={key:value for key,value in obj.items() if key not in ('metadata','status')}
    return hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def validate_residual_inventory(inv, contract, context, live_cluster):
    """Only caller-authenticated saved-bundle contract; never trust an env filename."""
    require(contract.get('schema_version')==1 and contract.get('cluster_arn')==live_cluster['arn'] and
            contract.get('cluster_created_at')==live_cluster['createdAt'] and contract.get('source_sha')==context['source_sha'] and
            contract.get('generation')==context['generation'],'Residual contract belongs to another cluster/snapshot.')
    approved=contract.get('approved_residuals');require(isinstance(approved,list),'Missing approved residuals.')
    remaining={kind:list(rows) for kind,rows in inv.items()};seen=set();controller_uids=set();hook_job_uids=set();matched=[]
    safe_kinds={'namespaces','customresourcedefinitions','deployments','statefulsets','services','configmaps','secrets','applications','appprojects','networkpolicies','jobs','pods'}|set(INSTALLER_RESIDUAL_READS)
    for row in approved:
        require(set(row) in ({'resource','namespace','name','uid','spec_sha256'},{'resource','namespace','name','uid','spec_sha256','metadata_policy_sha256'}) and row['resource'] in safe_kinds,'Unknown residual contract field/resource.')
        if row['resource'] in INSTALLER_RESIDUAL_READS:require('metadata_policy_sha256' in row,'Installer residual metadata proof missing.')
        if 'metadata_policy_sha256' in row:require(isinstance(row['metadata_policy_sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['metadata_policy_sha256']),'Invalid residual metadata-policy hash.')
        key=(row['resource'],row['namespace'],row['name']);require(key not in seen,'Duplicate residual object.');seen.add(key)
        objects=[x for x in remaining.get(row['resource'],[]) if x['metadata'].get('namespace','')==row['namespace'] and x['metadata']['name']==row['name']]
        require(len(objects)==1,'Approved residual missing or duplicated.')
        obj=objects[0];require(obj['metadata']['uid']==row['uid'] and residual_spec_hash(obj)==row['spec_sha256'],'Residual UID/spec changed after review.')
        if row['resource'] in VELERO_RESIDUAL_READS:require(obj.get('apiVersion')=='velero.io/v1','Residual metadata is outside the exact Velero API.')
        if 'metadata_policy_sha256' in row:
            metadata={k:obj['metadata'].get(k) for k in ('labels','annotations','finalizers','ownerReferences')}
            require(hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()).hexdigest()==row['metadata_policy_sha256'],'Residual metadata-policy changed after review.')
        if row['resource'] in ('jobs','pods'):
            require('metadata_policy_sha256' in row and obj['metadata'].get('namespace')=='argocd' and bool(obj['metadata'].get('annotations',{}).get('helm.sh/hook')),'Only exact completed Argo chart hook jobs/pods may remain.')
            if row['resource']=='jobs':
                require(not obj.get('status',{}).get('active') and not obj.get('status',{}).get('failed') and any(x.get('type')=='Complete' and x.get('status')=='True' for x in obj.get('status',{}).get('conditions',[])),'Chart hook Job is not successfully complete.')
                hook_job_uids.add(row['uid'])
            else:require(obj.get('status',{}).get('phase')=='Succeeded','Chart hook Pod is not successfully complete.')
        if row['resource'] in ('deployments','statefulsets','jobs'):controller_uids.add(row['uid'])
        remaining[row['resource']].remove(obj);matched.append(key)
    for kind in ('replicasets','pods'):
        for obj in list(remaining.get(kind,[])):
            refs=obj['metadata'].get('ownerReferences',[])
            if len(refs)==1 and refs[0].get('controller') is True and refs[0].get('uid') in controller_uids:
                require(obj['metadata'].get('namespace')=='argocd','Residual-generated workload outside reviewed Argo namespace.')
                if refs[0]['uid'] in hook_job_uids:require(kind=='pods' and refs[0].get('kind')=='Job' and obj.get('status',{}).get('phase')=='Succeeded','Residual chart hook child is not an exact successful Job-owned Pod.')
                controller_uids.add(obj['metadata']['uid']);remaining[kind].remove(obj)
    for kind in ('applications','appprojects',*INSTALLER_RESIDUAL_READS):
        if kind in remaining:require(not remaining.pop(kind),'Unknown Argo application/project remains.')
    validate_inventory(remaining)
    return {'exact_residual_count':len(matched),'baseline_only_after_exact_residuals':True}

def authenticated_residual_contract(context):
    """Descriptor-only handoff; authentication lives in the central CAS barrier."""
    chapter=os.environ.get('COMPLETED_CHAPTER','')
    require(context.get('operation')=='down','Residual handoff is Down-only.')
    if chapter=='BU06':return None # Node-less control plane: no installer/Argo resources exist.
    early=chapter=='BU07'
    if early:require(context.get('source_capability',{}).get('operations_access') is True,'Early residual handoff requires the exact reviewed access source capability.')
    barrier=load('eks_authenticated_barriers',CI/'lifecycle-barriers.py')
    store=barrier.h.Store(context['backend']['bucket'],context['account'])
    try:descriptors=json.loads(os.environ.get('LIFECYCLE_BARRIER_RECEIPTS',''))
    except (TypeError,ValueError):raise SafeError('Authenticated hook receipt descriptors missing.') from None
    result=barrier.for_consumer(store,context,descriptors,step='hook:cluster-private-api-check' if early else 'hook:platform-core')
    if early:
        require(result.get('no_mutation') is True and result.get('checkpoint_generation')==context['generation'] and isinstance(result.get('bootstrap_binding'),dict) and isinstance(result.get('residual_contract'),dict),'Authenticated early bootstrap residual result is incomplete.')
    else:require(result.get('load_balancers_absent') is True and isinstance(result.get('residual_contract'),dict),'Authenticated core cleanup result is incomplete.')
    return result['residual_contract']

def live_guard(context,rows,upstream):
    region=context['backend']['region'];env,eks,relay,vpc_root=roots(context)
    require(context.get('operation')=='down','Global inventory is Down-only; Up uses bounded AWS readiness.')
    require(os.environ.get('AWS_ROLE_ARN')=='arn:aws:iam::'+context['account']+':role/gha-infra-'+env+'-lifecycle-destroy','Global Down inventory requires the dedicated lifecycle-destroy role.')
    if context['root']==relay:
        reader=VersionedStateReader(context['backend']['bucket'],context['account'],region)
        s=state(reader(key(eks)));require(s is None or not managed_resources(s),'EKS must be fully down before relay deletion.')
        clusters=p.aws(region,'eks','list-clusters')['clusters']
        for name in clusters:
            live=p.aws(region,'eks','describe-cluster','--name',name)['cluster']
            relay_vpcs={r['values']['vpc_id'] for r in rows if r['type']=='aws_security_group'}
            require(live['resourcesVpcConfig']['vpcId'] not in relay_vpcs,'Live EKS cluster still uses relay VPC.')
        relays=[r['values'] for r in rows if r['type']=='aws_instance']
        require(len(relays)==1,'Exact relay instance missing.')
        instances=p.aws(region,'ec2','describe-instances','--instance-ids',relays[0]['id'])['Reservations']
        actual=[i for r in instances for i in r['Instances']]
        require(len(actual)==1 and actual[0]['InstanceId']==relays[0]['id'],'Exact live relay missing.')
        disks=actual[0]['BlockDeviceMappings']
        require(len(disks)==1 and disks[0]['DeviceName']==actual[0]['RootDeviceName'] and disks[0]['Ebs']['DeleteOnTermination'] is True,'Relay persistent/extra disk requires reviewed retention.')
        return {'eks_state_empty':True}
    residual_contract=authenticated_residual_contract(context) if context.get('operation')=='down' else None
    clusters=[r['values'] for r in rows if r['type']=='aws_eks_cluster']
    require(len(clusters)==1,'Partial EKS deletion requires reviewed recovery; do not skip live inventory.')
    cluster=clusters[0]; relay_state=state(upstream.get(relay));require(relay_state is not None,'Private relay State missing.')
    relays=[r['values']['id'] for r in managed_resources(relay_state) if r['type']=='aws_instance' and r['name']=='relay']
    require(len(relays)==1,'Exact relay identity missing.')
    with tempfile.TemporaryDirectory(prefix='eks-check-') as directory:
        with p.private_api(cluster['name'],relays[0],region,Path(directory)/'kubeconfig') as (env,live):
            require(live['arn']==cluster['arn'] and dt.datetime.fromisoformat(live['createdAt'].replace('Z','+00:00'))==dt.datetime.fromisoformat(cluster['created_at'].replace('Z','+00:00')),'Live cluster identity differs from saved State.')
            kinds=('namespaces','services','pods','deployments','daemonsets','replicasets','statefulsets','jobs','cronjobs','persistentvolumes','persistentvolumeclaims','ingresses','volumeattachments','customresourcedefinitions','secrets','configmaps','networkpolicies','mutatingwebhookconfigurations','validatingwebhookconfigurations')
            inv={}
            for kind in kinds:
                value=json.loads(p.command(['kubectl','--request-timeout=60s','get',kind,'--all-namespaces','-o','json'],env=env))
                require(not value.get('metadata',{}).get('continue'),'Incomplete Kubernetes pagination.')
                inv[kind]=value['items']
            if residual_contract:
                for kind in ('applications','appprojects'):
                    value=json.loads(p.command(['kubectl','--request-timeout=60s','get',kind+'.argoproj.io','--all-namespaces','-o','json'],env=env))
                    require(not value.get('metadata',{}).get('continue'),'Incomplete Argo residual inventory.')
                    inv[kind]=value['items']
                # Installer RBAC/admission/default accounts are fetched only by
                # exact authenticated receipt identities, never by a name exemption.
                for row in residual_contract['approved_residuals']:
                    if row['resource'] not in INSTALLER_RESIDUAL_READS:continue
                    require('metadata_policy_sha256' in row and re.fullmatch(r'[A-Za-z0-9][-A-Za-z0-9:._]*',row['name']),'Unreviewed installer residual identity/metadata.')
                    namespaced=INSTALLER_RESIDUAL_READS[row['resource']]
                    require(bool(row['namespace'])==namespaced,'Installer residual scope mismatch.')
                    if namespaced:require(re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?',row['namespace']),'Invalid installer namespace.')
                    args=['kubectl','--request-timeout=60s','get',VELERO_RESIDUAL_READS.get(row['resource'],row['resource']),row['name']]
                    if namespaced:args+=['-n',row['namespace']]
                    value=json.loads(p.command(args+['-o','json'],env=env))
                    if row['resource'] in VELERO_RESIDUAL_READS:require(value.get('apiVersion')=='velero.io/v1','Authenticated residual is not the exact Velero API.')
                    inv.setdefault(row['resource'],[]).append(value)
                evidence=validate_residual_inventory(inv,residual_contract,context,live)
            else:evidence=validate_inventory(inv)
            for crd in inv['customresourcedefinitions']:
                value=json.loads(p.command(['kubectl','--request-timeout=60s','get',crd['metadata']['name'],'--all-namespaces','-o','json'],env=env))
                require(not value.get('metadata',{}).get('continue'),'Incomplete CR inventory.')
                if residual_contract and crd['metadata']['name'] in ('applications.argoproj.io','appprojects.argoproj.io'):
                    kind=crd['metadata']['name'].split('.')[0]
                    require(isinstance(value.get('items'),list) and {(x['metadata']['uid'],residual_spec_hash(x)) for x in value['items']}=={(x['metadata']['uid'],residual_spec_hash(x)) for x in inv[kind]},'Argo residual changed during CR validation.')
                elif residual_contract and crd['metadata']['name'] in VELERO_RESIDUAL_READS.values():
                    kind=crd['metadata']['name'].split('.')[0]
                    def identity(obj):
                        metadata={k:obj['metadata'].get(k) for k in ('labels','annotations','finalizers','ownerReferences')}
                        return (obj['metadata']['uid'],residual_spec_hash(obj),hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()).hexdigest())
                    require(isinstance(value.get('items'),list) and all(x.get('apiVersion')=='velero.io/v1' for x in value['items']) and {identity(x) for x in value['items']}=={identity(x) for x in inv.get(kind,[])},'Unknown or changed Velero metadata remains outside authenticated residual proof.')
                else:require(value.get('items')==[],'Custom Kubernetes consumers remain.')
            nodes=json.loads(p.command(['kubectl','--request-timeout=60s','get','nodes','-o','json'],env=env))
            # Root disks only: any extra attached disk must be handled separately.
            instances=[]
            for n in nodes['items']:
                provider=n['spec']['providerID'];require(re.fullmatch(r'aws:///[^/]+/i-[0-9a-f]+',provider) is not None,'Unknown node provider identity.')
                instances.append(provider.rsplit('/',1)[1])
            if instances:
                reservations=p.aws(region,'ec2','describe-instances','--instance-ids',*instances)['Reservations']
                actual=[i for r in reservations for i in r['Instances']]
                require({i['InstanceId'] for i in actual}==set(instances),'Incomplete EC2 node inventory.')
                for i in actual:
                    disks=i['BlockDeviceMappings']
                    require(len(disks)==1 and disks[0]['DeviceName']==i['RootDeviceName'] and disks[0]['Ebs']['DeleteOnTermination'] is True,'Additional/persistent node disk: reviewed retention needed.')
    vpc=cluster['vpc_config'][0]['vpc_id']
    # Account-wide list, auto-pagination enabled; fail if any VPC LB remains.
    for service in ('elb','elbv2'):
        lbs=p.aws(region,service,'describe-load-balancers')
        require(not any(l.get('VpcId',l.get('VPCId'))==vpc for l in lbs['LoadBalancers' if service=='elbv2' else 'LoadBalancerDescriptions']),'VPC load balancer remains; never delete blindly.')
    return evidence

def guard_destroy(workspace,context,raw,plan,expected_resources=None,upstream_states=None,stage='plan',previous_absence_targets=None):
    require(isinstance(plan,dict) and str(plan.get('format_version','')).split('.')[0]=='1' and plan.get('complete',True) is True and plan.get('errored',False) is False and not plan.get('deferred_changes'),'Incomplete/deferred destroy plan.')
    delete_proof=load('eks_delete_plan_proof',CI/'network-consumer-proof.py').validate_delete_plan(raw,plan)
    rows=validate_state(context,raw,expected_resources,upstream_states)
    validate_plan_contracts(context,plan,upstream_states)
    changes=[r for r in plan.get('resource_changes',[]) if r.get('mode')!='data' and r['change']['actions']!=['no-op']]
    owned={r['address'] for r in rows}
    require(len(changes)==len({r['address'] for r in changes}) and {r['address'] for r in changes}==owned and all(r['change']['actions']==['delete'] for r in changes),'Destroy must delete exactly the owned root, without replacement or extra resources.')
    by_address={row['address']:row for row in rows}
    for change in changes:
        owned_row=by_address[change['address']]
        before=change.get('change',{}).get('before')
        require(change.get('mode')=='managed' and change.get('type')==owned_row['type'] and isinstance(before,dict) and before.get('id')==owned_row['values']['id'] and change['change'].get('after') is None,'Saved destroy plan identity differs from exact owned State.')
    if not rows:
        require(previous_absence_targets is not None,'Empty root has no prior approved AWS absence targets; reviewed recovery required.')
        proof=verify_absent(context,expected_resources,absence_targets=previous_absence_targets)
        return {'deferred_runtime_consumer_check':False,'absence_targets':previous_absence_targets,'recovered_empty_state_proof':proof}
    absence=capture_absence_targets(context,rows)
    if stage=='apply':return {**live_guard(context,rows,upstream_states),'absence_targets':absence}
    # Relay is still a dependency during bundle planning; live absence checked at apply.
    return {'deferred_runtime_consumer_check':True,'scope':'exact-owned-resources-and-authenticated-residuals','absence_targets':absence}

ABSENCE_READS={
 ('sts','get-caller-identity'),('eks','describe-cluster'),
 ('autoscaling','describe-auto-scaling-groups'),('ec2','describe-instances'),
 ('ec2','describe-volumes'),('ec2','describe-security-groups'),
 ('ec2','describe-security-group-rules'),('ec2','describe-launch-templates'),
 ('iam','get-role'),('iam','get-instance-profile'),('iam','get-open-id-connect-provider'),
 ('logs','describe-log-groups')}
MISSING={('eks','describe-cluster'):'ResourceNotFoundException',
 ('iam','get-role'):'NoSuchEntity',('iam','get-instance-profile'):'NoSuchEntity',
 ('iam','get-open-id-connect-provider'):'NoSuchEntity',
 ('ec2','describe-security-group-rules'):'InvalidSecurityGroupRuleId.NotFound'}

def absence_read(service,operation,*args):
    require((service,operation) in ABSENCE_READS,'Unregistered absence read API.')
    result=subprocess.run(['aws',service,operation,*args,'--output','json','--no-cli-pager'],capture_output=True,timeout=180)
    if result.returncode:
        match=re.search(rb'An error occurred \(([A-Za-z0-9.]+)\) when calling',result.stderr)
        code=match.group(1).decode() if match else None
        if (service,operation)==('eks','describe-cluster') and code=='ClientException' and '--name' in args:
            name=args[args.index('--name')+1]
            expected=('No cluster found for name: '+name).encode()
            require(result.stderr.rstrip().rstrip(b'.').endswith(expected),'Ambiguous EKS ClientException is not absence.')
            return {'__absence_error':'ResourceNotFoundException'}
        require(code is not None and code==MISSING.get((service,operation)),'AWS absence read denied/failed; missing is not inferred.')
        return {'__absence_error':code}
    try:value=json.loads(result.stdout)
    except ValueError:raise SafeError('Invalid absence API JSON.') from None
    require(isinstance(value,dict) and '__absence_error' not in value,'Malformed absence API response.')
    return value

def exact_list(value,field):
    require(isinstance(value,dict) and not any(value.get(k) for k in ('NextToken','nextToken','NextMarker','Marker','NextContinuationToken')) and value.get('IsTruncated') is not True,'Incomplete absence API pagination.')
    rows=value.get(field);require(isinstance(rows,list) and all(isinstance(x,dict) for x in rows),'Missing/malformed absence list.')
    return rows

def capture_absence_targets(context,rows,*,aws_call=None):
    call=aws_call or absence_read;region=context['backend']['region'];account=context['account']
    _,eks,relay,_=roots(context)
    require(call('sts','get-caller-identity','--region',region).get('Account')==account,'AWS caller differs from approved absence account.')
    asgs=set();instances={r['values']['id'] for r in rows if r['type']=='aws_instance'};volumes=set();managed_sgs=set()
    for row in rows:
        if row['type']=='aws_eks_node_group':
            resources=row['values'].get('resources');require(isinstance(resources,list) and len(resources)==1,'Managed node ASG relationship missing.')
            groups=resources[0].get('autoscaling_groups');require(isinstance(groups,list) and groups,'Managed node ASG names missing.')
            asgs.update(x['name'] for x in groups)
        if row['type']=='aws_eks_cluster':
            cluster=row['values']
            observed=call('eks','describe-cluster','--name',cluster['name'],'--region',region).get('cluster')
            require(isinstance(observed,dict) and observed.get('arn')==cluster.get('arn') and observed.get('resourcesVpcConfig',{}).get('clusterSecurityGroupId')==cluster['vpc_config'][0].get('cluster_security_group_id'),'Live EKS service-created SG ownership differs from State.')
            identity=row['values']['vpc_config'][0].get('cluster_security_group_id')
            require(isinstance(identity,str) and re.fullmatch(r'sg-[0-9a-f]+',identity),'Service-created cluster SG identity missing.')
            managed_sgs.add(identity)
    if asgs:
        require(all(isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,255}',x) for x in asgs),'Invalid exact ASG identity.')
        groups=exact_list(call('autoscaling','describe-auto-scaling-groups','--auto-scaling-group-names',*sorted(asgs),'--region',region),'AutoScalingGroups')
        require({x.get('AutoScalingGroupName') for x in groups}==asgs,'Owned node ASG missing before apply.')
        for group in groups:
            require(group.get('AutoScalingGroupARN','').split(':')[4:5]==[account],'Foreign ASG account.')
            require(isinstance(group.get('Instances'),list),'ASG membership missing.')
            instances.update(x['InstanceId'] for x in group['Instances'])
    if instances:
        require(all(re.fullmatch(r'i-[0-9a-f]+',x) for x in instances),'Invalid owned instance identity.')
        reservations=exact_list(call('ec2','describe-instances','--instance-ids',*sorted(instances),'--region',region),'Reservations')
        require(all(x.get('OwnerId')==account and isinstance(x.get('Instances'),list) for x in reservations),'Foreign/incomplete instance account.')
        owned=[i for row in reservations for i in row['Instances']]
        require({x['InstanceId'] for x in owned}==instances,'Incomplete owned instance membership.')
        for instance in owned:
            disks=instance.get('BlockDeviceMappings');require(isinstance(disks,list) and len(disks)==1 and disks[0].get('DeviceName')==instance.get('RootDeviceName') and disks[0].get('Ebs',{}).get('DeleteOnTermination') is True,'Only exact disposable root disks allowed.')
            volumes.add(disks[0]['Ebs']['VolumeId'])
    require(all(re.fullmatch(r'vol-[0-9a-f]+',x) for x in volumes),'Invalid owned root volume identity.')
    return {'schema':1,'account':account,'region':region,'root':context['root'],'asgs':sorted(asgs),'instances':sorted(instances),'volumes':sorted(volumes),'managed_cluster_sgs':sorted(managed_sgs)}

def verify_absent(context,original,*,absence_targets,aws_call=None):
    """Exact independent AWS proof, not empty State or a broad VPC assumption."""
    call=aws_call or absence_read;region=context['backend']['region'];account=context['account']
    _,eks,relay,_=roots(context)
    require(call('sts','get-caller-identity','--region',region).get('Account')==account,'Wrong account for AWS absence proof.')
    require(isinstance(original,list) and len(original)==len({r.get('address') for r in original}),'Invalid/duplicate original resource identities.')
    require(all(isinstance(r,dict) and set(r)=={'address','type','id'} and all(isinstance(r[k],str) and r[k] for k in ('address','type','id')) and r['type'] in allowed_types(context['root']) for r in original),'Unsupported original resource identities.')
    scope=original
    require(isinstance(absence_targets,dict) and set(absence_targets)=={'schema','account','region','root','asgs','instances','volumes','managed_cluster_sgs'} and
            absence_targets['schema']==1 and absence_targets['account']==account and absence_targets['region']==region and absence_targets['root']==context['root'],'Absence target receipt identity mismatch.')
    require(all(isinstance(absence_targets[k],list) and len(absence_targets[k])==len(set(absence_targets[k])) for k in ('asgs','instances','volumes','managed_cluster_sgs')),'Invalid/duplicate absence targets.')
    counts={};clusters=[r['id'] for r in scope if r['type']=='aws_eks_cluster']
    require((context['root']==eks and len(clusters)==1) or (context['root']==relay and not clusters),'Original root/cluster absence identity mismatch.')
    for name in clusters:
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}',name),'Invalid original EKS cluster name.')
        value=call('eks','describe-cluster','--name',name,'--region',region)
        require(value=={'__absence_error':'ResourceNotFoundException'},'Original EKS cluster remains or absence is ambiguous.')
    require(len(absence_targets['managed_cluster_sgs'])==len(clusters),'Missing/extra managed cluster SG absence target.')
    require(not any(r['type']=='aws_eks_node_group' for r in scope) or bool(absence_targets['asgs']),'Managed node group ASG absence targets missing.')
    covered={'terraform_data','aws_eks_cluster'}
    # These are owned EKS API children, never independent outside this cluster.
    for kind in ('aws_eks_addon','aws_eks_node_group','aws_eks_access_entry','aws_eks_access_policy_association'):
        children=[r for r in scope if r['type']==kind]
        require(not children or len(clusters)==1,'Child EKS resource without original cluster identity.')
        for row in children:
            separator='#' if kind=='aws_eks_access_policy_association' else ':'
            require(row['id'].startswith(clusters[0]+separator),'Child EKS resource belongs to another cluster.')
        covered.add(kind);counts[kind]=len(children)
    for kind,operation,flag in (('aws_iam_role','get-role','--role-name'),('aws_iam_instance_profile','get-instance-profile','--instance-profile-name'),('aws_iam_openid_connect_provider','get-open-id-connect-provider','--open-id-connect-provider-arn')):
        ids=[r['id'] for r in scope if r['type']==kind]
        for identity in ids:
            if kind=='aws_iam_openid_connect_provider':require(identity.startswith('arn:aws:iam::'+account+':oidc-provider/oidc.eks.'+region+'.amazonaws.com/id/'),'Only exact cluster IRSA OIDC absence may be read.')
            else:require(re.fullmatch(r'[A-Za-z0-9_+=,.@-]{1,128}',identity),'Invalid original IAM identity.')
            require(call('iam',operation,flag,identity,'--region',region)=={'__absence_error':'NoSuchEntity'},'Original IAM identity remains or absence is ambiguous.')
        covered.add(kind);counts[kind]=len(ids)
    attachments=[r for r in scope if r['type']=='aws_iam_role_policy_attachment']
    roles=[r for r in scope if r['type']=='aws_iam_role']
    require(not attachments or roles,'Policy attachments without owned absent IAM roles.')
    # validate_rows previously proved every attachment targets these owned roles.
    covered.add('aws_iam_role_policy_attachment');counts['aws_iam_role_policy_attachment']=len(attachments)
    for kind,operation,field,filter_name,identity_field,pattern in (
        ('aws_security_group','describe-security-groups','SecurityGroups','group-id','GroupId',r'sg-[0-9a-f]+'),
        ('aws_launch_template','describe-launch-templates','LaunchTemplates','launch-template-id','LaunchTemplateId',r'lt-[0-9a-f]+')):
        ids={r['id'] for r in scope if r['type']==kind}
        if kind=='aws_security_group':ids.update(absence_targets['managed_cluster_sgs'])
        if ids:
            require(all(re.fullmatch(pattern,x) for x in ids),'Invalid original EC2 resource identity.')
            rows=exact_list(call('ec2',operation,'--filters','Name='+filter_name+',Values='+','.join(sorted(ids)),'--region',region),field)
            require(not rows,'Original EC2 group/template remains after Down.')
        covered.add(kind);counts[kind]=len(ids)
    for kind in ('aws_vpc_security_group_ingress_rule','aws_vpc_security_group_egress_rule'):
        ids=[r['id'] for r in scope if r['type']==kind]
        for identity in ids:
            require(re.fullmatch(r'sgr-[0-9a-f]+',identity),'Invalid original SG rule identity.')
            value=call('ec2','describe-security-group-rules','--security-group-rule-ids',identity,'--region',region)
            require(value=={'__absence_error':'InvalidSecurityGroupRuleId.NotFound'} or exact_list(value,'SecurityGroupRules')==[],'Original SG rule remains.')
        covered.add(kind);counts[kind]=len(ids)
    groups=absence_targets['asgs']
    if groups:require(not exact_list(call('autoscaling','describe-auto-scaling-groups','--auto-scaling-group-names',*groups,'--region',region),'AutoScalingGroups'),'Owned managed-node ASG remains.')
    instances=absence_targets['instances']
    if instances:
        require(all(re.fullmatch(r'i-[0-9a-f]+',x) for x in instances),'Invalid original instance identity.')
        reservations=exact_list(call('ec2','describe-instances','--filters','Name=instance-id,Values='+','.join(instances),'--region',region),'Reservations')
        for reservation in reservations:
            require(reservation.get('OwnerId')==account and isinstance(reservation.get('Instances'),list),'Unexpected absence instance owner.')
            for instance in reservation['Instances']:require(instance.get('InstanceId') in instances and instance.get('State',{}).get('Name')=='terminated','Owned EC2 instance remains live.')
    require({r['id'] for r in scope if r['type']=='aws_instance'}<=set(instances),'Original relay missing from absence targets.')
    covered.add('aws_instance');counts['aws_instance']=len(instances)
    volumes=absence_targets['volumes']
    if volumes:
        require(all(re.fullmatch(r'vol-[0-9a-f]+',x) for x in volumes),'Invalid original volume identity.')
        require(not exact_list(call('ec2','describe-volumes','--filters','Name=volume-id,Values='+','.join(volumes),'--region',region),'Volumes'),'Owned disposable root volume remains.')
    for row in scope:
        if row['type']=='aws_cloudwatch_log_group':
            require(len(clusters)==1 and row['id']=='/aws/eks/'+clusters[0]+'/cluster','Unknown original log group identity.')
            groups=exact_list(call('logs','describe-log-groups','--log-group-name-prefix',row['id'],'--region',region),'logGroups')
            require(all(x.get('logGroupName')!=row['id'] for x in groups),'Original EKS log group remains.')
    covered.add('aws_cloudwatch_log_group')
    require({r['type'] for r in scope}<=covered,'Unsupported original resource has no exact AWS absence proof.')
    return {'schema':1,'mode':'exact-aws-absence','root':context['root'],'account':account,'region':region,'cluster_names':clusters,'resource_counts':counts,'node_asgs':len(absence_targets['asgs']),'root_volumes':len(volumes)}


def after_up(context,raw,upstream):
    """AWS-only pre-bootstrap readiness. Never reads Kubernetes Secrets/inventory.

    A newly-created operations-contract cluster has no group RBAC until the
    protected bootstrap handoff. Functional Pod probes are a later barrier.
    """
    env,eks,relay,vpc_root=roots(context);region=context['backend']['region']
    rows=validate_state(context,raw)
    if context['root']==relay:
        instances=[r['values'] for r in rows if r['type']=='aws_instance']
        require(len(instances)==1,'Restored relay identity missing.')
        for attempt in range(30):
            got=p.aws(region,'ssm','describe-instance-information','--filters',json.dumps([{'Key':'InstanceIds','Values':[instances[0]['id']]}]))['InstanceInformationList']
            if len(got)==1 and got[0]['InstanceId']==instances[0]['id'] and got[0]['PingStatus']=='Online':break
            time.sleep(10)
        else:raise SafeError('Restored relay not Online within 5 minutes; keep paused and retry fresh run.')
        return {'schema':1,'mode':'exact-aws-readiness','relay_instance_id':instances[0]['id'],'ssm_online':True}
    clusters=[r['values'] for r in rows if r['type']=='aws_eks_cluster']
    require(len(clusters)==1,'Restored EKS cluster State identity missing.')
    cluster=clusters[0];live=p.aws(region,'eks','describe-cluster','--name',cluster['name'])['cluster']
    require(live.get('arn')==cluster.get('arn') and live.get('name')==cluster['name'] and live.get('status')=='ACTIVE','Restored EKS cluster is not the exact ACTIVE State owner.')
    require(dt.datetime.fromisoformat(live['createdAt'].replace('Z','+00:00'))==dt.datetime.fromisoformat(cluster['created_at'].replace('Z','+00:00')),'Restored cluster incarnation differs from State.')
    vpc=cluster['vpc_config'][0]['vpc_id'];network=state(upstream.get(vpc_root))
    require(network is not None and network.get('outputs',{}).get('vpc_id',{}).get('value')==vpc,'Restored EKS cluster VPC differs from pinned upstream State.')
    config=live['resourcesVpcConfig']
    require(config.get('vpcId')==vpc and config.get('endpointPrivateAccess') is True and config.get('endpointPublicAccess') is False and config.get('clusterSecurityGroupId')==cluster['vpc_config'][0].get('cluster_security_group_id'),'Restored private cluster network differs from State.')
    require(live.get('endpoint')==cluster.get('endpoint') and live.get('certificateAuthority',{}).get('data')==cluster.get('certificate_authority',[{}])[0].get('data'),'Restored API endpoint/CA differs from State.')
    groups=[];addons=[];instances=set()
    for row in rows:
        a=row['values']
        if row['type']=='aws_eks_addon':
            got=p.aws(region,'eks','describe-addon','--cluster-name',a['cluster_name'],'--addon-name',a['addon_name'])['addon']
            require(got.get('clusterName')==cluster['name'] and got.get('addonName')==a['addon_name'] and got.get('status')=='ACTIVE' and not got.get('health',{}).get('issues'),'Restored add-on is not the exact healthy ACTIVE owner.')
            if a.get('arn'):require(got.get('addonArn')==a['arn'],'Restored add-on ARN differs from State.')
            addons.append(a['addon_name'])
        if row['type']=='aws_eks_node_group':
            got=p.aws(region,'eks','describe-nodegroup','--cluster-name',a['cluster_name'],'--nodegroup-name',a['node_group_name'])['nodegroup']
            require(got.get('clusterName')==cluster['name'] and got.get('nodegroupName')==a['node_group_name'] and got.get('status')=='ACTIVE' and not got.get('health',{}).get('issues'),'Restored node group is not the exact healthy ACTIVE owner.')
            if a.get('arn'):require(got.get('nodegroupArn')==a['arn'],'Restored node group ARN differs from State.')
            names={x['name'] for x in a['resources'][0]['autoscaling_groups']}
            require(names and names=={x['name'] for x in got['resources']['autoScalingGroups']},'Restored node ASG membership differs from State.')
            autos=p.aws(region,'autoscaling','describe-auto-scaling-groups','--auto-scaling-group-names',*sorted(names))['AutoScalingGroups']
            require({x['AutoScalingGroupName'] for x in autos}==names,'Restored node ASG lookup incomplete.')
            count=0
            for group in autos:
                require(group.get('AutoScalingGroupARN','').split(':')[4:5]==[context['account']],'Restored ASG belongs to a different account.')
                require(len(group['Instances'])==group['DesiredCapacity'] and all(x.get('HealthStatus')=='Healthy' and x.get('LifecycleState')=='InService' for x in group['Instances']),'Restored node ASG is not at healthy desired capacity.')
                instances.update(x['InstanceId'] for x in group['Instances']);count+=len(group['Instances'])
            require(count==got['scalingConfig']['desiredSize'],'Restored node count differs from desired size.')
            groups.append(a['node_group_name'])
    require(not groups or instances,'Restored cluster node groups have no running capacity.')
    if instances:
        reservations=p.aws(region,'ec2','describe-instances','--instance-ids',*sorted(instances))['Reservations']
        require(all(x.get('OwnerId')==context['account'] for x in reservations),'Restored node EC2 account differs.')
        actual=[x for r in reservations for x in r['Instances']]
        require({x['InstanceId'] for x in actual}==instances,'Restored exact node instance lookup incomplete.')
        for node in actual:
            require(node.get('VpcId')==vpc and node.get('State',{}).get('Name')=='running','Restored node VPC/readiness differs.')
            disks=node['BlockDeviceMappings']
            require(len(disks)==1 and disks[0]['DeviceName']==node['RootDeviceName'] and disks[0]['Ebs']['DeleteOnTermination'] is True,'Restored node has unexpected persistent disks.')
    return {'schema':1,'mode':'exact-aws-readiness','cluster_arn':live['arn'],'cluster_created_at':live['createdAt'],
            'node_groups':sorted(groups),'addons':sorted(addons),'instance_ids':sorted(instances),
            'functional_probe_barrier_required':bool(groups)}
