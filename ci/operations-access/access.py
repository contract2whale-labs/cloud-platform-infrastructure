#!/usr/bin/env python3
"""Compile reviewed, account-local operation access. Offline; never calls AWS/Kubernetes.

IAM output belongs to bootstrap/ci-identity. EKS resources belong to modules/eks.
RBAC is installed over the private relay by the gated initial installer.
"""
import argparse, hashlib, json, pathlib, re

ROLES = ('gitops-bootstrap', 'gitops-apply', 'incident-plan', 'incident-apply', 'lifecycle-destroy')
READ = ['get', 'list', 'watch']
MUTATE = ['create', 'patch', 'update', 'delete']
FIXTURES = ['incident-fixture-t'+str(n) for n in range(3, 7)]
NAMESPACES = ['course-node-probes','argocd','contract2whale-demo','monitoring','observability','team-mesh-check',
              'team-mesh-outside','team-platform-check','backup-probe','backup-probe-restored','velero',
              'incident-drill','incident-t8a'] + FIXTURES

def require(ok, message):
    if not ok: raise ValueError(message)

def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'))
def statement(sid, actions, resources, condition=None, effect='Allow'):
    row = dict(Sid=sid, Effect=effect, Action=actions, Resource=resources)
    if condition: row['Condition'] = condition
    return row

def validate(c):
    require(c['environment'] in ('dev','prod'), 'environment must be dev or prod')
    for key in ('bootstrap_chart_sha256','bootstrap_render_sha256'):
        require(re.fullmatch('[0-9a-f]{64}',c[key]),'Exact reviewed digest required: '+key)
    require(re.fullmatch('[0-9a-f]{40}',c['reviewed_source_sha']),'Reviewed immutable source SHA required')
    require(re.fullmatch(r'\d{12}',c['account_id']), 'exact account required')
    require(re.fullmatch(r'[a-z]{2}-[a-z]+-\d',c['region']), 'region required')
    require(re.fullmatch(r'\d+',c['repository_id']), 'numeric repository_id required')
    require(re.fullmatch(r'[A-Za-z0-9_-]+', c['cluster_name']), 'cluster name required')
    require(re.fullmatch(r'i-[a-f0-9]+',c['relay_id']), 'exact current relay instance required')
    require(c['state_keys'] and all(re.fullmatch(r'[a-zA-Z0-9_/-]+/terraform\.tfstate',k) for k in c['state_keys']), 'explicit State keys required')
    for key in ('state_bucket','evidence_bucket','operator_evidence_bucket'):
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',c[key]), 'invalid bucket '+key)
    for key in ('state_kms_arn','evidence_kms_arn','operator_evidence_kms_arn'):
        require(key in c and (c[key] is None or isinstance(c[key],str) and re.fullmatch(r'arn:aws:kms:'+c['region']+':'+c['account_id']+r':key/[a-zA-Z0-9-]+',c[key])), 'Explicit null for AES256 or exact account/region KMS key required: '+key)
    bucket_keys={}
    for bucket_field,key_field in (('state_bucket','state_kms_arn'),('evidence_bucket','evidence_kms_arn'),('operator_evidence_bucket','operator_evidence_kms_arn')):
        bucket,key=c[bucket_field],c[key_field]
        require(bucket not in bucket_keys or bucket_keys[bucket]==key,'The same actual bucket cannot have conflicting encryption registrations')
        bucket_keys[bucket]=key
    for field,service,resource in (('ecr_arns','ecr','repository/'),('rds_arns','rds','db:'),('rds_snapshot_arns','rds','snapshot:'),('secret_metadata_arns','secretsmanager','secret:'),('lambda_arns','lambda','function:'),('s3_gateway_endpoint_arns','ec2','vpc-endpoint/')):
        for arn in c.get(field,[]):
            require(arn.startswith('arn:aws:'+service+':'+c['region']+':'+c['account_id']+':'+resource) and not any(x in arn for x in '*?${'), 'exact local ARN required: '+field)
    require(type(c.get('bootstrap_only',False)) is bool,'Invalid bootstrap-only registration flag')
    require(isinstance(c.get('application_names'),list) and (bool(c['application_names']) or c.get('bootstrap_only') is True) and all(isinstance(n,str) and re.fullmatch(r'[a-z0-9-]+',n) for n in c['application_names']), 'reviewed Argo Application names required')
    require(len(c['application_names'])==len(set(c['application_names'])) and (not c.get('bootstrap_only') or c['application_names']==[]),'Bootstrap-only registration cannot carry future application names')
    require(set(c['bootstrap_cluster_objects']) == {'customresourcedefinitions','clusterroles','clusterrolebindings'}, 'rendered bootstrap cluster inventory required')
    for names in c['bootstrap_cluster_objects'].values():
        require(names and len(names)==len(set(names)) and all(re.fullmatch(r'[a-z0-9.:-]+',n) for n in names), 'invalid bootstrap cluster name inventory')
    if c.get('msk'):
        m=c['msk'];require(re.fullmatch(r'[a-zA-Z0-9-]+',m['cluster_name']), 'exact MSK name required')
        require(m['cluster_arn'].startswith('arn:aws:kafka:'+c['region']+':'+c['account_id']+':cluster/'+m['cluster_name']+'/') and '*' not in m['cluster_arn'], 'exact MSK ARN required')
        require(re.fullmatch(r'arn:aws:kms:'+c['region']+':'+c['account_id']+r':key/[a-zA-Z0-9-]+',m['kms_arn']), 'exact MSK KMS key required')
    return c

def policies(c, role):
    e,a,r,repo = (c[k] for k in ('environment','account_id','region','repository_id'))
    bucket='arn:aws:s3:::'+c['state_bucket']; eb='arn:aws:s3:::'+c['evidence_bucket']; ob='arn:aws:s3:::'+c['operator_evidence_bucket']
    cluster='arn:aws:eks:'+r+':'+a+':cluster/'+c['cluster_name']
    region={'StringEquals':{'aws:RequestedRegion':r}}
    common=[statement('DescribeExactCluster',['eks:DescribeCluster'],[cluster]),
      statement('InspectPrivateRelay',['ec2:DescribeInstances','ssm:DescribeInstanceInformation'],['*'],region),
      statement('StartOnlyPrivateRelay',['ssm:StartSession'],['arn:aws:ec2:'+r+':'+a+':instance/*'],{'StringEquals':{'ssm:resourceTag/Name':'cp-'+e+'-private-api-relay','ssm:resourceTag/Environment':e,'ssm:resourceTag/Component':'platform-private-api','ssm:resourceTag/ManagedBy':'Terraform'}}),
      statement('OnlyPortForwardDocument',['ssm:StartSession'],['arn:aws:ssm:'+r+'::document/AWS-StartPortForwardingSession']),
      statement('OwnSessionDataChannel',['ssmmessages:OpenDataChannel','ssm:ResumeSession','ssm:TerminateSession'],['arn:aws:ssm:'+r+':'+a+':session/${aws:userid}-*']),
      statement('NoIdentityOrAccessSelfEdit',['iam:*','eks:CreateAccessEntry','eks:UpdateAccessEntry','eks:DeleteAccessEntry','eks:AssociateAccessPolicy','eks:DisassociateAccessPolicy'],['*'],effect='Deny')]
    if role=='lifecycle-destroy':
        # Terraform resource policies/evidence are assembled by lifecycle-destroy.tf.
        # Do not deny all IAM: reviewed Terraform destroys non-CI workload identities.
        common[-1]=statement('NoIdentitySelfEdit',['iam:CreateRole','iam:UpdateAssumeRolePolicy','iam:PutRolePolicy','iam:DeleteRolePolicy','iam:AttachRolePolicy','iam:DetachRolePolicy','iam:DeleteRole','iam:PutRolePermissionsBoundary','iam:DeleteRolePermissionsBoundary'],['arn:aws:iam:'+':'+a+':role/'+n for n in ['gha-infra-'+e+'-lifecycle-destroy','gha-infra-'+e+'-plan','gha-infra-'+e+'-apply']]+['arn:aws:iam::'+a+':role/cp-'+e+'-'+x for x in ROLES if x!='lifecycle-destroy'],effect='Deny')
        return {'transport':common}
    incident=role.startswith('incident-');apply=role=='incident-apply'
    keys=list(c['state_keys'])+[f'ci-lifecycle/{repo}/{e}/course.json',f'ci-incidents/{repo}/{e}/active.json']
    if e=='dev':keys += [f'ci-lifecycle/{repo}/dev/network-{x}.json' for x in ('vpc','peer','transit')]
    roots=[f'ci-plans/{repo}/*/*/*/{e}/incidents/*',f'ci-logs/{repo}/*/*/*/{e}/incidents/*',f'ci-logs/{repo}/*/*/*/{e}/incident/*'] if incident else []
    evidence=[statement('InspectPrivateEvidenceBuckets',['s3:GetBucketVersioning','s3:GetBucketPublicAccessBlock','s3:GetEncryptionConfiguration','s3:GetLifecycleConfiguration'],list(dict.fromkeys([bucket,eb,ob]))),
      statement('DiscoverExactStateAndMarkers',['s3:ListBucket'],[bucket],{'StringEquals':{'s3:prefix':keys}}),
      statement('ReadVersionedStateAndMarkers',['s3:GetObject','s3:GetObjectVersion'],[bucket+'/'+k for k in keys+roots]),
      statement('DiscoverInstalledAccess',['s3:ListBucket'],[bucket],{'StringLike':{'s3:prefix':'operation-access/'+e+'/*/complete.json'}}),
      statement('ReadInstalledAccess',['s3:GetObject','s3:GetObjectVersion'],[bucket+'/operation-access/'+e+'/*/complete.json']),
      statement('NeverDeleteEvidenceOrState',['s3:DeleteObject','s3:DeleteObjectVersion'],[bucket+'/*',eb+'/*',ob+'/*'],effect='Deny')]
    if incident:
        evidence += [statement('ReadOperatorPublication',['s3:GetObject','s3:GetObjectVersion'],[ob+'/operator-publication/'+e+'/*']),
          statement('WritePlan' if not apply else 'WriteCompletion',['s3:PutObject'],[bucket+'/'+(roots[0] if not apply else roots[1]+'/apply/*')])]
        marker=bucket+f'/ci-incidents/{repo}/{e}/active.json'
        if apply:
            evidence += [statement('CompareAndSwapIncidentMarker',['s3:PutObject'],[marker]),statement('RequireMarkerCAS',['s3:PutObject'],[marker],{'Null':{'s3:if-match':'true','s3:if-none-match':'true'}},'Deny')]
        else: evidence += [statement('PlanCannotMutateMarker',['s3:PutObject'],[marker],effect='Deny')]
    else:
        evidence += [statement('WriteGitOpsReceipt',['s3:PutObject'],[eb+'/gitops/'+e+'/*/*/receipt.json'])]
    if role=='gitops-bootstrap':
        evidence += [statement('DiscoverBootstrapReceipt',['s3:ListBucket'],[bucket],{'StringLike':{'s3:prefix':'operation-access/'+e+'/*'}}),statement('BootstrapIncarnationReceipts',['s3:GetObject','s3:GetObjectVersion','s3:PutObject'],[bucket+'/operation-access/'+e+'/*/started.json',bucket+'/operation-access/'+e+'/*/complete.json',bucket+'/operation-access/'+e+'/*/access-refresh.json'])]
        common += [statement('VerifyOwnBootstrapAccess',['eks:DescribeAccessEntry','eks:ListAssociatedAccessPolicies'],['arn:aws:eks:'+r+':'+a+':access-entry/'+c['cluster_name']+'/*'],{'ArnEquals':{'eks:principalArn':'arn:aws:iam::'+a+':role/cp-'+e+'-gitops-bootstrap'}})]
    # S3 bucket keys use bucket ARN; non-bucket-key objects use object ARN. No direct KMS use.
    for index,(key,b) in enumerate(dict.fromkeys((key,b) for key,b in [(c['state_kms_arn'],bucket),(c['evidence_kms_arn'],eb),(c['operator_evidence_kms_arn'],ob)] if key is not None)):
        evidence += [statement('PrivateS3Encryption'+str(index),['kms:Decrypt','kms:GenerateDataKey'],[key],{'StringEquals':{'kms:ViaService':'s3.'+r+'.amazonaws.com','kms:CallerAccount':a},'StringLike':{'kms:EncryptionContext:aws:s3:arn':[b,b+'/*']}})]
    cloud=[]
    if incident:
        cloud += [statement('InventoryConsumers',['eks:ListClusters','ecs:ListClusters','lambda:ListFunctions','ec2:DescribeVolumes','ec2:DescribeSnapshots','ec2:DescribeVpcEndpoints','secretsmanager:ListSecrets'],['*'],region),
          statement('InspectPodIdentity',['eks:DescribePodIdentityAssociation'],['arn:aws:eks:'+r+':'+a+':podidentityassociation/'+c['cluster_name']+'/*'])]
        for sid,actions,field in [('InspectECR',['ecr:DescribeRepositories','ecr:DescribeImages','ecr:ListImages','ecr:BatchGetImage'],'ecr_arns'),('InspectDatabase',['rds:DescribeDBInstances'],'rds_arns'),('InspectRetainedSnapshot',['rds:DescribeDBSnapshots'],'rds_snapshot_arns'),('InspectCredentialMetadata',['secretsmanager:DescribeSecret'],'secret_metadata_arns'),('InspectImageConsumers',['lambda:GetFunction'],'lambda_arns')]:
            if c.get(field):cloud += [statement(sid,actions,c[field])]
        if apply and e=='dev' and c.get('s3_gateway_endpoint_arns'):cloud += [statement('RecoverExactS3EndpointPolicy',['ec2:ModifyVpcEndpoint'],c['s3_gateway_endpoint_arns'])]
        if apply and e=='dev' and c.get('ecr_arns'):cloud += [statement('RetireExactImages',['ecr:BatchDeleteImage'],c['ecr_arns'])]
        if apply and e=='prod' and c.get('rds_arns'):cloud += [statement('ReviewedDeletionProtectionTransition',['rds:ModifyDBInstance'],c['rds_arns'])]
        if c.get('msk'):
            m=c['msk'];secret='arn:aws:secretsmanager:'+r+':'+a+':secret:AmazonMSK_'+m['cluster_name']+'_queue-admin_*'
            cloud += [statement('InspectManagedQueue',['kafka:DescribeClusterV2','kafka:ListScramSecrets'],[m['cluster_arn']]),statement('InspectTemporaryQueueSecret',['secretsmanager:DescribeSecret'],[secret])]
            if apply:
                cloud += [statement('AssociateTemporarySCRAM',['kafka:BatchAssociateScramSecret','kafka:BatchDisassociateScramSecret'],[m['cluster_arn']]),
                  statement('TagTemporaryQueueSecret',['secretsmanager:TagResource'],[secret],{'Null':{'aws:RequestTag/platform-queue-run':'false','aws:RequestTag/platform-queue-request':'false'}}),
                  statement('CreateTaggedTemporaryQueueSecret',['secretsmanager:CreateSecret'],[secret],{'Null':{'aws:RequestTag/platform-queue-run':'false','aws:RequestTag/platform-queue-request':'false'},'StringEquals':{'secretsmanager:KmsKeyArn':m['kms_arn']}}),
                  statement('ScheduleRecoverableQueueSecretDeletion',['secretsmanager:DeleteSecret'],[secret],{'NumericGreaterThanEquals':{'secretsmanager:RecoveryWindowInDays':7},'BoolIfExists':{'secretsmanager:ForceDeleteWithoutRecovery':'false'}}),
                  statement('QueueSecretEncryption',['kms:GenerateDataKey','kms:Decrypt'],[m['kms_arn']],{'StringEquals':{'kms:ViaService':'secretsmanager.'+r+'.amazonaws.com','kms:CallerAccount':a}})]
        cloud += [statement('NeverBulkReadCredentialsOrDeleteData',['secretsmanager:BatchGetSecretValue','ec2:DeleteVolume','ec2:DeleteSnapshot','rds:DeleteDBInstance'],['*'],effect='Deny')]
        if apply and c.get('msk'):
            cloud += [statement('RecoverOnlyOriginalTemporaryCredential',['secretsmanager:GetSecretValue'],[secret],{'StringEquals':{'secretsmanager:VersionId':'${aws:ResourceTag/platform-queue-run}'}})]
            cloud += [dict(Sid='NoApplicationCredentialValues',Effect='Deny',Action=['secretsmanager:GetSecretValue'],NotResource=[secret])]
        else:cloud += [statement('NeverReadCredentialValues',['secretsmanager:GetSecretValue'],['*'],effect='Deny')]
    return {'transport':common,'evidence':evidence,**({'cloud':cloud} if cloud else {})}

def aws_fixed_bridge(c):
    """Dev-only supplements existing aws_iam_role.aws_ops, never new identities."""
    require(c['environment']=='dev','AWS fixed bridge is Dev only')
    rows=policies(c,'gitops-apply')['transport']
    rows[-1]['Action']=[a for a in rows[-1]['Action'] if not a.startswith('iam:')]
    bucket='arn:aws:s3:::'+c['state_bucket']
    keys=['eks/terraform.tfstate','platform/private-api/terraform.tfstate']
    rows += [statement('ReadFreshProbeBinding',['s3:GetObject','s3:GetObjectVersion'],[bucket+'/'+k for k in keys]+[bucket+'/operation-access/dev/*/complete.json']),
      statement('DiscoverFreshProbeBinding',['s3:ListBucket'],[bucket],{'StringLike':{'s3:prefix':keys+['operation-access/dev/*/complete.json']}})]
    if c['state_kms_arn'] is not None:rows += [statement('DecryptPrivateProbeBinding',['kms:Decrypt'],[c['state_kms_arn']],{'StringEquals':{'kms:ViaService':'s3.'+c['region']+'.amazonaws.com','kms:CallerAccount':c['account_id']},'StringLike':{'kms:EncryptionContext:aws:s3:arn':[bucket,bucket+'/*']}})]
    return rows

def rule(group,resources,verbs,names=None):
    row={'apiGroups':[group],'resources':resources,'verbs':verbs}
    if names:row['resourceNames']=names
    return row

def object_(kind,name,**extra):return {'apiVersion':'rbac.authorization.k8s.io/v1','kind':kind,'metadata':{'name':name},**extra}

def rbac(c):
    e=c['environment'];items=[]
    namespaces=[ns for ns in NAMESPACES if (e=='dev' or ns not in FIXTURES+['team-mesh-check','team-mesh-outside','incident-drill','incident-t8a'])]
    def bind(name,groups,rules,namespace=None):
        kind='Role' if namespace else 'ClusterRole';obj=object_(kind,name,rules=rules)
        if namespace:obj['metadata']['namespace']=namespace
        binding=object_(kind+'Binding',name,roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':kind,'name':name},subjects=[{'kind':'Group','apiGroup':'rbac.authorization.k8s.io','name':g} for g in groups])
        if namespace:binding['metadata']['namespace']=namespace
        items.extend([obj,binding])
    group=lambda role:'cp:'+e+':'+role
    allgroups=[group(x) for x in ROLES]+[group('lifecycle-plan'),group('lifecycle-apply')]+([group('aws-fixed-plan'),group('aws-fixed-apply')] if e=='dev' else [])
    bind('cp-destruction-inventory-'+e,[group('lifecycle-destroy')],[rule('*',['*'],READ)])
    bind('cp-readyz-'+e,allgroups,[{'nonResourceURLs':['/readyz','/api','/api/*','/apis','/apis/*','/version'],'verbs':['get']}])
    for ns in namespaces:
        md={'name':ns}
        if ns=='course-node-probes':md['labels']={'course-lifecycle/probe-namespace':'true','pod-security.kubernetes.io/enforce':'restricted','pod-security.kubernetes.io/enforce-version':'latest'}
        if ns in FIXTURES:md['labels']={'platform.course/fixture-namespace':ns.rsplit('-',1)[1],'pod-security.kubernetes.io/enforce':'restricted','pod-security.kubernetes.io/enforce-version':'latest'}
        items.append({'apiVersion':'v1','kind':'Namespace','metadata':md})
    argo=([rule('argoproj.io',['applications'],['get','patch','update','delete'],c['application_names']),rule('argoproj.io',['applications'],['create','list','watch'])] if c['application_names'] else [])+[rule('',['services'],['get'],['argocd-server']),rule('',['pods'],['get','list','watch']),rule('',['pods/portforward'],['create'])]
    # Application CREATE cannot be resourceNames-constrained; admission below enforces the reviewed set.
    bind('cp-gitops-'+e,[group('gitops-apply'),group('gitops-bootstrap'),group('lifecycle-apply'),group('lifecycle-destroy')],argo,'argocd')
    bind('cp-lifecycle-argo-plan-'+e,[group('lifecycle-plan')],[rule('argoproj.io',['applications'],READ)],'argocd')
    bootstrap=[rule('', ['configmaps','secrets','serviceaccounts','services','pods'], READ+MUTATE),rule('apps',['deployments','statefulsets','replicasets'],READ+MUTATE),rule('batch',['jobs'],READ+MUTATE),rule('networking.k8s.io',['networkpolicies'],READ+MUTATE),rule('policy',['poddisruptionbudgets'],READ+MUTATE),rule('rbac.authorization.k8s.io',['roles','rolebindings'],READ+MUTATE+['bind','escalate']),rule('argoproj.io',['appprojects'],READ+MUTATE)]
    bind('cp-bootstrap-argocd-'+e,[group('gitops-bootstrap')],bootstrap,'argocd')
    clusterboot=[]
    for res,names in c['bootstrap_cluster_objects'].items():
        api='apiextensions.k8s.io' if res=='customresourcedefinitions' else 'rbac.authorization.k8s.io'
        clusterboot.extend([rule(api,[res],['create']),rule(api,[res],['get','patch','update','delete']+(['escalate','bind'] if res=='clusterroles' else []),names)])
    clusterboot += [rule('',['nodes'],READ),rule('',['namespaces'],['get'],['argocd'])]
    bind('cp-bootstrap-cluster-'+e,[group('gitops-bootstrap')],clusterboot)
    bind('cp-bootstrap-health-'+e,[group('gitops-bootstrap')],[rule('apps',['deployments'],READ,['coredns']),rule('apps',['daemonsets'],READ,['eks-pod-identity-agent'])],'kube-system')
    incidentgroups=[group('incident-plan'),group('incident-apply')]
    bind('cp-node-network-probe-'+e,[group('lifecycle-apply')],[rule('',['pods'],['create']),rule('',['pods'],['get','watch','delete'],['probe-pull','probe-net']),rule('',['pods/exec'],['create'],['probe-net'])],'course-node-probes')
    if e=='dev':
        bind('cp-aws-trace-read-dev',[group('aws-fixed-plan'),group('aws-fixed-apply')],[rule('',['pods','pods/log'],READ)],'observability')
        bind('cp-aws-trace-write-dev',[group('aws-fixed-apply')],[rule('',['pods'],['create','delete'])],'observability')
        bind('cp-aws-trace-namespace-dev',[group('aws-fixed-plan'),group('aws-fixed-apply')],[rule('',['namespaces'],['get'],['observability'])])
    # Explicit global read only for ECR consumer/drain/strict-policy closure. No Secret read.
    bind('cp-incident-consumers-'+e,incidentgroups,[rule('',['pods','nodes','persistentvolumes'],READ),rule('',['namespaces'],['get'],NAMESPACES),rule('apps',['deployments','statefulsets','daemonsets'],READ),rule('batch',['jobs','cronjobs'],READ),rule('argoproj.io',['rollouts'],READ),rule('security.istio.io',['peerauthentications'],READ)])
    readrules=[rule('',['pods','pods/log','services','configmaps','serviceaccounts','persistentvolumeclaims','events','resourcequotas'],READ),rule('apps',['deployments','statefulsets','replicasets','daemonsets'],READ),rule('batch',['jobs','cronjobs'],READ),rule('autoscaling',['horizontalpodautoscalers'],READ),rule('policy',['poddisruptionbudgets'],READ),rule('networking.k8s.io',['networkpolicies'],READ),rule('argoproj.io',['rollouts'],READ),rule('external-secrets.io',['externalsecrets'],READ),rule('security.istio.io',['peerauthentications'],READ),rule('monitoring.coreos.com',['prometheusrules'],READ)]
    for ns in namespaces:
        if ns=='argocd':bind('cp-incident-read-'+e,incidentgroups,[rule('argoproj.io',['applications'],READ),rule('',['configmaps'],['get'],['delivery-env']),rule('',['services'],['get'],['argocd-server']),rule('',['pods'],READ),rule('',['pods/portforward'],['create'])],ns)
        elif ns!='course-node-probes':bind('cp-incident-read-'+e,incidentgroups,readrules,ns)
    writes={
      'argocd':([rule('argoproj.io',['applications'],['patch'],c['application_names'])] if c['application_names'] else [])+[rule('',['configmaps'],['get'],['delivery-env'])],
      'contract2whale-demo':[rule('argoproj.io',['rollouts'],['patch'],['commerce-web']),rule('batch',['jobs'],['create','delete']),rule('',['configmaps'],['create','delete']),rule('',['pods/eviction'],['create']),rule('apps',['deployments'],['delete'],['incident-t4','incident-t5','incident-t6']),rule('',['services','serviceaccounts'],['delete'],['incident-t4','incident-t5','incident-t6']),rule('networking.k8s.io',['networkpolicies'],['delete'],['incident-t4','incident-t5','incident-t6']),rule('policy',['poddisruptionbudgets'],['delete'],['incident-t8-web','incident-t8-api']),rule('security.istio.io',['peerauthentications'],['create','delete'])],
      'monitoring':[rule('networking.k8s.io',['networkpolicies'],['delete'],['queue-admin']),rule('apps',['statefulsets'],['patch'],['platform-tempo-e3-block-builder']),rule('',['pods'],['create','delete']),rule('',['pods/exec'],['create'],['queue-admin']),rule('external-secrets.io',['externalsecrets'],['patch'],['grafana-admin']),rule('monitoring.coreos.com',['prometheusrules'],['create','delete'])],
      'observability':[rule('',['pods'],['create','delete'])],
      'team-mesh-check':[rule('apps',['deployments'],['create','delete'])],
      'team-mesh-outside':[rule('apps',['deployments'],['create','delete'])],
      'team-platform-check':[rule('apps',['deployments'],['create','delete']),rule('',['pods'],['delete'],['agent-log-check'])],
      'incident-drill':[rule('apps',['deployments'],['patch'],['imagepull-drill'])],
      'incident-t8a':[rule('apps',['deployments'],['patch','delete'],['incident-t8a-demand'])],
      'backup-probe':[rule('',['pods/exec'],['create'],['writer'])],
      'backup-probe-restored':[rule('',['pods/exec'],['create'],['writer']),rule('',['pods'],['delete'],['writer']),rule('',['persistentvolumeclaims'],['delete'],['data'])],
      'velero':[rule('velero.io',['backups','restores'],READ+['create'])]}
    for ns in FIXTURES:writes[ns]=[rule('',['resourcequotas','configmaps','serviceaccounts'],['create','delete']),rule('apps',['deployments'],['create','patch','delete']),rule('networking.k8s.io',['networkpolicies'],['create','delete']),rule('',['pods/exec'],['create'])]
    for ns,rules in writes.items():
        if ns in namespaces:bind('cp-incident-mutate-'+e,[group('incident-apply')],rules,ns)
    bind('cp-retirement-cluster-read-'+e,incidentgroups,[rule('kyverno.io',['clusterpolicies'],['get'],c.get('retirement_cluster_policies',['verify-image-signature','restrict-image-registries','require-image-digest']))])
    bind('cp-velero-plan-'+e,incidentgroups,[rule('velero.io',['backups','restores'],READ)],'velero')
    # The lifecycle retirement handler operates only these two source-declared
    # synthetic objects. No backup create/delete or arbitrary Pod execution.
    for ns in ('backup-probe','backup-probe-restored'):
        bind('cp-lifecycle-velero-synthetic-'+e,[group('lifecycle-destroy')],[rule('',['pods'],['get','delete'],['writer']),rule('',['pods/exec'],['create'],['writer']),rule('',['persistentvolumeclaims'],['get','delete'],['data'])],ns)
    bind('cp-lifecycle-velero-metadata-'+e,[group('lifecycle-destroy')],[rule('velero.io',['backups','restores'],['get','patch'],['platform-storage-probe']),rule('velero.io',['schedules'],['get','patch'],['platform-daily']),rule('velero.io',['backupstoragelocations','volumesnapshotlocations'],['get','patch'],['default'])],'velero')
    # Disposable lab handlers enumerate only Pod/PVC; they cannot read Secrets.
    if e=='dev':
        bind('cp-node-operations-'+e,[group('incident-apply')],[rule('',['nodes'],['patch']),rule('scheduling.k8s.io',['priorityclasses'],['get','delete'],['incident-t8a-low'])])
        bind('cp-node-plan-'+e,[group('incident-plan')],[rule('scheduling.k8s.io',['priorityclasses'],['get'],['incident-t8a-low'])])
    bind('cp-lifecycle-readiness-'+e,[group('lifecycle-plan'),group('lifecycle-apply')],[rule('',['nodes'],READ),rule('',['namespaces'],['get'],NAMESPACES)])
    bind('cp-lifecycle-system-readiness-'+e,[group('lifecycle-plan'),group('lifecycle-apply')],[rule('apps',['deployments','daemonsets'],READ)],'kube-system')
    # Shared fixed database-bootstrap handler: inspect the writer boundary, then
    # create only its immutable UUID-paired Job/ConfigMap. Admission below is
    # mandatory because RBAC resourceNames cannot constrain dynamic CREATEs.
    bind('cp-lifecycle-database-read-'+e,[group('lifecycle-plan'),group('lifecycle-apply')],[rule('',['pods','configmaps','serviceaccounts'],['get','list']),rule('apps',['deployments','statefulsets'],['get','list']),rule('batch',['jobs','cronjobs'],['get','list'])],'contract2whale-demo')
    bind('cp-lifecycle-database-create-'+e,[group('lifecycle-apply')],[rule('batch',['jobs'],['create']),rule('',['configmaps'],['create'])],'contract2whale-demo')
    # Next Down consumes the authenticated prior completion/UIDs. Its shared
    # cleanup sends UID + resourceVersion preconditions and observes absence.
    bind('cp-lifecycle-database-cleanup-'+e,[group('lifecycle-destroy')],[rule('batch',['jobs'],['delete']),rule('',['configmaps'],['delete'])],'contract2whale-demo')
    return items

def database_bootstrap_admission(c):
    """Bound the existing shared bootstrap handler, without new registration inputs.

    Exact image/publication, endpoints, Secret ARNs, association and saved UIDs
    remain authenticated by the handler's versioned State/receipt checks. These
    policies additionally deny arbitrary commands, Secret/env injection, updates
    and unguarded deletes even when the namespace CREATE/DELETE RBAC is present.
    """
    e=c['environment'];prefix='cp:'+e+':'
    apply,down,incident=[prefix+x for x in ('lifecycle-apply','lifecycle-destroy','incident-apply')]
    groups=[apply,down,incident];items=[]
    run="variables.target.metadata.labels['contract2whale.course/run-id']"
    uuid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    empty=lambda path:'(!has('+path+') || '+path+'.size() == 0)'
    false=lambda path:'(!has('+path+') || '+path+' == false)'
    image='^'+re.escape(c['account_id']+'.dkr.ecr.'+c['region']+'.amazonaws.com/')+'[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$'
    role='^arn:aws:iam::'+c['account_id']+':role/[A-Za-z0-9+=,.@_/-]+$'
    secret='^arn:aws:secretsmanager:'+c['region']+':'+c['account_id']+':secret:[A-Za-z0-9/_+=.@!-]+$'
    common=[
      "request.namespace == 'contract2whale-demo' && variables.target.metadata.namespace == 'contract2whale-demo'",
      "(request.operation == 'CREATE' && request.userInfo.groups.exists(g, g in "+json.dumps([apply,incident])+
      ")) || (request.operation == 'DELETE' && request.userInfo.groups.exists(g, g in "+json.dumps([down,incident])+"))",
      "has(variables.target.metadata.labels) && variables.target.metadata.labels['app.kubernetes.io/name'] == 'database-bootstrap' && variables.target.metadata.labels['app.kubernetes.io/part-of'] == 'contract2whale' && "+run+'.matches('+json.dumps(uuid)+") && variables.target.metadata.name == 'database-bootstrap-' + "+run,
      empty('variables.target.metadata.annotations')+' && '+empty('variables.target.metadata.ownerReferences'),
      "request.operation != 'DELETE' || (has(request.options.preconditions) && request.options.preconditions.uid == oldObject.metadata.uid && request.options.preconditions.resourceVersion == oldObject.metadata.resourceVersion && request.options.propagationPolicy == 'Foreground')",
    ]
    for resource,api in [('jobs','batch'),('configmaps','')]:
        name='cp-database-bootstrap-'+resource+'-'+e
        variables=[{'name':'target','expression':"request.operation == 'DELETE' ? oldObject : object"}]
        checks=list(common)
        if resource=='jobs':
            variables += [{'name':'pod','expression':'variables.target.spec.template.spec'},{'name':'container','expression':'variables.pod.containers[0]'}]
            checks += [
              "variables.target.spec.backoffLimit == 0 && variables.target.spec.activeDeadlineSeconds == 600 && !has(variables.target.spec.ttlSecondsAfterFinished) && (!has(variables.target.spec.parallelism) || variables.target.spec.parallelism == 1) && (!has(variables.target.spec.completions) || variables.target.spec.completions == 1) && "+false('variables.target.spec.suspend')+' && '+false('variables.target.spec.manualSelector'),
              "variables.pod.serviceAccountName == 'database-operator' && variables.pod.automountServiceAccountToken == false && variables.pod.restartPolicy == 'Never' && variables.pod.nodeSelector == {'workload':'app'}",
              "variables.target.spec.template.metadata.labels['app.kubernetes.io/name'] == 'database-bootstrap' && variables.target.spec.template.metadata.labels['app.kubernetes.io/part-of'] == 'contract2whale' && variables.target.spec.template.metadata.labels['contract2whale.course/run-id'] == "+run+' && '+empty('variables.target.spec.template.metadata.annotations'),
              ' && '.join(false('variables.pod.'+x) for x in ('hostNetwork','hostPID','hostIPC','shareProcessNamespace'))+' && '+' && '.join(empty('variables.pod.'+x) for x in ('volumes','initContainers','ephemeralContainers','imagePullSecrets','hostAliases')),
              "!has(variables.pod.nodeName) && !has(variables.pod.runtimeClassName) && (!has(variables.pod.dnsPolicy) || variables.pod.dnsPolicy == 'ClusterFirst') && (!has(variables.pod.schedulerName) || variables.pod.schedulerName == 'default-scheduler')",
              "variables.pod.securityContext.runAsNonRoot == true && variables.pod.securityContext.runAsUser == 1000 && variables.pod.securityContext.seccompProfile.type == 'RuntimeDefault' && "+empty('variables.pod.securityContext.sysctls')+' && '+empty('variables.pod.securityContext.supplementalGroups')+" && !has(variables.pod.securityContext.fsGroup) && !has(variables.pod.securityContext.seLinuxOptions)",
              "variables.pod.containers.size() == 1 && variables.container.name == 'bootstrap' && variables.container.image.matches("+json.dumps(image)+") && variables.container.command == ['bash','/opt/contract2whale/operator/bootstrap.sh'] && "+empty('variables.container.args'),
              "variables.container.env.size() == 2 && variables.container.env[0].name == 'BOOTSTRAP_RUN_ID' && variables.container.env[0].value == "+run+" && !has(variables.container.env[0].valueFrom) && variables.container.env[1].name == 'EXPECTED_OPERATOR_ROLE_ARN' && variables.container.env[1].value.matches("+json.dumps(role)+") && !has(variables.container.env[1].valueFrom)",
              "variables.container.envFrom.size() == 1 && !has(variables.container.envFrom[0].secretRef) && (!has(variables.container.envFrom[0].prefix) || variables.container.envFrom[0].prefix == '') && variables.container.envFrom[0].configMapRef.name == variables.target.metadata.name && "+false('variables.container.envFrom[0].configMapRef.optional'),
              ' && '.join(empty('variables.container.'+x) for x in ('volumeMounts','volumeDevices','ports'))+" && !has(variables.container.lifecycle) && !has(variables.container.livenessProbe) && !has(variables.container.readinessProbe) && !has(variables.container.startupProbe) && (!has(variables.container.workingDir) || variables.container.workingDir == '') && "+false('variables.container.stdin')+' && '+false('variables.container.tty'),
              "variables.container.securityContext.allowPrivilegeEscalation == false && variables.container.securityContext.readOnlyRootFilesystem == true && variables.container.securityContext.capabilities.drop == ['ALL'] && "+empty('variables.container.securityContext.capabilities.add')+' && '+false('variables.container.securityContext.privileged')+" && (!has(variables.container.securityContext.runAsUser) || variables.container.securityContext.runAsUser == 1000) && (!has(variables.container.securityContext.runAsNonRoot) || variables.container.securityContext.runAsNonRoot == true) && (!has(variables.container.securityContext.procMount) || variables.container.securityContext.procMount == 'Default') && (!has(variables.container.securityContext.seccompProfile) || variables.container.securityContext.seccompProfile.type == 'RuntimeDefault') && !has(variables.container.securityContext.seLinuxOptions)",
              "request.operation != 'DELETE' || (oldObject.status.succeeded == 1 && (!has(oldObject.status.active) || oldObject.status.active == 0) && (!has(oldObject.status.failed) || oldObject.status.failed == 0) && (!has(oldObject.status.conditions) || oldObject.status.conditions.all(x, x.type != 'Failed' && x.type != 'FailureTarget' || x.status != 'True')))",
            ]
        else:
            fixed={'DATA_ENVIRONMENT':e,'DATA_ACCOUNT_ID':c['account_id'],'DATA_REGION':c['region'],'DATA_REDIS_TLS':'true','DATA_DB_MIGRATION_ROLE':'commerce_migrator','DATA_DB_RUNTIME_ROLE':'commerce_runtime'}
            patterns={'DATA_DB_ADDRESS':r'^[a-zA-Z0-9.-]+\.'+re.escape(c['region'])+r'\.rds\.amazonaws\.com$', 'DATA_REDIS_ADDRESS':r'^[a-zA-Z0-9.-]+\.cache\.amazonaws\.com$', 'DATA_DB_PORT':r'^[0-9]{1,5}$','DATA_REDIS_PORT':r'^[0-9]{1,5}$','DATA_DB_NAME':r'^[a-zA-Z_][a-zA-Z0-9_]{0,62}$','DATA_DB_SCHEMA':r'^[a-zA-Z_][a-zA-Z0-9_]{0,62}$','DATA_DB_ENGINE_VERSION':r'^[0-9]+(\.[0-9]+)*$',**{k:secret for k in ('DATA_MASTER_SECRET_ARN','DATA_MIGRATION_SECRET_ARN','DATA_RUNTIME_SECRET_ARN','DATA_APP_SECRET_ARN')}}
            keys=list(fixed)+list(patterns)
            checks += ['variables.target.immutable == true && '+empty('variables.target.binaryData'),
              'variables.target.data.size() == '+str(len(keys))+' && variables.target.data.all(k, k in '+json.dumps(keys)+')']
            checks += ['variables.target.data['+json.dumps(k)+'] == '+json.dumps(v) for k,v in fixed.items()]
            checks += ['variables.target.data['+json.dumps(k)+'].matches('+json.dumps(v)+')' for k,v in patterns.items()]
            checks += ["int(variables.target.data["+json.dumps(k)+"]) > 0 && int(variables.target.data["+json.dumps(k)+"]) <= 65535" for k in ('DATA_DB_PORT','DATA_REDIS_PORT')]
        spec={'failurePolicy':'Fail','matchConstraints':{'resourceRules':[{'apiGroups':[api],'apiVersions':['v1'],'operations':['CREATE','UPDATE','DELETE'],'resources':[resource],'scope':'Namespaced'}]},
          'matchConditions':[{'name':'fixed-runner-groups','expression':'request.userInfo.groups.exists(g, g in '+json.dumps(groups)+')'},
            # Keep unrelated incident handlers unchanged. Lifecycle groups have
            # no name escape: every request of these kinds enters the boundary.
            {'name':'bootstrap-handler-target','expression':'request.userInfo.groups.exists(g, g in '+json.dumps([apply,down])+") || (request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name).startsWith('database-bootstrap-')"}],
          'variables':variables,'validations':[{'expression':x,'message':'Only the reviewed immutable database bootstrap shape and exact completed UID cleanup are permitted.'} for x in checks]}
        items += [{'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicy','metadata':{'name':name},'spec':spec},
          {'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicyBinding','metadata':{'name':name},'spec':{'policyName':name,'validationActions':['Deny']}}]
    return items

def admission(c):
    """Native v1 policies: no webhook/network bootstrap dependency; fail closed."""
    e=c['environment'];items=[]
    def add(name,groups,rules,expression):
        items.append({'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicy','metadata':{'name':name},'spec':{'failurePolicy':'Fail','matchConstraints':{'resourceRules':rules},'matchConditions':[{'name':'fixed-runner-groups','expression':'request.userInfo.groups.exists(g, g in '+json.dumps(groups)+')'}],'validations':[{'expression':expression,'message':'Object is outside the reviewed operation access inventory.'}]}})
        items.append({'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicyBinding','metadata':{'name':name},'spec':{'policyName':name,'validationActions':['Deny']}})
    def rr(group,resources,scope):return {'apiGroups':[group],'apiVersions':['*'],'operations':['CREATE','UPDATE','DELETE'],'resources':resources,'scope':scope}
    names=json.dumps(c['application_names'])
    add('cp-argo-object-boundary-'+e,['cp:'+e+':'+x for x in ('gitops-apply','gitops-bootstrap','lifecycle-apply','lifecycle-destroy','incident-apply')],[rr('argoproj.io',['applications'],'Namespaced')],"request.namespace == 'argocd' && (request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name) in "+names)
    image_prefix=c['account_id']+'.dkr.ecr.'+c['region']+'.amazonaws.com/course-bu07-'
    probe_expression=("request.namespace == 'course-node-probes' && (request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name) in ['probe-pull','probe-net'] && (request.operation == 'DELETE' || ("
        "has(object.metadata.labels) && 'course-lifecycle/probe-run' in object.metadata.labels && object.metadata.labels['course-lifecycle/probe-run'].matches('^[0-9]+$') && "
        "has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false && "
        "(!has(object.spec.serviceAccountName) || object.spec.serviceAccountName == '' || object.spec.serviceAccountName == 'default') && "
        "(!has(object.spec.hostNetwork) || !object.spec.hostNetwork) && (!has(object.spec.hostPID) || !object.spec.hostPID) && (!has(object.spec.hostIPC) || !object.spec.hostIPC) && "
        "(!has(object.spec.volumes) || object.spec.volumes.size() == 0) && (!has(object.spec.initContainers) || object.spec.initContainers.size() == 0) && (!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.size() == 0) && "
        "object.spec.containers.size() == 1 && object.spec.containers.all(x, x.image.startsWith("+json.dumps(image_prefix)+") && x.image.matches('^.+@sha256:[0-9a-f]{64}$')) && "
        "object.spec.containers[0].image.startsWith("+json.dumps(image_prefix)+" + (object.metadata.name == 'probe-pull' ? 'pause@' : 'python@'))"+"))")
    add('cp-node-network-probe-'+e,['cp:'+e+':lifecycle-apply'],[rr('',['pods'],'Namespaced')],probe_expression)
    for res,names in c['bootstrap_cluster_objects'].items():
        names=names+[x['metadata']['name'] for x in rbac(c) if x['kind']=={'clusterroles':'ClusterRole','clusterrolebindings':'ClusterRoleBinding'}.get(res)]
        group='apiextensions.k8s.io' if res=='customresourcedefinitions' else 'rbac.authorization.k8s.io'
        add('cp-bootstrap-'+res+'-'+e,['cp:'+e+':gitops-bootstrap'],[rr(group,[res],'Cluster')],"(request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name) in "+json.dumps(names))
    return items+database_bootstrap_admission(c)

def terraform_identity(c):
    e=c['environment'];out=['# GENERATED by operations-access-proposal/access.py. Review in identity-admin only.\n']
    for role in ROLES:
        label=role.replace('-','_');name=('gha-infra-'+e+'-lifecycle-destroy') if role=='lifecycle-destroy' else ('cp-'+e+'-'+role);gates=['gitops-'+e+'-'+role.split('-')[1]] if role.startswith('gitops-') else (['incident-'+e+'-plan'] if role=='incident-plan' else ['incident-'+e+'-mutate','incident-'+e+'-destructive'])
        if role=='lifecycle-destroy':gates=['infra-'+e+'-destroy']
        subjects=', '.join('"${local.subject_prefix}:environment:'+g+'"' for g in gates)
        subject_value=subjects if len(gates)==1 else '['+subjects+']'
        out.append(f'''resource "aws_iam_role" "operations_{label}" {{
  name = "{name}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {{ Federated = local.provider_arn }}
      Condition = {{ StringEquals = {{
        "${{local.oidc_host}}:aud" = "sts.amazonaws.com"
        "${{local.oidc_host}}:sub" = {subject_value}
      }} }}
    }}]
  }})
  lifecycle {{ prevent_destroy = true }}
}}
''')
        for section in policies(c,role):
            out.append(f'''resource "aws_iam_policy" "operations_{label}_{section}" {{
  name = "cp-{e}-ci-{role}-{section}"
  policy = file("${{path.module}}/operations-policies/{role}-{section}.json")
}}
resource "aws_iam_role_policy_attachment" "operations_{label}_{section}" {{
  role = aws_iam_role.operations_{label}.name
  policy_arn = aws_iam_policy.operations_{label}_{section}.arn
}}
''')
    out.append('output \"operations_lifecycle_destroy_role_arn\" { value = aws_iam_role.operations_lifecycle_destroy.arn }\n')
    return '\n'.join(out)

def write(c,dest):
    c=validate(c);dest=pathlib.Path(dest);(dest/'identity'/'operations-policies').mkdir(parents=True,exist_ok=True)
    for role in ROLES:
        for section,rows in policies(c,role).items():
            document={'Version':'2012-10-17','Statement':rows}
            require(len(canonical(document))<=6144, 'AWS managed-policy size limit exceeded; split '+role+'/'+section)
            (dest/'identity'/'operations-policies'/(role+'-'+section+'.json')).write_text(json.dumps(document,indent=2)+'\n')
    if c['environment']=='dev':
        rows=aws_fixed_bridge(c);document={'Version':'2012-10-17','Statement':rows}
        require(len(canonical(document))<=6144,'AWS fixed bridge exceeds IAM policy size')
        (dest/'identity'/'operations-policies'/'aws-fixed-bridge.json').write_text(json.dumps(document,indent=2)+'\n')
        optional=dest/'optional-aws-fixed';optional.mkdir(exist_ok=True)
        (optional/'aws-fixed-bridge.generated.tf').write_text('''# Install only alongside original aws-fixed-operations.tf in Dev identity root.
resource "aws_iam_policy" "operations_aws_fixed_bridge" {
  name = "cp-dev-ci-aws-fixed-private-probes"
  policy = file("${path.module}/operations-policies/aws-fixed-bridge.json")
}
resource "aws_iam_role_policy_attachment" "operations_aws_fixed_bridge" {
  for_each = aws_iam_role.aws_ops
  role = each.value.name
  policy_arn = aws_iam_policy.operations_aws_fixed_bridge.arn
}
''')
    (dest/'registration.json').write_text(json.dumps(c,indent=2)+'\n')
    (dest/'identity'/'operations.generated.tf').write_text(terraform_identity(c))
    for name,items in [('rbac',rbac(c)),('admission',admission(c))]:
        (dest/(name+'.json')).write_text(json.dumps({'apiVersion':'v1','kind':'List','items':items},indent=2)+'\n')
    descriptor={'schema_version':1,'environment':c['environment'],'account_id':c['account_id'],'cluster_name':c['cluster_name'],'relay_id':c['relay_id'],'config_sha256':hashlib.sha256(canonical(c).encode()).hexdigest(),'files':{}}
    for f in sorted(dest.rglob('*')):
        if f.is_file() and f.name!='access-manifest.json':descriptor['files'][str(f.relative_to(dest))]=hashlib.sha256(f.read_bytes()).hexdigest()
    (dest/'access-manifest.json').write_text(json.dumps(descriptor,indent=2)+'\n')
    return descriptor

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    write(json.loads(pathlib.Path(a.config).read_text()),a.out)
