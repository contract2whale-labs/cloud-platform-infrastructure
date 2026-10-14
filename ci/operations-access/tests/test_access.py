import copy, fnmatch, hashlib, importlib.util, json, pathlib, tempfile, unittest
BASE=pathlib.Path(__file__).resolve().parents[1]
def load(name,file):
 s=importlib.util.spec_from_file_location(name,file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
access=load('access',BASE/'access.py');receipt=load('receipt',BASE/'bootstrap_receipt.py')
C=json.loads((BASE/'examples/dev.json').read_text())

def allows(items,group,verb,api,resource,namespace=None,name=''):
 by={(x['kind'],x['metadata'].get('namespace'),x['metadata']['name']):x for x in items if x['kind'] in ('Role','ClusterRole')}
 for binding in items:
  if binding['kind'] not in ('RoleBinding','ClusterRoleBinding'):continue
  ns=binding['metadata'].get('namespace')
  if ns is not None and ns!=namespace:continue
  if not any(s['name']==group for s in binding['subjects']):continue
  ref=binding['roleRef'];obj=by[(ref['kind'],ns if ref['kind']=='Role' else None,ref['name'])]
  for r in obj['rules']:
   if ('*' in r.get('apiGroups',[]) or api in r.get('apiGroups',[])) and ('*' in r.get('resources',[]) or resource in r.get('resources',[])) and ('*' in r['verbs'] or verb in r['verbs']) and ('resourceNames' not in r or name in r['resourceNames']):return True
 return False

class AccessTests(unittest.TestCase):
 def test_compilation_is_deterministic_and_under_quota(self):
  with tempfile.TemporaryDirectory() as d:
   a=access.write(C,d);b=access.write(C,d);self.assertEqual(a,b)
   self.assertEqual(len(list(pathlib.Path(d,'identity','operations-policies').glob('*.json'))),12)
   for p in pathlib.Path(d,'identity','operations-policies').glob('*.json'):self.assertLessEqual(len(access.canonical(json.loads(p.read_text()))),6144)
 def test_exact_account_and_arn_validation(self):
  for field,value in [('account_id','*'),('relay_id','i-*'),('ecr_arns',['arn:aws:ecr:ap-northeast-2:999999999999:repository/x']),('state_keys',['*'])]:
   c=copy.deepcopy(C);c[field]=value
   with self.assertRaises(ValueError):access.validate(c)
 def test_no_normal_iam_or_access_self_edit(self):
  for role in access.ROLES[:-1]:
   rows=access.policies(C,role)['transport'];deny=next(x for x in rows if x['Sid']=='NoIdentityOrAccessSelfEdit')
   self.assertEqual(deny['Effect'],'Deny');self.assertIn('iam:*',deny['Action']);self.assertIn('eks:AssociateAccessPolicy',deny['Action'])
 def test_transport_recreated_relay_is_tag_bounded(self):
  rows=access.policies(C,'incident-plan')['transport'];rule=next(x for x in rows if x['Sid']=='StartOnlyPrivateRelay')
  self.assertEqual(rule['Resource'],['arn:aws:ec2:ap-northeast-2:111111111111:instance/*'])
  self.assertEqual(rule['Condition']['StringEquals']['ssm:resourceTag/Name'],'cp-dev-private-api-relay')
  self.assertEqual(len(rule['Condition']['StringEquals']),4)
  doc=next(x for x in rows if x['Sid']=='OnlyPortForwardDocument');self.assertTrue(doc['Resource'][0].endswith('::document/AWS-StartPortForwardingSession'))
 def test_plan_cannot_perform_cloud_operations(self):
  rows=access.policies(C,'incident-plan')['cloud'];actions={a for x in rows if x['Effect']=='Allow' for a in x['Action']}
  self.assertFalse(actions & {'ecr:BatchDeleteImage','rds:ModifyDBInstance','secretsmanager:CreateSecret','secretsmanager:GetSecretValue','kafka:BatchAssociateScramSecret'})
 def test_apply_has_actual_operations_not_registration_only(self):
  rows=access.policies(C,'incident-apply')['cloud'];actions={a for x in rows if x['Effect']=='Allow' for a in x['Action']}
  self.assertTrue({'ecr:BatchDeleteImage','secretsmanager:CreateSecret','kafka:BatchAssociateScramSecret','secretsmanager:GetSecretValue'}<=actions)
  recovery=next(x for x in rows if x['Sid']=='RecoverOnlyOriginalTemporaryCredential');self.assertEqual(recovery['Condition']['StringEquals']['secretsmanager:VersionId'],'${aws:ResourceTag/platform-queue-run}')
  deletion=next(x for x in rows if x['Sid']=='ScheduleRecoverableQueueSecretDeletion');self.assertEqual(deletion['Condition']['NumericGreaterThanEquals']['secretsmanager:RecoveryWindowInDays'],7)
 def test_normal_gitops_has_only_argo_namespace(self):
  items=access.rbac(C);g='cp:dev:gitops-apply'
  self.assertTrue(allows(items,g,'patch','argoproj.io','applications','argocd','commerce-api-dev'))
  self.assertFalse(allows(items,g,'patch','argoproj.io','applications','argocd','unreviewed'))
  for ns in ('argocd','monitoring','contract2whale-demo',None):self.assertFalse(allows(items,g,'list','','secrets',ns))
  self.assertFalse(allows(items,g,'patch','','nodes',None,'node'))
  self.assertTrue(allows(items,g,'create','','pods/portforward','argocd','argocd-server-123'))
 def test_plan_has_no_kubernetes_mutating_verbs(self):
  items=access.rbac(C)
  for ns in access.NAMESPACES+[None]:
   for res,api in [('pods/exec',''),('deployments','apps'),('nodes',''),('applications','argoproj.io'),('pods',''),('jobs','batch')]:
    for verb in access.MUTATE:self.assertFalse(allows(items,'cp:dev:incident-plan',verb,api,res,ns,'writer'))
 def test_incident_namespaces_and_names_are_bounded(self):
  items=access.rbac(C);g='cp:dev:incident-apply'
  self.assertTrue(allows(items,g,'patch','argoproj.io','rollouts','contract2whale-demo','commerce-web'))
  self.assertFalse(allows(items,g,'patch','argoproj.io','rollouts','contract2whale-demo','other'))
  self.assertTrue(allows(items,g,'create','batch','jobs','contract2whale-demo','database-bootstrap-UUID'))
  self.assertFalse(allows(items,g,'create','batch','jobs','kube-system','x'))
  self.assertFalse(allows(items,g,'delete','','namespaces',None,'incident-fixture-t3'))
 def test_only_dedicated_destroy_has_global_secret_inventory(self):
  items=access.rbac(C)
  for role in ('gitops-apply','incident-plan','incident-apply','lifecycle-plan','lifecycle-apply'):
   self.assertFalse(allows(items,'cp:dev:'+role,'list','','secrets'))
  self.assertTrue(allows(items,'cp:dev:lifecycle-destroy','list','','secrets'))
  self.assertFalse(allows(items,'cp:dev:lifecycle-destroy','delete','','secrets','kube-system','x'))
 def test_disposable_lab_does_not_read_secret_values(self):
  c=copy.deepcopy(C);c['environment']='prod';items=access.rbac(c)
  self.assertFalse(allows(items,'cp:prod:incident-plan','list','','secrets','backup-probe'))
  self.assertFalse(allows(items,'cp:prod:incident-plan','list','','secrets','monitoring'))
  self.assertFalse(allows(items,'cp:prod:incident-plan','create','','pods/exec','backup-probe','writer'))
 def test_fixture_namespaces_preprovisioned_and_restricted(self):
  items=access.rbac(C)
  for ns in access.FIXTURES:
   obj=next(x for x in items if x['kind']=='Namespace' and x['metadata']['name']==ns)
   self.assertEqual(obj['metadata']['labels']['pod-security.kubernetes.io/enforce'],'restricted')
   self.assertTrue(allows(items,'cp:dev:incident-apply','create','apps','deployments',ns,'fixture'))
 def test_admission_covers_dynamic_rbac_create_gap(self):
  policies=[x for x in access.admission(C) if x['kind']=='ValidatingAdmissionPolicy']
  self.assertEqual(len(policies),7)
  for p in policies:self.assertEqual(p['spec']['failurePolicy'],'Fail')
  p=next(p for p in policies if 'clusterroles' in p['metadata']['name'])
  self.assertIn('cp-destruction-inventory-dev',p['spec']['validations'][0]['expression'])
 def test_destroy_trust_single_exact_environment(self):
  tf=access.terraform_identity(C);part=tf.split('resource "aws_iam_role" "operations_lifecycle_destroy"')[1].split('resource "aws_iam_policy"')[0]
  self.assertIn('name = "gha-infra-dev-lifecycle-destroy"',part)
  self.assertIn('"${local.oidc_host}:sub" = "${local.subject_prefix}:environment:infra-dev-destroy"',part)
  self.assertNotIn('incident-',part)
 def test_bootstrap_is_the_only_persistent_eks_admin(self):
  tf=(BASE/'terraform'/'eks-access.tf').read_text()
  self.assertEqual(tf.count('AmazonEKSClusterAdminPolicy'),1)
  association=tf.split('resource "aws_eks_access_policy_association" "operations_bootstrap"')[1].split('output ')[0]
  self.assertIn('operations["gitops-bootstrap"].principal_arn',association)
  self.assertNotIn('install_window',tf)
 def test_no_unhandled_policy_creation_under_destroy_role(self):
  rows=access.policies(C,'lifecycle-destroy')['transport'];deny=next(x for x in rows if x['Sid']=='NoIdentitySelfEdit')
  self.assertNotIn('arn:aws:iam::111111111111:role/cp-dev-*',deny['Resource'])
  self.assertIn('arn:aws:iam::111111111111:role/gha-infra-dev-lifecycle-destroy',deny['Resource'])
 def test_required_handler_cloud_actions_and_private_prefixes(self):
  apply=access.policies(C,'incident-apply');plan=access.policies(C,'incident-plan')
  actions={a for row in apply['cloud'] if row['Effect']=='Allow' for a in row['Action']}
  self.assertIn('ec2:ModifyVpcEndpoint',actions)
  endpoint=next(row for row in apply['cloud'] if row['Sid']=='RecoverExactS3EndpointPolicy')
  self.assertEqual(endpoint['Resource'],C['s3_gateway_endpoint_arns'])
  self.assertFalse(any('ec2:ModifyVpcEndpoint' in row['Action'] and row['Effect']=='Allow' for row in plan['cloud']))
  p=next(row for row in plan['evidence'] if row['Sid']=='WritePlan')
  a=next(row for row in apply['evidence'] if row['Sid']=='WriteCompletion')
  self.assertIn('/ci-plans/12345678/',p['Resource'][0]);self.assertIn('/ci-logs/12345678/',a['Resource'][0]);self.assertTrue(a['Resource'][0].endswith('/apply/*'))
 def test_prod_policy_does_not_get_dev_cloud_operations(self):
  c=copy.deepcopy(C);c['environment']='prod'
  rows=access.policies(c,'incident-apply')['cloud'];actions={a for row in rows if row['Effect']=='Allow' for a in row['Action']}
  self.assertIn('rds:ModifyDBInstance',actions)
  self.assertFalse(actions & {'ec2:ModifyVpcEndpoint','ecr:BatchDeleteImage'})
 def test_portforward_is_transport_not_plan_workload_exec(self):
  items=access.rbac(C)
  self.assertTrue(allows(items,'cp:dev:incident-plan','create','','pods/portforward','argocd','server'))
  self.assertFalse(allows(items,'cp:dev:incident-plan','create','','pods/exec','argocd','server'))
 def test_node_network_probe_is_scoped_and_namespace_retained(self):
  items=access.rbac(C);g='cp:dev:lifecycle-apply'
  self.assertTrue(allows(items,g,'create','','pods','course-node-probes','probe-net'))
  self.assertTrue(allows(items,g,'create','','pods/exec','course-node-probes','probe-net'))
  self.assertFalse(allows(items,g,'create','','pods/exec','course-node-probes','other'))
  self.assertFalse(allows(items,g,'create','','pods','kube-system','probe-net'))
  self.assertFalse(allows(items,g,'delete','','namespaces',None,'course-node-probes'))
  self.assertFalse(allows(items,g,'list','','secrets','course-node-probes'))
  policies=[x for x in access.admission(C) if x['kind']=='ValidatingAdmissionPolicy']
  expr=next(x for x in policies if x['metadata']['name']=='cp-node-network-probe-dev')['spec']['validations'][0]['expression']
  self.assertIn('course-bu07-',expr);self.assertIn('automountServiceAccountToken == false',expr);self.assertIn('hostNetwork',expr)
 def test_aws_fixed_bridge_preserves_target_iam_operation(self):
  rows=access.aws_fixed_bridge(C)
  self.assertFalse(any(x['Effect']=='Deny' and 'iam:*' in x['Action'] and x['Resource']==['*'] for x in rows))
  self.assertTrue(any('eks:DescribeCluster' in x['Action'] for x in rows))
  self.assertFalse(any(x['Effect']=='Allow' and any(a.startswith('iam:') for a in x['Action']) for x in rows))
 def test_aws_fixed_probe_roles_are_only_observability(self):
  items=access.rbac(C)
  self.assertTrue(allows(items,'cp:dev:aws-fixed-apply','create','','pods','observability','aws-trace-fault-send-id'))
  self.assertFalse(allows(items,'cp:dev:aws-fixed-plan','create','','pods','observability','aws-trace-fault-send-id'))
  self.assertFalse(allows(items,'cp:dev:aws-fixed-apply','create','','pods','monitoring','x'))
  self.assertFalse(allows(items,'cp:dev:aws-fixed-apply','create','','pods/exec','observability','x'))
  self.assertFalse(allows(items,'cp:dev:aws-fixed-apply','list','','secrets','observability'))
 def test_canonical_helper_copy(self):self.assertEqual((BASE/'bootstrap_receipt.py').read_bytes(),(BASE.parent/'operations-access.py').read_bytes())
 def test_proof_key_binds_cluster_incarnation(self):
  self.assertNotEqual(receipt.key_for('dev','arn','time1'),receipt.key_for('dev','arn','time2'))

class ReceiptTests(unittest.TestCase):
 def c(self):return {'environment':'dev','account_id':'111111111111','cluster_arn':'arn','cluster_created_at':'time','bootstrap_chart_sha256':'chart','operations_access_config_sha256':'config','operator_image':'image@sha256:123','tool_sha256':{'kubectl':'hash'}}
 def proof(self,c):return {'schema_version':1,'environment':c['environment'],'account_id':c['account_id'],'cluster_arn':c['cluster_arn'],'cluster_created_at':c['cluster_created_at'],'complete':True,'access_config_sha256':'config','chart_sha256':'chart','toolchain_sha256':hashlib.sha256(access.canonical({'operator_image':c['operator_image'],'tool_sha256':c['tool_sha256']}).encode()).hexdigest(),'lifecycle_generation':'1-1'}
 def store(self,raw):
  class Store:
   def state(self,key):return {'exists':True,'version':'v1'}
   def call(self,op,*args):pathlib.Path(args[-1]).write_bytes(raw);return {'VersionId':'v1','ServerSideEncryption':'aws:kms'}
  return Store()
 def test_hash_is_exact_stored_bytes(self):
  c=self.c();raw=json.dumps(self.proof(c),indent=4).encode();result=receipt.verify_bootstrap_receipt(c,self.store(raw),generation='1-1')
  self.assertEqual(result['sha256'],hashlib.sha256(raw).hexdigest())
 def test_wrong_incarnation_digest_and_generation_rejected(self):
  c=self.c();base=self.proof(c)
  for field,value in [('cluster_created_at','old'),('access_config_sha256','old'),('chart_sha256','old'),('toolchain_sha256','old'),('lifecycle_generation','old')]:
   proof=dict(base,**{field:value})
   with self.assertRaises(RuntimeError):receipt.verify_bootstrap_receipt(c,self.store(json.dumps(proof).encode()),generation='1-1')

if __name__=='__main__':unittest.main()
