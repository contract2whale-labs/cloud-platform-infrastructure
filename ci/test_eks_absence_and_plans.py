import copy,importlib.util,json,os,subprocess,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,file):
 s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
g=load('absence_guard','eks-lifecycle-guard.py');a=load('absence_adapter','eks-lifecycle.py')
class HardeningTests(unittest.TestCase):
 def setUp(self):
  self.ctx={'root':g.EKS,'account':'111111111111','backend':{'region':'ap-northeast-2'}}
  self.targets={'schema':1,'root':g.EKS,'account':'111111111111','region':'ap-northeast-2','asgs':['eks-owned'],'instances':['i-0123'],'volumes':['vol-0123'],'managed_cluster_sgs':['sg-0123']}
  self.original=[{'address':'module.component.aws_eks_cluster.this','type':'aws_eks_cluster','id':'lab'},{'address':'module.component.aws_eks_node_group.groups["system"]','type':'aws_eks_node_group','id':'lab:system'},{'address':'module.component.aws_iam_role.cluster','type':'aws_iam_role','id':'lab-cluster'}]
 def api(self,service,op,*args):
  if service=='sts':return {'Account':'111111111111'}
  if service=='eks':return {'__absence_error':'ResourceNotFoundException'}
  if service=='iam':return {'__absence_error':'NoSuchEntity'}
  return { {'describe-security-groups':'SecurityGroups','describe-auto-scaling-groups':'AutoScalingGroups','describe-instances':'Reservations','describe-volumes':'Volumes'}[op]:[]}
 def test_exact_absence(self):
  self.assertEqual(g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=self.api)['mode'],'exact-aws-absence')
 def test_wrong_account_never_assumes_missing(self):
  with self.assertRaises(g.SafeError):g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=lambda *args:{'Account':'222222222222'})
 def test_running_instance_fails(self):
  def api(s,o,*args):
   if o=='describe-instances':return {'Reservations':[{'OwnerId':'111111111111','Instances':[{'InstanceId':'i-0123','State':{'Name':'running'}}]}]}
   return self.api(s,o,*args)
  with self.assertRaises(g.SafeError):g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=api)
 def test_terminated_instance_allowed_tombstone(self):
  def api(s,o,*args):
   if o=='describe-instances':return {'Reservations':[{'OwnerId':'111111111111','Instances':[{'InstanceId':'i-0123','State':{'Name':'terminated'}}]}]}
   return self.api(s,o,*args)
  g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=api)
 def test_leftover_asg_sg_or_volume_fails(self):
  for target,field in [('describe-auto-scaling-groups','AutoScalingGroups'),('describe-security-groups','SecurityGroups'),('describe-volumes','Volumes')]:
   def api(s,o,*args):return {field:[{}]} if o==target else self.api(s,o,*args)
   with self.assertRaises(g.SafeError):g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=api)
 def test_incomplete_or_missing_list_fails(self):
  for value in ({},{'SecurityGroups':[],'NextToken':'more'}):
   def api(s,o,*args):return value if o=='describe-security-groups' else self.api(s,o,*args)
   with self.assertRaises(g.SafeError):g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=api)
 def test_child_wrong_cluster_fails(self):
  self.original[1]['id']='other:system'
  with self.assertRaises(g.SafeError):g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=self.api)
 def test_policy_association_hash_separator(self):
  self.original.append({'address':'module.component.aws_eks_access_policy_association.admin["x"]','type':'aws_eks_access_policy_association','id':'lab#arn:aws:iam::111111111111:role/admin#arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy'})
  g.verify_absent(self.ctx,self.original,absence_targets=self.targets,aws_call=self.api)
 def test_aws_denied_not_missing(self):
  error=subprocess.CompletedProcess([],255,b'',b'An error occurred (AccessDeniedException) when calling the DescribeCluster operation')
  with patch.object(g.subprocess,'run',return_value=error):
   with self.assertRaises(g.SafeError):g.absence_read('eks','describe-cluster','--name','lab')
 def test_exact_notfound_recognized(self):
  error=subprocess.CompletedProcess([],255,b'',b'An error occurred (ResourceNotFoundException) when calling the DescribeCluster operation')
  with patch.object(g.subprocess,'run',return_value=error):self.assertEqual(g.absence_read('eks','describe-cluster','--name','lab'),{'__absence_error':'ResourceNotFoundException'})
 def test_plan_rejects_incomplete_deferred_errored(self):
  a.ROOT=g.EKS
  for changes in ({'complete':False},{'errored':True},{'deferred_changes':[{}]},{'format_version':'2.0'}):
   with self.assertRaises(a.h.SafeError):a.validate_supported_plan({'format_version':'1.2',**changes},g)
 def test_up_rejects_forget_and_unknown(self):
  a.ROOT=g.EKS
  for actions in (['forget'],['delete'],['delete','create'],[],['import']):
   with self.assertRaises(a.h.SafeError):a.validate_up({'format_version':'1.2','resource_changes':[{'mode':'managed','type':'aws_eks_cluster','change':{'actions':actions}}]},g)
 def test_exact_up_completion(self):
  plan={'planned_values':{'root_module':{'resources':[{'mode':'managed','type':'terraform_data','address':'terraform_data.environment_boundary'}]}}}
  state={'version':4,'resources':[{'mode':'managed','type':'terraform_data','name':'environment_boundary','instances':[{'attributes':{'id':'a'}}]}]}
  a.validate_up_completion(plan,state,g)
  state['resources'].append({'mode':'managed','type':'aws_s3_bucket','name':'unexpected','instances':[{'attributes':{'id':'b'}}]})
  with self.assertRaises(a.h.SafeError):a.validate_up_completion(plan,state,g)
 def test_nodeless_bu06_needs_no_bootstrap_residual_receipt(self):
  with patch.dict(os.environ,{'COMPLETED_CHAPTER':'BU06'}),patch.object(g,'load') as loader:
   self.assertIsNone(g.authenticated_residual_contract({'operation':'down'}));loader.assert_not_called()
 def test_later_receipt_requires_central_authentication(self):
  ctx={**self.ctx,'operation':'down','backend':{'region':'ap-northeast-2','bucket':'private'}}
  gate=types.SimpleNamespace(h=types.SimpleNamespace(Store=lambda *args:object()))
  gate.for_consumer=lambda *args,**kwargs: (_ for _ in ()).throw(g.SafeError('untrusted CAS receipt'))
  with patch.dict(os.environ,{'COMPLETED_CHAPTER':'BU08','LIFECYCLE_BARRIER_RECEIPTS':'{}'}),patch.object(g,'load',return_value=gate):
   with self.assertRaisesRegex(g.SafeError,'untrusted CAS'):g.authenticated_residual_contract(ctx)
 def test_capture_exact_asg_instances_and_volumes(self):
  rows=[{'type':'aws_eks_cluster','values':{'name':'lab','arn':'arn:aws:eks:ap-northeast-2:111111111111:cluster/lab','vpc_config':[{'cluster_security_group_id':'sg-0123'}]}},{'type':'aws_eks_node_group','values':{'resources':[{'autoscaling_groups':[{'name':'eks-owned'}]}]}}]
  def api(s,o,*args):
   if o=='get-caller-identity':return {'Account':'111111111111'}
   if o=='describe-cluster':return {'cluster':{'arn':'arn:aws:eks:ap-northeast-2:111111111111:cluster/lab','resourcesVpcConfig':{'clusterSecurityGroupId':'sg-0123'}}}
   if o=='describe-auto-scaling-groups':return {'AutoScalingGroups':[{'AutoScalingGroupName':'eks-owned','AutoScalingGroupARN':'arn:aws:autoscaling:ap-northeast-2:111111111111:autoScalingGroup:a','Instances':[{'InstanceId':'i-0123'}]}]}
   return {'Reservations':[{'OwnerId':'111111111111','Instances':[{'InstanceId':'i-0123','RootDeviceName':'/dev/xvda','BlockDeviceMappings':[{'DeviceName':'/dev/xvda','Ebs':{'VolumeId':'vol-0123','DeleteOnTermination':True}}]}]}]}
  self.assertEqual(g.capture_absence_targets(self.ctx,rows,aws_call=api),self.targets)
 def test_empty_retry_needs_prior_targets_and_fresh_cloud_proof(self):
  raw={'version':4,'resources':[]};plan={'format_version':'1.2','planned_values':{},'resource_changes':[]}
  upstream={g.VPC:{'state':{'version':4,'resources':[]}}}
  with self.assertRaises(g.SafeError):g.guard_destroy('.',self.ctx,raw,plan,self.original,upstream)
  with patch.object(g,'verify_absent',return_value={'mode':'exact-aws-absence'}) as verify:
   evidence=g.guard_destroy('.',self.ctx,raw,plan,self.original,upstream,previous_absence_targets=self.targets)
   self.assertEqual(evidence['absence_targets'],self.targets);verify.assert_called_once()
 def test_markers(self):
  a.ROOT=g.EKS;self.assertEqual(a.marker_key('9'),'ci-lifecycle/9/dev/eks.json')
  a.ROOT=g.RELAY;self.assertEqual(a.marker_key('9'),'ci-lifecycle/9/dev/platform-private-api.json')
if __name__=='__main__':unittest.main()
