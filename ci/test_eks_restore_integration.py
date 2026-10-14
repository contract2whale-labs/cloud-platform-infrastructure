import copy
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

g=load('eks_integration_guard','eks-lifecycle-guard.py')
a=load('eks_integration_adapter','eks-lifecycle.py')
p=load('eks_integration_probes','eks-network-probes.py')
w=load('eks_probe_wrapper','eks-probe-lifecycle.py')
i=load('eks_initial_wrapper','initial-eks-network-probes.py')
ACCOUNT='111111111111'

def context(env='dev'):
    return {'root':f'terraform/environments/{env}/eks','environment':env,'account':ACCOUNT,'backend':{'region':'ap-northeast-2','bucket':'private'},'operation':'up'}

def cluster():
    return {'name':'owned','id':'owned','arn':f'arn:aws:eks:ap-northeast-2:{ACCOUNT}:cluster/owned','created_at':'2026-10-13T00:00:00Z','deletion_protection':False,'endpoint':'https://owned.eks.amazonaws.com','certificate_authority':[{'data':'CA'}],'vpc_config':[{'vpc_id':'vpc-123','endpoint_public_access':False,'cluster_security_group_id':'sg-123'}]}

def entry(ctx,kind,index):
    principal,group=g.access_identities(ctx)[kind][index]
    return {'type':'aws_eks_access_entry','name':kind,'address':f'module.component.aws_eks_access_entry.{kind}["{index}"]','values':{'id':'owned:'+principal,'principal_arn':principal,'cluster_name':'owned','type':'STANDARD','kubernetes_groups':[group]}}

class RestoreIntegration(unittest.TestCase):
    def test_prod_roots_markers_state_and_upstreams(self):
        ctx=context('prod');a.ROOT=ctx['root']
        self.assertEqual(a.marker_key('7'),'ci-lifecycle/7/prod/eks.json')
        rows=g.read_upstreams('.',ctx,load_state=lambda key:{'fingerprint':key,'state':{}})
        self.assertEqual(set(rows),{'terraform/environments/prod/network/vpc','terraform/environments/prod/platform/private-api'})
        self.assertEqual(g.key(ctx['root']),'eks/terraform.tfstate')
    def test_prod_configure_exact_engine(self):
        ctx=context('prod');env={'ROOT_PATH':ctx['root'],'LIFECYCLE_ENVIRONMENT':'prod','LIFECYCLE_ENGINE':'prod-eks-v1','LIFECYCLE_CONFIG_SHA256':'a'*64,'LIFECYCLE_SELECTED_ROOTS':json.dumps([ctx['root']]),'LIFECYCLE_SNAPSHOT_SHA':'b'*40,'LIFECYCLE_GENERATION':'1-1','COMPLETED_CHAPTER':'BU16'}
        with patch.dict(os.environ,env,clear=True):self.assertEqual(a.configure(),[ctx['root']])
        for bad in ({'LIFECYCLE_ENGINE':'dev-eks-v1'},{'LIFECYCLE_ENVIRONMENT':'dev'},{'COMPLETED_CHAPTER':'BU07'},{'LIFECYCLE_SELECTED_ROOTS':json.dumps([ctx['root'],'terraform/environments/dev/eks'])}):
            with patch.dict(os.environ,{**env,**bad},clear=True),self.assertRaises(a.h.SafeError):a.configure()
    def test_operations_lifecycle_exact_entries(self):
        for env in ('dev','prod'):
            ctx=context(env)
            for kind,identities in g.access_identities(ctx).items():
                for index in identities:
                    row=entry(ctx,kind,index);g.validate_access_row(ctx,row,cluster())
                    for field,value in [('principal_arn',f'arn:aws:iam::{ACCOUNT}:role/admin'),('kubernetes_groups',['system:masters']),('cluster_name','foreign'),('type','EC2_LINUX')]:
                        bad=copy.deepcopy(row);bad['values'][field]=value
                        with self.assertRaises(g.SafeError):g.validate_access_row(ctx,bad,cluster())
    def test_bootstrap_cluster_admin_never_ordinary_apply(self):
        ctx=context('prod');principal=g.access_identities(ctx)['operations']['gitops-bootstrap'][0]
        row={'type':'aws_eks_access_policy_association','name':'operations_bootstrap','address':'module.component.aws_eks_access_policy_association.operations_bootstrap','values':{'cluster_name':'owned','principal_arn':principal,'policy_arn':'arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy','access_scope':[{'type':'cluster','namespaces':[]}]}}
        g.validate_access_row(ctx,row,cluster())
        for principal in (g.access_identities(ctx)['lifecycle']['apply'][0],g.access_identities(ctx)['operations']['gitops-apply'][0]):
            bad=copy.deepcopy(row);bad['values']['principal_arn']=principal
            with self.assertRaises(g.SafeError):g.validate_access_row(ctx,bad,cluster())
    def test_prod_cannot_gain_dev_aws_fixed_entry(self):
        with self.assertRaises(g.SafeError):g.validate_access_row(context('prod'),entry(context(),'aws_fixed','apply'),cluster())
    def test_down_inventory_refuses_ordinary_apply_before_any_api(self):
        ctx={**context(),'operation':'down'}
        with patch.dict(os.environ,{'AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-dev-apply'}),patch.object(g.p,'aws') as aws:
            with self.assertRaisesRegex(g.SafeError,'dedicated lifecycle-destroy'):g.live_guard(ctx,[],{})
            aws.assert_not_called()
    def test_up_cannot_call_global_inventory_even_destroy_role(self):
        with patch.dict(os.environ,{'AWS_ROLE_ARN':f'arn:aws:iam::{ACCOUNT}:role/gha-infra-dev-lifecycle-destroy'}),patch.object(g.p,'aws') as aws:
            with self.assertRaisesRegex(g.SafeError,'Down-only'):g.live_guard(context(),[],{})
            aws.assert_not_called()
    def test_aws_only_fresh_cluster_readiness_never_kubectl(self):
        ctx=context('prod');values=cluster();row={'type':'aws_eks_cluster','values':values}
        live={'name':'owned','arn':values['arn'],'createdAt':values['created_at'],'status':'ACTIVE','endpoint':values['endpoint'],'certificateAuthority':{'data':'CA'},'resourcesVpcConfig':{'vpcId':'vpc-123','endpointPrivateAccess':True,'endpointPublicAccess':False,'clusterSecurityGroupId':'sg-123'}}
        upstream={'terraform/environments/prod/network/vpc':{'state':{'outputs':{'vpc_id':{'value':'vpc-123'}}}}}
        with patch.object(g,'validate_state',return_value=[row]),patch.object(g.p,'aws',return_value={'cluster':live}),patch.object(g.p,'command') as kubectl,patch.object(g,'live_guard') as global_guard:
            self.assertEqual(g.after_up(ctx,{},upstream)['mode'],'exact-aws-readiness');kubectl.assert_not_called();global_guard.assert_not_called()
            live['createdAt']='2026-10-12T00:00:00Z'
            with self.assertRaises(g.SafeError):g.after_up(ctx,{},upstream)
    def test_source_capability_requires_exact_access_fragment(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);root=base/context()['root'];root.mkdir(parents=True);(root/'main.tf').write_text('module "component" {\n source = "../../../../modules/eks"\n}')
            module=base/'modules/eks';module.mkdir(parents=True)
            with self.assertRaises(g.SafeError):g.source_capability(base,context(),'BU16')
            fragment=(HERE/'eks-operations-access.tf').read_bytes();(module/'eks-access.tf').write_bytes(fragment)
            self.assertTrue(g.source_capability(base,context(),'BU16')['operations_access'])
            (module/'eks-access.tf').write_bytes(fragment+b'\n')
            with self.assertRaises(g.SafeError):g.source_capability(base,context(),'BU16')
    def test_probe_cleanup_only_named_uid_owned_pod(self):
        calls=[]
        with patch.object(p,'get',return_value={'metadata':{'uid':'owned'}}),patch.object(p,'command',side_effect=lambda args,env,body=None:calls.append((args,body)) or b''):
            p.delete_owned_pod({},'course-node-probes','probe-net','owned')
        self.assertEqual(calls[0][1]['preconditions'],{'uid':'owned'})
        self.assertIn('/api/v1/namespaces/course-node-probes/pods/probe-net',calls[0][0])
        for namespace,name in [('other','probe-net'),('course-node-probes','foreign')]:
            with self.assertRaises(p.p.GuardError):p.delete_owned_pod({},namespace,name,'owned')
    def test_probe_staged_manifest_and_no_replay(self):
        ctx={'operation':'up'};manifest={'schema':1,'kind':'gitops-lifecycle','context':ctx,'control':{'version':'1'},'binding':{'eks':'1'},'created_at':100,'expires_at':100+w.h.TTL_SECONDS}
        w.validate_manifest(manifest,ctx,{'version':'1'},{'eks':'1'},101)
        for control,binding,now in [({'version':'2'},{'eks':'1'},101),({'version':'1'},{'eks':'2'},101),({'version':'1'},{'eks':'1'},100+w.h.TTL_SECONDS)]:
            with self.assertRaises(w.h.SafeError):w.validate_manifest(manifest,ctx,control,binding,now)
    def test_installer_residual_metadata_and_receipt_identity(self):
        baseline=load('probe_residual_baseline','test_eks_guard.py').baseline()
        obj={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':'cp-node-probe','uid':'owned','labels':{'owner':'bootstrap'}},'rules':[]}
        baseline['clusterroles']=[obj]
        metadata={k:obj['metadata'].get(k) for k in ('labels','annotations','finalizers','ownerReferences')}
        row={'resource':'clusterroles','namespace':'','name':'cp-node-probe','uid':'owned','spec_sha256':g.residual_spec_hash(obj),'metadata_policy_sha256':hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        ctx={'source_sha':'a'*40,'generation':'1-1'};live={'arn':'arn:cluster','createdAt':'now'}
        contract={'schema_version':1,'cluster_arn':live['arn'],'cluster_created_at':live['createdAt'],**ctx,'approved_residuals':[row]}
        self.assertTrue(g.validate_residual_inventory(baseline,contract,ctx,live))
        obj['metadata']['labels']['owner']='other'
        with self.assertRaises(g.SafeError):g.validate_residual_inventory(baseline,contract,ctx,live)
        del row['metadata_policy_sha256']
        with self.assertRaises(g.SafeError):g.validate_residual_inventory(baseline,contract,ctx,live)
    def test_probe_wrapper_down_claims_once_and_never_runs_mutation(self):
        fixtures=load('probe_store_fixture','test_vpc_lifecycle.py')
        store=fixtures.Store()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);out=path/'out';out.write_text('')
            ctx={'step_id':w.STEP,'snapshot_sha':'a'*40,'generation':'1-1','probe_inputs':{'probe_image':'p','pause_image':'q'},'probe_policy_sha256':'b'*64,'source_capability':{'operations_access':True},'registration_sha256':'c'*64,'operation':'down','prefix':'ci-plans/1/2/1/sha/dev/hooks/node-network-probes/lifecycle-down/'}
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(out)},clear=True),patch.object(w,'settings',return_value=(path,{},store,'marker',ctx)),patch.object(w,'binding',return_value={'eks':'one'}),patch.object(w.h,'ensure_current_main'),patch.object(w.p,'run_probe_completion') as mutate:
                w.run('start');w.run('plan')
                emitted=dict(line.split('=',1) for line in out.read_text().splitlines())
                os.environ.update(MANIFEST_KEY=emitted['manifest_key'],MANIFEST_VERSION=emitted['manifest_version'],EXPECTED_MANIFEST_SHA=emitted['manifest_sha'],EXPECTED_PLAN_SHA=emitted['plan_sha'])
                w.run('verify');w.run('apply');mutate.assert_not_called()
                record,_=w.c.read_json(store,'marker')
                self.assertEqual(record['last_result'],'down-complete');self.assertIn('claimed_manifest',record)
                with self.assertRaises(w.h.SafeError):w.run('apply')

    def test_initial_cannot_run_from_local_shell(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'},clear=True),patch.object(i.h,'aws') as aws:
            with self.assertRaises(i.h.SafeError):i.settings()
            aws.assert_not_called()

if __name__=='__main__':unittest.main()
