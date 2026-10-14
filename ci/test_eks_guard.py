#!/usr/bin/env python3
import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('guard',HERE/'eks-lifecycle-guard.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

def baseline():
    inv={k:[] for k in ('namespaces','services','pods','deployments','daemonsets','replicasets','statefulsets','jobs','cronjobs','persistentvolumes','persistentvolumeclaims','ingresses','volumeattachments','customresourcedefinitions','secrets','configmaps','networkpolicies','mutatingwebhookconfigurations','validatingwebhookconfigurations')}
    inv['namespaces']=[{'metadata':{'name':x}} for x in ('default','kube-system','kube-public','kube-node-lease')]
    inv['services']=[{'metadata':{'namespace':'default','name':'kubernetes'},'spec':{'type':'ClusterIP'}}]
    return inv

class GuardTests(unittest.TestCase):
    def test_baseline(self):self.assertTrue(g.validate_inventory(baseline())['baseline_only'])
    def test_missing_inventory_fails(self):
        inv=baseline();del inv['persistentvolumes']
        with self.assertRaises(g.SafeError):g.validate_inventory(inv)
    def test_later_namespace_fails(self):
        inv=baseline();inv['namespaces'].append({'metadata':{'name':'argocd'}})
        with self.assertRaises(g.SafeError):g.validate_inventory(inv)
    def test_pv_and_unknown_crd_fail(self):
        for k in ('persistentvolumes','persistentvolumeclaims','ingresses','volumeattachments','customresourcedefinitions'):
            inv=baseline();inv[k]=[{'metadata':{'name':'unknown'}}]
            with self.assertRaises(g.SafeError):g.validate_inventory(inv)
    def test_unknown_service_fails(self):
        inv=baseline();inv['services'].append({'metadata':{'name':'app','namespace':'default'},'spec':{'type':'LoadBalancer'}})
        with self.assertRaises(g.SafeError):g.validate_inventory(inv)
    def test_owner_uid_required(self):
        inv=baseline();inv['pods']=[{'metadata':{'namespace':'kube-system','name':'aws-node-impostor','ownerReferences':[{'uid':'unseen'}]}}]
        with self.assertRaises(g.SafeError):g.validate_inventory(inv)
    def test_baseline_addon_owner(self):
        inv=baseline();inv['daemonsets']=[{'metadata':{'namespace':'kube-system','name':'aws-node','uid':'a'}}]
        inv['pods']=[{'metadata':{'namespace':'kube-system','name':'aws-node-xyz','ownerReferences':[{'uid':'a'}]}}]
        self.assertTrue(g.validate_inventory(inv)['baseline_only'])
    def test_s3_kms_ci_types_fail(self):
        context={'root':g.RELAY,'account':'111111111111'}
        for t in ('aws_s3_bucket','aws_s3_bucket_policy','aws_kms_key','aws_iam_openid_connect_provider','aws_iam_policy'):
            with self.assertRaises(g.SafeError):g.validate_rows(context,[{'type':t,'name':'relay','address':t+'.relay','values':{}}])
    def test_ci_role_misplaced_fails(self):
        with self.assertRaises(g.SafeError):g.validate_rows({'root':g.RELAY,'account':'111111111111'},[{'type':'aws_iam_role','name':'relay','address':'aws_iam_role.relay','values':{'name':'github-ci-apply'}}])
    def test_downstream_not_pinned(self):
        got=g.read_upstreams('.',{'root':g.RELAY,'account':'111111111111','backend':{'bucket':'b','region':'ap-northeast-2'}},load_state=lambda key:{'fingerprint':key,'state':None})
        self.assertEqual(set(got),{g.VPC})
    def test_module_boundary(self):
        with self.assertRaises(g.SafeError):g.validate_rows({'root':g.RELAY,'account':'111111111111'},[{'type':'aws_security_group','name':'relay','address':'module.other.aws_security_group.relay','values':{}}])
    def test_oidc_exact_cluster_binding(self):
        issuer='https://oidc.eks.ap-northeast-2.amazonaws.com/id/EXACT'
        cluster={'type':'aws_eks_cluster','name':'this','address':'module.component.aws_eks_cluster.this','values':{'id':'lab','name':'lab','deletion_protection':False,'vpc_config':[{'endpoint_public_access':False}],'identity':[{'oidc':[{'issuer':issuer}]}]}}
        oidc={'type':'aws_iam_openid_connect_provider','name':'cluster','address':'module.component.aws_iam_openid_connect_provider.cluster','values':{'id':'arn:aws:iam::111111111111:oidc-provider/'+issuer.removeprefix('https://'),'url':issuer,'arn':'arn:aws:iam::111111111111:oidc-provider/'+issuer.removeprefix('https://')}}
        ctx={'root':g.EKS,'account':'111111111111'};g.validate_rows(ctx,[cluster,oidc])
        oidc['values']['url']='https://token.actions.githubusercontent.com'
        with self.assertRaises(g.SafeError):g.validate_rows(ctx,[cluster,oidc])

if __name__=='__main__':unittest.main()
