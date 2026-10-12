#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded first-controller bootstrap. Never used for normal platform updates."""
import argparse, json, os, re, subprocess, tempfile
from pathlib import Path
import yaml

IMAGE=re.compile(r'^ghcr\.io/[a-z0-9._-]+/platform-toolchain@sha256:[0-9a-f]{64}$')
REPO=re.compile(r'^git@github\.com:[A-Za-z0-9-]+/cloud-platform-infrastructure\.git$')

def output(command):return subprocess.check_output(command,text=True)
def execute(command,content=None):subprocess.run(command,input=content,text=True,check=True)

def preflight(a):
    if not IMAGE.fullmatch(a.toolchain_image):raise ValueError('toolchain image must be published immutable GHCR digest')
    if not REPO.fullmatch(a.repo_url):raise ValueError('target infrastructure repository SSH URL required')
    if not re.fullmatch('[0-9a-f]{40}',a.revision):raise ValueError('approved Git commit required')
    if output(['git','-C',str(a.repo),'rev-parse','HEAD']).strip()!=a.revision:raise ValueError('source HEAD differs from approved bootstrap revision')
    execute(['git','-C',str(a.repo),'diff','--exit-code']);execute(['git','-C',str(a.repo),'diff','--cached','--exit-code'])
    source='gitops/clusters/'+a.environment+'/platform-applications'
    if output(['git','-C',str(a.repo),'status','--porcelain','--untracked-files=all','--ignored=matching','--',source,'bootstrap/argocd']).strip():
        raise ValueError('bootstrap inputs contain unreviewed files')
    committed=output(['git','-C',str(a.repo),'ls-tree','-r','--name-only',a.revision,'--',source]).splitlines()
    if not committed:
        raise ValueError('platform Application source must exist in the approved commit')
    account=output(['aws','--profile',a.profile,'--region','ap-northeast-2','sts','get-caller-identity','--query','Account','--output','text']).strip()
    if account!=a.expect_account:raise ValueError('AWS execution account differs from target')
    endpoint=output(['aws','--profile',a.profile,'--region','ap-northeast-2','eks','describe-cluster','--name',a.cluster,'--query','cluster.endpoint','--output','text']).strip()
    config=json.loads(output(['kubectl','--context',a.context,'config','view','--minify','-o','json']))
    cluster=config['clusters'][0]['cluster']
    if cluster.get('server')!=endpoint or cluster.get('insecure-skip-tls-verify') or not (cluster.get('certificate-authority-data') or cluster.get('certificate-authority')):
        raise ValueError('Kubernetes context TLS endpoint differs from expected EKS cluster')
    execute(['kubectl','--context',a.context,'get','--raw=/readyz'])
    execute(['kubectl','--context',a.context,'wait','node','--all','--for=condition=Ready','--timeout=5m'])
    for kind,name in [('deployment','coredns'),('daemonset','eks-pod-identity-agent')]:
        execute(['kubectl','--context',a.context,'-n','kube-system','rollout','status',kind+'/'+name,'--timeout=5m'])
    if not (a.repo/'gitops/clusters'/a.environment/'platform-applications').is_dir():
        raise ValueError('platform Application source directory must be committed before bootstrap')
    if not a.ssh_private_key.is_file() or a.ssh_private_key.stat().st_mode & 0o077:
        raise ValueError('repository read-only deploy key requires local mode 600')

def configured_values(toolchain_image):
    root=Path(__file__).resolve().parent
    values=yaml.safe_load((root/'values.yaml').read_text())
    values['configs']['ssh']={'knownHosts':(root/'github-known-hosts').read_text()}
    values['repoServer'].update({
      'initContainers':[{'name':'pinned-renderers','image':toolchain_image,'command':['sh','-c','cp /usr/local/bin/helm /usr/local/bin/kustomize /custom-tools/'],'volumeMounts':[{'name':'custom-tools','mountPath':'/custom-tools'}],'resources':{'requests':{'cpu':'50m','memory':'64Mi'},'limits':{'memory':'128Mi'}}}],
      'volumes':[{'name':'custom-tools','emptyDir':{}}],
      'volumeMounts':[{'name':'custom-tools','mountPath':'/usr/local/bin/helm','subPath':'helm'},{'name':'custom-tools','mountPath':'/usr/local/bin/kustomize','subPath':'kustomize'}]})
    return values

def bootstrap(a):
    preflight(a)
    kubectl=['kubectl','--context',a.context]
    existing=subprocess.run(kubectl+['-n','argocd','get','secret','argocd-repo-gitops','--ignore-not-found','-o','name'],capture_output=True,text=True,check=True)
    if existing.stdout.strip():raise ValueError('repository Secret already exists; use reviewed takeover procedure instead of bootstrap')
    values=configured_values(a.toolchain_image)
    with tempfile.TemporaryDirectory() as work:
        p=Path(work)/'values.yaml';p.write_text(yaml.safe_dump(values,sort_keys=False))
        execute(['helm','--kube-context',a.context,'upgrade','--install','argocd','argo-cd','--repo','https://argoproj.github.io/argo-helm','--version','10.9.0','--namespace','argocd','--create-namespace','--values',str(p),'--wait','--timeout','15m'])
    # The private key stays in a protected local file. Serialized Secret is sent
    # directly to kubectl stdin; it is never printed or saved as an artifact.
    encoded=output(kubectl+['-n','argocd','create','secret','generic','argocd-repo-gitops','--from-literal=type=git','--from-literal=url='+a.repo_url,'--from-file=sshPrivateKey='+str(a.ssh_private_key),'--dry-run=client','-o','json'])
    secret=json.loads(encoded);secret['metadata']['labels']={'argocd.argoproj.io/secret-type':'repository'}
    execute(kubectl+['apply','--server-side','--field-manager=platform-bootstrap','-f','-'],json.dumps(secret))
    project={'apiVersion':'argoproj.io/v1alpha1','kind':'AppProject','metadata':{'name':'platform','namespace':'argocd'},'spec':{'sourceRepos':[a.repo_url,'https://argoproj.github.io/argo-helm','https://charts.jetstack.io','quay.io/jetstack/charts','https://istio-release.storage.googleapis.com/charts','https://aws.github.io/eks-charts','https://kubernetes-sigs.github.io/external-dns/','docker.io/envoyproxy','https://kubernetes-sigs.github.io/metrics-server/','https://kubernetes.github.io/autoscaler','https://charts.external-secrets.io','https://fluent.github.io/helm-charts','https://vmware-tanzu.github.io/helm-charts','https://prometheus-community.github.io/helm-charts','https://grafana.github.io/helm-charts','https://grafana-community.github.io/helm-charts','https://open-telemetry.github.io/opentelemetry-helm-charts','https://stakater.github.io/stakater-charts','https://kyverno.github.io/kyverno/','https://strimzi.io/charts/'], 'destinations':[{'server':'https://kubernetes.default.svc','namespace':'*'}],'clusterResourceWhitelist':[{'group':'*','kind':'*'}]}}
    app={'apiVersion':'argoproj.io/v1alpha1','kind':'Application','metadata':{'name':'platform-root-'+a.environment,'namespace':'argocd'},'spec':{'project':'platform','source':{'repoURL':a.repo_url,'targetRevision':'main','path':'gitops/clusters/'+a.environment+'/platform-applications','directory':{'recurse':False}},'destination':{'server':'https://kubernetes.default.svc','namespace':'argocd'},'syncPolicy':{'syncOptions':['FailOnSharedResource=true']}}}
    execute(kubectl+['apply','--server-side','--field-manager=platform-bootstrap','-f','-'],yaml.safe_dump_all([project,app],sort_keys=False))
    print('Minimal controller and root created. Review and sync the approved root revision, then gate each child by actual readiness.')

def main():
    p=argparse.ArgumentParser();p.add_argument('--environment',choices=['dev','prod'],required=True);p.add_argument('--profile',required=True);p.add_argument('--expect-account',required=True);p.add_argument('--context',required=True);p.add_argument('--cluster',required=True);p.add_argument('--repo',type=Path,default=Path('.'));p.add_argument('--repo-url',required=True);p.add_argument('--revision',required=True);p.add_argument('--toolchain-image',required=True);p.add_argument('--ssh-private-key',type=Path,required=True);a=p.parse_args()
    try:bootstrap(a)
    except (ValueError,KeyError,subprocess.CalledProcessError) as e:p.exit(2,'bootstrap stopped: '+str(e)+'\n')

if __name__=='__main__':main()
