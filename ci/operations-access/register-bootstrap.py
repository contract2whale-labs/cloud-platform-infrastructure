#!/usr/bin/env python3
"""Offline registration of the exact pinned Helm render's cluster object names.

Input render may contain credentials: keep it in a private temporary directory.
Only names and SHA-256 fingerprints are written to the reviewed registration.
"""
import argparse, hashlib, json, pathlib
import yaml

def main():
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--chart',required=True);p.add_argument('--rendered',required=True);p.add_argument('--source-sha',required=True);p.add_argument('--out',required=True);a=p.parse_args()
 c=json.loads(pathlib.Path(a.config).read_text());chart=pathlib.Path(a.chart).read_bytes();raw=pathlib.Path(a.rendered).read_bytes()
 result={'customresourcedefinitions':[],'clusterroles':[],'clusterrolebindings':[]};mapping={'CustomResourceDefinition':'customresourcedefinitions','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings'}
 for obj in yaml.safe_load_all(raw):
  if not obj:continue
  kind=obj['kind'];md=obj['metadata']
  if kind in mapping:result[mapping[kind]].append(md['name'])
  elif kind=='Namespace':
   if md['name']!='argocd':raise ValueError('Unreviewed chart namespace')
  elif md.get('namespace','argocd')!='argocd':raise ValueError('Chart escapes Argo namespace')
  elif kind not in ('ConfigMap','Secret','ServiceAccount','Service','Pod','Deployment','StatefulSet','ReplicaSet','Job','Role','RoleBinding','NetworkPolicy','PodDisruptionBudget'):raise ValueError('Unreviewed chart kind '+kind)
 c.update(bootstrap_cluster_objects={k:sorted(v) for k,v in result.items()},bootstrap_chart_sha256=hashlib.sha256(chart).hexdigest(),bootstrap_render_sha256=hashlib.sha256(raw).hexdigest(),reviewed_source_sha=a.source_sha)
 pathlib.Path(a.out).write_text(json.dumps(c,indent=2)+'\n')
if __name__=='__main__':main()
