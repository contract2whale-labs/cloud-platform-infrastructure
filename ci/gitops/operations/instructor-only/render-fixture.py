#!/usr/bin/env python3
"""Render exactly the CI-authored fixture for review; never apply it locally."""
import argparse,json,os,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import incident_ops,fixture_ops
p=argparse.ArgumentParser();p.add_argument('--case',choices=('t3','t4','t5','t6'),required=True);p.add_argument('--image',required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
os.environ.setdefault('GITHUB_RUN_ID','review-only')
docs=fixture_ops.manifests(incident_ops.fixture_io(),{'fixture_image':a.image,'operator_image':a.image},{},a.case)
a.output.write_text(json.dumps({'apiVersion':'v1','kind':'List','items':docs},indent=2)+'\n')
print('Rendered review manifest only. Create/inject/restore/cleanup through protected CI.')
