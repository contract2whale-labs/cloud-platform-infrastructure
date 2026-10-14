#!/usr/bin/env python3
import json, os, re
from pathlib import Path
import gitops_ops as ops
cfg = json.loads((Path(__file__).parent/'operations.json').read_text())
try:
    ops.require(cfg.get('enabled') is True, 'Activation required')
    image = cfg['operator_image']
    ops.require(re.fullmatch(r'ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}', image), 'Immutable operator image required')
    if os.environ['EVENT'] == 'push':
        rows = [(e, 'reconcile') for e in ('dev','prod') if e in cfg['environments']]
    else:
        rows = [(os.environ['TARGET'], os.environ['OPERATION'])]
        ops.require(rows[0][1]=='verify','Bootstrap must use protected gitops-access-bootstrap.yml; ordinary workflow cannot create its own access')
    ops.require(rows, 'No environments registered')
    matrix=[]
    for env, op in rows:
        ops.load(env, op)
        matrix.append({'environment': env, 'operation': op, 'gate': f'gitops-{env}-'+('bootstrap' if op=='bootstrap' else 'apply')})
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.write('matrix='+json.dumps({'include':matrix})+'\nimage='+image+'\n')
except Exception:
    raise SystemExit('GitOps prerequisites incomplete; no AWS credentials requested.')
