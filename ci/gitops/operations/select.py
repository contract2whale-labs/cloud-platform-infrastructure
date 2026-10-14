#!/usr/bin/env python3
import json, os, pathlib, re, sys
from incident_ops import OPERATION_IDS, PLATFORM_PROD_IDS, BOOTSTRAP_IDS, VELERO_IDS, QUEUE_IDS, RDS_PROTECTION_IDS, ARGO_PROD_IDS, gate_name, request_live
base=pathlib.Path(__file__).resolve().parent
try:
    env=os.environ['TARGET'];op=os.environ['OPERATION'];assert env in ('dev','prod') and op in OPERATION_IDS
    assert env=='dev' or op in ('ecr-cleanup',)+PLATFORM_PROD_IDS+BOOTSTRAP_IDS+VELERO_IDS+QUEUE_IDS+RDS_PROTECTION_IDS+ARGO_PROD_IDS
    cfg=json.loads((base.parent/'operations.json').read_text());assert cfg['enabled'] is True
    request=json.loads((base/'requests.json').read_text())['environments'][env][op];request_live(request)
    image=cfg['operator_image'];assert re.fullmatch(r'ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}',image)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('image='+image+'\ngate='+gate_name(env,op)+'\n')
except Exception:raise SystemExit('Incident request/activation incomplete; no credentials requested.')
