import json,os,re
from pathlib import Path
cfg=json.loads((Path(__file__).resolve().parents[1]/'gitops/operations.json').read_text())
image=cfg.get('operator_image','')
if cfg.get('enabled') is not True or not re.fullmatch(r'ghcr\.io/[A-Za-z0-9_./-]+@sha256:[0-9a-f]{64}',image):raise SystemExit('Publish and register the reviewed immutable toolchain before AWS drill CI.')
with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('image='+image+'\n')
