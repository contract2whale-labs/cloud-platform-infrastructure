#!/usr/bin/env python3
import re
from pathlib import Path
from ruamel.yaml import YAML

def main():
 root=Path(__file__).resolve().parents[1];yaml=YAML(typ='safe')
 for path in sorted((root/'.github/workflows').glob('*.y*ml')):
  d=yaml.load(path.read_text());events=d.get('on',{});events=[events] if isinstance(events,str) else events
  pr=any(e in events for e in ['pull_request','pull_request_target','merge_group'])
  if 'pull_request_target' in events:raise SystemExit(path.name+': protected-context PR event requires separate review; unsupported by default')
  for jobname,job in d.get('jobs',{}).items():
   permission=job.get('permissions',d.get('permissions',{}))
   if pr and (not isinstance(permission,dict) or permission.get('contents')!='read' or any(v=='write' for v in permission.values())):
    raise SystemExit(path.name+'/'+jobname+': PR job must explicitly use contents read without write grants')
   for step in job.get('steps',[]):
    use=step.get('uses','')
    if use and not use.startswith('./') and not re.search(r'@[0-9a-f]{40}$',use):
     raise SystemExit(path.name+'/'+jobname+': action must be pinned to reviewed commit')
 print('workflow action pins and PR permission boundaries valid')

if __name__=='__main__':main()
