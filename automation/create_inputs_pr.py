#!/usr/bin/env python3
"""Publish the isolated non-secret input diff with a dedicated repository token.

The workflow token must come from the publisher GitHub App or another approved
credential that triggers PR checks. GITHUB_TOKEN-created PRs do not trigger the
usual subsequent workflows; do not silently substitute that token.
"""
import argparse,json,os,re,subprocess,urllib.error,urllib.request
from pathlib import Path
from update_objstore_revision import DESTINATIONS
from platform_input_registry import active_entries

def allowed_changed_paths(request,repo):
    entries=active_entries(json.loads((repo/'automation/platform-input-mappings.json').read_text()),request['root'],request['environment'])
    paths={target['file'].replace('{environment}',request['environment']) for entry in entries if entry['root']==request['root'] for target in entry['targets']}
    paths.add('gitops/inputs/'+request['environment']+'/'+request['root']+'.receipt.json')
    if request['root']=='observability':
        paths.update(relative.format(environment=request['environment']) for relative,keys in DESTINATIONS.values())
    return paths

def api(repo,method,path,payload=None):
    token=os.environ['PUBLISHER_TOKEN']
    request=urllib.request.Request('https://api.github.com/repos/'+repo+'/'+path,data=None if payload is None else json.dumps(payload).encode(),headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},method=method)
    with urllib.request.urlopen(request,timeout=30) as r:return json.load(r) if r.status!=204 else None

def main():
    p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--repository',required=True);a=p.parse_args();r=json.loads(a.request.read_text())
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',a.repository):raise ValueError('invalid repository')
    current=api(a.repository,'GET','git/ref/heads/main')['object']['sha']
    if current!=r['base_revision']:raise ValueError('main moved since apply; regenerate against the current approved base')
    changed=subprocess.check_output(['git','diff','--name-only'],text=True).splitlines()
    changed+=subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines()
    if not changed:print('no-op');return
    allowed=allowed_changed_paths(r,Path.cwd())
    if any(f not in allowed for f in changed):raise ValueError('unrelated changed path; refusing publisher write')
    branch='platform-inputs/'+r['environment']+'/'+r['root']+'/'+r['apply_revision'][:12]+'-'+str(r['state_serial'])
    tree=[]
    for name in sorted(set(changed)):
        content=Path(name).read_text()
        blob=api(a.repository,'POST','git/blobs',{'content':content,'encoding':'utf-8'})
        tree.append({'path':name,'mode':'100644','type':'blob','sha':blob['sha']})
    parent=api(a.repository,'GET','git/commits/'+current)
    obj=api(a.repository,'POST','git/trees',{'base_tree':parent['tree']['sha'],'tree':tree})
    commit=api(a.repository,'POST','git/commits',{'message':'Update '+r['environment']+' '+r['root']+' inputs from approved apply','tree':obj['sha'],'parents':[current]})
    try:api(a.repository,'POST','git/refs',{'ref':'refs/heads/'+branch,'sha':commit['sha']})
    except urllib.error.HTTPError as e:
        if e.code!=422:raise
        old=api(a.repository,'GET','git/ref/heads/'+branch)['object']['sha']
        if old!=commit['sha']:
            # Commit timestamps can differ on retry; compare trees, never force.
            oldcommit=api(a.repository,'GET','git/commits/'+old)
            if oldcommit['tree']['sha']!=obj['sha']:raise ValueError('existing request branch has different content')
    pulls=api(a.repository,'GET','pulls?state=open&head='+a.repository.split('/')[0]+':'+branch)
    if pulls:print(pulls[0]['html_url']);return
    body='Successful approved apply: '+r['apply_revision']+'\nRoot: '+r['root']+'\nEnvironment: '+r['environment']+'\nState serial: '+str(r['state_serial'])+'\n\nReview the native source diff and PR checks before merging. This publisher does not write to the cluster.'
    pr=api(a.repository,'POST','pulls',{'title':'Update '+r['environment']+' '+r['root']+' platform inputs','head':branch,'base':'main','body':body})
    print(pr['html_url'])

if __name__=='__main__':main()
