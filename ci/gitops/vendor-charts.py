#!/usr/bin/env python3
"""Prepare reviewed immutable chart source. Downloads/extracts locally; never deploys."""
import argparse,hashlib,json,pathlib,re,subprocess,tarfile,tempfile,urllib.parse
SAFE=re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}')
def extract(archive,destination):
 with tarfile.open(archive,'r:gz') as tar:
  for member in tar.getmembers():
   path=pathlib.PurePosixPath(member.name)
   if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):raise ValueError('Unsafe chart archive path/type')
  tar.extractall(destination,filter='data')
def main():
 p=argparse.ArgumentParser();p.add_argument('--lock',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,default=pathlib.Path('gitops/vendor'));p.add_argument('--inspect',action='store_true');a=p.parse_args()
 lock=json.loads(a.lock.read_text());assert lock['schema']==1 and isinstance(lock['charts'],list)
 for item in lock['charts']:
  assert set(item)=={'id','repository','chart','version','sha256'}
  assert all(SAFE.fullmatch(item[k]) for k in ('id','chart','version'))
  url=urllib.parse.urlparse(item['repository']);assert url.scheme=='https' and url.hostname and not url.username and not url.password and not url.query and not url.fragment
  with tempfile.TemporaryDirectory(prefix='review-chart-') as d:
   subprocess.run(['helm','pull',item['chart'],'--repo',item['repository'],'--version',item['version'],'--destination',d],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   archives=list(pathlib.Path(d).glob('*.tgz'));assert len(archives)==1;archive=archives[0];digest=hashlib.sha256(archive.read_bytes()).hexdigest()
   if a.inspect:print(json.dumps({'id':item['id'],'repository':item['repository'],'chart':item['chart'],'version':item['version'],'sha256':digest}));continue
   assert re.fullmatch('[a-f0-9]{64}',item['sha256']) and digest==item['sha256'],'Reviewed chart archive digest differs'
   target=a.output/item['id']/item['version'];assert not target.exists(),'Existing vendor target must be explicitly reviewed; never overwrite silently'
   target.mkdir(parents=True);extract(archive,target);(target/'archive.sha256').write_text(digest+'\n')
   print(json.dumps({'id':item['id'],'path':str(target/item['chart']),'sha256':digest}))
if __name__=='__main__':main()
