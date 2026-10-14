#!/usr/bin/env python3
"""Read-only verification of a published toolchain; writes local registration seed only."""
import argparse,json,pathlib,re,subprocess
TOOLS=('aws','kubectl','argocd','helm','session-manager-plugin','gh','cosign')
def verify(published):
 image=published['operator_image']
 if not re.fullmatch(r'ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}',image):raise ValueError('Immutable published GHCR image required')
 if not re.fullmatch('[a-f0-9]{40}',published['source_sha']):raise ValueError('Reviewed source SHA required')
 expected=published['binary_sha256']
 if set(expected)!=set(TOOLS) or not all(re.fullmatch('[a-f0-9]{64}',x) for x in expected.values()):raise ValueError('Complete binary fingerprints required')
 subprocess.run(['docker','pull',image],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 code='import hashlib,json,pathlib,shutil;print(json.dumps({x:hashlib.sha256(pathlib.Path(shutil.which(x)).read_bytes()).hexdigest() for x in '+repr(TOOLS)+'}))'
 actual=json.loads(subprocess.check_output(['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--entrypoint','python3',image,'-c',code],stderr=subprocess.DEVNULL))
 if actual!=expected:raise ValueError('Published binary fingerprints differ')
 return {'source_sha':published['source_sha'],'operator_image':image,'binary_sha256':actual}
def main():
 p=argparse.ArgumentParser();p.add_argument('--published',type=pathlib.Path,required=True);p.add_argument('--account',required=True);p.add_argument('--repository-id',required=True);p.add_argument('--region',required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
 if not re.fullmatch('[0-9]{12}',a.account) or not re.fullmatch('[0-9]+',a.repository_id) or not re.fullmatch('[a-z]{2}-[a-z]+-[0-9]',a.region):raise ValueError('Protected identity bindings required')
 seed=verify(json.loads(a.published.read_text()));seed.update(account_id=a.account,repository_id=a.repository_id,region=a.region)
 a.output.write_text(json.dumps({'schema_version':1,'enabled':False,'blocked_reason':'Add reviewed chart digest, exact State bindings, role ARNs and immutable app declarations using PUBLISH-AND-ACTIVATE.md before enabling.','toolchain':seed,'environments':{}},indent=2)+'\n')
 print('Verified toolchain seed written. Set protected LIFECYCLE_TOOLCHAIN_IMAGE to the verified operator_image; seed remains disabled.')
if __name__=='__main__':main()
