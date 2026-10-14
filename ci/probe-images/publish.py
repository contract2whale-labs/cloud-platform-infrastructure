#!/usr/bin/env python3
"""Invoked only by protected CI. Repository creation is separate Terraform CI."""
import hashlib,importlib.util,json,os,re,subprocess,tempfile
from pathlib import Path

def require(ok,message):
    if not ok:raise RuntimeError(message)
def cmd(*args,input=None):return subprocess.check_output(list(args),input=input,stderr=subprocess.PIPE).decode().strip()
def aws(*args,region='ap-northeast-2'):return json.loads(cmd('aws',*args,'--region',region,'--output','json','--no-cli-pager'))
def immutable(source):
    digest=cmd('docker','buildx','imagetools','inspect',source,'--format','{{.Manifest.Digest}}')
    require(re.fullmatch('sha256:[0-9a-f]{64}',digest),'Registry returned no immutable manifest digest.')
    return source.split('@')[0].rsplit(':',1)[0]+'@'+digest if ':' in source.rsplit('/',1)[-1] else source.split('@')[0]+'@'+digest

SKOPEO_IMAGE = 'quay.io/skopeo/stable@sha256:97772f3c64fd2fba720b2bafaf37239dc44d8b1c625c8383c64044832efe9ed9'

def load_ci(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),Path(__file__).resolve().parents[1]/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def copy_image(source,target):
    # Copy every platform and its blobs, not only a manifest between registries.
    config=Path(os.environ['DOCKER_CONFIG']).resolve()
    require((config/'config.json').is_file(),'Registry authentication file is missing.')
    cmd('docker','run','--rm','--user','0:0','--entrypoint','skopeo','--mount',
        'type=bind,source='+str(config)+',target=/auth,readonly',SKOPEO_IMAGE,
        'copy','--all','--preserve-digests','--authfile','/auth/config.json',
        'docker://'+source,'docker://'+target)
    require(immutable(target).split('@')[1]==source.split('@')[1],'Mirror changed the source digest.')

def publish_linux_pair(source,target):
    # The upstream pause index may include Windows: publish only the two lecture platforms.
    manifest=json.loads(cmd('docker','buildx','imagetools','inspect',source,'--raw'))
    selected=[]
    for arch in ('amd64','arm64'):
        rows=[x for x in manifest.get('manifests',[]) if x.get('platform',{}).get('os')=='linux' and x.get('platform',{}).get('architecture')==arch]
        require(len(rows)==1 and re.fullmatch(r'sha256:[0-9a-f]{64}',rows[0].get('digest','')),'Exact upstream platform child required.')
        child=rows[0]['digest'];child_source=source.split('@')[0]+'@'+child
        copy_image(child_source,target+'-'+arch)
        selected.append(target.rsplit(':',1)[0]+'@'+child)
    # Both child manifests and their blobs now exist in this SAME destination registry.
    cmd('docker','buildx','imagetools','create','--tag',target,*selected)
    return immutable(target)

def require_platforms(source):
    manifest=json.loads(cmd('docker','buildx','imagetools','inspect',source,'--raw'))
    platforms={(x.get('platform',{}).get('os'),x.get('platform',{}).get('architecture')) for x in manifest.get('manifests',[])}
    require({('linux','amd64'),('linux','arm64')} <= platforms,'Both amd64 and arm64 image manifests are required.')

def publication_context(mode):
    h=load_ci('saved-plan')
    account=os.environ['EXPECTED_ACCOUNT_ID'];sha=os.environ['GITHUB_SHA'];repo=os.environ['GITHUB_REPOSITORY_ID']
    require(re.fullmatch(r'[0-9]{12}',account) and re.fullmatch('[0-9a-f]{40}',sha) and repo.isdigit(),'Invalid publication identity.')
    require(cmd('git','rev-parse','HEAD')==sha,'Checkout SHA differs from publication source.')
    h.check_identity(account,os.environ['AWS_ROLE_ARN'])
    h.ensure_current_main({'sha':sha})
    store=h.Store(os.environ['STATE_BUCKET'],account);store.check()
    if mode=='learner':
        context={'repository_id':repo,'account':account,'root':'terraform/environments/dev/bootstrap/probe-images',
                 'backend':{'bucket':store.bucket,'region':os.environ['AWS_REGION']}}
        load_ci('lifecycle-state').assert_normal_allowed(store,context,Path(os.environ['GITHUB_WORKSPACE']))
    return h,store

def retain_receipt(h,store,path):
    key='ci-probe-images/'+os.environ['GITHUB_REPOSITORY_ID']+'/'+os.environ['GITHUB_RUN_ID']+'/'+os.environ['GITHUB_RUN_ATTEMPT']+'/receipt.json'
    response=store.call('put-object','--key',key,'--body',str(path),'--server-side-encryption','AES256','--if-none-match','*')
    require(response.get('VersionId') not in (None,'','null') and response.get('ServerSideEncryption')=='AES256','Versioned encrypted receipt write required.')
    descriptor={'bucket':store.bucket,'key':key,'version':response['VersionId'],'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    h.emit({'receipt_key':key,'receipt_version':descriptor['version'],'receipt_sha256':descriptor['sha256']})
    return descriptor

def publish():
    os.umask(0o077)
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REF')=='refs/heads/main','Publication is protected main CI only.')
    require(os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','Explicit publication request required.')
    require(os.environ.get('AWS_REGION')=='ap-northeast-2','Course publication backend region is Seoul.')
    mode=os.environ['PUBLICATION_MODE'];require(mode in ('instructor','learner'),'Unknown publication mode.')
    h,store=publication_context(mode)
    account=os.environ['EXPECTED_ACCOUNT_ID'];sha=os.environ['GITHUB_SHA']
    if mode=='instructor':cmd('docker','buildx','create','--name','course-probes','--driver','docker-container','--use')
    images={};sources={}
    if mode=='instructor':
        repositories=aws('ecr-public','describe-repositories','--repository-names','course-bu07-python','course-bu07-pause',region='us-east-1')['repositories']
        require(len(repositories)==2 and all(x['registryId']==account for x in repositories),'Exact precreated instructor repositories required.')
        registry='public.ecr.aws'
        password=cmd('aws','ecr-public','get-login-password','--region','us-east-1')
        cmd('docker','login','--username','AWS','--password-stdin',registry,input=password.encode())
        sources={'probe_image':immutable('public.ecr.aws/docker/library/python:3.13-alpine'),'pause_image':immutable('registry.k8s.io/pause:3.10')}
        # Public repository tags are not inherently immutable: refuse any existing
        # source tag and always distribute digest references, never tags.
        for repository in repositories:
            target=repository['repositoryUri']+':'+sha
            exists=subprocess.run(['aws','ecr-public','describe-images','--repository-name',repository['repositoryName'],'--image-ids','imageTag='+sha,'--region','us-east-1','--output','json'],capture_output=True)
            require(exists.returncode!=0 and b'ImageNotFoundException' in exists.stderr,'Publication tag exists or absence could not be verified; never overwrite.')
            if repository['repositoryName']=='course-bu07-python':
                cmd('docker','buildx','build','--platform','linux/amd64,linux/arm64','--provenance=false','--build-arg','BASE_IMAGE='+sources['probe_image'],'-f','ci/probe-images/Dockerfile','--tag',target,'--push','ci/probe-images')
                images['probe_image']=immutable(target)
            else:
                images['pause_image']=publish_linux_pair(sources['pause_image'],target)
    else:
        sources=json.loads(Path('ci/probe-images/instructor-release.json').read_text())['images']
        require(set(sources)=={'probe_image','pause_image'} and all(re.fullmatch(r'public\.ecr\.aws/[a-z0-9]+/course-bu07-(python|pause)@sha256:[0-9a-f]{64}',x) for x in sources.values()),'Commit the actual instructor receipt digest references through PR.')
        repositories=aws('ecr','describe-repositories','--repository-names','course-bu07-python','course-bu07-pause')['repositories']
        require(len(repositories)==2 and all(x['registryId']==account and x['imageTagMutability']=='IMMUTABLE' for x in repositories),'Exact immutable learner repositories required.')
        registry=account+'.dkr.ecr.ap-northeast-2.amazonaws.com'
        password=cmd('aws','ecr','get-login-password','--region','ap-northeast-2')
        cmd('docker','login','--username','AWS','--password-stdin',registry,input=password.encode())
        for repository in repositories:
            key='probe_image' if repository['repositoryName']=='course-bu07-python' else 'pause_image'
            source=sources[key];require(immutable(source)==source,'Instructor digest mismatch.')
            target=repository['repositoryUri']+':'+sha
            copy_image(source,target)
            images[key]=immutable(target)
            require(images[key].split('@')[1]==source.split('@')[1],'Mirror changed manifest digest.')
    for image in images.values():require_platforms(image)
    receipt={'schema':1,'account':account,'source_sha':sha,'run_id':os.environ['GITHUB_RUN_ID'],'mode':mode,'sources':sources,'images':images}
    path=Path(os.environ['RUNNER_TEMP'])/'bu07-images.json';path.write_text(json.dumps(receipt,indent=2)+'\n')
    descriptor=retain_receipt(h,store,path)
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as out:
        out.write('BU07 immutable image receipt\n\n'+json.dumps(receipt,indent=2)+'\n\nPrivate versioned receipt descriptor\n'+json.dumps(descriptor,indent=2)+'\n')
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('receipt_path='+str(path)+'\n')
def main():
    os.umask(0o077)
    previous=os.environ.get('DOCKER_CONFIG')
    with tempfile.TemporaryDirectory(prefix='probe-registry-',dir=os.environ['RUNNER_TEMP']) as config:
        os.environ['DOCKER_CONFIG']=config
        try:
            publish()
        finally:
            if os.environ.get('PUBLICATION_MODE')=='instructor':
                subprocess.run(['docker','buildx','rm','course-probes'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
            if previous is None:os.environ.pop('DOCKER_CONFIG',None)
            else:os.environ['DOCKER_CONFIG']=previous
if __name__=='__main__':main()
