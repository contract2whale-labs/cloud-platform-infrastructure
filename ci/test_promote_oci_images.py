"""Offline fixtures only; no image publication, credentials, or cloud API calls."""
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('promotion',Path(__file__).with_name('promote-oci-images.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PromotionFixtures(unittest.TestCase):
    def request(self):
        return {'schema':1,'environment':'prod','created_at':1000,'expires_at':2000,'tag':'v1.0.0','images':{app:{'repository':'owner/'+app,'sha':'a'*40,'digest':'sha256:'+'b'*64,'publish_run_id':42} for app in m.APPS}}
    def repositories(self):return {app:'owner/'+app for app in m.APPS}
    def layout(self, directory, multi=True):
        directory.mkdir(parents=True)
        (directory/'version').write_bytes(b'Directory Transport Version: 1.1\n')
        manifests=[]
        for architecture in (['amd64','arm64'] if multi else ['amd64']):
            config=json.dumps({'architecture':architecture,'os':'linux'}).encode()
            layer=('compressed-'+architecture).encode()
            descriptors=[]
            for raw in (config,layer):
                digest='sha256:'+m.sha(raw);(directory/digest[7:]).write_bytes(raw)
                descriptors.append({'mediaType':'application/octet-stream','digest':digest,'size':len(raw)})
            manifest=json.dumps({'schemaVersion':2,'mediaType':next(iter(m.MANIFEST)),'config':descriptors[0],'layers':[descriptors[1]]}).encode()
            digest='sha256:'+m.sha(manifest)
            manifests.append({'mediaType':next(iter(m.MANIFEST)),'digest':digest,'size':len(manifest),'platform':{'os':'linux','architecture':architecture}})
            (directory/(digest[7:]+'.manifest.json') if multi else directory/'manifest.json').write_bytes(manifest)
        if multi:
            manifest=json.dumps({'schemaVersion':2,'mediaType':next(iter(m.INDEX)),'manifests':manifests}).encode()
            (directory/'manifest.json').write_bytes(manifest)
        return 'sha256:'+m.sha(manifest)
    def test_exact_request(self):m.validate_request(self.request(),self.repositories(),1500)
    def test_expired_future_or_long_window(self):
        for now,change in [(2000,{}),(0,{}),(1500,{'expires_at':90000})]:
            with self.subTest(now=now,change=change):
                request=self.request();request.update(change)
                with self.assertRaises(m.PromotionError):m.validate_request(request,self.repositories(),now)
    def test_unregistered_source_or_example_digest(self):
        for field,value in [('repository','attacker/commerce-web'),('digest','sha256:'+'0'*64),('sha','short'),('publish_run_id',True)]:
            request=self.request();request['images']['commerce-web'][field]=value
            with self.assertRaises(m.PromotionError):m.validate_request(request,self.repositories(),1500)
    def test_mutable_version_tag_rejected(self):
        request=self.request();request['tag']='latest'
        with self.assertRaises(m.PromotionError):m.validate_request(request,self.repositories(),1500)
    def test_successful_main_publication_bound(self):
        item=self.request()['images']['commerce-web'];run={'status':'completed','conclusion':'success','head_branch':'main','head_sha':'a'*40,'event':'push','path':'.github/workflows/ci.yml','repository':{'full_name':item['repository']}}
        m.validate_publish_run(run,item)
        for key,value in [('conclusion','failure'),('head_branch','feature'),('head_sha','b'*40),('event','pull_request'),('path','.github/workflows/other.yml')]:
            with self.assertRaises(m.PromotionError):m.validate_publish_run({**run,key:value},item)
    def test_release_immutability_excludes_only_evidence(self):
        meta={'imageTagMutability':'IMMUTABLE_WITH_EXCLUSION','imageTagMutabilityExclusionFilters':[{'filterType':'WILDCARD','filter':'sha256-*.sig'},{'filterType':'WILDCARD','filter':'sha256-*.att'}]}
        self.assertTrue(m.immutable_tag(meta,'v1.0.0'));self.assertTrue(m.immutable_tag(meta,'build-'+'a'*12))
        self.assertFalse(m.immutable_tag(meta,'sha256-abc.sig'))
        self.assertFalse(m.immutable_tag({'imageTagMutability':'MUTABLE'},'v1.0.0'))
    def test_all_platforms_and_exact_object_inventory(self):
        with tempfile.TemporaryDirectory() as work:
            directory=Path(work)/'image';digest=self.layout(directory)
            result=m.verify_directory(directory,digest)
            self.assertEqual({p['architecture'] for p in result['platforms']},{'amd64','arm64'})
            self.assertEqual(len(result['objects']),7)
    def test_single_manifest(self):
        with tempfile.TemporaryDirectory() as work:
            directory=Path(work)/'image';digest=self.layout(directory,False)
            self.assertEqual(len(m.verify_directory(directory,digest)['objects']),3)
    def test_missing_blob_or_changed_bytes_fail(self):
        for remove in [False,True]:
            with tempfile.TemporaryDirectory() as work:
                directory=Path(work)/'image';digest=self.layout(directory)
                blob=next(p for p in directory.iterdir() if len(p.name)==64)
                blob.unlink() if remove else blob.write_bytes(b'changed')
                with self.assertRaises(m.PromotionError):m.verify_directory(directory,digest)
    def test_symlink_unknown_or_unreferenced_file_fails(self):
        for name,link in [('unexpected',False),('c'*64,False),('d'*64,True)]:
            with tempfile.TemporaryDirectory() as work:
                directory=Path(work)/'image';digest=self.layout(directory)
                (directory/name).symlink_to(directory/'version') if link else (directory/name).write_bytes(b'extra')
                with self.assertRaises(m.PromotionError):m.verify_directory(directory,digest)
    def test_external_descriptor_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            directory=Path(work)/'image';self.layout(directory)
            data=json.loads((directory/'manifest.json').read_bytes());data['manifests'][0]['urls']=['https://unexpected.invalid/blob']
            raw=json.dumps(data).encode();(directory/'manifest.json').write_bytes(raw)
            with self.assertRaises(m.PromotionError):m.verify_directory(directory,'sha256:'+m.sha(raw))
    def test_archive_roundtrip_exact_bytes(self):
        with tempfile.TemporaryDirectory() as work:
            base=Path(work);source=base/'source';source.mkdir();digests={app:self.layout(source/app) for app in m.APPS}
            (source/'dev-signing-public.pem').write_bytes(b'-----BEGIN PUBLIC KEY-----\nfixture\n')
            archive=base/'bundle.tar';m.pack_payload(source,archive);m.unpack_payload(archive,base/'restored')
            for app in m.APPS:self.assertEqual(m.verify_directory(source/app,digests[app]),m.verify_directory(base/'restored'/app,digests[app]))
    def test_archive_traversal_symlink_duplicate_rejected(self):
        for mode in ['traversal','link','duplicate','directory']:
            with tempfile.TemporaryDirectory() as work:
                base=Path(work);archive=base/'bad.tar'
                with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as tar:
                    info=tarfile.TarInfo('../escape' if mode=='traversal' else 'dev-signing-public.pem')
                    info.type=tarfile.SYMTYPE if mode=='link' else tarfile.DIRTYPE if mode=='directory' else tarfile.REGTYPE
                    info.linkname='/etc/passwd' if mode=='link' else ''
                    tar.addfile(info,io.BytesIO(b''))
                    if mode=='duplicate':tar.addfile(info,io.BytesIO(b''))
                with self.assertRaises(m.PromotionError):m.unpack_payload(archive,base/'unpacked')
                self.assertFalse((base/'escape').exists())
    def test_attestation_exact_digest_and_spdx(self):
        statement={'subject':[{'digest':{'sha256':'b'*64}}],'predicate':{'spdxVersion':'SPDX-2.3'}}
        raw=json.dumps({'payload':base64.b64encode(json.dumps(statement).encode()).decode()}).encode()
        self.assertTrue(m.verified_attestation(raw,'sha256:'+'b'*64));self.assertFalse(m.verified_attestation(raw,'sha256:'+'c'*64))
    def test_wrong_key_requires_signature_failure_not_network_error(self):
        m.verify_wrong_key_failure(1,b'',b'Error: no matching signatures')
        for code,error in [(0,b''),(1,b'AccessDenied'),(1,b'connection timeout')]:
            with self.assertRaises(m.PromotionError):m.verify_wrong_key_failure(code,b'',error)
    def test_workflow_is_separate_protected_jobs_no_public_artifact(self):
        text=Path(__file__).parents[1].joinpath('.github/workflows/app-image-promote.yml').read_text()
        for expected in ['dev-oci-export','prod-oci-import','needs: dev-export','--manifest-version','mask-aws-account-id: true']:self.assertIn(expected,text)
        self.assertNotIn('upload-artifact',text);self.assertNotIn('download-artifact',text)
    def test_container_git_uses_only_exact_workspace_safe_directory(self):
        text=Path(m.__file__).read_text()
        self.assertEqual(text.count("command(['git', '-c', 'safe.directory=' + str(repo),"),4)
        self.assertNotIn('safe.directory=*',text)
    def test_no_terraform_or_role_switch_or_delete(self):
        text=Path(m.__file__).read_text()
        for bad in ['assume_role(',"['terraform'",'batch_delete_image(','delete_object(']:self.assertNotIn(bad,text)

if __name__=='__main__':unittest.main()
