"""Offline tests: no AWS, GitHub, Terraform or external mutations."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stdout

sys.dont_write_bytecode = True

spec=importlib.util.spec_from_file_location('receipt',Path(__file__).with_name('collect-platform-receipt.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ReceiptContractTest(unittest.TestCase):
    def setUp(self):
        self.expected={'repository':'example/infra','repository_id':'17','run_id':'42','run_attempt':'2','sha':'a'*40,'root':'terraform/environments/prod/platform/core','environment':'prod','account':'123456789012','bucket':'approved-state','state_key':'platform/core/terraform.tfstate','prefix':'ci-logs/17/42/2/'+'a'*40+'/prod/platform/core/apply/'}
        self.context={k:v for k,v in self.expected.items() if k not in ('bucket','state_key','prefix')}
        self.context.update(backend={'bucket':'approved-state','key':'platform/core/terraform.tfstate','region':'ap-northeast-2'},workspace='default')
        self.run={'status':'completed','head_branch':'main','head_sha':'a'*40,'event':'push','path':'.github/workflows/terraform-apply.yml','run_attempt':2,'repository':{'id':17},'conclusion':'success'}
        self.completion={'schema':1,'kind':'apply-completion','context':self.context,'plan_sha':'b'*64,'state':{'version':'state-v2','etag':'"state-etag"','lineage':'12345678-1234-4234-8234-123456789abc','serial':7},'outputs':{'key':self.expected['prefix']+'outputs.json','version':'output-v1','sha256':'c'*64}}
        self.metadata={'schema_version':1,'environment':'prod','account_id':'123456789012','region':'ap-northeast-2','root':'core','apply_revision':'a'*40,'base_revision':'a'*40,'state_lineage':'12345678-1234-4234-8234-123456789abc','state_serial':7}
        self.entries=[{'field':'cert_manager_service_account','type':'string','source':{'output':'core_identity_contract','pointer':'/service_account'},'targets':[{'file':'gitops/platform/cert-manager/values/{environment}.yaml','pointer':'/serviceAccount/name'}]}]
        self.outputs={'core_identity_contract':{'sensitive':False,'value':{'service_account':'cert-manager'}},'unused':{'sensitive':True,'value':'not-for-receipt'}}
    def validate(self, name, value, kind, metadata):
        if kind=='string' and (not isinstance(value,str) or not value or '\n' in value):
            raise ValueError('invalid string')
    def check(self):return m.check_completion(self.completion,self.run,self.expected)
    def test_valid_success(self):self.assertEqual(self.check()[1],7)
    def test_later_root_failure_preserves_own_success(self):
        self.run['conclusion']='failure';self.assertEqual(self.check()[1],7)
    def test_running_attempt_rejected(self):
        self.run['status']='in_progress'
        with self.assertRaises(m.ReceiptError):self.check()
    def test_wrong_root_environment_account_sha_or_attempt(self):
        for key in ('root','environment','account','sha','run_attempt','repository_id'):
            with self.subTest(key=key):
                changed=copy.deepcopy(self.completion);changed['context'][key]='wrong'
                with self.assertRaises(m.ReceiptError):m.check_completion(changed,self.run,self.expected)
    def test_preview_never_becomes_apply(self):
        self.completion['kind']='preview'
        with self.assertRaises(m.ReceiptError):self.check()
    def test_wrong_workflow_or_branch_or_trigger(self):
        for key,value in [('path','.github/workflows/terraform-audit.yml'),('head_branch','feature/test'),('event','pull_request')]:
            with self.subTest(key=key):
                run={**self.run,key:value}
                with self.assertRaises(m.ReceiptError):m.check_completion(self.completion,run,self.expected)
    def test_wrong_backend(self):
        self.completion['context']['backend']['key']='other/terraform.tfstate'
        with self.assertRaises(m.ReceiptError):self.check()
    def test_outputs_from_other_run_rejected(self):
        self.completion['outputs']['key']=self.expected['prefix'].replace('/42/','/43/')+'outputs.json'
        with self.assertRaises(m.ReceiptError):self.check()
    def test_missing_version_or_hash_rejected(self):
        for key,value in [('version','null'),('sha256','incorrect')]:
            with self.subTest(key=key):
                changed=copy.deepcopy(self.completion);changed['outputs'][key]=value
                with self.assertRaises(m.ReceiptError):m.check_completion(changed,self.run,self.expected)
    def test_invalid_state_lineage_or_serial(self):
        for key,value in [('lineage','invalid'),('serial',True),('serial',-1),('version','null')]:
            with self.subTest(key=key):
                changed=copy.deepcopy(self.completion);changed['state'][key]=value
                with self.assertRaises(m.ReceiptError):m.check_completion(changed,self.run,self.expected)
    def test_exact_legacy_receipt_fields_and_allowlist(self):
        receipt=m.build_receipt(self.metadata,self.outputs,self.entries,self.validate)
        self.assertEqual(set(receipt),set(self.metadata)|{'values'})
        self.assertEqual(receipt['values'],{'cert_manager_service_account':'cert-manager'})
        self.assertNotIn('unused',json.dumps(receipt))
    def test_sensitive_and_unknown_sensitivity_rejected(self):
        for value in [True,None]:
            with self.subTest(value=value):
                self.outputs['core_identity_contract']['sensitive']=value
                with self.assertRaises(m.ReceiptError):m.build_receipt(self.metadata,self.outputs,self.entries,self.validate)
    def test_duplicate_or_missing_registry_rejected(self):
        for entries in [[],self.entries*2]:
            with self.assertRaises(m.ReceiptError):m.build_receipt(self.metadata,self.outputs,entries,self.validate)
    def test_bad_typed_value_rejected(self):
        self.outputs['core_identity_contract']['value']['service_account']='bad\nvalue'
        with self.assertRaises(ValueError):m.build_receipt(self.metadata,self.outputs,self.entries,self.validate)
    def test_metadata_allowlist(self):
        e=[{'field':'region','type':'region','source':{'metadata':'region'}}]
        receipt=m.build_receipt(self.metadata,self.outputs,e,self.validate)
        self.assertEqual(receipt['values'],{'region':'ap-northeast-2'})
        e[0]['source']['metadata']='apply_revision'
        with self.assertRaises(m.ReceiptError):m.build_receipt(self.metadata,self.outputs,e,self.validate)
    def test_escaped_json_pointer(self):self.assertEqual(m.pointer({'a/b':{'~key':['value']}},'/a~1b/~0key/0'),'value')
    def test_receipt_no_overwrite_or_symlink(self):
        with tempfile.TemporaryDirectory() as work:
            path=Path(work)/'receipt.json';m.write_new(path,self.metadata)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            with self.assertRaises(m.ReceiptError):m.write_new(path,self.metadata)
            link=Path(work)/'linked.json';link.symlink_to(path)
            with self.assertRaises(m.ReceiptError):m.write_new(link,self.metadata)
    def test_source_has_no_cloud_mutation_or_terraform_invocation(self):
        source=Path(m.__file__).read_text()
        for forbidden in ("['terraform'",'apply_and_collect.py','put-object','delete-object','git push','workflow run'):
            self.assertNotIn(forbidden,source)

    def source_tree(self, repo):
        for relative in m.SOURCE_FILES:
            path=repo/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')

    def git_read(self, args, cwd=None):
        self.assertEqual(args[0],'git')
        return ('a'*40).encode() if args[1:3]==['rev-parse','HEAD'] else b''

    def test_clean_source_checks_tracked_untracked_and_ignored_files(self):
        with tempfile.TemporaryDirectory() as work:
            repo=Path(work);self.source_tree(repo)
            with mock.patch.object(m,'execute',side_effect=self.git_read) as execute:
                m.check_source(repo,'a'*40)
            calls=[c.args[0] for c in execute.call_args_list]
            self.assertIn(['git','ls-files','--others','--exclude-standard','--','automation','schemas'],calls)
            self.assertIn(['git','ls-files','--others','--ignored','--exclude-standard','--','automation','schemas'],calls)

    def test_untracked_and_ignored_import_shadowing_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            repo=Path(work);self.source_tree(repo)
            for ignored in (False,True):
                with self.subTest(ignored=ignored):
                    def read(args,cwd=None):
                        if '--others' in args and ('--ignored' in args)==ignored:
                            return b'automation/jsonschema.py\n'
                        return self.git_read(args,cwd)
                    with mock.patch.object(m,'execute',side_effect=read):
                        with self.assertRaises(m.ReceiptError):m.check_source(repo,'a'*40)

    def test_source_file_and_parent_symlinks_rejected(self):
        for parent in (False,True):
            with self.subTest(parent=parent), tempfile.TemporaryDirectory() as work:
                repo=Path(work)/'repo';self.source_tree(repo)
                source=repo/'automation' if parent else repo/m.SOURCE_FILES[0]
                moved=Path(work)/'outside';source.rename(moved);source.symlink_to(moved,target_is_directory=parent)
                with mock.patch.object(m,'execute',side_effect=self.git_read):
                    with self.assertRaises(m.ReceiptError):m.check_source(repo,'a'*40)

    def test_nonisolated_interpreter_rejected_before_io(self):
        with mock.patch.object(m.sys,'flags',SimpleNamespace(isolated=0)), mock.patch.object(m,'execute') as execute:
            with self.assertRaises(m.ReceiptError):m.main()
            execute.assert_not_called()
        self.assertTrue(sys.dont_write_bytecode)

    def run_mocked_main(self, directory, state_change=None, bad_checksum=False):
        repo=Path(directory)/'repo';self.source_tree(repo)
        (repo/'automation/platform-input-mappings.json').write_text(json.dumps(self.entries))
        schema={'type':'object','additionalProperties':False,'required':list(self.metadata)+['values'],'properties':{k:{} for k in self.metadata}|{'values':{'type':'object'}}}
        (repo/'schemas/platform-inputs.schema.json').write_text(json.dumps(schema))
        output=Path(directory)/'private/receipt.json'
        outputs_bytes=json.dumps(self.outputs).encode()
        completion=copy.deepcopy(self.completion)
        completion['outputs']['sha256']=m.sha256(outputs_bytes)
        completion_bytes=json.dumps(completion).encode()
        checksum='0'*64 if bad_checksum else m.sha256(completion_bytes)
        argv=['collect-platform-receipt.py','--repo',str(repo),'--root','core','--environment','prod','--expect-account','123456789012','--expect-revision','a'*40,'--repository','example/infra','--apply-run-id','42','--run-attempt','2','--state-bucket','approved-state','--profile','approved-readonly','--completion-version','completion-v1','--completion-sha256',checksum,'--output',str(output)]
        head_calls=0;commands=[]
        def execute(args,cwd=None):
            nonlocal head_calls
            commands.append(args)
            if args[0]=='git':return self.git_read(args,cwd)
            if args[0]=='gh':
                return json.dumps(self.run if '/actions/runs/' in args[-1] else {'id':17}).encode()
            self.assertEqual(args[:5],['aws','--profile','approved-readonly','--region','ap-northeast-2'])
            service,operation=args[5:7]
            if (service,operation)==('sts','get-caller-identity'):return b'{"Account":"123456789012"}'
            if (service,operation)==('s3api','head-object'):
                head_calls+=1
                version='changed' if state_change==head_calls else 'state-v2'
                return json.dumps({'VersionId':version,'ETag':'"state-etag"'}).encode()
            self.assertEqual((service,operation),('s3api','get-object'))
            version=args[args.index('--version-id')+1];target=Path(args[args.index('--version-id')+2])
            target.write_bytes(completion_bytes if version=='completion-v1' else outputs_bytes)
            return json.dumps({'VersionId':version,'ServerSideEncryption':'AES256'}).encode()
        modules=[SimpleNamespace(active_entries=lambda registry,root,environment:registry),SimpleNamespace(validate_value=self.validate)]
        original_path=list(sys.path);previous_umask=os.umask(0o077)
        try:
            with mock.patch.object(sys,'argv',argv), mock.patch.object(m,'execute',side_effect=execute), mock.patch.object(m,'load_module',side_effect=modules), redirect_stdout(io.StringIO()) as captured:
                m.main()
            self.assertNotIn('not-for-receipt',captured.getvalue())
            self.assertFalse(any(repo.rglob('__pycache__')))
            return output,commands
        finally:
            sys.path[:]=original_path;os.umask(previous_umask)

    def test_main_reads_versioned_evidence_and_writes_only_allowlisted_receipt(self):
        with tempfile.TemporaryDirectory() as work:
            output,commands=self.run_mocked_main(work)
            receipt=json.loads(output.read_text())
            self.assertEqual(receipt['values'],{'cert_manager_service_account':'cert-manager'})
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            self.assertEqual(sum(c[0]=='aws' and c[6]=='head-object' for c in commands),2)
            self.assertEqual(sum(c[:3]==['git','rev-parse','HEAD'] for c in commands),3)

    def test_main_rejects_state_changed_before_or_during_collection(self):
        for change in (1,2):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as work:
                with self.assertRaises(m.ReceiptError):self.run_mocked_main(work,state_change=change)
                self.assertFalse((Path(work)/'private/receipt.json').exists())

    def test_main_rejects_wrong_completion_checksum(self):
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaises(m.ReceiptError):self.run_mocked_main(work,bad_checksum=True)
            self.assertFalse((Path(work)/'private/receipt.json').exists())

if __name__=='__main__':unittest.main()
