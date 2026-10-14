"""Offline integration of the exact wrapper profile with actual adapter guards."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
w=load('profile_wrapper','run-lifecycle.py')
h=load('profile_saved','saved-plan.py')
LOCK=(HERE/'oidc-tests/toolchain/.terraform.lock.hcl').read_bytes()

def env(stage='plan'):
    return dict(GITHUB_ACTIONS='true',GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',
        GITHUB_REPOSITORY='example/course',GITHUB_REPOSITORY_ID='234',GITHUB_REPOSITORY_OWNER_ID='123',
        GITHUB_RUN_ID='456',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40,
        GITHUB_WORKFLOW_REF='example/course/.github/workflows/terraform-lifecycle.yml@refs/heads/main',
        LIFECYCLE_ENVIRONMENT='dev',OPERATION='up' if stage=='up' else 'down',
        EXPECTED_ACCOUNT_ID='123456789012',AWS_REGION='ap-northeast-2',
        AWS_ROLE_ARN='arn:aws:iam::123456789012:role/gha-infra-dev-'+w.oidc.STAGE_MODE[stage],
        EXPECTED_APPLY_ROLE_ARN='arn:aws:iam::123456789012:role/gha-infra-dev-apply',
        ACTIONS_ID_TOKEN_REQUEST_URL='https://run-actions-1.actions.githubusercontent.com/abc/idtoken?api-version=2.0',
        ACTIONS_ID_TOKEN_REQUEST_TOKEN='LOCAL-FAKE-REQUEST',STATE_BUCKET='test-private-state',GITHUB_WORKSPACE=str(HERE.parent))

class ProfileBoundary(unittest.TestCase):
    def test_actual_adapter_guards_accept_exact_profile(self):
        for name in ('network-lifecycle.py','eks-lifecycle.py'):
            adapter=load(name[:-3]+'_profile',name)
            for stage in ('start','plan','apply','up'):
                original=env(stage);binding=w.oidc.make_binding(original,stage)
                with self.subTest(adapter=name,stage=stage), w.private_profile(binding,original) as clean, patch.dict(os.environ,clean,clear=True):
                    with patch.object(adapter.h,'execute',return_value=b'a'*40), patch.object(adapter.h,'ensure_current_main'), patch.object(adapter.h,'check_identity'), patch.object(adapter.h,'Store'), patch.object(adapter,'check_retention'):
                        adapter.environment()
    def test_component_content_and_permission_tampering_rejected(self):
        for component in ('binding.json','config','credentials','terraform.rc','oidc_process.py'):
            original=env();binding=w.oidc.make_binding(original,'plan')
            with self.subTest(component=component),w.private_profile(binding,original) as clean,patch.dict(os.environ,clean,clear=True):
                path=Path(clean['AWS_CONFIG_FILE']).parent/component
                path.chmod(0o600)
                with self.assertRaises(h.SafeError):h.refresh_profile_guard()
                path.write_bytes(b'unreviewed');path.chmod(0o400)
                with self.assertRaises(h.SafeError):h.refresh_profile_guard()
    def test_arbitrary_rc_and_alternate_aws_source_rejected(self):
        with patch.dict(os.environ,{'TF_CLI_CONFIG_FILE':'/tmp/anything'},clear=True):
            with self.assertRaises(h.SafeError):h.refresh_profile_guard()
        for key in ('AWS_ACCESS_KEY_ID','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_CONTAINER_CREDENTIALS_FULL_URI','AWS_ENDPOINT_URL'):
            original=env();binding=w.oidc.make_binding(original,'plan')
            with self.subTest(key=key),w.private_profile(binding,original) as clean,patch.dict(os.environ,{**clean,key:'unreviewed'},clear=True):
                with self.assertRaises(h.SafeError):h.refresh_profile_guard()
    def test_snapshot_lock_enforced_before_init(self):
        original=env('up');binding=w.oidc.make_binding(original,'up')
        with tempfile.TemporaryDirectory() as temp,w.private_profile(binding,original) as clean,patch.dict(os.environ,clean,clear=True):
            root=Path(temp);lock=root/'.terraform.lock.hcl';lock.write_bytes(LOCK)
            with patch.object(h,'execute',return_value=b'default') as execute:
                h.initialize(root,root/'backend.hcl',root,'up')
                self.assertEqual(execute.call_count,2)
                execute.reset_mock();lock.write_bytes(LOCK.replace(b'6.62.0',b'6.61.0'))
                with self.assertRaises(h.SafeError):h.initialize(root,root/'backend.hcl',root,'up')
                execute.assert_not_called()
    def test_normal_ci_without_private_profile_is_unchanged(self):
        with patch.dict(os.environ,{},clear=True):h.refresh_profile_guard()

if __name__=='__main__':unittest.main()
