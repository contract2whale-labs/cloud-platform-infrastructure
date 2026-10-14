"""Real Terraform+AWS provider against LOCAL fake STS, fake credentials only."""
import http.server
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from support import PROCESS_FIXTURE, environment, oidc, wrapper

TERRAFORM = Path(os.environ.get('OIDC_TEST_TERRAFORM', '/tmp/course-terraform/terraform'))
PROVIDER = Path(os.environ.get('OIDC_TEST_PROVIDER', '/tmp/bu04-08-provider-validate/.terraform/providers/registry.terraform.io/hashicorp/aws/6.62.0/linux_amd64/terraform-provider-aws_v6.62.0_x5'))


class FakeSTS(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        if b'Action=GetCallerIdentity' not in body:
            self.send_error(400)
            return
        match = re.search(r'Credential=([^/]+)/', self.headers.get('Authorization', ''))
        self.server.keys.append(match.group(1) if match else 'UNSIGNED')
        if len(self.server.keys) == 1:
            time.sleep(3)  # Make the first fake two-second session expire.
        payload = (b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                   b'<GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/gha-infra-dev-plan/local-test</Arn>'
                   b'<UserId>LOCALFAKE:local-test</UserId><Account>123456789012</Account></GetCallerIdentityResult>'
                   b'<ResponseMetadata><RequestId>local-test</RequestId></ResponseMetadata></GetCallerIdentityResponse>')
        self.send_response(200)
        self.send_header('Content-Type', 'text/xml')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@unittest.skipUnless(TERRAFORM.is_file() and PROVIDER.is_file(), 'Pinned Terraform/provider binaries unavailable')
class ActualTerraformProvider(unittest.TestCase):
    def exercise(self, mode):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeSTS)
        server.keys = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='oidc-terraform-') as temp:
                root = Path(temp)
                mirror = root / 'mirror/registry.terraform.io/hashicorp/aws/6.62.0/linux_amd64'
                mirror.mkdir(parents=True)
                (mirror / PROVIDER.name).symlink_to(PROVIDER)
                cli = root / 'terraform.rc'
                cli.write_text('provider_installation { filesystem_mirror { path = "' + str(root / 'mirror') + '" } }\ndisable_checkpoint = true\n')
                counter = root / 'count'
                config = root / 'config'
                config.write_text('[profile course-lifecycle]\nregion = ap-northeast-2\ncredential_process = '
                                  f'"{sys.executable}" "{PROCESS_FIXTURE}" "{counter}" {mode}\n')
                (root / 'credentials').write_text('')
                (root / 'main.tf').write_text('''
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "= 6.62.0"
    }
  }
}
provider "aws" {
  region = "ap-northeast-2"
  skip_credentials_validation = true
  skip_requesting_account_id = true
  skip_metadata_api_check = true
  endpoints { sts = "http://127.0.0.1:PORT" }
}
data "aws_caller_identity" "first" {}
data "aws_caller_identity" "second" { depends_on = [data.aws_caller_identity.first] }
output "account" { value = data.aws_caller_identity.second.account_id }
'''.replace('PORT', str(server.server_port)))
                source = dict(os.environ, **environment(), AWS_ACCESS_KEY_ID='POISON_STATIC', AWS_SECRET_ACCESS_KEY='POISON_STATIC',
                              AWS_WEB_IDENTITY_TOKEN_FILE='/does/not/exist', AWS_CONTAINER_CREDENTIALS_FULL_URI='http://127.0.0.1:9')
                env = wrapper.clean_environment(source, oidc.make_binding(source, 'plan'))
                env.update(AWS_CONFIG_FILE=str(config), AWS_SHARED_CREDENTIALS_FILE=str(root / 'credentials'),
                           TF_CLI_CONFIG_FILE=str(cli), TF_IN_AUTOMATION='true', CHECKPOINT_DISABLE='1', TF_LOG='DEBUG')
                initialized = subprocess.run([str(TERRAFORM), 'init', '-backend=false', '-input=false', '-no-color'], cwd=root,
                                             env=env, text=True, capture_output=True, timeout=90)
                self.assertEqual(initialized.returncode, 0, initialized.stdout + initialized.stderr)
                result = subprocess.run([str(TERRAFORM), 'plan', '-input=false', '-no-color', '-lock=false', '-parallelism=1'], cwd=root,
                                        env=env, text=True, capture_output=True, timeout=45)
                if not counter.exists() and 'socket: operation not permitted' in result.stderr:
                    if os.environ.get('OIDC_REQUIRE_TERRAFORM') == '1':
                        self.fail('Terraform provider RPC Unix socket blocked by executor sandbox.')
                    self.skipTest('BLOCKED: executor denies the Terraform provider RPC Unix socket; credentials were never loaded')
                self.assertTrue(counter.exists(), result.stdout + result.stderr)
                self.assertGreaterEqual(int(counter.read_text()), 2, result.stdout + result.stderr)
                self.assertTrue(server.keys)
                self.assertTrue(all(key.startswith('ASIA') for key in server.keys), server.keys)
                self.assertNotIn('POISON_STATIC', server.keys)
                if mode.endswith('failure'):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('credential', (result.stdout + result.stderr).lower())
                    self.assertEqual(len(set(server.keys)), 1)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertGreaterEqual(len(set(server.keys)), 2, server.keys)
                    self.assertIn('123456789012', result.stdout)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_real_provider_process_chain_and_in_process_expiry_refresh(self):
        self.exercise('terraform')

    def test_real_provider_expired_refresh_failure_stops_plan(self):
        self.exercise('terraform-failure')


if __name__ == '__main__':
    unittest.main()
