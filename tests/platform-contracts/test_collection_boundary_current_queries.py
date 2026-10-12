"""Collection gate evidence/current query failures; fake kubectl only, no cloud calls."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
a = sys.argv[1:]
case = os.environ['BOUNDARY_CASE']
with Path(os.environ['BOUNDARY_CALLS']).open('a') as stream:
    stream.write(json.dumps(a) + '\n')
def reply(text='', rc=0):
    if text: print(text)
    sys.exit(rc)
if 'auth' in a:
    if 'pods' in a: reply('yes', 7 if case == 'pods-auth-error' else 0)
    reply('no', 7 if case == 'secret-auth-error' else (0 if case == 'no-exit-zero' else 1))
if 'exec' in a:
    reply(rc=3 if a[-2] == '10.100.0.1' else 0)
if 'apply' in a:
    if 'collection-hostpath-denied.yaml' in ' '.join(a):
        print('mount host log paths read-only', file=sys.stderr); reply(rc=1)
    reply()
if 'get' in a:
    kind = a[a.index('get') + 1]
    if kind == 'networkpolicy': reply('default-deny-egress\nallow-dns-egress\nallow-telemetry-egress')
    if kind == 'namespaces': reply('observability\nteam-platform-check', 7 if case == 'namespace-partial-error' else 0)
    if kind.startswith('deployment/'):
        reply('1', 7 if case == 'ready-partial-error' else 0)
    if kind == 'svc':
        if 'default' in a: reply('10.100.0.1', 7 if case == 'deny-partial-error' else 0)
        reply('10.100.12.34', 7 if case == 'gateway-partial-error' else 0)
print('Unsupported fixture call', file=sys.stderr)
sys.exit(88)
'''

class CollectionBoundaryCurrentQueries(unittest.TestCase):
    def run_case(self, case, missing=False):
        with tempfile.TemporaryDirectory(prefix='collection-local-fixture-') as folder:
            work = Path(folder)
            root = work / 'observability'
            (root / 'scripts').mkdir(parents=True)
            source = ROOT / 'platform/environments/dev/observability/scripts/check-collection-boundary.sh'
            shutil.copyfile(source, root / 'scripts/check-collection-boundary.sh')
            inputs = root / 'local-inputs'
            inputs.mkdir()
            evidence = inputs / 'collection-boundary-evidence.tsv'
            evidence.write_text('STALE_PRIOR_PASS')
            bindir = work / 'bin'
            bindir.mkdir()
            fake = bindir / 'kubectl'
            fake.write_text(FAKE)
            fake.chmod(0o755)
            calls = work / 'calls.jsonl'
            # Only fixture variables/PATH: never inherit AWS/GitHub credentials.
            env = {'PATH': str(bindir) + ':' + os.environ['PATH'],
                   'BOUNDARY_CASE': case, 'BOUNDARY_CALLS': str(calls),
                   'PROBE_IMAGE': ('example.invalid/probe:latest' if case == 'invalid-digest' else 'example.invalid/probe@sha256:' + 'a' * 64)}
            if not missing: env['KUBE_CONTEXT'] = 'fixture'
            result = subprocess.run(['bash', str(root / 'scripts/check-collection-boundary.sh')],
                                    env=env, capture_output=True, text=True)
            return result, evidence.read_text(), ([json.loads(row) for row in calls.read_text().splitlines()] if calls.exists() else [])

    def test_normal_no_exit_one_is_a_verified_denial(self):
        result, evidence, _ = self.run_case('valid')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('verdict\tPASS', evidence)
        self.assertNotIn('STALE_PRIOR_PASS', evidence)

    def test_partial_target_output_and_error_cannot_pass(self):
        for case in ['ready-partial-error', 'gateway-partial-error', 'deny-partial-error']:
            with self.subTest(case=case):
                result, evidence, calls = self.run_case(case)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('verdict\tINCONCLUSIVE', evidence)
                self.assertFalse(any('exec' in call for call in calls))

    def test_partial_auth_output_and_error_cannot_pass(self):
        for case in ['pods-auth-error', 'secret-auth-error', 'no-exit-zero', 'namespace-partial-error']:
            with self.subTest(case=case):
                result, evidence, _ = self.run_case(case)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('authorization incomplete:', evidence)

    def test_missing_input_invalidates_prior_evidence_without_requests(self):
        result, evidence, calls = self.run_case('valid', missing=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(evidence, '')
        self.assertEqual(calls, [])

    def test_invalid_digest_invalidates_prior_evidence_without_requests(self):
        result, evidence, calls = self.run_case('invalid-digest')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(evidence, '')
        self.assertEqual(calls, [])

if __name__ == '__main__':
    unittest.main()
