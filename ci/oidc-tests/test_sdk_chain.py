"""Actual botocore credential chain/process, no AWS network calls."""
import datetime as dt
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from support import PROCESS_FIXTURE, environment, oidc, wrapper

try:
    import botocore.session
    import botocore.exceptions
except ImportError:
    botocore = None


@unittest.skipIf(botocore is None, 'botocore unavailable; add the pinned test dependency to PYTHONPATH')
class ActualSDKChain(unittest.TestCase):
    def exercise(self, mode):
        temp = tempfile.TemporaryDirectory(prefix='oidc-sdk-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        counter = root / 'count'
        config = root / 'config'
        config.write_text('[profile course-lifecycle]\nregion = ap-northeast-2\ncredential_process = '
                          f'"{sys.executable}" "{PROCESS_FIXTURE}" "{counter}" {mode}\n')
        credentials = root / 'credentials'
        credentials.write_text('')
        source = dict(os.environ, **environment(), AWS_ACCESS_KEY_ID='POISON_STATIC', AWS_SECRET_ACCESS_KEY='POISON_STATIC',
                      AWS_WEB_IDENTITY_TOKEN_FILE='/does/not/exist', AWS_CONTAINER_CREDENTIALS_FULL_URI='http://127.0.0.1:9',
                      AWS_PROFILE='poison', AWS_DEFAULT_PROFILE='poison')
        env = wrapper.clean_environment(source, oidc.make_binding(source, 'plan'))
        env.update(AWS_CONFIG_FILE=str(config), AWS_SHARED_CREDENTIALS_FILE=str(credentials))
        with patch.dict(os.environ, env, clear=True):
            session = botocore.session.Session()
            creds = session.get_credentials()
            self.assertEqual(creds.method, 'custom-process')
            first = creds.get_frozen_credentials()
            self.assertEqual(first.access_key, 'ASIA0000000000000001')
            self.assertEqual(counter.read_text(), '1')
            # Actual SDK clock only; production issuance still validates a full
            # hour. Advance close enough to make refresh mandatory.
            creds._time_fetcher = lambda: dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=3598)
            if mode.endswith('failure'):
                with self.assertRaises(botocore.exceptions.CredentialRetrievalError):
                    creds.get_frozen_credentials()
            else:
                second = creds.get_frozen_credentials()
                self.assertEqual(second.access_key, 'ASIA0000000000000002')
                self.assertNotEqual(first.token, '')
            self.assertEqual(counter.read_text(), '2')

    def test_real_process_chain_and_refresh(self):
        self.exercise('botocore')

    def test_mandatory_refresh_failure_does_not_fall_back(self):
        self.exercise('botocore-failure')


if __name__ == '__main__':
    unittest.main()
