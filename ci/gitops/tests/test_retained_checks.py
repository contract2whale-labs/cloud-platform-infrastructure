"""Offline retained-asset evidence tests; all AWS/cosign/S3 calls are mocked."""
import base64
import copy
import hashlib
import json
import pathlib
import re
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import retained_checks as retained


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.executable = pathlib.Path(self.directory.name) / 'cosign'
        self.executable.write_bytes(b'pinned test executable; never executed')
        self.digest = 'sha256:' + 'a' * 64
        self.repository = '123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/database-operator'
        self.key = 'arn:aws:kms:ap-northeast-2:123456789012:key/00000000-0000-0000-0000-000000000001'
        self.row = {'image': self.repository + '@' + self.digest, 'signing_key_arn': self.key,
                    'source_sha': 'b' * 40, 'publication_receipt': {
                        'key': 'operator-publication/dev/1234/operator-publication.json',
                        'version': 'version-1', 'sha256': ''}}
        self.config = {'account_id': '123456789012', 'region': 'ap-northeast-2', '_environment': 'dev',
                       'operator_evidence_bucket': 'retained-private-evidence',
                       'retained_operator_images': [self.row],
                       'tool_sha256': {'cosign': hashlib.sha256(self.executable.read_bytes()).hexdigest()}}
        self.publication = {'schema_version': 1, 'source_revision': self.row['source_sha'],
                            'operator_image_digest': self.digest, 'account_id': self.config['account_id'],
                            'region': self.config['region'], 'environment': 'dev', 'repository': self.repository,
                            'signing_key_arn': self.key, 'signature_verified': True, 'spdx_attestation_verified': True}
        self.publish()
        self.public_key = b'PUBLIC KEY TEST FIXTURE\n'
        self.signature_payloads = [{'critical': {'image': {'docker-manifest-digest': self.digest},
                                                'identity': {'docker-reference': self.repository},
                                                'type': 'cosign container image signature'}, 'optional': None}]
        self.statement = {'_type': 'https://in-toto.io/Statement/v0.1',
                          'predicateType': 'https://spdx.dev/Document',
                          'subject': [{'name': self.repository, 'digest': {'sha256': self.digest[7:]}}],
                          'predicate': {'spdxVersion': 'SPDX-2.3', 'name': 'database-operator', 'packages': []}}
        self.envelopes = [self.envelope(self.statement)]
        self.signature_raw = None
        self.attestation_raw = None
        self.store = Mock()
        self.store.get.side_effect = lambda descriptor, path: path.write_bytes(self.publication_bytes)
        self.factory = Mock(return_value=self.store)
        self.api = types.SimpleNamespace(check=require, ops=types.SimpleNamespace(
            run=Mock(side_effect=self.run_command), DIGEST=re.compile(r'.+@sha256:[0-9a-f]{64}'),
            shared_file=Mock(return_value=ROOT.parent / 'ci' / 'saved-plan.py')))
        fake_spec = types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda module: None))
        for patcher in (
            patch.object(retained.shutil, 'which', return_value=str(self.executable)),
            patch.object(retained.importlib.util, 'spec_from_file_location', return_value=fake_spec),
            patch.object(retained.importlib.util, 'module_from_spec', return_value=types.SimpleNamespace(Store=self.factory)),
            patch('subprocess.run', side_effect=AssertionError('No live commands allowed')),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def envelope(self, statement):
        return {'payloadType': 'application/vnd.in-toto+json',
                'payload': base64.b64encode(encoded(statement)).decode(),
                'signatures': [{'keyid': '', 'sig': base64.b64encode(b'verified-signature').decode()}]}

    def publish(self):
        self.publication_bytes = encoded(self.publication)
        self.row['publication_receipt']['sha256'] = hashlib.sha256(self.publication_bytes).hexdigest()

    def run_command(self, args):
        if args[:3] == ['aws', 'ecr', 'describe-images']:
            return encoded({'imageDetails': [{'imageDigest': self.digest}]})
        if args[:3] == ['aws', 'kms', 'describe-key']:
            return encoded({'KeyMetadata': {'Arn': self.row['signing_key_arn'], 'Enabled': True, 'KeyUsage': 'SIGN_VERIFY'}})
        if args[:2] == [str(self.executable), 'public-key']:
            return self.public_key
        if args[:2] == [str(self.executable), 'verify']:
            return self.signature_raw if self.signature_raw is not None else encoded(self.signature_payloads)
        if args[:2] == [str(self.executable), 'verify-attestation']:
            return self.attestation_raw if self.attestation_raw is not None else b'\n'.join(encoded(value) for value in self.envelopes)
        raise AssertionError('Unexpected command: ' + repr(args))

    def evidence(self):
        return retained.images(self.config, self.api)[0]

    def test_exact_receipt_key_source_and_verified_evidence_are_returned(self):
        result = self.evidence()
        for field in ('image', 'source_sha', 'signing_key_arn', 'publication_receipt'):
            self.assertEqual(result[field], self.row[field])
        self.assertIsNot(result['publication_receipt'], self.row['publication_receipt'])
        self.assertEqual(result['publication_bucket'], self.config['operator_evidence_bucket'])
        self.assertEqual(result['signing_public_key_sha256'], hashlib.sha256(self.public_key).hexdigest())
        self.assertTrue(result['signature_verified'])
        self.assertTrue(result['spdx_verified'])
        self.assertEqual(len(result['signature_payload_sha256']), 1)
        self.assertEqual(len(result['spdx_evidence']['envelope_sha256']), 1)
        self.assertEqual(len(result['spdx_evidence']['statement_sha256']), 1)
        self.factory.assert_called_once_with(self.config['operator_evidence_bucket'], self.config['account_id'])
        self.store.check.assert_called_once_with()
        self.assertEqual(self.store.get.call_args.args[0], self.row['publication_receipt'])
        commands = [call.args[0] for call in self.api.ops.run.call_args_list]
        self.assertEqual([command[1] for command in commands if command[0] == str(self.executable)],
                         ['public-key', 'verify', 'verify-attestation'])
        for command in commands:
            if command[:2] in ([str(self.executable), 'verify'], [str(self.executable), 'verify-attestation']):
                self.assertIn('--k8s-keychain', command)
                self.assertIn('--insecure-ignore-tlog', command)
                self.assertFalse(any('insecure-registry' in argument for argument in command))
        self.assertNotIn(self.public_key.decode(), json.dumps(result))

    def test_publication_descriptor_version_change_changes_evidence(self):
        before = self.evidence()
        self.row['publication_receipt']['version'] = 'version-2'
        self.assertNotEqual(before, self.evidence())

    def test_publication_descriptor_key_change_changes_evidence(self):
        before = self.evidence()
        self.row['publication_receipt']['key'] = 'operator-publication/dev/5678/operator-publication.json'
        self.assertNotEqual(before, self.evidence())

    def test_publication_bucket_change_changes_evidence(self):
        before = self.evidence()
        self.config['operator_evidence_bucket'] = 'another-private-evidence-bucket'
        self.assertNotEqual(before, self.evidence())

    def test_receipt_bytes_change_changes_evidence(self):
        before = self.evidence()
        self.publication['new_metadata'] = 'new receipt'
        self.publish()
        self.assertNotEqual(before, self.evidence())

    def test_signing_key_substitution_changes_evidence_when_receipt_also_changes(self):
        before = self.evidence()
        self.row['signing_key_arn'] = self.key[:-1] + '2'
        self.publication['signing_key_arn'] = self.row['signing_key_arn']
        self.publish()
        self.assertNotEqual(before, self.evidence())

    def test_signing_key_substitution_without_receipt_rejected(self):
        self.row['signing_key_arn'] = self.key[:-1] + '2'
        with self.assertRaisesRegex(RuntimeError, 'binding differs'):
            self.evidence()

    def test_signing_public_key_change_changes_evidence(self):
        before = self.evidence()
        self.public_key = b'DIFFERENT KEY\n'
        self.assertNotEqual(before, self.evidence())

    def test_signature_verified_payload_change_changes_evidence(self):
        before = self.evidence()
        self.signature_payloads[0]['optional'] = {'source': 'different signed metadata'}
        self.assertNotEqual(before['signature_payload_sha256'], self.evidence()['signature_payload_sha256'])

    def test_spdx_payload_change_changes_evidence(self):
        before = self.evidence()
        self.statement['predicate']['packages'] = [{'name': 'new-package'}]
        self.envelopes = [self.envelope(self.statement)]
        after = self.evidence()
        self.assertNotEqual(before['spdx_evidence']['statement_sha256'], after['spdx_evidence']['statement_sha256'])
        self.assertNotEqual(before['spdx_evidence']['envelope_sha256'], after['spdx_evidence']['envelope_sha256'])

    def test_spdx_signature_change_changes_evidence(self):
        before = self.evidence()
        self.envelopes[0]['signatures'][0]['sig'] = base64.b64encode(b'new-valid-signature').decode()
        after = self.evidence()
        self.assertEqual(before['spdx_evidence']['statement_sha256'], after['spdx_evidence']['statement_sha256'])
        self.assertNotEqual(before['spdx_evidence']['envelope_sha256'], after['spdx_evidence']['envelope_sha256'])

    def test_serialization_and_verified_record_order_are_stable(self):
        self.signature_payloads.append({**self.signature_payloads[0], 'optional': {'record': 2}})
        second = copy.deepcopy(self.statement)
        second['predicate']['name'] = 'another-valid-spdx-document'
        self.envelopes.append(self.envelope(second))
        self.envelopes[0]['signatures'].append({'keyid': 'second', 'sig': base64.b64encode(b'other-signature').decode()})
        before = self.evidence()
        self.signature_raw = json.dumps(list(reversed(self.signature_payloads)), indent=2).encode()
        self.envelopes[0]['signatures'].reverse()
        self.attestation_raw = json.dumps(list(reversed(self.envelopes)), indent=2).encode()
        self.assertEqual(before, self.evidence())

    def test_invalid_or_unpinned_receipt_descriptors_rejected(self):
        valid = copy.deepcopy(self.row['publication_receipt'])
        for update in ({'version': ''}, {'version': 'null'}, {'version': 1}, {'sha256': 'g' * 64},
                       {'extra': 'unreviewed'}, {'key': 'operator-publication/prod/1234/operator-publication.json'},
                       {'key': 'operator-publication/dev/../operator-publication.json'},
                       {'key': 'operator-publication/dev/nested/1234/operator-publication.json'}):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                self.row['publication_receipt'] = {**valid, **update}
                self.evidence()
        self.assertEqual(self.store.get.call_count, 0)

    def test_publication_checksum_mismatch_rejected(self):
        self.publication_bytes += b'\n'
        with self.assertRaisesRegex(RuntimeError, 'checksum differs'):
            self.evidence()

    def test_all_publication_identity_fields_required(self):
        original = copy.deepcopy(self.publication)
        for field, value in (('schema_version', 2), ('account_id', '111111111111'), ('region', 'us-east-1'),
                             ('environment', 'prod'), ('repository', 'other'), ('source_revision', 'f' * 40),
                             ('operator_image_digest', 'sha256:' + 'f' * 64), ('signature_verified', False),
                             ('spdx_attestation_verified', False), ('signing_key_arn', self.key[:-1] + '2')):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'binding differs'):
                self.publication = {**original, field: value}
                self.publish()
                self.evidence()

    def test_wrong_image_signature_rejected_even_with_valid_signature(self):
        wrong = copy.deepcopy(self.signature_payloads[0])
        wrong['critical']['image']['docker-manifest-digest'] = 'sha256:' + 'f' * 64
        self.signature_payloads.append(wrong)
        with self.assertRaisesRegex(RuntimeError, 'signature digest differs'):
            self.evidence()

    def test_empty_malformed_or_duplicate_verified_signature_evidence_rejected(self):
        for raw in (b'', b'[]', b'null', b'[true]', b'{', b'{"critical": {}, "critical": {}}', b'{"x": NaN}'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                self.signature_raw = raw
                self.evidence()

    def test_empty_or_malformed_spdx_evidence_rejected(self):
        for raw in (b'', b'[]', b'null', b'{}', b'{', b'{"payload": "a", "payload": "b"}'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                self.attestation_raw = raw
                self.evidence()

    def test_spdx_statement_must_match_type_version_and_image(self):
        original = copy.deepcopy(self.statement)
        for update in ({'_type': 'unknown'}, {'predicateType': 'https://example.invalid/attestation'},
                       {'predicate': {'spdxVersion': 'SPDX-2.2'}}, {'subject': []},
                       {'subject': [{'digest': {'sha256': 'f' * 64}}]},
                       {'subject': original['subject'] + [{'digest': {'sha256': 'f' * 64}}]}):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                self.envelopes = [self.envelope({**original, **update})]
                self.evidence()

    def test_invalid_dsse_envelope_or_signatures_rejected(self):
        original = copy.deepcopy(self.envelopes[0])
        for update in ({'payload': 'not base64'}, {'payloadType': 'text/plain'}, {'signatures': []},
                       {'signatures': [{'sig': ''}]}, {'signatures': [{'sig': 'bad encoding'}]}):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                self.envelopes = [{**original, **update}]
                self.evidence()

    def test_failed_cosign_verification_propagates(self):
        original_run = self.run_command
        for operation in ('verify', 'verify-attestation'):
            def fail(args):
                if args[:2] == [str(self.executable), operation]:
                    raise RuntimeError('Cryptographic verification failed')
                return original_run(args)
            with self.subTest(operation=operation), self.assertRaisesRegex(RuntimeError, 'verification failed'):
                self.api.ops.run.side_effect = fail
                self.evidence()

    def test_unpinned_executable_rejected_before_network_commands(self):
        self.config['tool_sha256']['cosign'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'Pinned cosign'):
            self.evidence()
        self.api.ops.run.assert_not_called()

    def test_duplicate_retained_image_rejected(self):
        self.config['retained_operator_images'].append(copy.deepcopy(self.row))
        with self.assertRaisesRegex(RuntimeError, 'Duplicate retained operator image'):
            self.evidence()


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.hook = 'queue-credentials-provision'
        self.records = {purpose: {'arn': 'arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:AmazonMSK_' + purpose,
                                  'version_id': character * 64} for purpose, character in [('writer', 'a'), ('reader', 'b')]}
        self.config = {'account_id': '123456789012', 'region': 'ap-northeast-2',
                       'retained_credentials': {self.hook: self.records}}
        self.metadata = {record['arn']: {'ARN': record['arn'], 'Name': 'AmazonMSK_' + purpose,
                                       'KmsKeyId': 'customer-managed-key',
                                       'VersionIdsToStages': {record['version_id']: ['AWSCURRENT']}}
                         for purpose, record in self.records.items()}
        self.api = types.SimpleNamespace(check=require, ops=types.SimpleNamespace(
            run=Mock(side_effect=lambda args: encoded(self.metadata[args[4]]))))

    def evidence(self):
        return retained.credentials(self.config, self.hook, self.api)

    def test_exact_versions_returned_using_only_metadata(self):
        evidence = self.evidence()
        for purpose, record in self.records.items():
            self.assertEqual(evidence[purpose], {**record, 'current': True})
        for call in self.api.ops.run.call_args_list:
            self.assertEqual(call.args[0][:3], ['aws', 'secretsmanager', 'describe-secret'])

    def test_rotated_current_version_rejected(self):
        record = self.records['reader']
        self.metadata[record['arn']]['VersionIdsToStages'] = {record['version_id']: ['AWSPREVIOUS'], 'c' * 64: ['AWSCURRENT']}
        with self.assertRaisesRegex(RuntimeError, 'version changed/deleted'):
            self.evidence()

    def test_ambiguous_current_versions_rejected(self):
        self.metadata[self.records['reader']['arn']]['VersionIdsToStages']['c' * 64] = ['AWSCURRENT']
        with self.assertRaisesRegex(RuntimeError, 'version changed/deleted'):
            self.evidence()

    def test_registration_and_current_version_change_changes_evidence(self):
        before = self.evidence()
        record = self.records['reader']
        record['version_id'] = 'c' * 64
        self.metadata[record['arn']]['VersionIdsToStages'] = {record['version_id']: ['AWSCURRENT']}
        self.assertNotEqual(before, self.evidence())

    def test_deleted_or_wrong_arn_secret_rejected(self):
        record = self.records['reader']
        original = copy.deepcopy(self.metadata[record['arn']])
        for update in ({'DeletedDate': 123}, {'ARN': self.records['writer']['arn']}):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                self.metadata[record['arn']] = {**original, **update}
                self.evidence()

    def test_version_labels_must_be_arrays(self):
        record = self.records['reader']
        self.metadata[record['arn']]['VersionIdsToStages'] = {record['version_id']: 'AWSCURRENT'}
        with self.assertRaisesRegex(RuntimeError, 'version metadata'):
            self.evidence()

    def test_secret_values_forbidden_in_registration(self):
        self.records['reader']['value'] = 'never accept a plaintext credential'
        with self.assertRaisesRegex(RuntimeError, 'metadata only'):
            self.evidence()

    def test_external_secret_purposes_return_exact_versions(self):
        self.hook = 'argocd-external-secrets-provision'
        self.records = {'repository': self.records['writer'], 'oidc': self.records['reader']}
        self.config['retained_credentials'] = {self.hook: self.records}
        self.assertEqual(self.evidence(), {purpose: {**record, 'current': True} for purpose, record in self.records.items()})


if __name__ == '__main__':
    unittest.main()
