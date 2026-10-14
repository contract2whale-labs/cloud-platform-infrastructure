"""Lifecycle reuses existing protected credentials/images; never reissues them."""
import base64
import binascii
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import tempfile


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate evidence field')
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('Non-JSON evidence value')


def _verified_objects(raw, api):
    """Cosign emits arrays for signatures and JSON streams for attestations."""
    decoder = json.JSONDecoder(object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
    result = []
    try:
        remaining = raw.decode() if isinstance(raw, bytes) else raw
        while remaining.strip():
            value, end = decoder.raw_decode(remaining.lstrip())
            result.extend(value if isinstance(value, list) else [value])
            remaining = remaining.lstrip()[end:]
    except (ValueError, UnicodeError, AttributeError, TypeError):
        api.check(False, 'Malformed verified signature/attestation evidence')
    api.check(bool(result) and all(isinstance(value, dict) for value in result),
              'Empty or invalid verified signature/attestation evidence')
    return result


def credentials(c, hook, api):
    selected = c.get('retained_credentials', {}).get(hook)
    expected = {'queue-credentials-provision': {'writer', 'reader'},
                'argocd-external-secrets-provision': {'repository', 'oidc'}}[hook]
    api.check(isinstance(selected, dict) and set(selected) == expected,
              'Exact retained credential registration required')
    result = {}
    for purpose, record in selected.items():
        api.check(isinstance(record, dict) and set(record) == {'arn', 'version_id'},
                  'Credential metadata only; never values')
        arn, version = record['arn'], record['version_id']
        prefix = 'arn:aws:secretsmanager:' + c['region'] + ':' + c['account_id'] + ':secret:'
        api.check(isinstance(arn, str) and arn.startswith(prefix) and
                  re.fullmatch(r'[A-Za-z0-9/_+=.@-]+', arn[len(prefix):]) and
                  isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9-]{32,64}', version),
                  'Credential ARN/version scope differs')
        metadata = json.loads(api.ops.run(['aws', 'secretsmanager', 'describe-secret', '--secret-id', arn,
                                           '--region', c['region']]))
        stages = metadata.get('VersionIdsToStages', {})
        api.check(isinstance(stages, dict) and all(isinstance(labels, list) and
                  all(isinstance(label, str) for label in labels) for labels in stages.values()),
                  'Invalid retained credential version metadata')
        current = [version_id for version_id, labels in stages.items() if 'AWSCURRENT' in labels]
        api.check(metadata.get('ARN') == arn and not metadata.get('DeletedDate') and current == [version],
                  'Retained credential version changed/deleted')
        if hook == 'queue-credentials-provision':
            api.check(isinstance(metadata.get('Name'), str) and metadata['Name'].startswith('AmazonMSK_')
                      and metadata.get('KmsKeyId') and metadata['KmsKeyId'] != 'alias/aws/secretsmanager',
                      'Managed queue credential encryption differs')
        # Only immutable metadata is returned. Never call GetSecretValue.
        result[purpose] = {'arn': arn, 'version_id': version, 'current': True}
    return result


def _publication_descriptor(descriptor, environment, api):
    api.check(isinstance(descriptor, dict) and set(descriptor) == {'key', 'version', 'sha256'},
              'Exact immutable publication receipt descriptor required')
    api.check(all(isinstance(value, str) and value for value in descriptor.values()) and
              descriptor['version'] != 'null' and re.fullmatch(r'[0-9a-f]{64}', descriptor['sha256']),
              'Invalid publication receipt version/digest')
    api.check(re.fullmatch(r'operator-publication/' + re.escape(environment) +
                          r'/[A-Za-z0-9][A-Za-z0-9._-]*/operator-publication\.json', descriptor['key']),
              'Publication receipt namespace differs')
    return dict(descriptor)


def _signature_evidence(raw, image_digest, api):
    verified = _verified_objects(raw, api)
    for value in verified:
        critical = value.get('critical')
        api.check(isinstance(critical, dict) and isinstance(critical.get('image'), dict) and
                  critical['image'].get('docker-manifest-digest') == image_digest,
                  'Image signature digest differs')
    # These are the payloads returned by successful cryptographic verification,
    # not digests of the image or a boolean copied from the publication receipt.
    return sorted({_sha256(_canonical(value)) for value in verified})


def _spdx_evidence(raw, image_digest, api):
    envelopes, statements = set(), set()
    for envelope in _verified_objects(raw, api):
        api.check(envelope.get('payloadType') == 'application/vnd.in-toto+json' and
                  isinstance(envelope.get('payload'), str), 'Invalid verified SPDX envelope')
        signatures = envelope.get('signatures')
        api.check(isinstance(signatures, list) and signatures and all(
            isinstance(signature, dict) and isinstance(signature.get('sig'), str) and signature['sig']
            for signature in signatures), 'Verified SPDX signatures missing')
        try:
            payload = base64.b64decode(envelope['payload'], validate=True)
            statement = json.loads(payload, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
            for signature in signatures:
                api.check(bool(base64.b64decode(signature['sig'], validate=True)),
                          'Invalid verified SPDX signature encoding')
        except (ValueError, UnicodeError, binascii.Error):
            api.check(False, 'Malformed verified SPDX payload/signature')
        api.check(isinstance(statement, dict) and
                  statement.get('_type') in ('https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1')
                  and statement.get('predicateType') == 'https://spdx.dev/Document' and
                  isinstance(statement.get('predicate'), dict) and
                  statement['predicate'].get('spdxVersion') == 'SPDX-2.3',
                  'Verified attestation must contain an SPDX-2.3 statement')
        subjects = statement.get('subject')
        api.check(isinstance(subjects, list) and subjects and all(
            isinstance(subject, dict) and isinstance(subject.get('digest'), dict) and
            subject['digest'].get('sha256') == image_digest.removeprefix('sha256:')
            for subject in subjects), 'Verified SPDX subject digest differs')
        # Preserve the exact signed payload bytes, but normalize envelope object
        # and signature ordering so harmless CLI serialization changes are stable.
        normalized = dict(envelope)
        normalized['signatures'] = sorted(signatures, key=_canonical)
        envelopes.add(_sha256(_canonical(normalized)))
        statements.add(_sha256(payload))
    return {'envelope_sha256': sorted(envelopes), 'statement_sha256': sorted(statements)}


def images(c, api):
    records = c.get('retained_operator_images')
    api.check(isinstance(records, list) and records, 'Retained signed operator publication required')
    executable = shutil.which('cosign')
    api.check(executable and _sha256(pathlib.Path(executable).read_bytes()) == c['tool_sha256'].get('cosign'),
              'Pinned cosign executable required')
    result, seen = [], set()
    for row in records:
        api.check(isinstance(row, dict) and set(row) == {'image', 'signing_key_arn', 'source_sha', 'publication_receipt'},
                  'Unexpected publication fields')
        api.check(isinstance(row['image'], str) and api.ops.DIGEST.fullmatch(row['image']) and
                  isinstance(row['source_sha'], str) and re.fullmatch(r'[0-9a-f]{40}', row['source_sha']),
                  'Immutable published image/source required')
        api.check(row['image'] not in seen, 'Duplicate retained operator image')
        seen.add(row['image'])
        match = re.fullmatch(re.escape(c['account_id']) + r'\.dkr\.ecr\.' + re.escape(c['region']) +
                             r'\.amazonaws\.com/([a-z0-9][a-z0-9/_.-]*)@(sha256:[0-9a-f]{64})', row['image'])
        api.check(match, 'Operator ECR belongs to another account/region')
        repository, image_digest = match[1], match[2]
        descriptor = _publication_descriptor(row['publication_receipt'], c['_environment'], api)
        response = json.loads(api.ops.run(['aws', 'ecr', 'describe-images', '--repository-name', repository,
                                           '--image-ids', 'imageDigest=' + image_digest, '--region', c['region']]))
        details = response.get('imageDetails', [])
        api.check(len(details) == 1 and details[0].get('imageDigest') == image_digest, 'Retained operator image missing')
        key = row['signing_key_arn']
        api.check(isinstance(key, str) and re.fullmatch(r'arn:aws:kms:' + re.escape(c['region']) + ':' +
                  re.escape(c['account_id']) + r':key/[a-f0-9-]+', key), 'Signing key outside registered account/region')
        metadata = json.loads(api.ops.run(['aws', 'kms', 'describe-key', '--key-id', key,
                                           '--region', c['region']]))['KeyMetadata']
        api.check(metadata.get('Arn') == key and metadata.get('Enabled') is True and
                  metadata.get('KeyUsage') == 'SIGN_VERIFY', 'Signing key unavailable')
        spec = importlib.util.spec_from_file_location('retained_publication_store', api.ops.shared_file('saved-plan.py'))
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        store = helper.Store(c['operator_evidence_bucket'], c['account_id'])
        store.check()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'publication.json'
            store.get(descriptor, path)
            raw_publication = path.read_bytes()
            api.check(_sha256(raw_publication) == descriptor['sha256'], 'Publication receipt checksum differs')
            publication = json.loads(raw_publication, object_pairs_hook=_unique_pairs)
            api.check(publication.get('schema_version') == 1 and
                      publication.get('source_revision') == row['source_sha'] and
                      publication.get('operator_image_digest') == image_digest and
                      publication.get('account_id') == c['account_id'] and publication.get('region') == c['region'] and
                      publication.get('environment') == c['_environment'] and
                      publication.get('repository') == row['image'].split('@')[0] and
                      publication.get('signing_key_arn') == key and publication.get('signature_verified') is True and
                      publication.get('spdx_attestation_verified') is True,
                      'Publication receipt source/image/key binding differs')
            public = api.ops.run([executable, 'public-key', '--key', 'awskms:///' + key])
            api.check(isinstance(public, bytes) and public.strip(), 'Signing public key unavailable')
            pem = pathlib.Path(directory) / 'signing.pem'
            pem.write_bytes(public)
            # Resolve private ECR credentials from the ambient AWS identity in a
            # clean CI job. This does not disable registry TLS verification.
            args = ['--key', str(pem), '--insecure-ignore-tlog', '--k8s-keychain']
            signatures = _signature_evidence(api.ops.run([executable, 'verify', *args, row['image']]), image_digest, api)
            spdx = _spdx_evidence(api.ops.run([executable, 'verify-attestation', '--type', 'spdxjson',
                                             *args, row['image']]), image_digest, api)
        result.append({'image': row['image'], 'source_sha': row['source_sha'], 'signing_key_arn': key,
                       'signing_public_key_sha256': _sha256(public),
                       'publication_bucket': c['operator_evidence_bucket'], 'publication_receipt': descriptor,
                       'signature_verified': True, 'signature_payload_sha256': signatures,
                       'spdx_verified': True, 'spdx_evidence': spdx})
    return sorted(result, key=lambda value: value['image'])
