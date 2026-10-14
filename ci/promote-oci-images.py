#!/usr/bin/env python3
"""CI-only two-account promotion. Skopeo preserves raw manifests and all blobs."""
import argparse
import base64
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

SKOPEO_IMAGE = 'quay.io/skopeo/stable@sha256:97772f3c64fd2fba720b2bafaf37239dc44d8b1c625c8383c64044832efe9ed9'
APPS = ('commerce-web', 'commerce-api')
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
FILE = re.compile(r'^(?:version|manifest\.json|[0-9a-f]{64}(?:\.manifest\.json)?)$')
INDEX = {'application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'}
MANIFEST = {'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'}
MAX_BUNDLE = 4 * 1024**3

class PromotionError(Exception):
    pass

def need(condition, message):
    if not condition:
        raise PromotionError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()

def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, **kwargs)
    need(result.returncode == 0, 'An approved tool/API check failed; preserve private evidence before retrying.')
    return result.stdout

def validate_request(request, repositories, now):
    need(set(request) == {'schema', 'environment', 'created_at', 'expires_at', 'tag', 'images'}, 'Unexpected promotion request fields.')
    need(request['schema'] == 1 and request['environment'] == 'prod', 'Only the reviewed Prod promotion request is accepted.')
    need(type(request['created_at']) is int and type(request['expires_at']) is int, 'UTC epoch times are required.')
    need(request['created_at'] <= now + 300 and now < request['expires_at'] <= request['created_at'] + 86400, 'Promotion request is expired or outside its one-day window.')
    need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', request['tag']) is not None, 'An exact version release tag is required.')
    need(set(request['images']) == set(APPS) and set(repositories) == set(APPS), 'Exactly the two registered application repositories are required.')
    for app in APPS:
        item = request['images'][app]
        need(set(item) == {'repository', 'sha', 'digest', 'publish_run_id'}, 'Unexpected image request fields.')
        need(item['repository'] == repositories[app] and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', item['repository']) is not None, 'Source repository is not registered.')
        need(SHA.fullmatch(item['sha']) is not None and DIGEST.fullmatch(item['digest']) is not None and item['digest'] != 'sha256:' + '0' * 64, 'Exact source SHA and non-example digest are required.')
        need(type(item['publish_run_id']) is int and item['publish_run_id'] > 0, 'A successful source publication run is required.')

def validate_publish_run(run, item):
    need(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Source publication has not succeeded.')
    need(run.get('head_branch') == 'main' and run.get('head_sha') == item['sha'] and run.get('event') == 'push', 'Source publication does not match the approved main SHA.')
    need(run.get('path', '').split('@')[0] == '.github/workflows/ci.yml' and run.get('repository', {}).get('full_name') == item['repository'], 'Unexpected source publication workflow/repository.')

def immutable_tag(repository, tag):
    mode = repository.get('imageTagMutability')
    if mode == 'IMMUTABLE':
        return True
    if mode != 'IMMUTABLE_WITH_EXCLUSION':
        return False
    filters = repository.get('imageTagMutabilityExclusionFilters', [])
    return all(item.get('filterType') == 'WILDCARD' and not fnmatch.fnmatchcase(tag, item.get('filter', '*')) for item in filters)

def verify_directory(directory, expected_digest):
    """Validate the complete containers/image dir transport graph, not just its index."""
    need(DIGEST.fullmatch(expected_digest) is not None, 'Invalid requested digest.')
    need(directory.is_dir() and not directory.is_symlink(), 'Missing protected image directory.')
    files = {}
    for path in directory.iterdir():
        need(path.is_file() and not path.is_symlink() and FILE.fullmatch(path.name) is not None, 'Unexpected archive member.')
        need(path.stat().st_size <= MAX_BUNDLE, 'Image file exceeds transfer limit.')
        files[path.name] = path
    need('version' in files and files['version'].read_bytes() == b'Directory Transport Version: 1.1\n', 'Unsupported Skopeo directory format.')
    visited, objects, platforms = {'version'}, [], []
    def object_file(name, digest, size=None):
        need(name in files and DIGEST.fullmatch(digest) is not None, 'A referenced image object is missing.')
        path = files[name]
        need(file_hash(path) == digest[7:], 'Image object digest differs.')
        need(size is None or (type(size) is int and size >= 0 and path.stat().st_size == size), 'Image object size differs.')
        if name not in visited:
            visited.add(name)
            objects.append({'file': name, 'digest': digest, 'size': path.stat().st_size})
        return path
    def descend(name, digest, size=None, depth=0):
        need(depth <= 16, 'Manifest nesting exceeds the allowed limit.')
        path = object_file(name, digest, size)
        need(path.stat().st_size <= 4 * 1024**2, 'Manifest exceeds its size limit.')
        value = json.loads(path.read_bytes())
        need(value.get('schemaVersion') == 2, 'Unsupported image schema.')
        media = value.get('mediaType')
        if media in INDEX:
            need(isinstance(value.get('manifests'), list) and bool(value['manifests']), 'Empty image index.')
            for child in value['manifests']:
                need(not child.get('urls') and DIGEST.fullmatch(child.get('digest', '')) is not None, 'External or malformed image descriptor.')
                if child.get('platform'):
                    platforms.append(child['platform'])
                descend(child['digest'][7:] + '.manifest.json', child['digest'], child['size'], depth + 1)
        else:
            need(media in MANIFEST, 'Unsupported manifest media type.')
            need(isinstance(value.get('config'), dict) and isinstance(value.get('layers'), list), 'Malformed image manifest.')
            for child in [value['config']] + value['layers']:
                need(not child.get('urls') and DIGEST.fullmatch(child.get('digest', '')) is not None, 'External or malformed blob descriptor.')
                object_file(child['digest'][7:], child['digest'], child['size'])
    descend('manifest.json', expected_digest)
    need(set(files) == visited, 'Unreferenced objects must not cross the account boundary.')
    return {'digest': expected_digest, 'objects': sorted(objects, key=lambda x: x['file']), 'platforms': platforms}

def pack_payload(source, archive):
    with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for app in APPS:
            for path in sorted((source / app).iterdir()):
                need(path.is_file() and not path.is_symlink() and FILE.fullmatch(path.name), 'Unsafe source file.')
                tar.add(path, arcname=app + '/' + path.name, recursive=False)
        tar.add(source / 'dev-signing-public.pem', arcname='dev-signing-public.pem', recursive=False)
    need(archive.stat().st_size <= MAX_BUNDLE, 'Image bundle exceeds the 4 GiB course limit.')

def unpack_payload(archive, target):
    need(archive.stat().st_size <= MAX_BUNDLE and not target.exists(), 'Invalid archive size or destination.')
    target.mkdir(mode=0o700)
    seen, total = set(), 0
    with tarfile.open(archive, 'r:') as tar:
        for entry in tar:
            parts = entry.name.split('/')
            permitted = entry.name == 'dev-signing-public.pem' or (len(parts) == 2 and parts[0] in APPS and FILE.fullmatch(parts[1]))
            need(permitted and entry.isfile() and entry.name not in seen and not entry.pax_headers, 'Unsafe or duplicate archive member.')
            need(entry.size >= 0 and (entry.name != 'dev-signing-public.pem' or entry.size <= 16384), 'Invalid archive member size.')
            total += entry.size
            need(total <= MAX_BUNDLE, 'Expanded bundle exceeds its limit.')
            seen.add(entry.name)
            destination = target / entry.name
            destination.parent.mkdir(exist_ok=True, mode=0o700)
            with tar.extractfile(entry) as stream, destination.open('xb') as output:
                while block := stream.read(1024**2):
                    output.write(block)
            destination.chmod(0o600)
    need('dev-signing-public.pem' in seen, 'Source signing public key is missing.')

def verified_attestation(raw, digest):
    values = []
    for line in raw.decode().splitlines():
        item = json.loads(line)
        values.extend(item if isinstance(item, list) else [item])
    for envelope in values:
        statement = json.loads(base64.b64decode(envelope['payload'], validate=True))
        if statement.get('predicate', {}).get('spdxVersion') == 'SPDX-2.3' and any(s.get('digest', {}).get('sha256') == digest[7:] for s in statement.get('subject', [])):
            return True
    return False

def verify_wrong_key_failure(returncode, stdout, stderr):
    need(returncode != 0 and b'no matching signatures' in (stdout + stderr).lower(), 'Wrong-key check is inconclusive or unexpectedly succeeded.')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['export', 'import'])
    parser.add_argument('--request', required=True)
    parser.add_argument('--manifest-version')
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    os.umask(0o077)
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Run only in the approved main workflow.')
    need(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Explicit promotion dispatch is required.')
    need(re.fullmatch(r'operations/promotions/[a-z0-9-]+\.json', args.request) is not None, 'Request must be a reviewed promotion source file.')
    repo = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    request_path = repo / args.request
    need(not request_path.is_symlink() and not any(p.is_symlink() for p in request_path.parents if p != repo and repo in p.parents), 'Symlink request is forbidden.')
    command(['git', '-c', 'safe.directory=' + str(repo), 'ls-files', '--error-unmatch', args.request], cwd=repo)
    command(['git', '-c', 'safe.directory=' + str(repo), 'diff', '--exit-code'], cwd=repo)
    command(['git', '-c', 'safe.directory=' + str(repo), 'diff', '--cached', '--exit-code'], cwd=repo)
    revision = os.environ['GITHUB_SHA']
    need(SHA.fullmatch(revision) is not None and command(['git', '-c', 'safe.directory=' + str(repo), 'rev-parse', 'HEAD'], cwd=repo).decode().strip() == revision, 'Checkout differs from the approved workflow source.')
    region = os.environ['AWS_REGION']
    dev, prod = os.environ['DEV_ACCOUNT_ID'], os.environ['PROD_ACCOUNT_ID']
    need(region == 'ap-northeast-2' and dev != prod and all(re.fullmatch(r'\d{12}', x) for x in (dev, prod)), 'Distinct approved Dev/Prod accounts and Seoul region are required.')
    request_bytes = request_path.read_bytes()
    request = json.loads(request_bytes)
    repositories = json.loads(os.environ['SOURCE_REPOSITORIES_JSON'])
    validate_request(request, repositories, int(time.time()))
    def github(path):
        req = urllib.request.Request('https://api.github.com/' + path, headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    need(github('repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/ref/heads/main')['object']['sha'] == revision, 'Main changed after approval; review a new promotion attempt.')
    import boto3
    from botocore.exceptions import ClientError
    account = dev if args.phase == 'export' else prod
    need(boto3.client('sts').get_caller_identity()['Account'] == account, 'CI assumed a role in the wrong account.')
    ecr, s3, kms = (boto3.client(service, region_name=region) for service in ('ecr', 's3', 'kms'))
    signing_key = os.environ['SIGNING_KEY_ARN']
    need(re.fullmatch(r'arn:aws:kms:ap-northeast-2:' + account + r':key/[a-zA-Z0-9-]+', signing_key) is not None, 'Signing key is outside the current account.')
    key = kms.describe_key(KeyId=signing_key)['KeyMetadata']
    need(key['KeyState'] == 'Enabled' and key['KeyUsage'] == 'SIGN_VERIFY' and key['KeySpec'] == 'ECC_NIST_P256', 'Enabled ECC signing key required.')
    bucket, owner, encryption = os.environ['PROMOTION_BUCKET'], os.environ['PROMOTION_BUCKET_OWNER'], os.environ['PROMOTION_KMS_KEY_ARN']
    need(owner == dev and re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket), 'Protected Dev-owned transfer bucket required.')
    need(re.fullmatch(r'arn:aws:kms:ap-northeast-2:' + owner + r':key/[a-zA-Z0-9-]+', encryption), 'Transfer encryption key differs from the approved owner.')
    context = {'repository': os.environ['GITHUB_REPOSITORY'], 'repository_id': os.environ['GITHUB_REPOSITORY_ID'], 'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'sha': revision, 'request_sha256': sha(request_bytes), 'dev_account': dev, 'prod_account': prod}
    need(all(re.fullmatch(r'[0-9]+', context[k]) for k in ('repository_id', 'run_id', 'run_attempt')), 'Invalid workflow execution identifiers.')
    prefix = 'oci-promotions/' + '/'.join(context[k] for k in ('repository_id', 'run_id', 'run_attempt', 'sha', 'request_sha256')) + '/'
    work_parent = repo / 'work/protected/oci-promotion'
    work_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    def put(path, key):
        need(path.stat().st_size <= MAX_BUNDLE, 'Evidence object exceeds its limit.')
        with path.open('rb') as body:
            result = s3.put_object(Bucket=bucket, ExpectedBucketOwner=owner, Key=key, Body=body, ServerSideEncryption='aws:kms', SSEKMSKeyId=encryption, BucketKeyEnabled=False, IfNoneMatch='*')
        need(result.get('VersionId') not in (None, '', 'null'), 'Versioned private evidence is required.')
        return {'key': key, 'version': result['VersionId'], 'sha256': file_hash(path)}
    def get(descriptor, expected_key, target):
        need(descriptor.get('key') == expected_key and descriptor.get('version') not in (None, '', 'null') and re.fullmatch(r'[0-9a-f]{64}', descriptor.get('sha256', '')), 'Wrong protected evidence descriptor.')
        response = s3.get_object(Bucket=bucket, ExpectedBucketOwner=owner, Key=expected_key, VersionId=descriptor['version'])
        need(response.get('VersionId') == descriptor['version'] and response.get('ServerSideEncryption') == 'aws:kms' and response.get('SSEKMSKeyId') == encryption and response['ContentLength'] <= MAX_BUNDLE, 'Private evidence version, encryption, or size differs.')
        with target.open('xb') as output:
            for block in iter(lambda: response['Body'].read(1024**2), b''):
                output.write(block)
        need(file_hash(target) == descriptor['sha256'], 'Private evidence checksum differs.')
    with tempfile.TemporaryDirectory(prefix=args.phase + '-', dir=work_parent) as temporary:
        work = Path(temporary)
        authdir = work / 'auth'; authdir.mkdir()
        registry = account + '.dkr.ecr.' + region + '.amazonaws.com'
        auth = ecr.get_authorization_token(registryIds=[account])['authorizationData']
        need(len(auth) == 1 and auth[0]['proxyEndpoint'] == 'https://' + registry, 'Unexpected ECR authentication endpoint.')
        authfile = authdir / 'config.json'
        authfile.write_text(json.dumps({'auths': {registry: {'auth': auth[0]['authorizationToken']}}}))
        os.environ['DOCKER_CONFIG'] = str(authdir)
        def skopeo(*params):
            return command(['docker', 'run', '--rm', '--user', '0:0', '--entrypoint', 'skopeo', '-v', str(work) + ':' + str(work), SKOPEO_IMAGE, *params])
        need(skopeo('--version').decode().startswith('skopeo version '), 'Pinned Skopeo image is unavailable.')
        def copy(source, destination):
            skopeo('copy', '--all', '--preserve-digests', '--authfile', str(authfile), source, destination)
        def inspect(reference):
            return skopeo('inspect', '--raw', '--authfile', str(authfile), 'docker://' + reference)
        def verify(reference, digest):
            flags = ['--key', 'awskms:///' + signing_key, '--insecure-ignore-tlog']
            command(['cosign', 'verify', *flags, reference])
            raw = command(['cosign', 'verify-attestation', *flags, '--type', 'spdxjson', reference])
            need(verified_attestation(raw, digest), 'Verified SBOM is not SPDX-2.3 for the approved digest.')
        def check_repository(app, tag):
            meta = ecr.describe_repositories(repositoryNames=[app])['repositories']
            need(len(meta) == 1 and meta[0]['repositoryUri'] == registry + '/' + app and immutable_tag(meta[0], tag), 'Release/source tags must be immutable in the registered ECR.')
        inventories = {}
        if args.phase == 'export':
            payload = work / 'payload'; payload.mkdir()
            public_key = command(['cosign', 'public-key', '--key', 'awskms:///' + signing_key])
            need(public_key.startswith(b'-----BEGIN PUBLIC KEY-----'), 'Source public verification key is unavailable.')
            (payload / 'dev-signing-public.pem').write_bytes(public_key)
            for app in APPS:
                item = request['images'][app]
                validate_publish_run(github('repos/' + item['repository'] + '/actions/runs/' + str(item['publish_run_id'])), item)
                build_tag = 'build-' + item['sha'][:12]
                check_repository(app, build_tag)
                detail = ecr.describe_images(repositoryName=app, imageIds=[{'imageTag': build_tag}])['imageDetails']
                need(len(detail) == 1 and detail[0]['imageDigest'] == item['digest'], 'Source build tag differs from its approved digest.')
                reference = registry + '/' + app + '@' + item['digest']
                need('sha256:' + sha(inspect(reference)) == item['digest'], 'Remote source manifest differs.')
                verify(reference, item['digest'])
                copy('docker://' + reference, 'dir:' + str(payload / app))
                inventories[app] = verify_directory(payload / app, item['digest'])
            archive = work / 'payload.tar'; pack_payload(payload, archive)
            descriptor = put(archive, prefix + 'export/payload.tar')
            manifest = {'schema': 1, 'kind': 'verified-dev-export', 'context': context, 'request': request, 'inventory': inventories, 'payload': descriptor, 'created_at': int(time.time()), 'expires_at': request['expires_at'], 'skopeo_image': SKOPEO_IMAGE}
            manifest_file = work / 'manifest.json'; manifest_file.write_text(json.dumps(manifest, sort_keys=True))
            result = put(manifest_file, prefix + 'export/manifest.json')
        else:
            manifest_file = work / 'manifest.json'
            get({'key': prefix + 'export/manifest.json', 'version': args.manifest_version, 'sha256': args.manifest_sha256}, prefix + 'export/manifest.json', manifest_file)
            manifest = json.loads(manifest_file.read_bytes())
            need(manifest.get('schema') == 1 and manifest.get('kind') == 'verified-dev-export' and manifest.get('context') == context and manifest.get('request') == request and manifest.get('skopeo_image') == SKOPEO_IMAGE, 'Export provenance differs from this approved workflow attempt.')
            need(int(time.time()) < manifest.get('expires_at', 0) == request['expires_at'], 'Private export has expired.')
            archive = work / 'payload.tar'; get(manifest['payload'], prefix + 'export/payload.tar', archive)
            payload = work / 'payload'; unpack_payload(archive, payload)
            for app in APPS:
                item = request['images'][app]
                inventories[app] = verify_directory(payload / app, item['digest'])
                need(inventories[app] == manifest['inventory'][app], 'Image graph differs from verified Dev export.')
                check_repository(app, request['tag'])
                try:
                    details = ecr.describe_images(repositoryName=app, imageIds=[{'imageTag': request['tag']}])['imageDetails']
                except ClientError as error:
                    if error.response['Error']['Code'] != 'ImageNotFoundException':
                        raise
                    details = []
                need(not details or (len(details) == 1 and details[0]['imageDigest'] == item['digest']), 'Existing immutable Prod release tag has a different digest.')
                reference = registry + '/' + app + '@' + item['digest']
                need(int(time.time()) < request['expires_at'], 'Approval expired before import.')
                if not details:
                    copy('dir:' + str(payload / app), 'docker://' + registry + '/' + app + ':' + request['tag'])
                need('sha256:' + sha(inspect(registry + '/' + app + ':' + request['tag'])) == item['digest'], 'Prod top-level digest differs after import.')
                # A second pull checks every uploaded platform/blob, not only the tag.
                copied = work / (app + '-verified')
                copy('docker://' + reference, 'dir:' + str(copied))
                need(verify_directory(copied, item['digest']) == inventories[app], 'Prod image graph differs after import.')
                # A failed verifier is never permission to overwrite signature evidence.
                signature_tags = ['sha256-' + item['digest'][7:] + suffix for suffix in ('.sig', '.att')]
                existing = []
                for tag in signature_tags:
                    try:
                        evidence = ecr.describe_images(repositoryName=app, imageIds=[{'imageTag': tag}])['imageDetails']
                        existing.append(bool(evidence))
                    except ClientError as error:
                        if error.response['Error']['Code'] != 'ImageNotFoundException':
                            raise
                        existing.append(False)
                need(existing in ([False, False], [True, True]), 'Partial signature publication exists; investigate instead of overwriting it.')
                if all(existing):
                    verify(reference, item['digest'])
                else:
                    need(int(time.time()) < request['expires_at'], 'Approval expired before signing.')
                    sbom = work / (app + '.spdx.json')
                    sbom.write_bytes(command(['syft', reference, '-o', 'spdx-json']))
                    need(json.loads(sbom.read_bytes()).get('spdxVersion') == 'SPDX-2.3', 'Generated SBOM must use SPDX-2.3.')
                    flags = ['--key', 'awskms:///' + signing_key, '--tlog-upload=false', '--use-signing-config=false', '--new-bundle-format=false', '--yes']
                    command(['cosign', 'sign', *flags, reference])
                    command(['cosign', 'attest', *flags, '--type', 'spdxjson', '--predicate', str(sbom), reference])
                    verify(reference, item['digest'])
                negative = subprocess.run(['cosign', 'verify', '--key', str(payload / 'dev-signing-public.pem'), '--insecure-ignore-tlog', reference], capture_output=True)
                verify_wrong_key_failure(negative.returncode, negative.stdout, negative.stderr)
            receipt = work / 'receipt.json'
            receipt.write_text(json.dumps({'schema': 1, 'kind': 'verified-prod-import', 'context': context, 'request': request, 'inventory': inventories, 'dev_export': {'version': args.manifest_version, 'sha256': args.manifest_sha256}, 'completed_at': int(time.time()), 'prod_signing_key': signing_key}, sort_keys=True))
            result = put(receipt, prefix + 'import/receipt.json')
        # Only object version/hash go to job outputs; detailed payload stays private.
        (work_parent / (args.phase + '-result.json')).write_text(json.dumps(result))
    print('Private OCI promotion phase verified; inspect its protected receipt.')

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Promotion stopped. Preserve this attempt and inspect approved inputs/private evidence; partial publication may exist.', file=sys.stderr)
        sys.exit(2)
