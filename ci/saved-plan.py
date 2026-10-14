#!/usr/bin/env python3
"""Version-pinned private S3 plans. Never print subprocess output in Actions."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading

TTL_SECONDS = 4 * 60 * 60
ENCRYPTION = {"AES256", "aws:kms", "aws:kms:dsse"}


class SafeError(Exception):
    """Only fixed, non-sensitive diagnostics may reach the public runner log."""


def require(ok, message):
    if not ok:
        raise SafeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def required(name):
    value = os.environ.get(name, "")
    require(bool(value), "A required CI setting is missing: " + name)
    return value


def execute(args, *, cwd=None, log=None):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if log:
        Path(log).write_bytes(result.stdout + b"\n" + result.stderr)
    require(result.returncode == 0, "A private command failed; inspect the private diagnostic object.")
    return result.stdout


def aws(service, operation, *args):
    raw = execute(["aws", service, operation, *args, "--output", "json", "--no-cli-pager"])
    return json.loads(raw or b"{}")


def select_root(workspace, value):
    require(bool(re.fullmatch(r"terraform/environments/(dev|prod)/[a-z0-9][a-z0-9/_-]*", value)), "Invalid root path.")
    require(".." not in value.split("/"), "Invalid root path.")
    rows = json.loads((workspace / "ci/roots.json").read_text())["roots"]
    rows = [row for row in rows if row.get("path") == value]
    require(len(rows) == 1, "Root must be registered exactly once.")
    env = value.split("/")[2]
    require(rows[0].get("env") == env, "Root and environment do not match.")
    root = workspace / value
    require(root.is_dir() and root.resolve().is_relative_to(workspace.resolve()), "Root directory is missing or outside checkout.")
    return env, "/".join(value.split("/")[3:]) + "/terraform.tfstate"


def emit(values):
    with open(required("GITHUB_OUTPUT"), "a", encoding="utf-8") as output:
        for key, value in values.items():
            require("\n" not in str(value) and "\r" not in str(value), "Invalid job output.")
            output.write(f"{key}={value}\n")


def check_identity(account, role):
    require(bool(re.fullmatch(r"\d{12}", account)), "Invalid account setting.")
    match = re.fullmatch(r"arn:(aws(?:-[a-z]+)*):iam::(\d{12}):role/(.+)", role)
    require(match is not None and match[2] == account, "Role and account settings do not match.")
    identity = aws("sts", "get-caller-identity")
    prefix = f"arn:{match[1]}:sts::{account}:assumed-role/{match[3].split('/')[-1]}/"
    require(identity.get("Account") == account and identity.get("Arn", "").startswith(prefix), "Unexpected AWS account or assumed role.")
    return identity["Arn"]


class Store:
    def __init__(self, bucket, owner):
        self.bucket, self.owner = bucket, owner

    def call(self, operation, *args):
        return aws("s3api", operation, "--bucket", self.bucket, "--expected-bucket-owner", self.owner, *args)

    def check(self):
        require(self.call("get-bucket-versioning").get("Status") == "Enabled", "State bucket versioning must be Enabled.")
        block = self.call("get-public-access-block").get("PublicAccessBlockConfiguration", {})
        require(all(block.get(k) is True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")), "All four bucket public-access blocks must be enabled.")
        rules = self.call("get-bucket-encryption").get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        require(any(r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") in ENCRYPTION for r in rules), "Bucket default encryption is required.")

    def put(self, key, path):
        response = self.call("put-object", "--key", key, "--body", str(path), "--if-none-match", "*")
        version = response.get("VersionId")
        require(bool(version) and version != "null", "Upload did not create a versioned object.")
        require(response.get("ServerSideEncryption") in ENCRYPTION, "Upload encryption was not verified.")
        return {"key": key, "version": version, "sha256": digest(path.read_bytes())}

    def get(self, descriptor, path):
        require(bool(descriptor.get("version")) and descriptor["version"] != "null", "An exact object version is required.")
        result = self.call("get-object", "--key", descriptor["key"], "--version-id", descriptor["version"], str(path))
        require(result.get("VersionId") == descriptor["version"] and result.get("ServerSideEncryption") in ENCRYPTION, "Object version or encryption does not match.")
        require(digest(path.read_bytes()) == descriptor["sha256"], "Private object checksum mismatch.")

    def state(self, key):
        # List first: 403 or other failures must never be mistaken for a new State.
        listed = self.call("list-objects-v2", "--prefix", key, "--max-keys", "2")
        if not any(item.get("Key") == key for item in listed.get("Contents", [])):
            return {"exists": False}
        info = self.call("head-object", "--key", key)
        return {"exists": True, "version": info.get("VersionId"), "etag": info["ETag"], "size": info["ContentLength"]}


def ensure_current_main(context):
    remote = execute(["gh", "api", "repos/" + required("GITHUB_REPOSITORY") + "/git/ref/heads/main", "--jq", ".object.sha"]).decode().strip()
    require(remote == context["sha"], "A newer main commit exists; this stale root run will not deploy.")


def validate_effective_inputs(plan_json, context):
    expected = {"state_bucket_name": context["backend"]["bucket"], "region": context["backend"]["region"], "expected_account_id": context["account"], "environment": context["environment"]}
    # Inspect Terraform's effective values, including any tracked auto.tfvars overrides.
    variables = plan_json.get("variables", {})
    for key, value in expected.items():
        if key in variables:
            require(variables[key].get("value") == value, "Effective Terraform target input does not match the protected CI environment: " + key)


def read_state_memory(store, key):
    """Stream S3 State into an anonymous pipe, never a disk file or runner log."""
    read_fd, write_fd = os.pipe()
    chunks = []
    def drain():
        with os.fdopen(read_fd, "rb") as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    reader = threading.Thread(target=drain)
    reader.start()
    process = None
    try:
        # /proc/self/fd addresses this inherited anonymous pipe on the Linux runner.
        process = subprocess.Popen([
            "aws", "s3api", "get-object", "--bucket", store.bucket,
            "--expected-bucket-owner", store.owner, "--key", key,
            f"/proc/self/fd/{write_fd}", "--output", "json", "--no-cli-pager"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(write_fd,))
    finally:
        os.close(write_fd)
        if process is None:
            reader.join()
    metadata_raw, _private_error = process.communicate()
    reader.join()
    require(process.returncode == 0, "Apply succeeded but post-State collection failed; no completion receipt was published.")
    metadata = json.loads(metadata_raw)
    require(metadata.get("ServerSideEncryption") in ENCRYPTION, "Post-State encryption was not verified.")
    state = json.loads(b"".join(chunks))
    require(isinstance(state.get("lineage"), str) and bool(state["lineage"]) and type(state.get("serial")) is int and state["serial"] >= 0, "Invalid post-State lineage or serial.")
    fingerprint = {"exists": True, "version": metadata.get("VersionId"), "etag": metadata["ETag"], "size": metadata["ContentLength"]}
    require(bool(fingerprint["version"]) and fingerprint["version"] != "null", "Post-State must have an exact S3 version.")
    return {"version": fingerprint["version"], "etag": fingerprint["etag"], "lineage": state["lineage"], "serial": state["serial"]}, fingerprint


def validate_manifest(manifest, context, plan_sha, now):
    require(manifest.get("schema") == 1 and manifest.get("kind") == "plan", "Only a main deployment manifest can be applied.")
    require(manifest.get("context") == context, "Approved plan context or inputs changed.")
    require(manifest.get("plan", {}).get("sha256") == plan_sha, "Plan digest does not match the plan job.")
    created, expires = manifest.get("created_at", 0), manifest.get("expires_at", 0)
    require(isinstance(created, int) and isinstance(expires, int) and created <= now < expires and expires - created == TTL_SECONDS, "Saved plan expired or has invalid timestamps; create a new run.")
    prefix = manifest["context"]["prefix"]
    for name, filename in (("plan", "change.tfplan"), ("review", "review.txt")):
        item = manifest.get(name, {})
        require(item.get("key") == prefix + filename and bool(item.get("version")) and item["version"] != "null", "Private object is outside the approved run.")
        require(bool(re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))), "Invalid object digest.")


def normalized_root_inputs(source, relative, environment, account, region):
    """Only the retained BU03 storage root has target-derived non-secret defaults.

    Never default an absent/malformed TF_VARS_JSON document or another root.
    Explicit storage input values must equal the protected target boundaries.
    """
    require(isinstance(source, dict), "TF_VARS_JSON must be an object.")
    if relative == "network/log-storage":
        defaults = {"expected_account_id": account, "region": region, "environment": environment}
        explicit = source.get(relative, {})
        require(isinstance(explicit, dict) and set(explicit) <= set(defaults), "Invalid retained log-storage input object.")
        require(all(value == defaults[key] for key, value in explicit.items()), "Log-storage input override differs from the protected CI target.")
        return {**defaults, **explicit}
    require(relative in source and isinstance(source[relative], dict), "TF_VARS_JSON must contain an object for this root.")
    return dict(source[relative])


def prepare(workspace, temp, mode):
    root_path = required("ROOT_PATH")
    env, key = select_root(workspace, root_path)
    require(required("STATE_KEY") == key, "State key does not match the registered root.")
    if mode == "preview":
        require(bool(re.fullmatch(r"refs/pull/\d+/merge", required("GITHUB_REF"))), "Preview requires a pull-request merge ref.")
    else:
        require(required("GITHUB_REF") == "refs/heads/main", "Only main may deploy.")
    sha = required("GITHUB_SHA")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", sha)), "Invalid checkout SHA.")
    require(execute(["git", "rev-parse", "HEAD"], cwd=workspace).decode().strip() == sha, "Checkout SHA mismatch.")
    repo_id, run, attempt = (required(k) for k in ("GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    require(all(v.isdigit() for v in (repo_id, run, attempt)), "Invalid run identity.")
    account, region, bucket = (required(k) for k in ("EXPECTED_ACCOUNT_ID", "AWS_REGION", "STATE_BUCKET"))
    role = required("AWS_ROLE_ARN")
    caller = check_identity(account, role)
    apply_role = required("EXPECTED_APPLY_ROLE_ARN") if mode in ("plan", "preview", "audit") else role
    require(bool(re.fullmatch(r"arn:aws(?:-[a-z]+)*:iam::" + account + r":role/.+", apply_role)), "Invalid expected apply role.")
    require(not any(k.startswith("TF_VAR_") or k.startswith("TF_CLI_ARGS") for k in os.environ), "Unapproved Terraform environment inputs are present.")
    require(os.environ.get("TF_WORKSPACE", "default") == "default", "Only the default Terraform workspace is supported.")
    source = json.loads(required("TF_VARS_JSON"))
    relative = key.removesuffix("/terraform.tfstate")
    normalized = normalized_root_inputs(source, relative, env, account, region)
    root = workspace / root_path
    input_files = {}
    for path in sorted(root.glob("*")):
        if path.name in ("terraform.tfvars", "terraform.tfvars.json"):
            raise SafeError("Do not commit or pre-create terraform.tfvars files; use the protected root input.")
        if path.name.endswith((".auto.tfvars", ".auto.tfvars.json")):
            execute(["git", "ls-files", "--error-unmatch", str(path.relative_to(workspace))], cwd=workspace)
            input_files[path.name] = digest(path.read_bytes())
    validate_effective_inputs({"variables": {k: {"value": v} for k, v in normalized.items()}}, {"backend": {"bucket": bucket, "region": region}, "account": account, "environment": env})
    inputs = canonical(normalized)
    (root / "terraform.tfvars.json").write_bytes(inputs)
    backend = {"bucket": bucket, "key": key, "region": region, "encrypt": True, "use_lockfile": True, "allowed_account_ids": [account]}
    backend_path = temp / "backend.hcl"
    backend_path.write_text("\n".join(f"{k} = {json.dumps(v)}" for k, v in backend.items()) + "\n")
    lock = root / ".terraform.lock.hcl"
    require(lock.is_file(), "A reviewed provider lock file must be committed.")
    execute(["git", "ls-files", "--error-unmatch", str(lock.relative_to(workspace))], cwd=workspace)
    version = json.loads(execute(["terraform", "version", "-json"]))["terraform_version"]
    require(version == "1.16.0", "Unexpected Terraform version.")
    prefix = f"ci-plans/{repo_id}/{run}/{attempt}/{sha}/{env}/{relative}/"
    context = {"repository": required("GITHUB_REPOSITORY"), "repository_id": repo_id, "run_id": run, "run_attempt": attempt, "sha": sha, "root": root_path, "environment": env, "account": account, "backend": backend, "workspace": "default", "terraform_version": version, "lock_sha256": digest(lock.read_bytes()), "input_sha256": digest(inputs), "tracked_auto_inputs": input_files, "apply_role_arn": apply_role, "prefix": prefix}
    store = Store(bucket, account)
    store.check()
    return root, backend_path, context, store, caller


def upstream_states(store, context, workspace):
    graph = json.loads((workspace / "ci/deploy-roots.json").read_text())["dependencies"]
    require(context["root"] in graph, "Root is missing from the dependency registry.")
    return {p: store.state("/".join(p.split("/")[3:]) + "/terraform.tfstate") for p in graph[context["root"]]}



def refresh_profile_guard(root=None):
    """Admit only the fixed same-job rc; normal non-lifecycle CI is unchanged."""
    if os.environ.get("AWS_PROFILE") == "course-lifecycle" or os.environ.get("TF_CLI_CONFIG_FILE"):
        import importlib.util
        spec = importlib.util.spec_from_file_location("saved_plan_oidc", Path(__file__).with_name("oidc_process.py"))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        try:
            module.validate_private_profile(os.environ)
            if root is not None:
                lock = Path(root) / ".terraform.lock.hcl"
                require(lock.is_file() and not lock.is_symlink(), "The snapshot provider lock is missing or redirected.")
                module.provider_lock(lock.read_bytes())
        except Exception:
            raise SafeError("The private credential profile or snapshot provider lock differs from the reviewed smoke contract.") from None


def initialize(root, backend, temp, mode):
    refresh_profile_guard(root)
    execute(["terraform", "init", "-input=false", "-no-color", "-lockfile=readonly", f"-backend-config={backend}"], cwd=root, log=temp / f"{mode}-init.log")
    require(execute(["terraform", "workspace", "show"], cwd=root).decode().strip() == "default", "Unexpected Terraform workspace.")


def publish_summary(context, manifest, descriptor):
    with open(required("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as out:
        out.write("## 비공개 저장 plan\n\n")
        out.write(f"- Root: `{context['root']}`\n- Commit: `{context['sha']}`\n- Run/attempt: `{context['run_id']}/{context['run_attempt']}`\n")
        out.write("- Resource action counts (replacement counts in create/delete too): " + json.dumps(manifest["counts"]) + "\n")
        out.write(f"- Plan SHA-256: `{manifest['plan']['sha256']}`\n- Manifest SHA-256: `{descriptor['sha256']}`\n")
        expires = dt.datetime.fromtimestamp(manifest["expires_at"], dt.timezone.utc).isoformat()
        out.write(f"- 만료(UTC): `{expires}`\n\n")
        out.write("승인자는 아래 객체를 본인의 승인된 읽기 전용 SSO 세션으로 내려받아 검토합니다. STATE_BUCKET과 ACCOUNT_ID는 이 환경의 승인된 값입니다. 원문을 PR/Actions에 붙여 넣지 마세요.\n\n```bash\n")
        for label, item in (("manifest.json", descriptor), ("review.txt", manifest["review"])):
            # AWS-generated VersionIds and validated keys cannot contain shell syntax.
            import shlex
            out.write('aws s3api get-object --bucket "$STATE_BUCKET" --expected-bucket-owner "$ACCOUNT_ID" --key ' + shlex.quote(item["key"]) + ' --version-id ' + shlex.quote(item["version"]) + ' ' + label + ' >/dev/null\n')
            out.write(f"sha256sum {label}\n# expected SHA-256: {item['sha256']}\n")
        out.write("less review.txt\n```\n\n")
        if manifest["kind"] == "network-lifecycle":
            if context.get("operation") == "down":
                out.write("누적 네트워크 Down plan입니다. 전체 묶음을 infra-dev-destroy에서 승인한 뒤 같은 파일만 역순 적용합니다.\n")
            else:
                out.write("누적 Dev Up plan입니다. 보존한 source/input과 현재 상위 output으로 계획한 같은 파일을 즉시 자동 적용합니다.\n")
        elif manifest["kind"] == "vpc-lifecycle":
            out.write("VPC lifecycle 전용 plan입니다. down은 infra-dev-destroy 승인 뒤 같은 파일만 적용합니다.\n")
        elif manifest["kind"] == "preview":
            out.write("PR 검토용 plan입니다. 병합 후 main SHA로 새 배포 plan을 만들며 이 preview 파일을 적용하지 않습니다.\n")
        elif manifest["kind"] == "audit":
            out.write("감사 전용 plan입니다. apply job은 없습니다. 변경 감지: " + str(manifest["has_changes"]).lower() + "\n")
        elif context["environment"] == "prod":
            out.write("계정·backend·입력 해시·변경 값·삭제/교체를 검토한 뒤 같은 run의 infra-prod-apply를 승인합니다.\n")
        else:
            out.write("Dev: 보호된 PR 검토·병합 뒤 만든 배포 plan을 자동 적용합니다. 삭제·교체도 PR에서 검토해야 합니다. 별도 승인 클릭은 없습니다.\n")


def lifecycle_gate(store, context, workspace):
    # 일반 배포와 수명주기는 workflow-level 공통 concurrency도 함께 사용합니다.
    import importlib.util
    spec = importlib.util.spec_from_file_location("lifecycle_state_guard", Path(__file__).with_name("lifecycle-state.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.assert_normal_allowed(store, context, workspace)


def run(mode):
    os.umask(0o077)
    workspace = Path(required("GITHUB_WORKSPACE")).resolve()
    if mode == "pick":
        env, key = select_root(workspace, required("INPUT_ROOT"))
        require(required("GITHUB_REF") == "refs/heads/main", "Only main may deploy.")
        require(execute(["git", "rev-parse", "origin/main"], cwd=workspace).decode().strip() == required("GITHUB_SHA"), "Run must start from the current main commit.")
        emit({"env": env, "key": key})
        return
    require(mode in ("plan", "preview", "audit", "apply"), "Unknown command.")
    store = context = None
    completion_payload = None
    generated_input = workspace / os.environ.get("ROOT_PATH", "") / "terraform.tfvars.json"
    input_existed = generated_input.exists()
    with tempfile.TemporaryDirectory(prefix="saved-plan-") as directory:
        temp = Path(directory)
        try:
            root, backend, context, store, caller = prepare(workspace, temp, mode)
            lifecycle_gate(store, context, workspace)
            if mode in ("plan", "preview", "audit"):
                if mode != "preview":
                    ensure_current_main(context)
                initialize(root, backend, temp, mode)
                before = store.state(context["backend"]["key"])
                upstream_before = upstream_states(store, context, workspace)
                plan_path = temp / "change.tfplan"
                execute(["terraform", "plan", "-input=false", "-no-color", "-lock-timeout=5m", f"-out={plan_path}"], cwd=root, log=temp / "plan.log")
                require(store.state(context["backend"]["key"]) == before and upstream_states(store, context, workspace) == upstream_before, "State changed during plan; create a new run.")
                if mode != "preview":
                    ensure_current_main(context)
                plan_json = json.loads(execute(["terraform", "show", "-json", str(plan_path)], cwd=root))
                validate_effective_inputs(plan_json, context)
                destructive = any("delete" in r.get("change", {}).get("actions", []) for r in plan_json.get("resource_changes", []))
                review_text = execute(["terraform", "show", "-no-color", str(plan_path)], cwd=root, log=temp / "show.log")
                review_path = temp / "review.txt"
                review_path.write_bytes(b"APPROVAL CONTEXT\n" + json.dumps(context, ensure_ascii=False, indent=2).encode() + b"\nPLAN ROLE\n" + caller.encode() + b"\nPLAN SHA256\n" + digest(plan_path.read_bytes()).encode() + b"\n\n" + review_text)
                plan_item = store.put(context["prefix"] + "change.tfplan", plan_path)
                review_item = store.put(context["prefix"] + "review.txt", review_path)
                now = int(dt.datetime.now(dt.timezone.utc).timestamp())
                manifest = {"schema": 1, "kind": mode, "context": context, "plan_role_arn": required("AWS_ROLE_ARN"), "plan_caller_arn": caller, "created_at": now, "expires_at": now + TTL_SECONDS, "state": before, "upstream_states": upstream_before, "destructive": destructive, "has_changes": any(r.get("change", {}).get("actions", ["no-op"]) != ["no-op"] for r in plan_json.get("resource_changes", [])) or any(c.get("actions", ["no-op"]) != ["no-op"] for c in plan_json.get("output_changes", {}).values()), "counts": {"create": sum("create" in r.get("change", {}).get("actions", []) for r in plan_json.get("resource_changes", [])), "update": sum("update" in r.get("change", {}).get("actions", []) for r in plan_json.get("resource_changes", [])), "delete": sum("delete" in r.get("change", {}).get("actions", []) for r in plan_json.get("resource_changes", [])), "replace": sum(set(r.get("change", {}).get("actions", [])) == {"create", "delete"} for r in plan_json.get("resource_changes", []))}, "plan": plan_item, "review": review_item}
                manifest_path = temp / "manifest.json"
                manifest_path.write_bytes(canonical(manifest))
                descriptor = store.put(context["prefix"] + "manifest.json", manifest_path)
                emit({"manifest_key": descriptor["key"], "manifest_version": descriptor["version"], "manifest_sha": descriptor["sha256"], "plan_sha": plan_item["sha256"], "has_changes": str(manifest["has_changes"]).lower()})
                publish_summary(context, manifest, descriptor)
                print({"preview": "PR preview saved privately. Review before merge.", "audit": "Audit plan saved privately. No apply job.", "plan": "Deployment plan saved privately. Apply uses this exact binary."}[mode])
            else:
                descriptor = {"key": required("MANIFEST_KEY"), "version": required("MANIFEST_VERSION"), "sha256": required("EXPECTED_MANIFEST_SHA")}
                require(descriptor["key"] == context["prefix"] + "manifest.json", "Manifest belongs to another run or attempt; start a new run.")
                manifest_path = temp / "manifest.json"
                store.get(descriptor, manifest_path)
                manifest = json.loads(manifest_path.read_bytes())
                validate_manifest(manifest, context, required("EXPECTED_PLAN_SHA"), int(dt.datetime.now(dt.timezone.utc).timestamp()))
                plan_path = temp / "change.tfplan"
                store.get(manifest["plan"], plan_path)
                initialize(root, backend, temp, mode)
                require(store.state(context["backend"]["key"]) == manifest["state"] and upstream_states(store, context, workspace) == manifest["upstream_states"], "Root or upstream State changed; create a new plan run.")
                validate_manifest(manifest, context, required("EXPECTED_PLAN_SHA"), int(dt.datetime.now(dt.timezone.utc).timestamp()))
                ensure_current_main(context)
                lifecycle_gate(store, context, workspace)
                # Terraform acquires the backend lock and also rejects a stale saved plan.
                execute(["terraform", "apply", "-input=false", "-no-color", "-lock-timeout=5m", str(plan_path)], cwd=root, log=temp / "apply.log")
                with open(required("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as out:
                    out.write(f"## Apply 완료\n\n저장한 배포 plan SHA-256 `{manifest['plan']['sha256']}`를 적용했습니다. 장별 기능 검증은 별도 결과를 확인하세요.\n")
                print("The exact saved deployment plan was applied. No replan was performed.")
                try:
                    post_apply_state = store.state(context["backend"]["key"])
                    outputs = execute(["terraform", "output", "-json"], cwd=root, log=temp / "output-command.log")
                    json.loads(outputs)
                    (temp / "outputs.json").write_bytes(outputs)
                    receipt_state, collected_state = read_state_memory(store, context["backend"]["key"])
                    require(collected_state == post_apply_state and store.state(context["backend"]["key"]) == post_apply_state, "Post-State changed during output collection; completion receipt refused.")
                    completion_payload = {"schema": 1, "kind": "apply-completion", "context": context, "plan_sha": manifest["plan"]["sha256"], "completed_at": int(dt.datetime.now(dt.timezone.utc).timestamp()), "state": receipt_state}
                except Exception:
                    raise SafeError("Apply succeeded but output collection failed. Do not repeat apply; recover outputs separately.")
        finally:
            # Apply can write diagnostics only under ci-logs/, never overwrite plans.
            output_delivery_failed = False
            output_descriptor = None
            if store and context:
                for log in sorted([*temp.glob("*.log"), *temp.glob("outputs.json")]):
                    try:
                        item = store.put(context["prefix"].replace("ci-plans/", "ci-logs/", 1) + mode + "/" + log.name, log)
                        if log.name == "outputs.json":
                            output_descriptor = item
                        with open(required("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as out:
                            out.write(f"\nPrivate diagnostic: `{item['key']}`; version `{item['version']}`.\n")
                    except Exception:
                        if log.name == "outputs.json":
                            output_delivery_failed = True
                        print("Private diagnostic upload failed; no raw log was published.")
                if completion_payload is not None and output_descriptor is not None:
                    try:
                        completion_payload["outputs"] = output_descriptor
                        path = temp / "completion.json"
                        path.write_bytes(canonical(completion_payload))
                        item = store.put(context["prefix"].replace("ci-plans/", "ci-logs/", 1) + "apply/completion.json", path)
                        with open(required("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as out:
                            out.write(f"\nPrivate completion: `{item['key']}`; version `{item['version']}`; SHA-256 `{item['sha256']}`.\n")
                    except Exception:
                        output_delivery_failed = True
                        print("Apply succeeded but private completion publication failed. Do not repeat apply.")
            root_path = os.environ.get("ROOT_PATH", "")
            if re.fullmatch(r"terraform/environments/(dev|prod)/[a-z0-9][a-z0-9/_-]*", root_path):
                generated = workspace / root_path / "terraform.tfvars.json"
                if not input_existed and generated.is_file():
                    generated.unlink()
            if output_delivery_failed:
                raise SafeError("Apply succeeded but private result delivery failed. Do not repeat apply; recover result delivery separately.")


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "Expected pick, plan or apply.")
        run(sys.argv[1])
    except SafeError as exc:
        print("::error::" + str(exc))
        sys.exit(1)
    except Exception:
        # JSON errors and provider/AWS errors may include private input values.
        print("::error::Invalid CI input or private operation failure. Inspect authorized private diagnostics.")
        sys.exit(1)
