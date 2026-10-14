# BU06–BU08 Private API·접근 권한 실행

설치된 인프라 저장소의 `ci/operations-access/`, `ci/gitops/`, `.github/workflows/`를 기준으로 합니다. 아래 로컬 명령은 소스 준비·검증과 읽기 전용 조회입니다. 클러스터 변경은 보호된 GitHub Actions에서만 실행합니다. 예시 계정·ARN·digest를 실제 값으로 간주하지 않습니다.

## 1. 경로와 실제 등록값

```bash
set -euo pipefail
set +x
umask 077
: "${INFRA_ROOT:?인프라 저장소의 절대 경로}"
: "${TOOLING_ROOT:?원본 tooling 저장소의 절대 경로}"
: "${AWS_PROFILE:?BU01에서 승인한 읽기 전용 조회 프로파일}"
cd "$INFRA_ROOT"
TARGET=dev
export INFRA_ROOT TOOLING_ROOT TARGET
PRIVATE_DIR=$(mktemp -d)
export PRIVATE_DIR
trap 'rm -rf "$PRIVATE_DIR"' EXIT
REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
REPOSITORY_ID=$(gh api "repos/$REPO" --jq .id)
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export REPOSITORY_ID ACCOUNT_ID
REG="$INFRA_ROOT/ci/operations-access/registrations/$TARGET.json"
BUNDLE="$INFRA_ROOT/ci/operations-access/bundles/$TARGET"
export REG BUNDLE
mkdir -p "$(dirname "$REG")"
```

`REG`가 아직 없다면 `ci/operations-access/examples/dev.json`을 복사해 등록 PR을 준비합니다. Dev/Prod는 각 계정의 별도 등록입니다. 다음 값은 실제 완료한 원본 장의 결과로 채웁니다.

- 계정·저장소 ID: 위 조회값. Region은 `ap-northeast-2`
- State/evidence 버킷·KMS ARN: BU01에서 승인한 실제 출력. `state_keys`는 현재 필요한 정확한 State 키
- EKS/relay: BU06/BU07 State의 현재 클러스터 이름·relay ID. 실행기는 재조회한 버전 고정 State로 실제 대상을 검증
- 아직 없는 ECR/RDS/MSK 등의 예시 ARN은 제거하고 해당 선택 목록을 비움. 필요한 장에서 실제 자원으로 추가
- `ci/gitops/operations.json`: 게시한 단일 toolchain의 실제 `operator_image`, 환경별 `tool_sha256`, 계정/Region/역할/State 정보, 검토한 bootstrap 이미지 digest와 프로젝트·Application 선언

Toolchain의 이미지와 7개 바이너리 해시는 `gitops-toolchain-publish` 성공 실행 Summary에서 `ci/gitops/published.json`의 `source_sha`, `operator_image`, `binary_sha256`으로 옮깁니다. 다음 명령은 해당 digest를 다시 읽어 검증하며, 미완성 seed를 활성화하지 않습니다.

```bash
python3 ci/gitops/register-toolchain.py \
  --published ci/gitops/published.json --account "$ACCOUNT_ID" \
  --repository-id "$REPOSITORY_ID" --region ap-northeast-2 \
  --output "$PRIVATE_DIR/toolchain-registration.json"
sha256sum "$TOOLING_ROOT/assets/infrastructure/bootstrap/argocd/values.yaml" \
  ci/gitops/bootstrap-values.yaml
```

원본 values와 설치본 차이를 검토합니다. 보호된 `gitops-$TARGET-bootstrap` Environment에는 main 제한, 독립 승인자, 우회 금지와 `GITOPS_ROLE_ARN`, `AWS_ACCOUNT_ID`, `AWS_REGION`을 설정합니다. 역할은 정확히 `cp-$TARGET-gitops-bootstrap`입니다. 기존 승인 절차로 준비한 Argo 토큰·서명키·저장소 읽기 키는 보호 Secret에만 저장합니다. 셸 출력·PR·render 파일 공유로 전달하지 않습니다.

### 기존 버킷 암호화에서 KMS 입력 얻기

CMK를 새로 만들거나 버킷 암호화를 바꾸지 않습니다. 실제 메타데이터를 읽어 세 등록값을 정합니다. 버킷이 같으면 등록값도 같아야 합니다. 아래 코드는 `REG`의 실제 버킷 이름을 사용하며 로컬 등록 파일만 갱신합니다.

```bash
python3 - <<'PY_ENCRYPTION'
import json,os,pathlib,subprocess
path=pathlib.Path(os.environ['REG']); c=json.loads(path.read_text())
assert c['account_id']==os.environ['ACCOUNT_ID']
for bucket_field,key_field in [('state_bucket','state_kms_arn'),('evidence_bucket','evidence_kms_arn'),('operator_evidence_bucket','operator_evidence_kms_arn')]:
    raw=subprocess.check_output(['aws','s3api','get-bucket-encryption','--bucket',c[bucket_field],'--expected-bucket-owner',c['account_id'],'--region',c['region'],'--output','json'],stderr=subprocess.PIPE)
    rules=json.loads(raw)['ServerSideEncryptionConfiguration']['Rules']; assert len(rules)==1
    encryption=rules[0]['ApplyServerSideEncryptionByDefault']; algorithm=encryption['SSEAlgorithm']
    if algorithm=='AES256': c[key_field]=None
    else:
        assert algorithm in ('aws:kms','aws:kms:dsse') and encryption.get('KMSMasterKeyID')
        raw=subprocess.check_output(['aws','kms','describe-key','--key-id',encryption['KMSMasterKeyID'],'--region',c['region'],'--output','json'],stderr=subprocess.PIPE)
        key=json.loads(raw)['KeyMetadata']; assert key['AWSAccountId']==c['account_id']
        c[key_field]=key['Arn']
path.write_text(json.dumps(c,indent=2)+'\n')
PY_ENCRYPTION
```

`AES256`은 세 `*_kms_arn` 필드에 명시적인 JSON `null`을 사용하고 해당 KMS grant를 생성하지 않습니다. SSE-KMS/DSSE의 실제 key ID를 확인할 수 없으면 중단합니다. 임의 CMK ARN이나 빈 문자열로 대체하지 않습니다. 읽기 권한·실제 버킷 암호화 검사는 생략되지 않습니다.

## 2. BU06 예외와 BU07 등록

- **BU06은 노드 없는 control plane입니다.** `initial`/Helm 설치를 실행하지 않습니다. 공통 lifecycle의 `cluster-private-api-check`는 정확한 EKS access source, EKS/relay/VPC State, 인증된 lifecycle 그룹과 private `/readyz`만 검사합니다. nodegroup이 있으면 BU06 범위로 통과하지 않습니다.
- **BU07 최초 설치**는 Ready worker nodes가 필요합니다. 미래 Application 이미지·root 선언을 요구하지 않도록 두 등록에 `bootstrap_only: true`를 명시합니다. 접근 등록의 `application_names`는 `[]`; GitOps 환경의 `applications`, `authority_applications`, `projects`는 `[]`, `authority_children`는 `{}`입니다. `rbac_applications`와 `deferred_applications`도 없거나 빈 목록이어야 합니다. 일반 reconcile은 이 등록에서 차단됩니다.
- `ci/eks-operations-access.tf`와 **바이트가 같은** 조각을 기존 `modules/eks`에 한 번 병합해야 합니다. 별도 클러스터·State·동명 역할을 만들지 않습니다.

등록용 chart 렌더는 로컬 비공개 디렉터리에만 저장합니다. 아래 렌더는 차트 소유 클러스터 객체 이름·이미지 고정을 검토하는 입력이며, 런타임 자격증명은 보호 CI에서만 주입합니다. `ci/gitops/vendor/argo-cd-10.9.0.tgz`는 공식 index digest와 대조하여 검토한 archive여야 합니다.

```bash
python3 - <<'PY'
import json, os, pathlib, yaml
root=pathlib.Path(os.environ['INFRA_ROOT']); private=pathlib.Path(os.environ['PRIVATE_DIR'])
c=json.loads((root/'ci/gitops/operations.json').read_text())['environments'][os.environ['TARGET']]
values=yaml.safe_load((root/'ci/gitops/bootstrap-values.yaml').read_text())
for component, image in c['bootstrap_image_values'].items():
    values.setdefault(component,{})['image']=image
(private/'render-values.yaml').write_text(yaml.safe_dump(values))
PY
helm template argocd ci/gitops/vendor/argo-cd-10.9.0.tgz \
  --namespace argocd --include-crds --values "$PRIVATE_DIR/render-values.yaml" \
  > "$PRIVATE_DIR/render.yaml"
python3 ci/operations-access/register-bootstrap.py \
  --config "$REG" --chart ci/gitops/vendor/argo-cd-10.9.0.tgz \
  --rendered "$PRIVATE_DIR/render.yaml" --source-sha "$(git rev-parse HEAD)" \
  --out "$REG"
python3 ci/operations-access/access.py --config "$REG" --out "$BUNDLE"
```

다음 검증이 전부 성공한 경우에만 등록 파일을 활성화 후보로 씁니다. source·chart·toolchain·계정·Application 범위·생성 bundle 파일을 확인하며, `enabled`만 수동으로 바꾸지 않습니다.

```bash
python3 - <<'PY'
import hashlib, importlib.util, json, os, pathlib, sys, tempfile
from unittest.mock import patch
import yaml
root=pathlib.Path(os.environ['INFRA_ROOT']); target=os.environ['TARGET']
sys.path.insert(0,str(root/'ci/gitops')); import gitops_ops as ops
reg=json.loads(pathlib.Path(os.environ['REG']).read_text())
bundle=pathlib.Path(os.environ['BUNDLE']); manifest=json.loads((bundle/'access-manifest.json').read_text())
assert reg['environment']==target and reg['account_id']==os.environ['ACCOUNT_ID']
assert reg['repository_id']==os.environ['REPOSITORY_ID'] and reg['region']=='ap-northeast-2'
for name,sha in manifest['files'].items():
    assert hashlib.sha256((bundle/name).read_bytes()).hexdigest()==sha
cfg_path=root/'ci/gitops/operations.json'; cfg=json.loads(cfg_path.read_text()); c=cfg['environments'][target]
seed=json.loads((pathlib.Path(os.environ['PRIVATE_DIR'])/'toolchain-registration.json').read_text())['toolchain']
assert cfg['operator_image']==seed['operator_image'] and c['tool_sha256']==seed['binary_sha256']
assert c['account_id']==reg['account_id'] and c['region']==reg['region'] and c['state_bucket']==reg['state_bucket']
chart=hashlib.sha256((root/'ci/gitops/vendor/argo-cd-10.9.0.tgz').read_bytes()).hexdigest()
assert chart==reg['bootstrap_chart_sha256']==c['bootstrap_chart_sha256']
assert set(reg['application_names'])=={a['metadata']['name'] for a in c['applications']+c['authority_applications']}
assert c.get('bootstrap_only',False)==reg.get('bootstrap_only',False)
ops.validate_images(list(yaml.safe_load_all((pathlib.Path(os.environ['PRIVATE_DIR'])/'render.yaml').read_text())))
c['operations_access_config_sha256']=manifest['config_sha256']; cfg['enabled']=True
with tempfile.TemporaryDirectory() as d:
    path=pathlib.Path(d); (path/'operations.json').write_text(json.dumps(cfg))
    with patch.object(ops,'BASE',path): checked=ops.load(target,'bootstrap')
    ops.registered_projects(checked)
fragment=(root/'ci/eks-operations-access.tf').read_bytes()
assert sum(p.read_bytes()==fragment for p in (root/'modules/eks').glob('*.tf'))==1
cfg_path.write_text(json.dumps(cfg,indent=2)+'\n')
PY
python3 -m unittest discover -s ci/operations-access/tests -v
python3 -m unittest discover -s ci/gitops/tests -v
python3 -m unittest ci/test_early_cluster_handoff.py -v
cp -R "$BUNDLE/identity" "$PRIVATE_DIR/identity-syntax-check"
terraform fmt -recursive "$PRIVATE_DIR/identity-syntax-check" > /dev/null
terraform fmt -check -recursive "$PRIVATE_DIR/identity-syntax-check"
```

manifest 생성 후 bundle 내부를 따로 수정·format하지 않습니다. 위 HCL 검사는 비공개 복사본에서만 수행합니다. 등록/생성 bundle/기존 EKS 모듈 변경을 PR로 검토·병합합니다. 생성된 identity 정책은 기존 `bootstrap/ci-identity`의 identity-admin 경로로 적용합니다. 일반 apply 역할로 설치하지 않습니다. `access-refresh.json` 읽기·CAS 쓰기 권한도 이 검토에 포함됩니다. main의 CI/provider 검증, 보호 Environment 및 실제 권한 검증이 끝나기 전에는 dispatch하지 않습니다. 테스트 통과를 실제 AWS/OIDC/차트 호환성 검증으로 표현하지 않습니다.

## 3. 실행 직전: main·bundle·checkpoint 해시

병합된 main checkout에서 1절의 경로/변수 설정을 유지합니다. 아래는 로컬 bundle 바이트와 main을 확인한 뒤, S3의 정확한 버전만 내려받습니다. ETag는 SHA-256이 아닙니다.

```bash
git fetch origin main
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
git diff --exit-code HEAD -- ci .github/workflows modules terraform
test "$(git rev-parse HEAD)" = "$(gh api "repos/$REPO/git/ref/heads/main" --jq .object.sha)"
BUNDLE_SHA=$(sha256sum "$BUNDLE/access-manifest.json" | awk '{print $1}')
STATE_BUCKET=$(jq -r .state_bucket "$REG")
AWS_REGION=$(jq -r .region "$REG")
CLUSTER_NAME=$(jq -r .cluster_name "$REG")
COURSE_KEY="ci-lifecycle/$REPOSITORY_ID/$TARGET/course.json"
export STATE_BUCKET AWS_REGION COURSE_KEY
cat > "$PRIVATE_DIR/read-version.py" <<'PY'
import hashlib,json,os,pathlib,subprocess,sys
key,name=sys.argv[1:]; directory=pathlib.Path(os.environ['PRIVATE_DIR'])
common=['--bucket',os.environ['STATE_BUCKET'],'--expected-bucket-owner',os.environ['ACCOUNT_ID'],'--region',os.environ['AWS_REGION'],'--output','json','--no-cli-pager']
head=subprocess.run(['aws','s3api','head-object',*common,'--key',key],capture_output=True)
if head.returncode:
    if name=='course' and b'(404)' in head.stderr:
        (directory/'course.json').unlink(missing_ok=True)
        (directory/'course-descriptor.json').unlink(missing_ok=True)
        sys.exit(0)
    raise SystemExit('정확한 객체 조회 실패: 권한/부재를 확인하고 중단하세요.')
metadata=json.loads(head.stdout); version=metadata.get('VersionId')
assert version and version!='null'
path=directory/(name+'.json')
raw=subprocess.check_output(['aws','s3api','get-object',*common,'--key',key,'--version-id',version,str(path)],stderr=subprocess.PIPE)
received=json.loads(raw)
assert received['VersionId']==version and received['ServerSideEncryption'] in ('AES256','aws:kms','aws:kms:dsse')
(directory/(name+'-descriptor.json')).write_text(json.dumps({'key':key,'version':version,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}))
PY
python3 "$PRIVATE_DIR/read-version.py" "$COURSE_KEY" course
CHECKPOINT_ARGS=()
if [[ -f "$PRIVATE_DIR/course.json" ]]; then
  CHECKPOINT_ARGS=(-f "checkpoint_version=$(jq -r .version "$PRIVATE_DIR/course-descriptor.json")"
    -f "checkpoint_sha256=$(jq -r .sha256 "$PRIVATE_DIR/course-descriptor.json")"
    -f "generation=$(jq -r .generation "$PRIVATE_DIR/course.json")")
fi
```

`course.json`은 Terraform 입력을 포함할 수 있으므로 `cat`, Actions 로그, PR 첨부를 하지 않습니다. 기존 checkpoint가 있으면 phase가 active이거나, paused Up에서 EKS가 완료된 인계 지점이어야 합니다. Down/incident 진행 중에는 설치·refresh를 실행하지 않습니다. 조회 403·불완전 버전·해시 불일치를 “checkpoint 없음”으로 처리하지 않습니다. 위 스크립트의 404 예외는 `course`에만 적용됩니다.

## 4. BU07 최초 설치와 같은 Up 재개

```bash
gh workflow run gitops-access-bootstrap.yml --repo "$REPO" --ref main \
  -f "environment=$TARGET" -f mode=initial -f "bundle_sha256=$BUNDLE_SHA" \
  "${CHECKPOINT_ARGS[@]}"
gh run list --repo "$REPO" --workflow gitops-access-bootstrap.yml --branch main \
  --limit 10 --json databaseId,headSha,status,conclusion
read -r -p "방금 요청한 source/run의 실행 ID: " BOOTSTRAP_RUN_ID
[[ "$BOOTSTRAP_RUN_ID" =~ ^[0-9]+$ ]]
gh run watch "$BOOTSTRAP_RUN_ID" --repo "$REPO" --exit-status
```

목록에서 방금 요청한 source/run을 확인한 ID만 입력합니다. 승인 gate를 통과해 성공해야 다음 단계로 갑니다. 초기 설치는 같은 incarnation에 한 번만 허용됩니다. `started`가 남은 실패를 다시 실행하거나 삭제하지 않습니다.

이미 공통 Up이 bootstrap 부재로 멈췄다면 **해당 Up 실행이 failed로 종료되어 공통 mutex를 반환한 뒤** bootstrap을 실행합니다. 성공 후 원래 checkpoint의 장을 그대로 사용해 새 main 실행을 요청합니다. 새로운 Down이나 임의 checkpoint를 만들지 않습니다.

```bash
if [[ -f "$PRIVATE_DIR/course.json" ]] && \
   [[ $(jq -r .phase "$PRIVATE_DIR/course.json") == paused ]] && \
   [[ $(jq -r .operation "$PRIVATE_DIR/course.json") == up ]]; then
  SAME_CHAPTER=$(jq -r .completed_chapter "$PRIVATE_DIR/course.json")
  gh workflow run terraform-lifecycle.yml --repo "$REPO" --ref main \
    -f "environment=$TARGET" -f operation=up -f "completed_chapter=$SAME_CHAPTER"
fi
```

Down/Up을 하지 않은 BU07 최초 학습은 bootstrap 성공 후 `gh workflow run eks-network-probes.yml --repo "$REPO" --ref main`으로 진단합니다. 필요한 `EKS_PROBE_IMAGE`, `EKS_PAUSE_IMAGE`는 해당 CI 게시 결과의 자기 계정 digest를 사용합니다. 로컬 Pod 생성/exec/삭제로 대체하지 않습니다. BU06 private readiness에는 이 이미지가 필요 없습니다.

## 5. BU08 등록 확장: 같은 클러스터에서 access-refresh

BU08 등록 PR에서는 `bootstrap_only`를 false로 바꾸고, 실제 완료한 source SHA에 고정된 leaf/root Applications, `authority_children`, 정확한 AppProjects와 접근 등록의 `application_names`를 함께 추가합니다. 미래 장을 미리 활성화하지 않습니다. 2절의 생성·검증과 identity-admin 정책 검토를 다시 수행합니다. chart, toolchain, 기존 자격증명은 유지합니다. 기존 선언 제거·chart 교체·자격증명 변경은 이 refresh의 범위가 아닙니다.

병합 후 3절을 다시 실행해 **새 bundle 해시와 현재 checkpoint descriptor**를 얻습니다. 다음 읽기 전용 조회로 현재 incarnation의 이전 완료 proof key/version/SHA-256을 얻습니다.

```bash
aws eks describe-cluster --region "$AWS_REGION" --name "$CLUSTER_NAME" \
  --query 'cluster.{arn:arn,createdAt:createdAt}' --output json \
  > "$PRIVATE_DIR/cluster-identity.json"
PREVIOUS_KEY=$(python3 - <<'PY'
import json,os,pathlib,sys
sys.path.insert(0,str(pathlib.Path(os.environ['INFRA_ROOT'])/'ci/operations-access'))
from bootstrap_receipt import key_for
c=json.loads((pathlib.Path(os.environ['PRIVATE_DIR'])/'cluster-identity.json').read_text())
print(key_for(os.environ['TARGET'],c['arn'],c['createdAt']))
PY
)
python3 "$PRIVATE_DIR/read-version.py" "$PREVIOUS_KEY" previous
PREVIOUS_VERSION=$(jq -r .version "$PRIVATE_DIR/previous-descriptor.json")
PREVIOUS_SHA=$(jq -r .sha256 "$PRIVATE_DIR/previous-descriptor.json")
gh workflow run gitops-access-bootstrap.yml --repo "$REPO" --ref main \
  -f "environment=$TARGET" -f mode=access-refresh -f "bundle_sha256=$BUNDLE_SHA" \
  -f "previous_receipt_version=$PREVIOUS_VERSION" \
  -f "previous_receipt_sha256=$PREVIOUS_SHA" "${CHECKPOINT_ARGS[@]}"
```

refresh는 현재 proof·State·기존 UID/spec/metadata를 인증하고, 생성 RBAC/admission·등록 AppProject·`argocd-rbac-cm`의 `policy.csv`만 갱신합니다. 기존 객체는 UID/resourceVersion으로 보호하며, 새 객체는 create-only입니다. chart를 재설치하거나 Secret 값을 교체하지 않습니다. 성공하면 같은 완료 key의 새 버전과 이전 proof 연결을 기록합니다. 현재 버전이 달라졌거나 `access-refresh.json`이 refreshing이면 중단하고 명시적 복구 검토를 받습니다. 실패를 새 hash·다른 역할로 우회하지 않습니다.

성공 실행을 확인한 뒤 같은 `PREVIOUS_KEY`를 `read-version.py`로 다시 읽어 새 descriptor를 검증합니다. paused Up이었다면 4절의 같은 Up 재개 명령을 사용합니다. 일반 BU08 진행은 검토한 기존 GitOps workflow로 이어갑니다. Private render, checkpoint 본문, receipt 본문은 이 셸의 임시 디렉터리에만 두고 종료 시 삭제합니다. 공개 증거는 workflow URL, 완료 여부, source/bundle/receipt의 버전·해시로 제한합니다.
