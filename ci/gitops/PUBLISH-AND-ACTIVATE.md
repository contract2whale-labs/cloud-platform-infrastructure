# 강사가 실제 digest를 만드는 절차

비활성 값은 제품 기능의 영구 차단이 아니라 학습자 계정별 설정 경계입니다. 예시 account ID/가짜 digest를 채워 우회하지 않습니다.

## 1. 제공된 locked toolchain 게시

`tooling/`에는 제공 tooling 원본의 Dockerfile, SHA256 URL lock, pip hash lock, 설치기가 포함되어 있습니다. 먼저 upstream 버전/해시·base image·빌드 명령을 PR로 검토합니다. `workflows/gitops-toolchain-publish.yml`을 실제 `.github/workflows/`로 배치하고 보호된 `gitops-toolchain-publish` Environment를 만듭니다. Actions에서 main의 workflow를 시작합니다. 실제 docker build/push는 이 CI에서만 수행합니다.

CI는 현재 source SHA 태그로 GHCR에 게시하고 조회한 `@sha256`을 다시 pull하여 필수 바이너리 fingerprint를 계산합니다. Summary에는 비밀 없는 source SHA/image digest/tool SHA256만 있습니다. 원문 빌드 로그·인증정보는 artifact로 올리지 않습니다. 출력 operator_image와 tool_sha256을 operations.json 등록 PR에 그대로 넣습니다. 게시가 실패하면 원격 tag/digest를 확인한 뒤 재시도를 결정합니다. hash 검증 실패를 무시하거나 latest로 대체하지 않습니다.

## 2. Argo chart vendor와 검토

다음은 외부 cloud mutation이 없는 파일 준비/정적 검증 명령입니다. 로컬 선택적 검사를 허용하는 사용자 범위에 맞습니다. CI 검증 job에서 같은 명령을 실행해도 됩니다.

```bash
mkdir -p ci/gitops/vendor
helm pull argo-cd --repo https://argoproj.github.io/argo-helm --version 10.9.0 --destination ci/gitops/vendor
curl --fail --proto '=https' --tlsv1.2 https://argoproj.github.io/argo-helm/index.yaml -o /tmp/argo-index.yaml
python3 - <<'PY'
import hashlib, pathlib, yaml
p=pathlib.Path('ci/gitops/vendor/argo-cd-10.9.0.tgz')
rows=[x for x in yaml.safe_load(pathlib.Path('/tmp/argo-index.yaml').read_text())['entries']['argo-cd'] if x['version']=='10.9.0']
assert len(rows)==1
actual=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==rows[0]['digest']
print(actual)
PY
```

공식 index digest와 archive를 함께 검토합니다. archive hash를 bootstrap_chart_sha256에 넣고 tarball을 등록 PR에 포함합니다. 이 단계는 제공 원본 버전 10.9.0을 임의로 업그레이드하지 않습니다. Helm chart 렌더에서 모든 image가 @sha256이 되도록 bootstrap_image_values를 검토합니다. chart의 image override 지원 여부는 실제 helm template 결과로 확인해야 합니다.

cert-manager/mesh chart도 source에 명시된 버전을 가져와 chart package/index/OCI digest를 검증하고 Git의 vendor 경로에 저장합니다. chart dependency와 remote Kustomize 참조를 vendor하여 네트워크상의 mutable 의존성이 남지 않게 합니다. values image를 @sha256으로 고정하고 렌더·test를 통과한 커밋의 전체 SHA를 Application source별로 등록합니다. 태그와 chart 버전 문자열만 기록하는 것으로 이 절차를 대신하지 않습니다.

## 3. 사용자 계정에서 활성화

BU01 보호 신원/State 설정 및 BU06/07 CI 완료 결과로 account/region/role/cluster/relay/owner 필드를 채웁니다. repo read-only key와 Argo 토큰은 승인된 신원 절차로 준비하고 보호 Secret에 저장합니다. 실제 Private API/SSM 접근과 Environment 승인을 검증한 뒤 enabled=true를 PR로 병합합니다. bootstrap은 별도 승인 CI로 한 번 실행합니다. 일반 Dev는 다음 main 변경부터 자동 reconcile됩니다. Prod는 승인 후 동일 SHA를 실행합니다.

기존 무승인 로컬 설치나 stale chart cache를 성공 증거로 재사용하지 않습니다. 각 learner가 채우는 값과 이미 구현된 workflow/adapter 코드를 구분합니다.

## One toolchain for BU06–BU16

Keep `ci/gitops/` in the learner repository; copy workflow files to `.github/workflows/` without changing their runtime paths. Publish once using the protected `gitops-toolchain-publish` workflow. Its summary contains the reviewed source SHA, immutable GHCR image and six binary fingerprints. Save those public fingerprints as `published.json` with keys `source_sha`, `operator_image`, `binary_sha256`. Verify locally (registry reads and local file write only):

```bash
python ci/gitops/register-toolchain.py \
  --published published.json --account "$ACCOUNT_ID" \
  --repository-id "$REPOSITORY_ID" --region "$AWS_REGION" \
  --output toolchain-registration.json
```

The generator pulls exactly the digest, runs its fixed fingerprint command with network disabled, and rejects mismatched tools. Review the source/image before running this command. Configure protected repository variable `LIFECYCLE_TOOLCHAIN_IMAGE` with verified `operator_image`; common lifecycle jobs use that same image from BU06 onward. Private GHCR requires the documented read-packages pull credentials. No per-chapter toolchain publication is needed. The generated GitOps registration deliberately remains disabled until actual chart digest, State identities, roles, repository credentials and immutable App declarations have been supplied and reviewed. Copy its toolchain values into each activated environment's existing configuration keys; do not treat this seed as an activated cloud binding.

## Preserve root ownership while preparing immutable chart sources

The course's root Applications stay app-of-apps. Prepare `authority_applications`, `authority_children` and `applications` from the same reviewed source tree; do not introduce a second leaf owner. Root-rendered child documents must exactly equal the registered documents, including sources, project, destination and metadata. Stage only children whose infrastructure dependencies are ready. The source directory's Argo self-management child requires its own bootstrap-to-Argo ownership handoff and is not enabled by this adapter; exclude it explicitly from the reviewed staged root render rather than letting it compete with the bootstrap Helm release. AppProject authority likewise comes from reviewed bootstrap documents, not arbitrary root children.

For each source Helm Application, copy the actual chart/repository/version coordinates from its source manifest to a reviewed chart lock:

```json
{"schema":1,"charts":[{"id":"cert-manager","repository":"https://charts.jetstack.io","chart":"cert-manager","version":"v1.21.1","sha256":"REPLACE_WITH_REVIEWED_ARCHIVE_SHA256"}]}
```

The coordinates above are a source example, not a verified published digest. First inspect the exact download, review the artifact/upstream provenance and lock its actual digest; then run the locked extraction:

```bash
python ci/gitops/vendor-charts.py --lock chart-lock.json --inspect
# Review and commit the printed actual SHA256 in chart-lock.json, then:
python ci/gitops/vendor-charts.py --lock chart-lock.json
```

Both commands only download/read/write local source. They do not connect to Kubernetes or create cloud resources. The extractor rejects traversal, symlinks, hardlinks and overwrites. Commit `gitops/vendor/<id>/<version>/<chart>` with its archive digest. In the original leaf Application, change the remote chart source to this same-repository Git path at the reviewed full commit SHA; preserve the source's Helm releaseName/valueFiles/parameters and its `$values` Git source, also at a full SHA. Replace every workload image value with its reviewed digest. Do not delete/add chart options by inference. Render with the locked Helm/Kustomize tools, inspect values/diffs, and commit matching child Application declarations and registration in a subsequent reviewed source commit. The root's immutable revision must be a commit containing those exact declarations. This two-step source preparation avoids self-referential commit hashes.

Bootstrap's own argo-cd archive remains the separately locked `vendor/argo-cd-10.9.0.tgz`; this chart helper prepares ordinary platform/application chart source. A digest fingerprint alone does not prove provenance, licensing suitability or a safe chart diff; those remain part of the instructor's source review before publication and activation.

## Fresh-cluster access receipt and lifecycle bindings

Compile and approve the supplied operations-access bundle first. Copy its actual access-manifest.json `config_sha256` into each GitOps environment's `operations_access_config_sha256`. Configure exact `lifecycle_destroy_role_arn`, `lifecycle_plan_role_arn`, and `lifecycle_apply_role_arn`; all Down stages use the dedicated destroy role. Prod Up plan uses plan, while Up apply and Dev Up use apply. Never substitute an ordinary role for the destroy inspector.

Install with `gitops-access-bootstrap.yml`, providing environment and the reviewed access-manifest.json bundle SHA-256. On lifecycle Up also provide the paused checkpoint's exact version, content SHA-256 and generation through the dedicated workflow inputs. The installer writes a private current-incarnation receipt. Resume the same checkpoint after it succeeds. Both Up adapters bind its S3 version and SHA to their reviewed actions; they do not install Argo a second time. Ordinary GitOps and incident jobs also require this receipt. Fixture namespace UIDs are taken from the authenticated current receipt, so EKS recreation does not require guessing or reusing old UIDs.

Optional local `trace-probe.sh query` uses the shipped `operations/read_trace.py` read-only Service port-forward transport. Regenerate the source helper from the revised lesson before using legacy extracted source: older helper copies created a Pod even for query. Synthetic trace sends are fixed CI operations. The builder experiment includes its own send/query/requery under the same incident marker.
