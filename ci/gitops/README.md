# BU08 / BU08B: 실제 CI GitOps 경로 (활성화 전 제안)

이 폴더는 실행 가능한 workflow와 bounded adapter입니다. 아직 사용자 계정에서 설치·실행하지 않았습니다. `operations.json`은 의도적으로 비활성입니다. 숫자·SHA·인증정보를 추정해 실습 완료라고 표시하지 않습니다.

## 학습자 순서

1. BU01에서 별도 GitOps OIDC 신원과 보호 Environment를 준비합니다. BU06/07 Terraform CI가 private EKS, SSM relay, 노드, Pod Identity를 먼저 만듭니다.
2. 강사가 아래 활성화 계약을 리뷰하여 채웁니다. workflow를 `.github/workflows/gitops-operations.yml`로 배치하고 두 proposal 폴더를 함께 배포합니다.
3. 최초 `bootstrap`은 main에서만 시작하며 Dev/Prod 모두 별도 bootstrap 승인자가 설치 범위를 승인합니다. gitops-access-bootstrap.yml의 GitHub-hosted runner에서 SSM 접속, 검증된 chart 설치, repo 인증/Project/RBAC 등록을 수행하고 새 클러스터의 bootstrap receipt를 남깁니다. Application 등록과 동기화는 그 receipt를 확인한 GitOps CI가 수행합니다.
4. 이후 변경은 로컬 편집·정적 검사·PR만 합니다. Application의 각 source를 검토된 전체 Git SHA로 고정합니다. 해당 source commit을 먼저 만들고 그 SHA를 Application 등록 PR에 넣습니다. main 병합은 Dev `reconcile`을 자동 실행합니다. Prod는 같은 SHA의 보호 Environment 승인 뒤 실행합니다. 일반 Dev 실행은 추가 승인하지 않습니다.
5. Actions 성공만 보지 말고 비공개 receipt의 실행 SHA와 Application 목록을 확인합니다. 코드에서 Sync/Health/operation revision을 대조한 뒤에만 receipt가 만들어집니다. 실패하면 수정 PR 또는 별도 승인 복구를 수행합니다. Argo/kubectl 변경은 개인 터미널로 실행하지 않습니다. 선택적인 로컬 읽기 진단은 가능합니다.

## 제공된 실제 경로

- `workflows/gitops-operations.yml`: main push → select → environment별 operate. dispatch는 verify만 허용합니다. 최초 설치와 재생성 후 설치는 별도 gitops-access-bootstrap.yml에서 incarnation-bound receipt를 남깁니다. shell, script, 임의 app, 임의 revision 입력은 없습니다.
- `gitops_ops.py`: STS 역할/계정, live EKS ARN·소유 태그·private-only endpoint, relay VPC·소유 태그 확인; SSM 세션; bootstrap 또는 등록된 Application만 갱신; 실제 Argo manifests/diff/sync/wait/get; revision receipt 검증.
- `../eks-adapter-proposal/private-api-session.py`: BU06 제공 경로인 SSM `AWS-StartPortForwardingSession` → relay Squid 3128 HTTP CONNECT → EKS 실제 endpoint/CA 유지. runner를 VPC에 설치했다고 가정하지 않습니다.
- SSH repo 인증은 미리 승인·등록한 read-only deploy key만 사용합니다. Argo 계정은 등록 app의 get/sync만 허용합니다. API용 Kubernetes 신원에는 정확한 argocd namespace의 Service/Pod 조회·port-forward 및 등록 Application 생성/patch 권한만 줍니다. bootstrap 역할만 controller/CRD/Project/Secret 설치 권한을 갖습니다.
- Terraform은 AWS/EKS/노드/add-on/Pod Identity의 소유자입니다. Argo는 BU08/08B 플랫폼 리소스의 소유자입니다. adapter는 Application 선언과 sync 요청만 관리합니다. CNI/CoreDNS/kube-proxy/Pod Identity agent 소유권 충돌은 거부합니다.

## 활성화 계약: 실측값 없이는 실행 불가

`operations.json` top-level: schema_version=1, enabled=true, operator_image=검증된 GHCR @sha256 digest, environments.dev 및 필요 시 environments.prod.

각 environment:

- account_id, role_arn, bootstrap_role_arn, region, cluster, cluster_arn, relay, owner. BU06/07 완료 결과의 cluster/relay를 정확히 등록합니다. 재생성하면 새 relay ID를 PR로 갱신합니다. CourseOwner 태그는 identity/infrastructure CI에서 일치시킵니다.
- repository: read-only Git SSH URL. applications: 의존 순서의 완전한 Application JSON 객체 목록. 등록 이름은 namespaces, cert-manager, admission-policy, network-policy, istio-base, istio-cni, istiod, ztunnel, mesh-policy 앞에 platform-, 뒤에 -dev/-prod를 붙입니다. 적용 시점까지 준비된 앱만 넣습니다.
- sources는 각각 동일한 등록 Git repository와 40자리 commit SHA여야 합니다. 여러 source는 위치별로 revision을 전달·검증합니다. chart version만으로 불변성은 증명되지 않습니다. BU08 v1.21.1 / BU08B 1.30.4 chart를 검증하여 Git에 vendor한 경로로 전환해야 합니다. 동적 remote Helm/Kustomize 의존성은 vendor 시 제거하고 dependency lock/렌더를 리뷰합니다. 자동 sync, 임의 plugin, destructive sync option은 허용하지 않습니다.
- tool_sha256: aws, kubectl, argocd, helm, session-manager-plugin 실행 파일의 실제 SHA256. operator image에는 Python3, PyYAML, 위 도구와 Actions 호환 runtime이 있어야 합니다. 출판된 immutable image가 아직 제공되지 않아 빈 값으로 대신 실행하지 않습니다.
- bootstrap_chart_sha256: `vendor/argo-cd-10.9.0.tgz`의 리뷰된 SHA256. bootstrap_image_values: global/controller/repoServer/server/redis/applicationSet/dex/notifications 중 chart가 지원하는 image override. 모든 실제 렌더된 container/initContainer/hook image에 @sha256이 있어야 통과합니다.
- project: 실제 platform AppProject 객체. sourceRepos는 repository 한 개, destination은 in-cluster만 허용됩니다. clusterResourceWhitelist는 각 장에서 실제 필요한 종류만 별도 리뷰해야 합니다.
- state_bucket: 동일 repository의 누적 lifecycle course marker를 읽는 State 버킷입니다. 일반 GitOps와 Terraform/lifecycle은 같은 repository concurrency group을 쓰며 paused 상태에서는 일반 GitOps 변경도 중단합니다.
- evidence_bucket, evidence_kms_arn: BU01에서 만든 비공개 SSE-KMS evidence 저장소. 퍼블릭 차단·bucket-owner-enforced·versioning·최소 접근·수명 정책과 KMS 권한을 환경 관리자가 확인해야 합니다. GitHub artifact에는 아무것도 올리지 않습니다.

Environment: `gitops-dev-apply`는 main만 허용하며 승인자 없음; `gitops-prod-apply`, `gitops-dev-bootstrap`, `gitops-prod-bootstrap`은 main만 허용하고 Required reviewers/자기승인 금지를 실제로 검증합니다. OIDC trust는 repository + 정확한 Environment subject + aud=sts.amazonaws.com으로 한정합니다. GITOPS_ROLE_ARN/AWS_ACCOUNT_ID/AWS_REGION 변수는 등록값과 일치해야 합니다. bootstrap은 별도 역할입니다.

Secret: ARGOCD_AUTH_TOKEN은 사전 승인된 만료 있는 ci:apiKey JWT. 최초 bootstrap Environment에만 ARGOCD_SERVER_SECRETKEY와 GITOPS_REPO_SSH_KEY를 추가합니다. token은 HS256 서명/issuer/subject/expiry/jti를 검증하고 기존 token을 등록합니다. 키·토큰 신규 발급/회전은 별도 승인된 신원 절차입니다. 이미 설치된 클러스터에 bootstrap을 재실행하지 않습니다.

네트워크: runner→AWS STS/EKS/SSM/ssmmessages, GitHub API, GHCR; relay→SSM/ssmmessages 및 private EKS 443; Argo repo-server→등록 Git source가 가능해야 합니다. SSM agent/plugin, relay Online, 노드 Ready, CoreDNS/Pod Identity agent 준비를 실제 계정에서 검증합니다. Argo 원본 설정은 ClusterIP HTTP입니다. CLI는 localhost에만 포워딩하며 외부 구간은 SSM+검증된 EKS TLS로 보호됩니다. 공용 Argo endpoint나 TLS 검증 생략을 추가하지 않습니다.

## 범위와 남은 검증

bootstrap 원본은 제공 tooling의 `assets/infrastructure/bootstrap/argocd/bootstrap.py`, values.yaml, github-known-hosts입니다. 원본은 chart 10.9.0, read-only repository Secret, Project와 root를 설치합니다. 제안은 원본의 floating main root와 넓은 Project를 그대로 실행하지 않고 검토된 root/child 관계와 immutable source를 검증하여 기존 app-of-apps를 유지하며 admin 계정을 끕니다. 원본 경로가 공통 CI 가이드에서 빠져 있었다고 installer 자체가 없다고 판단해서는 안 됩니다.

실제 GitHub 보호 설정, AWS OIDC/SSM, chart 렌더 호환성, Argo 인증/네트워크와 실클러스터 성공은 아직 미검증입니다. 등록 미완료는 select 단계에서 AWS 자격증명 전에 실패합니다. 테스트 성공은 배포 성공이 아닙니다.

누적 Down/Up은 추가된 `gitops-lifecycle.py`의 core/mesh/gateway bounded hook으로 수행합니다. 정확한 S3 bundle/승인/잔여 객체 증명을 누적 engine 및 EKS guard에 연결하는 계약은 HOOK-INTEGRATION.md에 있습니다. namespace/CRD는 검토된 잔여 객체로 최종 EKS 삭제까지 보존합니다. 임의 prune/강제 finalizer 제거는 없습니다. 일반 sync가 admission/network/mTLS 실험 진단까지 수행했다고 주장하지 않습니다. 선택적인 로컬 읽기 진단은 가능하지만 실험의 실제 변경은 등록된 CI 경로로만 수행합니다. 실제 digest 게시와 활성화 순서는 PUBLISH-AND-ACTIVATE.md를 따릅니다.

정적 테스트: `python -m unittest discover -s ci/gitops/tests -v`.

CLI 참고: https://argo-cd.readthedocs.io/en/stable/user-guide/commands/argocd_app_manifests/ (multi-source positions), https://argo-cd.readthedocs.io/en/stable/user-guide/commands/argocd_app_diff/.

## Retained app-of-apps ownership (BU08–BU15)

`authority_applications` contains exact reviewed `platform-root-<env>`, `delivery-root-<env>` and/or `platform-<env>` Application declarations in parent-first order. `authority_children` maps each authority name to its complete child names; each leaf has exactly one owner. `applications` remains the exact dependency-ordered leaf declarations. Root manifests must render only the declared children, with complete metadata/spec equal to their registry documents. Unknown children, different revisions/projects/destinations, duplicate owners, cycles and orphan leaves stop before root sync. CI applies only top-level root declarations, then validates/diffs/syncs/waits each authority followed by leaves. It never applies a competing leaf manager during ordinary deployment.

Source manifests affected by the immutable registration preparation: `gitops/clusters/<env>/bootstrap/root.yaml`, platform root source, `platform-applications/*.yaml`, and `apps/*.yaml`. Keep original names, app-of-apps paths, projects and Terraform/Argo ownership. Replace mutable targetRevision with reviewed source commits and chart fetches with verified vendored chart directories. Leaf chart/image/source changes must appear identically in committed root-rendered manifests and registry. The source's Argo self-management Application cannot take over the Helm-bootstrap controller without a separately reviewed controller ownership transition; it is intentionally not in the ordinary leaf allowlist. Do not silently sync an unregistered `argocd` child. Source `platform-projects` is likewise not an unbounded permission editor; bootstrap installs the explicitly reviewed AppProject documents.

The bootstrap role installs exact `projects` (platform/delivery as used by the registered Apps), while later mutation roles may not rewrite project privileges. The lifecycle `_hook` bootstrap installs controller/projects only; checkpoint authority restore is ordered separately after dependent leaf restore. A full source registration is not ready merely because these fields exist: run the local checks and review exact private root/child render before activation.

## Credential lifetime and bounded retries

GitOps operation jobs have a hard 45-minute runtime and request one 3600-second OIDC role session after checkout. Incident plan jobs are capped at 30 minutes and apply at 45 minutes with the same explicit session length. They never claim a 90-minute static session is refreshable. Large chapter registrations must finish within this bound; register reviewed chapter increments rather than deploying all future components in one initial run.

A timeout is failure, not receipt success. Ordinary reconcile can be rerun for the still-current reviewed main SHA after inspecting the unfinished Argo operation: exact source declarations remain pinned, no blanket prune occurs, and a new attempt gets its own receipt path. A bootstrap timeout before repository Secret creation may rerun the same exact Helm/bootstrap inputs; once that Secret exists, bootstrap deliberately refuses takeover. Inspect it and use ordinary reconcile for already-completed bootstrap rather than overwriting credentials. Incident timeouts retain the durable marker; use only the registered original-UID recovery/observe operation. Never rerun a credential-creating Job blindly or remove the marker to bypass recovery.
