# BU16 고정 운영 CI

`../workflows/bu16-incident-operations.yml`을 실제 `.github/workflows/`에 설치합니다. main의 검토된 요청을 선택하여 **plan → 보호 Environment 승인 → 같은 비공개 action 파일 apply**로 실행합니다. Run workflow 입력은 환경과 고정 operation 이름뿐입니다. 임의 shell/SQL/YAML/patch/API 호출을 입력할 수 없습니다.

## 제공 operation

- selfheal-demo: Dev `contract2whale-demo/commerce-web` Rollout만 2→3으로 UID/resourceVersion 조건부 변경하고 selfHeal로 2로 복귀하는지 확인합니다. 실패해도 동일 대상·spec일 때 원래 2로 복구합니다. selfHeal 실패와 복구 성공은 별도 결과입니다.
- builder-cycle: Dev `monitoring/platform-tempo-e3-block-builder`만 원래 replicas→0→원래 replicas. 검토된 관찰시간 1–900초 후 finally 복구합니다. Argo 자동 조정 중지, 정확한 완료 source, HPA 부재, UID/spec가 필요합니다. lag/알림/업무 회복 판정은 자동으로 성공 처리하지 않습니다.
- builder-restore: 취소·runner 장애 뒤 원래 marker의 동일 UID/원래 replicas만 복구합니다. 현재 0을 정상 목표로 추정하지 않습니다. API target이 교체되거나 다른 writer가 변경했으면 중단합니다.
- job-cleanup: 이번 UUID의 `contract2whale-demo` database-operator Job 중 요청에 명시한 정확한 생성 UID만 foreground 삭제합니다. 실행 중 Job, 소유자 불명 Job, 다른 실험 Job은 거부합니다. Job·소유 Pod 부재까지 확인합니다.
- ecr-cleanup: Dev/Prod delivery State의 commerce-web/commerce-api 저장소에서 요청에 나열한 digest만 삭제합니다. image/signature 전체를 retain/delete로 분류해야 합니다. repository State/ARN과 실제 workload 참조, Argo suspension을 대조합니다. 응답 failures, 삭제 집합, 남은 retain 집합을 검증합니다. repository 자체는 삭제하지 않습니다.
- pitr-read-source / pitr-read-restored / pitr-read-after: BU16 T16의 고정 읽기 Job template. DB ARN/DbiResourceId/TLS host, runtime Secret ARN, SA UID, Pod Identity association/role, operator image digest를 대조합니다.
- pitr-fix-row: T16 고정 transaction만 실행합니다. 승인한 synthetic product id+handle+현재 status 한 행만 draft↔published로 바꾸며 정확히 1행이 아니면 rollback합니다. SQL 문자열 입력은 없습니다.
- pool-diagnostic: T15 고정 AFTER 진단 Job. 정확한 ConfigMap UID/내용 fingerprint, SA UID, association, role, image digest를 묶습니다.

T15/T16 template JSON은 제공 교안의 YAML에서 추출했습니다. template의 shell은 검토된 고정 코드이며 workflow 입력/요청에서 shell이나 SQL을 전달하지 않습니다. Job create는 기존 객체를 채택·덮어쓰지 않습니다. 완료 Job도 명시적인 cleanup까지 증거로 남깁니다. pool template의 원래 TTL 600초는 유지합니다.

## 실제 설정과 요청

상위 operations.json의 환경에 incident_plan_role_arn과 incident_apply_role_arn을 추가합니다. 기존 toolchain/state_bucket/account/region/repository 및 EKS/relay 등록을 재사용합니다. private EKS 연결은 version-pinned Terraform State의 실제 cluster/relay와 AWS live identity를 대조한 SSM 세션입니다.

Environment:
- incident-dev-plan / incident-prod-plan: 읽기 및 비공개 plan 신규 쓰기 권한
- incident-dev-mutate: Dev 실험·복구/Job 실행의 명시적 승인
- incident-dev-destructive / incident-prod-destructive: Job/ECR 삭제의 명시적 승인

모든 mutation Environment는 Required reviewers, 자기승인 금지, 관리자 우회 금지, main-only를 실제 API로 검사합니다. OIDC trust는 정확한 repository+Environment와 sts audience로 한정합니다. INCIDENT_ROLE_ARN/AWS_ACCOUNT_ID/AWS_REGION 변수는 승인한 환경값이어야 합니다. plan 역할은 Kubernetes/AWS mutation을 허용하지 않습니다. apply 역할은 아래 고정 대상만 허용하고 일반 Terraform 역할과 분리합니다.

requests.json의 environments.dev 또는 prod 아래에 operation별 현재 요청을 PR로 등록합니다. 기본 파일이 빈 것은 사용자별 실제 UUID/UID/승인/보존 결정을 코드가 만들어 낼 수 없기 때문입니다. 공통 필드:

- source_sha: 검토된 전체 Git SHA (현재 main 조상)
- expires_at: timezone이 있는 현재 승인 만료
- change_request: 해당 변경/복구 승인 기록 참조
- data_decision: 명시적인 데이터 보존/변경 결정

replica 요청: normal_replicas; builder-cycle은 hold_seconds 1–900. selfheal은 정상 2로 고정합니다. source_sha는 해당 App의 현재 immutable source와 실제 완료 operation revision 모두에 일치해야 합니다. 각 관찰시간은 queue retention/비용/철회 조건을 검토하여 정하며 코드는 이를 임의로 늘리지 않습니다.

job-cleanup: experiment_id UUID, jobs=[{name,uid}] (1–10개). 현재 성공/실패한 비활성 Job만 대상으로 합니다. Job 이름은 incident- 접두어 및 이번 UUID 접미어이며 source/준비 기록의 UID를 그대로 사용합니다. 준비 담당자의 객체를 포함하면 이 요청 자체에 그 정확한 삭제 위임을 기록해야 합니다.

ecr-cleanup: data_decision='delete-exact-approved-image-digests'; repositories에는 commerce-web/commerce-api 중 대상만 넣고 각각 delete_digests (1–100)와 retain_digests를 넣습니다. 각 값은 sha256:64자리입니다. 미분류 이미지·서명, live K8s workload/앱, 추가 EKS/ECS 소비자 또는 Lambda 참조가 있으면 멈춥니다. 이 계정/리전에 외부 서비스 소비자가 있다면 별도 consumer adapter가 선행되어야 하며, 미확인을 삭제 허가로 바꾸지 않습니다.

고정 Job create 공통: experiment_id, job_name, operator_image, serviceaccount_uid, association_id, operator_role_arn. T16은 db_identifier, db_arn, db_resource_id, db_host, runtime_secret_arn, sample_handle을 추가합니다. pitr-fix-row는 sample_id, expected_status, new_status 및 data_decision='update-one-exact-synthetic-product-row'가 필요합니다. pool-diagnostic은 configmap_name/configmap_uid가 필요합니다. 이름은 각 operation의 정해진 접두어+UUID로 계산됩니다. DB 비밀번호와 Secret 값은 요청에 넣지 않습니다.

## 승인·증거·복구

plan/action/review/manifest는 ci-plans/.../incidents/<operation>/에 version+hash로 저장됩니다. apply는 승인한 동일 바이트·동일 run/attempt/source·같은 marker와 underlying State fingerprint를 다시 확인합니다. TTL은 1시간이며 승인 요청 자체의 만료도 별도로 확인합니다. 공개 Actions 로그·artifact에는 cloud output, psql 결과, 비밀을 올리지 않습니다. receipt는 ci-logs/.../apply/receipt.json이며 성공 여부와 exact plan hash를 담습니다.

`ci-incidents/<repo>/<env>/active.json`은 비만료 private CAS marker입니다. phase=active/recovery-required이면 일반 Terraform/GitOps/다른 사건이 시작되지 않도록 공통 guard와 연결합니다. owner='kubernetes-fixed-operations'와 원래 UID/복구 목표를 유지합니다. source·account·bucket·region·run/attempt를 기록합니다. 다른 owner의 사건은 이 adapter로 해제할 수 없습니다. course.json은 수정하지 않습니다.

정상 예외/SIGTERM은 builder finally 복구를 시도합니다. runner 강제 종료·네트워크 단절은 finally 실행을 보장하지 않으므로 marker를 지우지 않습니다. builder-restore를 새 승인으로 실행합니다. 부분 Job/ECR 삭제는 원래 승인 집합의 남은 동일 UID/digest subset만 새 plan으로 재검토할 수 있습니다. Job 생성 응답을 받지 못해 UID가 불명인 경우 자동 재실행·채택·삭제하지 않습니다. 실제 생성 증거를 검토한 별도 복구가 필요합니다.

S3 bucket/object/version, 데이터 backup, namespace 전체, finalizer 강제 제거, 임의 DB 삭제는 이 adapter의 삭제 대상이 아닙니다.

## 검증

- `python -m unittest discover -s ci/gitops/operations/tests -v`
- 실제 AWS/GitHub/Kubernetes mutation 실행은 하지 않았습니다. source 기반 고정 handler와 fixture 테스트는 live 승인·IAM·Pod Identity·DB 실행 성공을 뜻하지 않습니다.
- 전체 BU16 mutation coverage와 아직 별도 구현이 필요한 source 범위는 BU16-MUTATION-COVERAGE.md를 확인합니다. 일부 operation을 구현했다고 모든 BU16 실험을 완료로 표시하지 않습니다.

## 추가 고정 Kubernetes 작업과 새 instructor fixture

T3–T6는 원래 ZIP에서 준비 파일이 빠져 있어 **새로 작성한 격리 실험**으로 제공합니다. `instructor-only/`의 네 강사 문서와 `fixture_ops.py`가 실제 명세입니다. `fixture-tN-cycle`은 정상 확인→고정 실패→실제 증상 확인→finally 원복, `fixture-tN-restore`는 원래 UID 복구, `fixture-tN-cleanup`은 생성 receipt/marker로 제한한 다섯 객체 정리(namespace/RBAC 보존)입니다. `fixture_image`는 게시한 `operator_image`와 같은 digest여야 하며 EKS pull 권한/경로를 먼저 준비합니다. cycle 요청에는 공통 필드와 hold_seconds 30–900만 필요합니다. cleanup 요청의 creation_receipt는 exact key/version/sha256입니다.

T7 `db-connect-during`/`db-connect-after`는 원문 고정 Job을 사용하고 각각 실패/성공을 확인합니다. 요청은 `attempt_id=dbe-YYYYMMDDtHHMMSS`, 고정 이름, database-bootstrap ConfigMap UID, digest operator image와 Pod Identity binding을 포함합니다. `db-connect-cleanup`은 같은 attempt의 exact Job UID만 삭제합니다. T16 restored 읽기는 AWS PITR 생성 receipt의 ARN/resource ID/endpoint/experiment를 검증하는 `restore_receipt`가 필수입니다.

`demand-scale`은 incident-t8a-demand만 승인한 상한 50 이하 replicas로 hold_seconds 1–900 동안 조정하고 원래 값으로 finally 복구합니다. 강제 중단은 `demand-restore`로 원래 marker의 UID/spec/replicas를 복원합니다. `node-protection-cycle`은 정확한 두 app Node UID와 고정 nodegroup을 확인하고 원래 annotation absent/false/true를 기록한 뒤 잠시 true로 보호하며 finally 원복합니다. 요청 `nodes=[{name,uid},{name,uid}]`, hold_seconds 1–900; 중단 시 `node-protection-restore`. 이는 기존 출처 불명 baseline 파일을 믿고 annotation을 제거하는 경로가 아닙니다. 이 CI에서 캡처하지 않은 기존 보호 값은 별도 승인된 마이그레이션 증거 없이 변경하지 않습니다.

기존 객체 정리용 fixed operations는 `t8-pdb-cleanup`, `t8a-cleanup`, `query-pod-cleanup`, `probe-configmap-cleanup`입니다. `target_uids`는 고정 GVR/namespace/name → UID map과 정확히 일치해야 합니다. Namespace 전체 정리는 제공하지 않습니다. T3–T6는 격리 fixture 경로만 사용합니다. 부분 성공 후에는 marker의 미완료 UID 집합으로 새 승인 plan을 만듭니다.

전용 incident role은 plan의 AWS/State/Kubernetes read 및 SSM 접속, apply의 한정 namespace 리소스 verbs와 marker/plan/receipt prefix 권한이 필요합니다. Node 작업은 별도 검토한 nodes get/patch 권한이 있어야 하며 일반 Dev 역할에 추가하지 않습니다. Environment OIDC subject와 정확한 계정/role ARN이 등록과 일치해야 합니다. 이 바인딩은 실제 학습자 설치 작업이며 빈 등록을 ready로 간주하지 않습니다.

Self-heal demonstration accepts the course's manually synchronized pinned App: when automated sync is disabled, the approved action temporarily enables only selfHeal with prune/allowEmpty false on the captured App UID/spec. It restores the original policy before final replica recovery. A forced stop uses `selfheal-restore` with the original marker. No production policy is enabled and no mutable branch is accepted.

The dispatcher now also registers platform probe, Velero and database bootstrap modules contributed with their own typed source/receipt contracts; see `PLATFORM-PROBES.md`/module-specific integration documents where present. Registration values and examples are configuration seeds, never observed live success.

`builder-cycle` 요청에는 experiment_id(UUID)가 필요합니다. 같은 saved action 안에서 replicas=0 → 고정 synthetic trace 송신 → blocks-only 조회 → finally replicas 복원 → 같은 TraceID 재조회 → exact Pod UID 정리를 수행합니다. receipt의 trace_observations가 관찰 증거이며 readiness만으로 원인을 단정하지 않습니다.
