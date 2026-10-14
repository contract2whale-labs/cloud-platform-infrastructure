# 누적 lifecycle의 실행 가능한 GitOps hook 계약

`gitops-lifecycle.py.run(start|plan|verify|apply)`를 engine의 고정 adapter 매핑에 연결합니다. 임의 스크립트 인자나 hook 이름을 전달하지 않습니다.

등록 ID와 DAG:

- hook:platform-core: Up에서 EKS/노드/Pod Identity와 platform/core 이후, mesh 이전. Down에서 gateway/mesh 후, platform/core IAM와 EKS/relay 이전. namespaces는 최종 클러스터 삭제까지 유지합니다.
- hook:platform-mesh: Up에서 core 이후, gateway 이전. Down에서 gateway 이후, core 이전.
- hook:platform-gateway: Up에서 core/mesh와 Terraform platform/gateway 선행 identity 이후. Down에서 실제 Gateway/인증 선언 → ExternalDNS → Envoy Gateway → AWS LBC 순으로 처리하고 LB가 없어질 때까지 controller를 유지합니다. platform/edge의 외부 의존성이 있다면 별도 등록된 edge retirement가 먼저 완료되어야 합니다. BU09 전체의 identity/edge lifecycle을 이 hook이 구현했다는 뜻은 아닙니다.

이 hook들은 Terraform-managed State를 변경하지 않습니다. Down의 모든 TF plan 및 hook plan을 하나의 검토 bundle에 넣을 수 있습니다. start는 읽기 snapshot만 수행하고 controller pause marker만 CAS 갱신합니다. 실제 Kubernetes 삭제는 전체 bundle의 파괴 승인 후 apply에서만 실행합니다.

공통 환경: LIFECYCLE_STEP_ID, OPERATION, COMPLETED_CHAPTER, LIFECYCLE_SNAPSHOT_SHA, LIFECYCLE_GENERATION, LIFECYCLE_CONFIG_SHA256, GitHub SHA/run/attempt/repository, EXPECTED_ACCOUNT_ID, STATE_BUCKET, AWS_REGION, AWS_ROLE_ARN. registered 환경에는 lifecycle_plan_role_arn/lifecycle_apply_role_arn을 추가합니다. 후자는 bootstrap 재설치까지 승인된 EKS 권한이 필요합니다. 운영 역할의 자체 IAM 수정 권한은 추가하지 않습니다.

plan 출력은 manifest_key/manifest_version/manifest_sha/plan_sha입니다. plan_sha는 고정 schema action-list JSON의 SHA256이며 shell text가 아닙니다. verify/apply는 MANIFEST_KEY/MANIFEST_VERSION/EXPECTED_MANIFEST_SHA/EXPECTED_PLAN_SHA로 동일한 버전과 바이트를 읽습니다. step_id, run, attempt, SHA, generation, registry digest, 별도 marker version, EKS/relay State version fingerprint 및 TTL을 모두 대조합니다.

`ci-lifecycle/<repository_id>/dev/hook-<id>.json`은 만료 없는 독립 CAS checkpoint입니다. 원래 app UID/spec/source revision/관리 child UID/spec/GVR와 데이터 결정은 plan 만료나 실패에도 유지합니다. 새 plan은 동일 snapshot의 검토 만료시간만 갱신합니다. app별 성공 prefix를 CAS로 기록하며 재시도에서 이미 삭제한 앱을 다시 삭제하지 않습니다. Up은 원래 checkpoint의 Application revision을 사용하며 최신 main으로 바꾸지 않습니다.

## 삭제와 보존

- `argocd app delete`의 이름만 사용하는 경쟁 조건 대신 UID/resourceVersion/spec JSON-patch test로 Argo cascade finalizer를 설정하고 UID precondition의 foreground DELETE를 보냅니다. Argo controller가 실제 자원을 삭제합니다. 강제 삭제/임의 finalizer 제거는 없습니다.
- API discovery로 관리 child를 조회하고 실제 GVR/name/UID/spec 및 정책 metadata를 고정합니다. 삭제 직전에도 같은 소유자와 객체 집합인지 확인합니다.
- LB는 단순 태그만으로 승인하지 않습니다. 정확한 AWS ARN/DNS/VPC를 live Service hostname/UID와 연결하고 ownerReference UID chain을 등록된 Argo app tracking resource까지 확인합니다. Service 삭제 이후에는 이미 검토한 ARN만 기다립니다. AWS ELB delete 호출은 없습니다.
- PVC/PV/backup/restore/bucket/object/database/Kafka 및 미등록 CR kind는 cascade를 막습니다. 모든 외부 S3 데이터·버전·bucket·KMS는 손대지 않습니다.
- core 완료 receipt에는 계획에 있던 residual 중 동일 UID/spec로 남아 있는 정확한 subset을 넣습니다. EKS adapter는 이 receipt를 원래 검토한 bundle에 대조하여 승인된 subset임을 확인한 뒤에만 사용할 수 있습니다. 파일 경로나 환경변수의 JSON을 단독 신뢰하면 안 됩니다.
- 잔여 Argo controller/Namespace/CRD/Application/AppProject를 허용하는 것은 EKS source/consumer proof와 연결해야 합니다. 함수가 존재한다는 이유로 registry를 ready로 바꾸지 않습니다. engine이 receipt와 bundle을 검증하고 exact residual matcher를 실제 호출하는 것까지 release acceptance 항목입니다.

원본 tooling hook의 단순 app 목록/태그/이름 기반 검사를 강화했습니다. 선택적 로컬 읽기 진단은 허용할 수 있지만, 이 문서의 생성·동기화·삭제·복구 명령은 모두 CI에서만 실행합니다.
