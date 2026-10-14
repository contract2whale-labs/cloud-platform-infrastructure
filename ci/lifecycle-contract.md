# 누적 chapter lifecycle 계약

## 입력과 실행 경계

GitHub Actions의 `terraform-lifecycle` 하나만 사용합니다.

- `operation`: `down` 또는 `up`
- `environment`: 현재 `dev`; `prod`는 자격증명을 받기 전에 중단
- `completed_chapter`: 실제 완료한 장, 예: `BU05`

로컬 작업은 코드 편집·정적 검사·PR입니다. Terraform 생성·변경·Down·Up은 CI가 수행합니다. BU01 최초 State/CI identity bootstrap은 명시된 예외입니다. 이후 권한 수정은 별도 보호된 identity-admin CI를 거치며 일반 apply 역할이 자기 권한을 변경하지 않습니다.

`BU05`의 실행 대상은 중복을 제거한 세 root입니다.

- Down: `network/transit` → `network/peer` → `network/vpc`
- Up: `network/vpc` → `network/peer` → `network/transit`
- State, CI identity/GitHub OIDC, account baseline/DNS, `network/log-storage`는 유지합니다.

BU05의 direct TGW 경로는 현재 guard의 검증 대상입니다. Inspection/Network Firewall 경로는 별도 소유권·service ENI 검증 구현 중이므로 아직 완료 지원으로 표시하지 않습니다.

registry만 `ready`로 바꿔 미구현 root나 hook을 활성화할 수 없습니다. 실행 adapter는 Python의 정적 매핑과 resource/ownership guard도 함께 구현되어야 합니다. BU06 이후의 EKS·GitOps·DB·LB 단계와 Prod는 현재 실행 adapter가 없어서 차단합니다. 전체 장의 root 지도와 실행 지원은 서로 다른 사실입니다.

## 이미 이전 BU02 workflow로 Down했다면

기존 standalone workflow는 `operation`과 `source_sha`를 받으며 이 누적 엔진의 `course.json` checkpoint를 만들지 않았습니다. 현재 main에서 과거 source/input을 추정하거나 빈 State를 새로운 완료 기록으로 취급하지 않습니다.

1. 실제 성공한 이전 Down run의 source SHA와 원래 `network/vpc` 입력을 확인합니다.
2. 아직 이전 workflow가 설치된 상태에서 같은 SHA·입력으로 이전 Up을 성공시킵니다.
3. VPC/NAT의 복구와 그 run의 결과를 확인한 뒤, 새 누적 엔진과 retained-storage 분리를 PR로 설치합니다.
4. 그 다음 누적 Down이 기록한 checkpoint로 누적 Up을 사용합니다.

기존 paused VPC marker의 generation/lineage가 누적 checkpoint와 다르면 자동 이관하지 않습니다. 임의 State 복사, `state rm`, marker 삭제로 맞추지 않습니다.

## Down: 하나의 계획 묶음, 실제 승인 한 번

1. main SHA, 실제 완료 장, 중복 제거 root DAG, root별 보호 입력, provider lock hash를 비만료 private checkpoint에 기록합니다.
2. 모든 root가 아직 존재하는 상태에서 각 root의 새 destroy saved plan을 만듭니다. State·상위 State fingerprint, source/input/lock, 원래 resource identity와 보존 경계를 묶습니다.
3. binary plan, 사람이 읽는 review, manifest와 bundle은 버전이 있는 private S3 객체입니다. 공개 Summary에는 위치·VersionId·해시·동작 수만 기록합니다.
4. `infra-dev-destroy`의 실제 Required reviewers gate에서 전체 review를 검토하고 한 번 승인합니다. 관리자 우회 금지와 main 제한을 사전 검사합니다. 이 job은 AWS 자격증명을 받지 않습니다.
5. apply job은 전체 bundle의 모든 manifest/plan/상태/만료를 먼저 검증합니다. 이후 역순으로 각 root를 적용하며 바로 직전 조건도 다시 검사합니다. 승인 후 재계획하지 않고 저장된 동일 binary를 적용합니다.
6. 완료한 root를 CAS checkpoint에 하나씩 기록합니다. Down이 끝나도 `paused`를 유지합니다.

TGW가 살아 있는 동안 VPC의 최종 소비자 부재를 미리 증명할 수 없습니다. 선택된 transit/peer의 파괴 계획을 먼저 검토하되, VPC의 전체 live-consumer guard는 그 root를 실제 적용하기 직전에 수행합니다. ENI 설명·태그·서브넷만으로 소유자를 추정하지 않습니다. 외부 소비자가 남으면 그 root 전에 중단하며, 앞서 완료한 승인된 삭제는 checkpoint에 남습니다. 이는 전체 Down의 원자성 보장이 아닙니다.

## Up: root마다 새 계획 후 동일 파일 자동 적용

기록된 원래 Terraform source와 보호 입력으로 정방향 실행합니다. 상위 root가 성공한 뒤 하위 root의 새 plan을 만들므로 재생성된 VPC ID/TGW ID 등 실제 현재 output을 읽습니다. 각 plan을 즉시 같은 binary로 적용하며, Terraform을 두 번 plan해서 다른 결과로 바꾸지 않습니다.

Dev 자동 적용 정책이므로 `infra-dev-apply`에서 실행합니다. Up은 Down 승인 파일을 재사용하지 않습니다. apply 역할은 기존 `ci-plans/`에 쓰지 못하므로 Up 전용 `ci-up-plans/<repository_id>/.../lifecycle-up/` namespace만 조건부 신규 쓰기를 허용합니다. 일반 plan/apply 역할 분리와 일반 `ci-plans/` 쓰기 Deny는 유지합니다. Up plan 진단 로그는 기존 apply 전용 경로에 저장합니다.

모든 root의 apply·완료 검증·private receipt와 최종 checkpoint가 성공해야 `active`로 바꿉니다. 중간 성공만으로 일반 CI를 재개하지 않습니다.

## 실패·재시도·동시 변경

- Down/Up 실패나 취소는 pause를 해제하지 않습니다.
- 성공한 dependency-order prefix를 건너뛰고, 실패/미완료 root는 현재 State에서 새 run/attempt의 새 plan을 만듭니다.
- 앞선 binary plan을 다시 적용하거나, 과거 State를 덮어쓰거나, 자동 `state rm`/`-target`을 수행하지 않습니다.
- root State, upstream State, source, 보호 입력, registry, 객체 버전/해시, checkpoint 소유권, plan 유효기간 중 하나라도 다르면 중단합니다.
- `terraform-apply`와 lifecycle은 같은 repository-wide concurrency를 사용합니다. `saved-plan.py`는 plan/apply 시작과 실제 적용 직전에 course pause를 검사하여 모든 Dev root의 일반 변경을 차단합니다.
- 이 잠금은 다른 저장소·관리자·수동 AWS writer를 잠그지 않습니다. 별도 writer를 동결하고 실제 적용 직전 검사를 통과해야 합니다.

## 필수 정책·설정

- `ci-vpc-lifecycle.tf`는 역할당 managed policy 한 개입니다. 이름은 `gha-infra-dev-course-lifecycle-plan` / `gha-infra-dev-course-lifecycle-apply`입니다. 기존 inline `vpc_lifecycle`에서의 이관은 identity-admin plan으로 검토하며 attachment quota도 검사합니다.
- 정확한 네 marker: `course.json`, `network-vpc.json`, `network-peer.json`, `network-transit.json`
- marker 및 과거 version 삭제 금지; 만료 lifecycle rule 금지; apply만 CAS 갱신
- 일반 private saved-plan 권한은 그대로 유지. 새로운 Up namespace만 apply 읽기/조건부 신규 쓰기 추가
- State 버킷의 기존 단일 lifecycle resource에 `ci-up-plans/` 전용 짧은 만료 rule을 추가. `ci-lifecycle/`이나 bucket 전체 prefix를 만료시키지 않기
- 기존 `state_read`의 `ReadStateObjects`에 `s3:GetObjectVersion` 추가. 기존 exact State ARN 목록을 재사용하고 보호된 `bootstrap/ci-identity` State는 포함하지 않기
- `network/log-storage/terraform.tfstate`를 등록 State 목록과 읽기 정책에 포함
- retained CI identity root는 checkpoint에서 input/lock/State를 읽지 않습니다. 일반 역할의 STS identity와 실제 허용된 State만 검사합니다.
- BU03 network extension 및 BU05 실제 resource에 필요한 검토된 서비스 권한. 코드를 복사했다고 IAM이 설치된 것으로 취급하지 않기
- S3 bucket, object/version, bucket policy·access·encryption과 필요한 KMS/identity는 Down에서 유지. `force_destroy` 사용 금지

## IAM 크기와 설치 한도

검토한 managed lifecycle policy는 plan 4,165자, apply 5,647자이며 각각 6,144자 안에 듭니다. 장이 늘어나는 State ARN 목록을 이 policy에 반복하지 않습니다. BU01 state-read/write·identity deny·private-plan 원본을 합산한 예시에서 Dev State 24개를 등록한 apply 역할의 inline core는 8,674자입니다. 10,240자까지 1,566자만 남으므로 새 admin deny나 다른 inline policy를 더할 때 실제 전체 합계와 managed attachment 수를 검사해야 합니다. 이 숫자는 사용자의 실제 계정 정책을 조회한 결과가 아닙니다.

## 검증 범위

로컬 fixture 검증은 실제 AWS/Actions 배포 검증과 다릅니다. 모의 테스트는 DAG·중복 제거·순서·checkpoint·새 plan 재시도·stale/tampered manifest 거부·실제 Environment gate 연결·보존 resource 차단을 검사합니다. 실환경의 OIDC, IAM 전체 크기/권한, S3 API, Terraform provider, GitHub gate, TGW/Firewall 삭제 및 Up 완료는 별도 승인된 CI run에서 확인해야 합니다.
