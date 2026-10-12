# Cloud Platform Infrastructure

Dev와 Prod는 별도 AWS 계정과 Terraform 실행 디렉터리로 관리합니다.
AWS 인프라와 EKS managed add-on은 Terraform이 관리합니다.
영속 Kubernetes 선언은 gitops/에 저장하고 담당 Argo Application이 관리합니다.
Controller가 만든 Pod·StatefulSet·Secret 값은 해당 controller가 소유합니다.
Kubernetes에 필요한 비밀 값은 외부 Secret 저장소에서 ESO를 통해 동기화하며 Git·plan·일반 로그에 넣지 않습니다.
Namespace는 공유 namespaces Application 하나가 관리합니다.
일시 진단 객체는 격리된 namespace와 제한된 runner에서 생성하고 정리합니다.
작업 branch의 변경은 PR·CI·동료 리뷰를 거쳐 main에 병합합니다.
Dev에서 검증한 같은 이미지 digest를 승인된 Prod 승격으로 전달합니다.
Terraform root는 default workspace와 독립된 S3 State key를 사용합니다.
backend.hcl·State·plan·실제 credential은 커밋하지 않습니다.
유지하려는 노드 수·파드 설정 등 비밀이 없는 구성과 예시·lock 파일은 코드 리뷰에 포함합니다.
운영 증거는 docs/execution/에 코드 revision·대상·시각·실제 결과로 기록합니다.
