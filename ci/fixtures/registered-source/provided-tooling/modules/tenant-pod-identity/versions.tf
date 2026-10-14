# versions.tf — modules/tenant-pod-identity (dev · prod 루트 모듈이 공유하는 모듈)
# Pod Identity 재사용 모듈: 앱 네임스페이스의 Pod 신원 — 실행(runtime = commerce-api) · 운영자(operator) Role 과 세 ServiceAccount 의 Pod Identity 연결, 배포 플랫폼 migration Role 에 붙이는 데이터 권한을 관리합니다.
# 과정 내부 전용 모듈이라 루트 모듈과 같은 값을 등호로 고정합니다 (P7). provider 블록은 두지 않습니다 (데이터 루트 모듈과 PostgreSQL 버전 고정 identity 루트 모듈의 providers.tf 가 담당).

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (도구 저장소 tool-versions 고정값과 동일)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (과정 전체의 provider 고정값)
    }
  }
}
