# versions.tf — modules/alerting (dev · prod 루트 모듈이 공유하는 모듈)
# 계정 이벤트 경보 모듈: 계정 이벤트 경보(SNS 토픽 · 이메일 구독 · EventBridge 규칙 · 로그 지표 필터 · 경보 · Alertmanager Pod Identity)만 Terraform 으로 관리합니다.
# 과정 내부 전용 모듈이라 루트 모듈과 같은 값을 등호로 고정합니다 (P7). provider 블록은 두지 않습니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (이 버전에서만 실행합니다)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (AWS provider 를 한 버전으로 고정합니다)
    }
  }
}
