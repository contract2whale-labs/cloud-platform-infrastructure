# versions.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# 준비02에서 확인한 Dev 계정과 기존 SSO 프로필을 사용하는 독립 bootstrap 구성입니다.
# 최초 실행은 backend 블록이 없는 로컬 State 로 시작하고, BU01-T5에서 backend.tf 를 추가합니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (provider 기본값 변화로 인한 예기치 않은 변경 방지)
    }
  }
}
