# versions.tf — platform/dev-app-access 루트 모듈 (dev 전용)
# 승인된 개발자의 Private Dev 접근: 승인된 개발자의 Private Dev 접근 경로(고정 SSM 세션 문서 · 전용 IAM Role · NLB SG 출발지 규칙)를 이 루트 모듈이 직접 관리합니다 (모듈 없음; 원본 assets/access/dev-session/main.tf 의 재작성).

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (다른 루트 모듈과 같은 값)
    }
  }
}
