# providers.tf — platform/dev-app-access 루트 모듈 (dev 전용)
# 승인된 개발자의 Private Dev 접근: AWS API 만 사용합니다 (SSM 문서 · IAM · EC2 SG 규칙 · NLB 조회). 클러스터 안 객체는 만들지 않습니다.

provider "aws" {
  region              = var.region                # 예: "ap-northeast-2"
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (다른 계정이면 실행을 거부)

  default_tags {
    tags = {
      ManagedBy   = "Terraform"               # 예: "Terraform"
      Environment = var.environment           # 예: "dev"
      Component   = "platform-dev-app-access" # 예: "platform-dev-app-access"
    }
  }
}
