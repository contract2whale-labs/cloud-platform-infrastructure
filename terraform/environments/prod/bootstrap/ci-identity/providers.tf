# providers.tf — bootstrap/ci-identity 루트 모듈 (dev · prod 공통 코드)
# 인증은 AWS_PROFILE 과 공유 AWS 설정(SSO)이 담당합니다. 키를 코드에 적지 않습니다.

provider "aws" {
  region = var.region # 예: "ap-northeast-2"

  # 인증된 계정이 입력한 계정과 다르면 provider 초기화 단계에서 거부합니다.
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"]

  default_tags {
    tags = {
      ManagedBy = "Terraform"   # 예: "Terraform"
      Component = "ci-identity" # 예: "ci-identity" (어느 구성이 만든 것인지 표시)
    }
  }
}