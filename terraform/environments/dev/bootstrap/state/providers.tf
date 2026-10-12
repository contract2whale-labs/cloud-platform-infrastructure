# providers.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# 인증은 AWS_PROFILE 과 공유 AWS 설정(SSO)이 담당합니다. profile 이름과 access key 를 코드에 적지 않습니다.

provider "aws" {
  region = var.region # 예: "ap-northeast-2" (버킷을 만들 리전)

  # 인증된 계정이 입력한 계정과 다르면 provider 초기화 단계에서 거부합니다.
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (다른 계정 인증 시 즉시 중단)

  default_tags {
    tags = {
      ManagedBy = "Terraform"       # 예: "Terraform" (수동 생성 리소스와 구분)
      Component = "state-bootstrap" # 예: "state-bootstrap" (어느 구성이 만든 것인지 표시)
    }
  }
}
