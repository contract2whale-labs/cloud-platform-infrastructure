# providers.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)
# 알림 루트 모듈과 설치 검사: AWS API 만 사용합니다. Alertmanager 자체는 관측 파이프라인 가 Helm 으로 설치하며 Kubernetes provider 는 두지 않습니다.
# 리전은 변수로 받고 모듈의 precondition 이 계약(cluster_contract.region)과 대조합니다.

provider "aws" {
  region              = var.region                # 예: "ap-northeast-2" (서울 리전)
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (다른 계정이면 실행을 거부)

  # 지원되는 AWS 리소스에 공통 분류 태그를 전달합니다. IAM 권한이 아닙니다.
  default_tags {
    tags = {
      ManagedBy   = "Terraform"         # 예: "Terraform" (수동 생성 리소스와 구분)
      Environment = var.environment     # 예: "dev" (환경 구분)
      Component   = "platform-alerting" # 예: "platform-alerting" (이 루트 모듈이 만든 리소스에 공통으로 붙는 값)
    }
  }
}
