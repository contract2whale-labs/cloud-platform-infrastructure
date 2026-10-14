# providers.tf — identity 루트 모듈 (dev · prod 공통 코드)
# 데이터 루트 모듈과 PostgreSQL 버전 고정: AWS API 만 사용합니다 (ServiceAccount 는 gitops/platform/tenant-baseline 의 Application이 관리합니다). 연결은 클러스터 API 가 아니라 EKS API 로 만들어지므로 kubeconfig 가 필요 없습니다.

provider "aws" {
  region              = var.region                # 예: "ap-northeast-2" (서울 리전)
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (다른 계정이면 실행을 거부)

  default_tags {
    tags = {
      ManagedBy   = "Terraform"     # 예: "Terraform"
      Environment = var.environment # 예: "dev"
      Component   = "identity"      # 예: "identity" (이 루트 모듈이 만든 Role 에 붙는 값)
    }
  }
}
