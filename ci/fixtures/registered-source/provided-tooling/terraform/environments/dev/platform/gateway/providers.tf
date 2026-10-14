# providers.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)
# 이 Terraform root는 AWS provider만 사용합니다. controller chart와 Gateway·인증서 선언은 승인 Git source를 Argo CD Application이 적용하며, 이 root에 Kubernetes provider는 없습니다.
# 리전은 계약(cluster_contract.region)이 아니라 변수로 받습니다. provider 설정이 State 조회 결과에 의존하지 않게 하고, 변수 validation 과 모듈 validation 이 둘 다 ap-northeast-2 로 고정합니다.

provider "aws" {
  region              = var.region                # 예: "ap-northeast-2" (서울 리전; cluster_contract.region 과 같아야 함)
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (다른 계정이면 실행을 거부)

  # 지원되는 AWS 리소스에 공통 분류 태그를 전달합니다. IAM 권한이 아닙니다.
  default_tags {
    tags = {
      ManagedBy   = "Terraform"        # 예: "Terraform" (수동 생성 리소스와 구분)
      Environment = var.environment    # 예: "dev" (환경 구분)
      Component   = "platform-gateway" # 예: "platform-gateway" (이 루트 모듈이 만든 리소스에 공통으로 붙는 값)
    }
  }
}
