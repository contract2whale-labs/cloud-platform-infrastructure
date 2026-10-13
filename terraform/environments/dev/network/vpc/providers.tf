# providers.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# AWS 인증은 해당 CI job의 OIDC 임시 자격 증명을 사용합니다. 코드에 profile 이름과 access key를 적지 않습니다.

provider "aws" {
  region              = var.region                # 예: "ap-northeast-2"
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (다른 계정 인증 시 즉시 중단)

  # 지원되는 AWS 리소스에 공통 분류 태그를 전달합니다. IAM 권한이 아닙니다.
  default_tags {
    tags = local.common_tags # 예: {ManagedBy="Terraform", Environment="dev", Component="vpc"}
  }
}
