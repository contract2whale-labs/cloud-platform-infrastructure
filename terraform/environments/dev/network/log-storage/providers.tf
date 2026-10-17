# CI의 OIDC 세션을 사용하고 다른 계정으로의 배포를 막습니다.
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = local.common_tags
  }
}