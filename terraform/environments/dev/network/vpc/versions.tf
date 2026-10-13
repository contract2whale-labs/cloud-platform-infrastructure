# versions.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 이 VPC 구성에서 검증한 CLI 와 provider 버전을 각각 고정합니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws"
      version = "= 6.62.0"      # 예: "= 6.62.0"
    }
  }
}
