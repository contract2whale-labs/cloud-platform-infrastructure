# versions.tf — bootstrap/ci-identity 루트 모듈 (dev · prod 공통 코드)
# State 버킷은 이미 있으므로 처음부터 S3 backend(backend.tf)를 사용합니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (bootstrap/state 와 같은 버전)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (bootstrap/state 와 같은 버전)
    }
  }
}