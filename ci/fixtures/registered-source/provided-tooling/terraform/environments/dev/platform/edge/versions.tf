# versions.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)
# 환경 root 두 개 연결: Terraform 과 provider 버전을 고정합니다. backend 선언은 backend.tf 에, 모듈 버전과 aws.global alias 선언은 modules/edge/versions.tf 에 있습니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (모듈과 같은 값)
    }
  }
}
