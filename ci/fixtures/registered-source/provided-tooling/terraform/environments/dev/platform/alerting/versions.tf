# versions.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)
# 알림 루트 모듈과 설치 검사: Terraform 과 provider 버전을 고정합니다. backend 선언은 backend.tf 에, 모듈 버전은 modules/alerting/versions.tf 에 있습니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (모듈과 같은 값)
    }
  }
}
