# 과정의 고정 도구 버전을 사용합니다. 새 root의 lock도 검토하여 커밋합니다.
terraform {
  required_version = "= 1.16.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.62.0"
    }
  }
}