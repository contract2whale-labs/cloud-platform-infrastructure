# 실제 backend 값은 CI Environment에서 생성합니다. VPC와 다른 key를 사용합니다.
terraform {
  backend "s3" {}
}