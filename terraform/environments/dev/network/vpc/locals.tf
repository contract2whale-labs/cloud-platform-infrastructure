# locals.tf — network/vpc 루트 모듈의 공통 태그
# 다음 편에서 이 태그를 유지하고 VPC 이름·주소 계산을 추가합니다.
locals {
  common_tags = {
    ManagedBy   = "Terraform"     # 예: "Terraform"
    Environment = var.environment # 예: "dev"
    Component   = "vpc"           # 예: "vpc"
  }
}
