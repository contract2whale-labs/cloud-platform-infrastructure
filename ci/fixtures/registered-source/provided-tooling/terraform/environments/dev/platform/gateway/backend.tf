# backend.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)
# 환경 root 두 개 연결: backend 인자는 커밋하지 않는 backend.hcl 이 제공합니다 (terraform init -backend-config=backend.hcl).
# key 는 platform/gateway/terraform.tfstate 로 실행 디렉터리 경로 규칙을 따릅니다 (platform/core/terraform.tfstate 와 같은 버킷; 원본의 platform/gateway-iam/dev/… 를 P2 규칙으로 바꿈).

terraform {
  backend "s3" {}
}
