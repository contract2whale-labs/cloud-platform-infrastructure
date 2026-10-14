# backend.tf — platform/dev-app-access 루트 모듈 (dev 전용)
# 승인된 개발자의 Private Dev 접근: backend 인자는 커밋하지 않는 backend.hcl 이 제공합니다 (terraform init -backend-config=backend.hcl).
# key 는 platform/dev-app-access/terraform.tfstate 로 실행 디렉터리 경로 규칙을 따릅니다 (원본의 platform/dev-app-access/dev/… 를 P2 규칙으로 바꿈).

terraform {
  backend "s3" {}
}
