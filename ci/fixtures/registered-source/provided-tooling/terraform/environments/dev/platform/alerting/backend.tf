# backend.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)
# 알림 루트 모듈과 설치 검사: backend 인자는 커밋하지 않는 backend.hcl 이 제공합니다 (terraform init -backend-config=backend.hcl).
# key 는 platform/alerting/terraform.tfstate 로 실행 디렉터리 경로 규칙을 따릅니다 (원본 platform/alerting/dev/terraform.tfstate — P2; platform/operations 와 다른 key, 같은 버킷).

terraform {
  backend "s3" {}
}
