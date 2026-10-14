# backend.tf — identity 루트 모듈 (dev · prod 공통 코드)
# 데이터 루트 모듈과 PostgreSQL 버전 고정: backend 인자는 커밋하지 않는 backend.hcl 이 제공합니다 (terraform init -backend-config=backend.hcl).
# key 는 identity/terraform.tfstate 로 실행 디렉터리 경로 규칙을 따릅니다 (P2). data 루트 모듈과 State 를 나누면 데이터 자원을 건드리지 않고 권한만 다시 적용할 수 있습니다.

terraform {
  backend "s3" {}
}
