# backend.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# backend 인자는 커밋하지 않는 backend.hcl 이 제공합니다 (terraform init -backend-config=backend.hcl).
# backend 블록에는 변수를 쓸 수 없으므로 환경별 값은 backend.hcl.example 을 복사해 채웁니다.

terraform {
  backend "s3" {}
}
