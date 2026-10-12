# backend.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# backend 인자는 커밋하지 않는 backend.hcl 이 제공합니다 (terraform init -input=false -lockfile=readonly -backend-config=backend.hcl).
# State 버킷은 state 의 버킷을 공유하고 key 로 루트 모듈을 구분합니다.

terraform {
  backend "s3" {}
}

