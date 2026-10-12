# backend.tf — bootstrap/ci-identity 루트 모듈 (dev · prod 공통 코드)
# 값은 init 할 때 backend.hcl 로 넘깁니다. 이 파일에는 실제 값을 적지 않습니다.

terraform {
  backend "s3" {}
}