# backend.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# backend 인자는 CI가 Environment 설정으로 생성합니다. 로컬 검사는 -backend=false 를 사용합니다.
# State 버킷은 state 의 버킷을 공유하고 key 로 루트 모듈을 구분합니다.

terraform {
  backend "s3" {}
}

