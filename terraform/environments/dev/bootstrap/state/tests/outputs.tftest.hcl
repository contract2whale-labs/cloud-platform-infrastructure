# tests/outputs.tftest.hcl — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# mock provider 로 plan 만 실행해 출력 4개가 입력 계약·버킷 이름과 일치하는지 확인합니다.
# 실제 버킷 존재와 리전은 state 검증 절의 aws s3api 조회가 판정합니다.

mock_provider "aws" {
  override_during = plan # 예: plan 단계에서도 computed 값(arn·id)을 가짜 값으로 채움

  mock_resource "aws_s3_bucket" {
    defaults = {
      id  = "company-dev-tfstate-111111111111"              # 예: 실제 S3 와 같게 id = 버킷 이름
      arn = "arn:aws:s3:::company-dev-tfstate-111111111111" # 예: 출력 ARN 형식 검사를 위한 고정 가짜 값
    }
  }
}

variables {
  expected_account_id = "111111111111"                     # 예: 실제 계정과 무관한 mock 12자리 ID
  region              = "ap-northeast-2"                   # 예: 고정 mock 리전
  state_bucket_name   = "company-dev-tfstate-111111111111" # 예: 실제 생성하지 않는 mock 이름
}

run "outputs_match_inputs" {
  command = plan

  assert {
    condition     = output.state_bucket_name == var.state_bucket_name && output.state_region == var.region && output.expected_account_id == var.expected_account_id
    error_message = "출력 3개는 입력 계약과 같아야 합니다."
  }

  assert {
    condition     = output.state_bucket_arn == "arn:aws:s3:::${var.state_bucket_name}"
    error_message = "출력 ARN 은 arn:aws:s3:::<버킷 이름> 형식이어야 합니다."
  }
}
