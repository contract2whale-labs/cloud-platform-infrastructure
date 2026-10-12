# tests/inputs.tftest.hcl — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# AWS API 와 자격 증명 없이 mock provider 로 입력 계약을 확인합니다.
# 정상 입력 1건은 계산값을, 잘못된 입력 6건은 validation 이 거부하는지(expect_failures) 확인합니다.

mock_provider "aws" {
  override_during = plan # 예: plan 단계에서도 computed 값(arn·id)을 가짜 값으로 채움
}

variables {
  expected_account_id = "111111111111"                     # 예: 형식이 맞는 12자리 계정 ID
  region              = "ap-northeast-2"                   # 예: 서울 리전
  state_bucket_name   = "company-dev-tfstate-111111111111" # 예: 규칙을 만족하는 32자 이름
}

run "accepts_valid_inputs" {
  command = plan

  assert {
    condition     = local.state_bucket_name == var.state_bucket_name && length(local.state_bucket_name) <= 63
    error_message = "local.state_bucket_name 은 입력을 그대로 담고 63자 이하여야 합니다."
  }

  assert {
    condition     = endswith(var.state_bucket_name, var.expected_account_id)
    error_message = "이 과정의 State 버킷 이름은 계정 ID 로 끝나는 관례를 따릅니다 (터미널 입력 실수 감지용)."
  }
}

run "reject_account_id_with_hyphens" {
  command = plan

  variables {
    expected_account_id = "1111-1111-1111" # 예: 하이픈이 섞인 계정 ID
  }

  expect_failures = [var.expected_account_id]
}

run "reject_uppercase_bucket_name" {
  command = plan

  variables {
    state_bucket_name = "Company-Dev-Tfstate" # 예: 대문자가 섞인 이름
  }

  expect_failures = [var.state_bucket_name]
}

run "reject_reserved_prefix" {
  command = plan

  variables {
    state_bucket_name = "sthree-company-dev-tfstate" # 예: AWS 예약 접두사
  }

  expect_failures = [var.state_bucket_name]
}

run "reject_reserved_suffix" {
  command = plan

  variables {
    state_bucket_name = "company-dev-tfstate--x-s3" # 예: 디렉터리 버킷 전용 접미사
  }

  expect_failures = [var.state_bucket_name]
}

run "reject_short_name" {
  command = plan

  variables {
    state_bucket_name = "ab" # 예: 3자 미만
  }

  expect_failures = [var.state_bucket_name]
}

run "reject_region_format" {
  command = plan

  variables {
    region = "seoul" # 예: 리전 이름 형식이 아닌 값
  }

  expect_failures = [var.region]
}
