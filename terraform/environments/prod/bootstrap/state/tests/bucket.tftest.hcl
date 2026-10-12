# tests/bucket.tftest.hcl — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# mock provider 로 plan 만 실행해 버킷 보호 설정 5종과 Deny 전용 정책이 코드에 선언된 대로인지 확인합니다.
# 실제 AWS 상태는 state 검증 절의 aws s3api 조회가 판정합니다.

mock_provider "aws" {
  override_during = plan # 예: plan 단계에서도 computed 값(arn·id)을 가짜 값으로 채움

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::company-dev-tfstate-111111111111" # 예: 정책 Resource 검사를 위한 고정 가짜 값
    }
  }
}

variables {
  expected_account_id = "111111111111"                     # 예: 실제 계정과 무관한 12자리 mock 입력
  region              = "ap-northeast-2"                   # 예: 고정 mock 리전
  state_bucket_name   = "company-dev-tfstate-111111111111" # 예: 가짜 ID로 끝나는 mock 이름 (실제 생성 안 함)
}

run "declares_protection_settings" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state.bucket == var.state_bucket_name && aws_s3_bucket.state.force_destroy == true
    error_message = "버킷 이름은 입력값과 같고, 실습 삭제 기본값 force_destroy = true 여야 합니다."
  }

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "State 버킷의 versioning 은 Enabled 여야 합니다."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256" # 예: rule 은 set 이므로 one() 으로 꺼냄
    error_message = "기본 암호화는 SSE-S3 (AES256) 여야 합니다."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.state.block_public_acls,
      aws_s3_bucket_public_access_block.state.block_public_policy,
      aws_s3_bucket_public_access_block.state.ignore_public_acls,
      aws_s3_bucket_public_access_block.state.restrict_public_buckets,
    ])
    error_message = "공개 차단 네 옵션이 모두 true 여야 합니다."
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.state.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "객체 소유권은 BucketOwnerEnforced 여야 합니다."
  }
}

run "policy_denies_only" {
  command = plan

  assert {
    condition     = alltrue([for statement in jsondecode(aws_s3_bucket_policy.state.policy).Statement : statement.Effect == "Deny"])
    error_message = "버킷 정책에는 Deny 문장만 있어야 합니다 (Allow 는 IAM 이 담당)."
  }

  assert {
    condition     = length(jsondecode(aws_s3_bucket_policy.state.policy).Statement[0].Resource) == 2
    error_message = "Deny 는 버킷 수준과 객체 수준 두 Resource 에 모두 적용되어야 합니다."
  }

  assert {
    condition     = jsondecode(aws_s3_bucket_policy.state.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "비TLS 전송만 거부하는 조건이 있어야 합니다."
  }
}
