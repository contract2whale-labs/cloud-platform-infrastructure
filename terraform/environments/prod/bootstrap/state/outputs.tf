# outputs.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# 뒤 구성들의 backend.hcl 과 State 접근 IAM 정책이 참조하는 식별자 4개를 내보냅니다.

# terraform output -raw state_bucket_name 으로 다음 명령에서 읽습니다.
output "state_bucket_name" {
  description = "Bucket created for Terraform state and S3 lock files."
  value       = aws_s3_bucket.state.id # 예: "company-dev-tfstate-111111111111" (S3 는 이름이 곧 ID)
}

# State 접근 역할(account)의 정책에서 버킷 리소스를 지정할 때 씁니다.
output "state_bucket_arn" {
  description = "ARN used when granting the runner access to the state bucket."
  value       = aws_s3_bucket.state.arn # 예: "arn:aws:s3:::company-dev-tfstate-111111111111"
}

output "state_region" {
  description = "Region to use in the S3 backend configuration."
  value       = var.region # 예: "ap-northeast-2" (backend.hcl 의 region 인자에 그대로 사용)
}

output "expected_account_id" {
  description = "AWS account allowed by this bootstrap provider configuration."
  value       = var.expected_account_id # 예: "111111111111" (backend.hcl 의 allowed_account_ids 에 사용)
}
