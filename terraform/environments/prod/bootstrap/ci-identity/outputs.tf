# outputs.tf — bootstrap/ci-identity 루트 모듈 (dev · prod 공통 코드)
# 아래 두 ARN 을 BU01 STEP 7.4 의 AWS_ROLE_ARN 에 넣습니다.

output "oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider used by the CI roles."
  value       = local.provider_arn
}

output "plan_role_arn" {
  description = "ARN of the plan role. Use as AWS_ROLE_ARN in the infra-<env>-plan GitHub Environment."
  value       = aws_iam_role.ci["plan"].arn
}

output "apply_role_arn" {
  description = "ARN of the apply role. Use as AWS_ROLE_ARN in the infra-<env>-apply GitHub Environment."
  value       = aws_iam_role.ci["apply"].arn
}

output "trusted_subjects" {
  description = "The GitHub OIDC subject each role trusts."
  value       = { for k, v in local.roles : k => "${local.subject_prefix}:environment:${v.environment}" }
}