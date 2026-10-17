# 정책·암호화·공개 차단·보존 설정까지 적용된 뒤 소비자에게 값을 넘깁니다.
output "network_logs_bucket_name" {
  description = "Name of the retained bucket shared by VPC Flow Logs and Resolver logs."
  value       = aws_s3_bucket.network_logs.bucket
  depends_on = [
    aws_s3_bucket_policy.network_logs,
    aws_s3_bucket_ownership_controls.network_logs,
    aws_s3_bucket_server_side_encryption_configuration.network_logs,
    aws_s3_bucket_public_access_block.network_logs,
    aws_s3_bucket_versioning.network_logs,
    aws_s3_bucket_lifecycle_configuration.network_logs,
  ]
}
output "network_logs_bucket_arn" {
  description = "ARN of the retained network log bucket."
  value       = aws_s3_bucket.network_logs.arn
  depends_on = [
    aws_s3_bucket_policy.network_logs,
    aws_s3_bucket_ownership_controls.network_logs,
    aws_s3_bucket_server_side_encryption_configuration.network_logs,
    aws_s3_bucket_public_access_block.network_logs,
    aws_s3_bucket_versioning.network_logs,
    aws_s3_bucket_lifecycle_configuration.network_logs,
  ]
}