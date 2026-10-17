# 실제 AWS나 S3 State에 연결하지 않고 plan으로 보존 계약을 검사합니다.
mock_provider "aws" {
  override_during = plan
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2"
      id  = "cp-testnet-network-logs-111111111111-ap-northeast-2"
    }
  }
}

variables {
  expected_account_id = "111111111111"
  region              = "ap-northeast-2"
  environment         = "testnet"
}

run "retain_bucket_and_all_object_versions" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket.network_logs.bucket == "cp-testnet-network-logs-111111111111-ap-northeast-2" &&
      aws_s3_bucket.network_logs.force_destroy == false &&
      aws_s3_bucket_versioning.network_logs.versioning_configuration[0].status == "Enabled" &&
      alltrue([for rule in aws_s3_bucket_lifecycle_configuration.network_logs.rule : rule.status == "Disabled"])
    )
    error_message = "The retained bucket must keep versions, disable expiration and never force-delete objects."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.network_logs.block_public_acls &&
      aws_s3_bucket_public_access_block.network_logs.block_public_policy &&
      aws_s3_bucket_public_access_block.network_logs.ignore_public_acls &&
      aws_s3_bucket_public_access_block.network_logs.restrict_public_buckets &&
      aws_s3_bucket_ownership_controls.network_logs.rule[0].object_ownership == "BucketOwnerEnforced" &&
      output.network_logs_bucket_arn == "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2"
    )
    error_message = "Storage protection and the stable output contract must remain intact."
  }
}

run "log_delivery_policy_and_delete_denial" {
  command = plan

  assert {
    condition = (
      length(local.network_logs_bucket_policy.Statement) == 4 &&
      local.network_logs_bucket_policy.Statement[0].Principal.Service == "delivery.logs.amazonaws.com" &&
      local.network_logs_bucket_policy.Statement[1].Condition.StringEquals["aws:SourceAccount"] == "111111111111" &&
      local.network_logs_bucket_policy.Statement[1].Condition.ArnLike["aws:SourceArn"] == "arn:aws:logs:ap-northeast-2:111111111111:*" &&
      toset(local.network_logs_bucket_policy.Statement[1].Resource) == toset([
        "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2/flow/AWSLogs/111111111111/*",
        "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2/dns/AWSLogs/111111111111/*"
      ]) &&
      local.network_logs_bucket_policy.Statement[2].Effect == "Deny" &&
      local.network_logs_bucket_policy.Statement[3].Effect == "Deny" &&
      toset(local.network_logs_bucket_policy.Statement[3].Action) == toset([
        "s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjectVersion"
      ])
    )
    error_message = "Log delivery must be account-scoped and bucket/object/version deletion explicitly denied."
  }
}