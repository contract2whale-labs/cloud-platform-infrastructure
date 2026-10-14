# 검토한 identity-admin으로 기존 Dev ci-identity root에 한 번 추가합니다.
# 기존 subject_prefix/provider_arn/bucket_arn/github_repository_id를 재사용합니다.
# 기존 EKS 출력/API에서 확인한 실제 nodegroup UUID ARN을 입력합니다.
variable "aws_ops_nodegroup_arn" {
  type    = string
  default = null
  validation {
    condition     = var.environment != "dev" || (var.aws_ops_nodegroup_arn != null && can(regex("^arn:aws:eks:ap-northeast-2:[0-9]{12}:nodegroup/contract2whale-dev-eks/contract2whale-dev-eks-app/[A-Za-z0-9-]+$", var.aws_ops_nodegroup_arn)))
    error_message = "Use the exact existing Dev app nodegroup ARN, including UUID."
  }
}
locals {
  aws_ops_writer_arn = "arn:aws:iam::${var.expected_account_id}:role/platform/cp-dev-observability-writer"
  aws_ops_marker     = "${local.bucket_arn}/ci-incidents/${var.github_repository_id}/dev/active.json"
  aws_ops_plans      = "${local.bucket_arn}/ci-ops-plans/${var.github_repository_id}/*"
  aws_ops_receipts   = "${local.bucket_arn}/ci-ops-receipts/${var.github_repository_id}/*"
}
resource "aws_iam_role" "aws_ops" {
  for_each             = var.environment == "dev" ? toset(["plan", "apply"]) : toset([])
  name                 = "gha-aws-ops-dev-${each.key}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = { StringEquals = {
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
        "${local.oidc_host}:sub" = "${local.subject_prefix}:environment:aws-ops-dev-${each.key}"
      } }
    }]
  })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = split(":", var.aws_ops_nodegroup_arn)[4] == var.expected_account_id
      error_message = "Nodegroup and existing account must match."
    }
  }
}
resource "aws_iam_role_policy" "aws_ops" {
  for_each = aws_iam_role.aws_ops
  role     = each.value.id
  name     = "fixed-course-operations"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Sid = "OnlyConditionalControlWrites", Effect = "Deny", Action = ["s3:PutObject"], Resource = [local.aws_ops_marker], Condition = { Null = { "s3:if-match" = "true", "s3:if-none-match" = "true" } } },
      { Sid = "ReadExactWriter", Effect = "Allow", Action = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies"], Resource = [local.aws_ops_writer_arn] },
      { Sid = "ReadExactNodegroup", Effect = "Allow", Action = ["eks:DescribeNodegroup", "eks:DescribeUpdate"], Resource = [var.aws_ops_nodegroup_arn, "arn:aws:eks:ap-northeast-2:${var.expected_account_id}:cluster/contract2whale-dev-eks"] },
      { Sid = "InspectPrivateBucket", Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration"], Resource = [local.bucket_arn] },
      { Sid = "ReadControlAndReview", Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = [local.aws_ops_marker, local.aws_ops_plans, "${local.bucket_arn}/ci-lifecycle/${var.github_repository_id}/dev/course.json", "${local.bucket_arn}/ci-lifecycle/${var.github_repository_id}/dev/network-vpc.json"] },
      { Sid = "NeverDeleteEvidence", Effect = "Deny", Action = ["s3:DeleteObject", "s3:DeleteObjectVersion"], Resource = [local.aws_ops_marker, local.aws_ops_plans, local.aws_ops_receipts] },
      { Sid = "NoRoleChaining", Effect = "Deny", Action = ["sts:AssumeRole", "iam:PassRole"], Resource = ["*"] },
      { Sid = "NoOwnIdentityMutation", Effect = "Deny", Action = ["iam:*"], Resource = concat([for role in aws_iam_role.aws_ops : role.arn], [local.provider_arn]) }
      ], each.key == "plan" ? [
      { Sid = "WritePlansOnly", Effect = "Allow", Action = ["s3:PutObject"], Resource = [local.aws_ops_plans] },
      { Sid = "NoMutationOrReceipts", Effect = "Deny", Action = ["s3:PutObject"], Resource = [local.aws_ops_marker, local.aws_ops_receipts] },
      { Sid = "NeverMutateTargets", Effect = "Deny", Action = ["iam:PutRolePolicy", "iam:DeleteRolePolicy", "eks:UpdateNodegroupConfig"], Resource = ["*"] }
      ] : [
      { Sid = "FixedIncidentPolicy", Effect = "Allow", Action = ["iam:DeleteRolePolicy", "iam:PutRolePolicy"], Resource = [local.aws_ops_writer_arn] },
      { Sid = "ExactNodegroupUpdate", Effect = "Allow", Action = ["eks:UpdateNodegroupConfig"], Resource = [var.aws_ops_nodegroup_arn] },
      { Sid = "WriteControlAndReceipt", Effect = "Allow", Action = ["s3:PutObject"], Resource = [local.aws_ops_marker, local.aws_ops_receipts] },
      { Sid = "NeverOverwritePlan", Effect = "Deny", Action = ["s3:PutObject"], Resource = [local.aws_ops_plans] },
    ])
  })
}
output "aws_ops_role_arns" { value = { for mode, role in aws_iam_role.aws_ops : mode => role.arn } }

# 일반 배포 역할은 작업 전용 역할이나 완료 증거를 바꾸지 못합니다.
resource "aws_iam_policy" "aws_ops_isolation" {
  count = var.environment == "dev" ? 1 : 0
  name  = "gha-course-dev-aws-operations-isolation"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadIncidentMarker", Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = [local.aws_ops_marker] },
      { Sid = "DiscoverIncidentMarker", Effect = "Allow", Action = ["s3:ListBucket"], Resource = [local.bucket_arn], Condition = { StringEquals = { "s3:prefix" = "ci-incidents/${var.github_repository_id}/dev/active.json" } } },
      { Sid = "ProtectOperationRoles", Effect = "Deny", Action = ["iam:*", "sts:AssumeRole"], Resource = [for role in aws_iam_role.aws_ops : role.arn] },
      { Sid = "ProtectOperationEvidence", Effect = "Deny", Action = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"], Resource = [local.aws_ops_marker, local.aws_ops_plans, local.aws_ops_receipts] }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "aws_ops_isolation" {
  for_each   = var.environment == "dev" && var.aws_ops_isolation_standalone_attachment ? local.roles : {}
  role       = aws_iam_role.ci[each.key].name
  policy_arn = aws_iam_policy.aws_ops_isolation[0].arn
}

variable "aws_ops_isolation_standalone_attachment" {
  type        = bool
  default     = true
  description = "False only after exact original isolation statements are read back in normal-role inline policies; keeps all Deny protection during migration."
}
