variable "github_repository_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "GitHub 저장소의 숫자 repository_id가 필요합니다."
  }
}

locals {
  ci_plan_objects = "${local.bucket_arn}/ci-plans/${var.github_repository_id}/*"
  ci_log_objects  = "${local.bucket_arn}/ci-logs/${var.github_repository_id}/*"
  ci_log_write_objects = {
    plan = [
      "${local.ci_log_objects}/plan/*.log",
      "${local.ci_log_objects}/preview/*.log",
      "${local.ci_log_objects}/audit/*.log",
    ]
    apply = [
      "${local.ci_log_objects}/apply/*.log",
      "${local.ci_log_objects}/apply/outputs.json",
      "${local.ci_log_objects}/apply/completion.json",
    ]
  }
}

data "aws_iam_policy_document" "ci_private_plan" {
  for_each = toset(["plan", "apply"])

  statement {
    sid = "InspectPrivatePlanBucket"
    actions = [
      "s3:GetBucketVersioning",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
    ]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "ReadExactPlanVersions"
    actions   = ["s3:GetObjectVersion"]
    resources = [local.ci_plan_objects]
  }

  dynamic "statement" {
    for_each = each.key == "plan" ? [1] : []
    content {
      sid       = "WriteNewPrivatePlans"
      actions   = ["s3:PutObject"]
      resources = [local.ci_plan_objects]
    }
  }

  statement {
    sid       = "WritePrivateDiagnosticLogs"
    actions   = ["s3:PutObject"]
    resources = local.ci_log_write_objects[each.key]
  }

  statement {
    sid     = "PreventOtherPhaseWrites"
    effect  = "Deny"
    actions = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = each.key == "plan" ? [
      "${local.ci_log_objects}/apply/*",
      ] : [
      local.ci_plan_objects,
      "${local.ci_log_objects}/plan/*",
      "${local.ci_log_objects}/preview/*",
      "${local.ci_log_objects}/audit/*",
    ]
  }

  statement {
    sid       = "NeverDeletePrivatePlanVersions"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [local.ci_plan_objects]
  }
}

resource "aws_iam_role_policy" "ci_private_plan" {
  for_each = toset(["plan", "apply"])
  name     = "ci-private-plan"
  role     = aws_iam_role.ci[each.key].id
  policy   = data.aws_iam_policy_document.ci_private_plan[each.key].json
}
