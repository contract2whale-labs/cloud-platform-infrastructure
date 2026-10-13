# 기존 Dev bootstrap/ci-identity 루트에만 추가합니다.
# 기존 역할, OIDC 신뢰, State 권한, VPC 읽기·쓰기 정책을 유지합니다.
locals {
  bu02_vpc_plan_objects = "${local.bucket_arn}/bu02-vpc-lifecycle/*/saved.tfplan"
}

data "aws_iam_policy_document" "bu02_vpc_plan" {
  for_each = toset(["plan", "apply"])

  statement {
    sid       = "CheckPrivateVersionedBucket"
    actions   = ["s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock"]
    resources = [local.bucket_arn]
  }
  statement {
    sid       = "ReadExactSavedPlan"
    actions   = ["s3:GetObjectVersion"]
    resources = [local.bu02_vpc_plan_objects]
  }
  statement {
    sid       = "UploadPrivateFailureLog"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/bu02-vpc-lifecycle/*/diagnostics/${each.key}.log"]
  }
  dynamic "statement" {
    for_each = each.key == "plan" ? [1] : []
    content {
      sid       = "UploadSavedPlan"
      actions   = ["s3:PutObject"]
      resources = [local.bu02_vpc_plan_objects]
    }
  }
  dynamic "statement" {
    for_each = each.key == "apply" ? [1] : []
    content {
      sid       = "ApplyCannotReplaceSavedPlan"
      effect    = "Deny"
      actions   = ["s3:PutObject"]
      resources = [local.bu02_vpc_plan_objects]
    }
  }
  statement {
    sid       = "NeverDeleteSavedPlanVersions"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [local.bu02_vpc_plan_objects]
  }
}

resource "aws_iam_role_policy" "bu02_vpc_plan" {
  for_each = toset(["plan", "apply"])
  name     = "ci-bu02-vpc-saved-plan"
  role     = aws_iam_role.ci[each.key].id
  policy   = data.aws_iam_policy_document.bu02_vpc_plan[each.key].json
}
