# main.tf — bootstrap/ci-identity 루트 모듈 (dev · prod 공통 코드)
# GitHub OIDC provider(선택), plan 역할, apply 역할과 그 권한을 만듭니다.

locals {
  oidc_host      = "token.actions.githubusercontent.com"
  repo           = "${var.github_org}/${var.github_repo}"
  subject_prefix = coalesce(var.github_subject_prefix, "repo:${local.repo}") # 예: repo:my-org@111/infrastructure@222 (immutable subject 저장소) 또는 repo:my-org/infrastructure
  provider_arn   = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_oidc_provider_arn
  bucket_arn     = "arn:aws:s3:::${var.state_bucket_name}"

  # 역할 이름과 신뢰할 GitHub Environment 이름입니다. Environment 이름은 BU01 STEP 7.4 의 이름과 같습니다.
  roles = {
    plan = {
      name        = "gha-infra-${var.environment}-plan"
      environment = "infra-${var.environment}-plan"
    }
    apply = {
      name        = "gha-infra-${var.environment}-apply"
      environment = "infra-${var.environment}-apply"
    }
  }

  state_object_arns = [for k in var.state_keys : "${local.bucket_arn}/${k}"]
  lock_object_arns  = [for k in var.state_keys : "${local.bucket_arn}/${k}.tflock"]
}

# provider 는 계정당 하나만 만들 수 있습니다. 이미 있으면 create_oidc_provider=false 로 ARN 을 참조합니다.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"] # 예: ["sts.amazonaws.com"] (configure-aws-credentials 의 기본 audience)
}

# 이 저장소의 해당 Environment 에서 온 토큰만 역할을 받을 수 있습니다.
data "aws_iam_policy_document" "trust" {
  for_each = local.roles

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["${local.subject_prefix}:environment:${each.value.environment}"] # 예: repo:my-org/infrastructure:environment:infra-dev-plan
    }
  }
}

resource "aws_iam_role" "ci" {
  for_each = local.roles

  name                 = each.value.name
  assume_role_policy   = data.aws_iam_policy_document.trust[each.key].json
  max_session_duration = 3600 # 예: 3600 (1시간)
}

# plan·apply 공통: 등록한 State key 읽기, State 버킷 설정 읽기, 잠금 객체 읽기·쓰기·삭제
data "aws_iam_policy_document" "state_read" {
  statement {
    sid       = "ListStateBucket"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]
  }

  statement {
    sid = "ReadStateBucketConfig"
    actions = [
      "s3:GetBucket*",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetAccelerateConfiguration",
      "s3:GetReplicationConfiguration",
    ]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "ReadStateObjects"
    actions   = ["s3:GetObject"]
    resources = local.state_object_arns
  }

  statement {
    sid       = "UseLockObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = local.lock_object_arns
  }
}

# apply 전용: 등록한 State key 쓰기
data "aws_iam_policy_document" "state_write" {
  statement {
    sid       = "WriteStateObjects"
    actions   = ["s3:PutObject"]
    resources = local.state_object_arns
  }
}

# apply 전용: 다른 권한이 더해져도 CI 신원 자체는 바꾸지 못하게 거부합니다.
data "aws_iam_policy_document" "deny_ci_identity_changes" {
  statement {
    sid    = "DenyCiIdentityChanges"
    effect = "Deny"
    actions = [
      "iam:Add*",
      "iam:Attach*",
      "iam:Delete*",
      "iam:Detach*",
      "iam:Put*",
      "iam:Remove*",
      "iam:Tag*",
      "iam:Untag*",
      "iam:Update*",
    ]
    resources = concat([for r in aws_iam_role.ci : r.arn], [local.provider_arn])
  }
}

resource "aws_iam_role_policy" "state_read" {
  for_each = local.roles

  name   = "state-read"
  role   = aws_iam_role.ci[each.key].id
  policy = data.aws_iam_policy_document.state_read.json
}

resource "aws_iam_role_policy" "state_write" {
  name   = "state-write"
  role   = aws_iam_role.ci["apply"].id
  policy = data.aws_iam_policy_document.state_write.json
}

resource "aws_iam_role_policy" "deny_ci_identity_changes" {
  name   = "deny-ci-identity-changes"
  role   = aws_iam_role.ci["apply"].id
  policy = data.aws_iam_policy_document.deny_ci_identity_changes.json
}

resource "aws_iam_role_policy_attachment" "plan_additional" {
  for_each = toset(var.plan_additional_policy_arns)

  role       = aws_iam_role.ci["plan"].name
  policy_arn = each.value
}

resource "aws_iam_role_policy_attachment" "apply_additional" {
  for_each = toset(var.apply_additional_policy_arns)

  role       = aws_iam_role.ci["apply"].name
  policy_arn = each.value
}