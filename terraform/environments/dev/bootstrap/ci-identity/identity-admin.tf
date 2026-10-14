# Add this file to BOTH existing bootstrap/ci-identity roots during BU01.
# It references BU01's variables, locals, OIDC provider and aws_iam_role.ci.
# Keep existing resource addresses and State key; do not recreate/import them.
# Reuse github_repository_id from the required CI-S3 saved-plan appendix.

locals {
  # Existing course managed-policy names stay unchanged during CI adoption.
  identity_managed_policy_arns = [
    for prefix in [
      "gha-course-${var.environment}-",
      "gha-infra-${var.environment}-vpc-",
      "gha-infra-${var.environment}-course-lifecycle-",
      "course-${var.environment}-ci-bu0912-",
      "cp-${var.environment}-ci-",
      "course-packed/cp-${var.environment}-ci-packed-",
    ] : "arn:aws:iam::${var.expected_account_id}:policy/${prefix}*"
  ]
  # Static BU01 capability: no caller-supplied names, wildcard roles or instructor role.
  # These identities are created later by reviewed identity-admin plans.
  operational_role_names = concat([
    "cp-${var.environment}-gitops-bootstrap",
    "cp-${var.environment}-gitops-apply",
    "cp-${var.environment}-incident-plan",
    "cp-${var.environment}-incident-apply",
    "gha-infra-${var.environment}-lifecycle-destroy",
  ], var.environment == "dev" ? ["gha-aws-ops-dev-plan", "gha-aws-ops-dev-apply"] : [])
  operational_role_arns = [for name in local.operational_role_names : "arn:aws:iam::${var.expected_account_id}:role/${name}"]
  # SSO owns both identity roles and their capability/trust/boundary changes.
  # Fixed names match aws_iam_role.identity below; IAM reads remain permitted.
  identity_role_arns = [
    for phase in ["plan", "apply"] : "arn:aws:iam::${var.expected_account_id}:role/gha-identity-${var.environment}-${phase}"
  ]
  normal_identity_isolation_arn = "arn:aws:iam::${var.expected_account_id}:policy/gha-course-${var.environment}-identity-isolation"
  # No managed identity capability/boundary exists in this source today.
  # Future SSO-owned identity control policies must use this reserved prefix,
  # or their exact ARNs must be added here by SSO before they are attached.
  frozen_identity_policy_arns = [
    local.normal_identity_isolation_arn,
    "arn:aws:iam::${var.expected_account_id}:policy/gha-identity-${var.environment}-*",
  ]
  maintained_role_arns = concat(
    [for role in aws_iam_role.ci : role.arn],
    local.operational_role_arns
  )
  identity_state = "${local.bucket_arn}/bootstrap/ci-identity/terraform.tfstate"
  identity_roles = {
    plan  = "identity-${var.environment}-plan"
    apply = "identity-${var.environment}-apply"
  }
  identity_plan_objects = "${local.bucket_arn}/ci-plans/${var.github_repository_id}/*/*/*/${var.environment}/bootstrap/ci-identity/*"
  identity_log_prefix   = "${local.bucket_arn}/ci-logs/${var.github_repository_id}/*/*/*/${var.environment}/bootstrap/ci-identity"
  identity_log_objects  = "${local.identity_log_prefix}/*"
  identity_log_write_objects = {
    plan = [
      "${local.identity_log_prefix}/plan/*.log",
      "${local.identity_log_prefix}/preview/*.log",
      "${local.identity_log_prefix}/audit/*.log",
    ]
    apply = [
      "${local.identity_log_prefix}/apply/*.log",
      "${local.identity_log_prefix}/apply/outputs.json",
      "${local.identity_log_prefix}/apply/completion.json",
    ]
  }
  protected_identity_arns = concat(
    [for role in aws_iam_role.ci : role.arn],
    [for role in aws_iam_role.identity : role.arn],
    local.operational_role_arns,
    [local.provider_arn],
    local.identity_managed_policy_arns,
    local.frozen_identity_policy_arns,
    var.plan_additional_policy_arns,
    var.apply_additional_policy_arns
  )
}

resource "aws_iam_role" "identity" {
  for_each             = local.identity_roles
  name                 = "gha-identity-${var.environment}-${each.key}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = { StringEquals = {
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
        "${local.oidc_host}:sub" = "${local.subject_prefix}:environment:${each.value}"
      } }
    }]
  })
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role_policy" "identity" {
  for_each = local.identity_roles
  name     = "identity-admin"
  role     = aws_iam_role.identity[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # This also denies deleting/replacing the inline policy containing
        # these Denies. External SSO administrators retain the repair path.
        Sid    = "DenyIdentityRoleMutation"
        Effect = "Deny"
        Action = [
          "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
          "iam:TagRole", "iam:UntagRole", "iam:PassRole",
        ]
        Resource = local.identity_role_arns
      },
      {
        # CreatePolicyVersion can itself select the new default version.
        Sid    = "DenyIdentityControlPolicyMutation"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
          "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:TagPolicy", "iam:UntagPolicy",
        ]
        Resource = local.frozen_identity_policy_arns
      },
      {
        Sid      = "KeepNormalIdentityIsolationAttached"
        Effect   = "Deny"
        Action   = ["iam:DetachRolePolicy"]
        Resource = [for role in aws_iam_role.ci : role.arn]
        Condition = { ArnEquals = {
          "iam:PolicyARN" = local.normal_identity_isolation_arn
        } }
      },
      {
        # Blocks direct role relay from an identity session. This does NOT
        # constrain a separate GitHub OIDC session or arbitrary policy JSON
        # placed on another maintained role; this remains a privileged role.
        Sid      = "DenyDirectIdentityRoleRelay"
        Effect   = "Deny"
        Action   = ["sts:AssumeRole", "iam:PassRole"]
        Resource = ["*"]
      },
      {
        Sid      = "ReadIdentity"
        Effect   = "Allow"
        Action   = ["iam:Get*", "iam:List*"]
        Resource = ["*"]
      },
      {
        Sid      = "InspectPrivateBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetEncryptionConfiguration"]
        Resource = [local.bucket_arn]
      },
      {
        Sid      = "ReadIdentityState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = [local.identity_state]
      },
      {
        Sid      = "LockIdentityState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = ["${local.identity_state}.tflock"]
      },
      {
        Sid      = "ReadSavedPlan"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = [local.identity_plan_objects]
      },
      {
        Sid      = "PrivateDiagnostics"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = local.identity_log_write_objects[each.key]
      },
      {
        Sid    = "PreventOtherPhaseWrites"
        Effect = "Deny"
        Action = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = each.key == "plan" ? ["${local.identity_log_prefix}/apply/*"] : [
          local.identity_plan_objects,
          "${local.identity_log_prefix}/plan/*",
          "${local.identity_log_prefix}/preview/*",
          "${local.identity_log_prefix}/audit/*",
        ]
      },
      {
        Sid      = "NeverDeletePrivatePlanVersions"
        Effect   = "Deny"
        Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = [local.identity_plan_objects]
      }
      ], [for statement in [
        {
          Sid      = "PublishSavedPlan"
          Effect   = "Allow"
          Action   = ["s3:PutObject"]
          Resource = [local.identity_plan_objects]
        }
        ] : statement if each.key == "plan"], [for statement in [
        {
          Sid      = "WriteIdentityState"
          Effect   = "Allow"
          Action   = ["s3:PutObject"]
          Resource = [local.identity_state]
        },
        {
          Sid      = "MaintainCourseServicePolicies"
          Effect   = "Allow"
          Action   = ["iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:TagPolicy", "iam:UntagPolicy"]
          Resource = local.identity_managed_policy_arns
        },
        {
          Sid      = "MaintainNamedCiRoles"
          Effect   = "Allow"
          Action   = ["iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:TagRole", "iam:UntagRole"]
          Resource = local.maintained_role_arns
        },
        {
          Sid      = "CreateOnlyFixedOperationalRoles"
          Effect   = "Allow"
          Action   = ["iam:CreateRole"]
          Resource = local.operational_role_arns
        },
        {
          Sid      = "AttachOnlyReviewedCoursePolicies"
          Effect   = "Allow"
          Action   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
          Resource = local.maintained_role_arns
          Condition = { ArnLike = { "iam:PolicyARN" = concat(
            local.identity_managed_policy_arns,
            var.plan_additional_policy_arns,
            var.apply_additional_policy_arns
          ) } }
        }
    ] : statement if each.key == "apply"])
  })
}

# Extra deny, in addition to BU01's original normal-apply deny. Protect BOTH
# normal roles, even if later lessons attach an excessively broad Allow.
resource "aws_iam_policy" "normal_identity_isolation" {
  name = "gha-course-${var.environment}-identity-isolation"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyIdentityAndAttachedPolicyMutation"
        Effect   = "Deny"
        Action   = ["iam:Add*", "iam:Attach*", "iam:Create*", "iam:Delete*", "iam:Detach*", "iam:Put*", "iam:Remove*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Update*", "iam:PassRole"]
        Resource = local.protected_identity_arns
      },
      {
        Sid      = "DenyIdentityRoleChaining"
        Effect   = "Deny"
        Action   = ["sts:AssumeRole"]
        Resource = concat([for role in aws_iam_role.identity : role.arn], local.operational_role_arns)
      },
      {
        Sid      = "DenyIdentityStorageMutation"
        Effect   = "Deny"
        Action   = ["s3:*"]
        Resource = [local.identity_state, "${local.identity_state}.tflock", local.identity_plan_objects, local.identity_log_objects]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "normal_identity_isolation" {
  for_each   = local.roles
  role       = aws_iam_role.ci[each.key].name
  policy_arn = aws_iam_policy.normal_identity_isolation.arn
}

output "identity_plan_role_arn" { value = aws_iam_role.identity["plan"].arn }
output "identity_apply_role_arn" { value = aws_iam_role.identity["apply"].arn }

# Add least-privilege service policy JSON through reviewed source/input, allowing
# policy creation as well as attachment without a second local IAM operation.
variable "ci_service_policies" {
  type    = map(object({ role = string, document = string }))
  default = {}
  validation {
    condition = alltrue([for name, item in var.ci_service_policies :
      name != "identity-isolation" && can(regex("^[a-z0-9-]+$", name)) && contains(["plan", "apply"], item.role) && can(jsondecode(item.document))
    ])
    error_message = "Use lower-case policy names other than reserved identity-isolation, plan/apply role, and JSON policy documents."
  }
}
resource "aws_iam_policy" "course_service" {
  for_each = var.ci_service_policies
  name     = "gha-course-${var.environment}-${each.key}"
  policy   = each.value.document
}
resource "aws_iam_role_policy_attachment" "course_service" {
  for_each   = var.ci_service_policies
  role       = aws_iam_role.ci[each.value.role].name
  policy_arn = aws_iam_policy.course_service[each.key].arn
}