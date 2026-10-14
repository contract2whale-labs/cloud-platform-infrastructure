# 기존 Dev bootstrap/ci-identity의 lifecycle inline policy를 이 버전으로 교체합니다.
# course + 검토된 network root checkpoint만 허용하며 역할 신뢰·일반 State 쓰기는 넓히지 않습니다.
# github_repository_id와 local.bucket_arn은 CI-S3-저장-plan-설정의 기존 선언을 재사용합니다.
locals {
  ci_vpc_lifecycle_keys = [
    for name in ["course", "network-vpc", "network-peer", "network-transit"] :
    "ci-lifecycle/${var.github_repository_id}/dev/${name}.json"
  ]
  ci_vpc_lifecycle_arns = [for key in local.ci_vpc_lifecycle_keys : "${local.bucket_arn}/${key}"]
  ci_network_up_plan_arns = [
    for root in ["vpc", "peer", "transit"] :
    "${local.bucket_arn}/ci-up-plans/${var.github_repository_id}/*/dev/network/${root}/lifecycle-up/*"
  ]
  ci_vpc_lifecycle_common = [
    {
      Sid      = "ReadExactSharedIncidentGate"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = ["${local.bucket_arn}/ci-incidents/${var.github_repository_id}/dev/active.json"]
    },
    {
      Sid      = "NeverDeleteAutomaticUpPlanVersions"
      Effect   = "Deny"
      Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
      Resource = local.ci_network_up_plan_arns
    },
    {
      Sid      = "DiscoverExactLifecycleMarker"
      Effect   = "Allow"
      Action   = ["s3:ListBucket"]
      Resource = [local.bucket_arn]
      Condition = {
        StringEquals = { "s3:prefix" = local.ci_vpc_lifecycle_keys }
      }
    },
    {
      Sid      = "ReadLifecycleMarker"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = local.ci_vpc_lifecycle_arns
    },
    {
      Sid    = "InspectVpcConsumers"
      Effect = "Allow"
      Action = [
        "ec2:DescribeVpcPeeringConnections", "ec2:DescribeTransitGatewayVpcAttachments",
        "ec2:DescribeVpnGateways", "ec2:DescribeInstances", "ec2:DescribeVpcEndpoints",
        "ec2:DescribeEgressOnlyInternetGateways", "eks:ListClusters",
        "elasticloadbalancing:DescribeLoadBalancers", "route53profiles:ListProfileAssociations",
      ]
      Resource  = "*"
      Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
    },
    {
      Sid      = "InspectPrivateHostedZoneConsumers"
      Effect   = "Allow"
      Action   = ["route53:ListHostedZonesByVPC"]
      Resource = "*"
    },
    {
      Sid      = "VerifyLifecycleMarkerHasNoExpiration"
      Effect   = "Allow"
      Action   = ["s3:GetLifecycleConfiguration"]
      Resource = [local.bucket_arn]
    },
    {
      Sid       = "InspectRegionalEksConsumers"
      Effect    = "Allow"
      Action    = ["eks:DescribeCluster"]
      Resource  = ["arn:aws:eks:${var.region}:${var.expected_account_id}:cluster/*"]
      Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
    },
    {
      Sid      = "NeverDeleteLifecycleMarker"
      Effect   = "Deny"
      Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
      Resource = local.ci_vpc_lifecycle_arns
    },
    {
      Sid      = "NeverWriteLifecycleWithoutCompareAndSwap"
      Effect   = "Deny"
      Action   = ["s3:PutObject"]
      Resource = local.ci_vpc_lifecycle_arns
      Condition = {
        Null = { "s3:if-match" = "true", "s3:if-none-match" = "true" }
      }
    },
  ]
  ci_vpc_lifecycle_phase = {
    plan = [
      {
        Sid      = "PlanCannotWriteAutomaticUpPlans"
        Effect   = "Deny"
        Action   = ["s3:PutObject"]
        Resource = local.ci_network_up_plan_arns
      },
      {
        Sid      = "PlanCannotChangeLifecycleMarker"
        Effect   = "Deny"
        Action   = ["s3:PutObject"]
        Resource = local.ci_vpc_lifecycle_arns
      },
    ]
    apply = [
      {
        # Dev Up만: 일반 ci-plans/ 쓰기 Deny는 그대로 유지합니다.
        Sid      = "ReadExactAutomaticUpPlans"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersion"]
        Resource = local.ci_network_up_plan_arns
      },
      {
        Sid       = "WriteNewAutomaticUpPlans"
        Effect    = "Allow"
        Action    = ["s3:PutObject"]
        Resource  = local.ci_network_up_plan_arns
        Condition = { StringEquals = { "s3:if-none-match" = "*" } }
      },
      {
        Sid       = "NeverOverwriteAutomaticUpPlans"
        Effect    = "Deny"
        Action    = ["s3:PutObject"]
        Resource  = local.ci_network_up_plan_arns
        Condition = { Null = { "s3:if-none-match" = "true" } }
      },
      {
        Sid      = "ApplyCreatesAbsentLifecycleMarker"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = local.ci_vpc_lifecycle_arns
        Condition = {
          StringEquals = { "s3:if-none-match" = "*" }
        }
      },
      {
        Sid      = "ApplyUpdatesMatchingLifecycleMarker"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = local.ci_vpc_lifecycle_arns
        Condition = {
          Null = { "s3:if-match" = "false" }
        }
      },
    ]
  }
  ci_vpc_lifecycle_documents = {
    for mode in ["plan", "apply"] : mode => jsonencode({
      Version   = "2012-10-17"
      Statement = concat(local.ci_vpc_lifecycle_common, local.ci_vpc_lifecycle_phase[mode])
    })
  }
}

# 기존 state_read의 ReadStateObjects에 s3:GetObjectVersion을 추가합니다.
# 정확한 state_object_arns를 재사용하되 bootstrap/ci-identity는 포함하지 않습니다.
# State ARN 목록을 여기서 반복하지 않아 장이 늘어도 policy 6,144 한도를 지킵니다.
# Dev에만 설치합니다. 기존 aws_iam_role_policy.vpc_lifecycle inline은
# 보호된 identity-admin saved plan에서 검토한 뒤 이 managed policy로 이관합니다.
resource "aws_iam_policy" "course_lifecycle" {
  for_each = var.environment == "dev" ? local.ci_vpc_lifecycle_documents : {}

  name   = "gha-infra-${var.environment}-course-lifecycle-${each.key}"
  policy = each.value
}

resource "aws_iam_role_policy_attachment" "course_lifecycle" {
  for_each = aws_iam_policy.course_lifecycle

  role       = aws_iam_role.ci[each.key].name
  policy_arn = each.value.arn
}
