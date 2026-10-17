# vpc-extension-permissions.tf — BU03 시작 전에 같은 ci-identity 루트에 추가합니다.
# vpc-permissions.tf의 지역·계정 경계와 기존 역할을 그대로 사용합니다.
locals {
  # 06편에서 생성할 네트워크 로그 보존용 S3 버킷의 ARN입니다.
  vpc_ext_bucket_arn = "arn:aws:s3:::cp-${var.environment}-network-logs-${var.expected_account_id}-${var.region}"

  # Route 53 Resolver DNS 질의 로그 설정 리소스의 ARN 패턴입니다.
  vpc_ext_query_arn = "arn:aws:route53resolver:${var.region}:${var.expected_account_id}:resolver-query-log-config/*"

  # 기존 BU02 EC2 리소스 목록에 VPC 엔드포인트와 Flow Log 리소스 ARN을 합칩니다.
  vpc_ext_resources = concat(local.vpc_ci_resources, [
    "${local.vpc_ci_ec2_prefix}:vpc-endpoint/*",
    "${local.vpc_ci_ec2_prefix}:vpc-flow-log/*",
    "${local.vpc_ci_ec2_prefix}:subnet-cidr-reservation/*",
  ])
}

# Plan 역할과 Apply 역할에 공통으로 부여할 BU03 읽기 전용(Read) 관리형 정책입니다.
resource "aws_iam_policy" "vpc_extension_read" {
  name        = "gha-infra-${var.environment}-vpc-extension-read"
  description = "BU03 endpoints, CIDR reservation and network logging reads"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 보존용 네트워크 로그 버킷과 내부 객체는 CI에서도 절대 삭제하지 못하도록 명시적으로 거부(Deny)합니다.
        Sid      = "NeverDeleteRetainedNetworkLogs"
        Effect   = "Deny"
        Action   = ["s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = [local.vpc_ext_bucket_arn, "${local.vpc_ext_bucket_arn}/*"]
      },
      {
        # VPC 엔드포인트, Prefix List, 서브넷 CIDR 예약, Flow Log 상태를 조회하는 권한입니다.
        Sid    = "ReadVpcExtensions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcEndpointServices",
          "ec2:DescribePrefixLists", "ec2:DescribeManagedPrefixLists",
          "ec2:GetManagedPrefixListEntries", "ec2:GetSubnetCidrReservations", "ec2:DescribeFlowLogs",
        ]
        Resource  = "*"
        Condition = local.vpc_ci_region
      },
      {
        # 네트워크 로그 보존용 S3 버킷의 설정(암호화, 수명주기, 정책 등)을 읽어오는 권한입니다.
        Sid    = "ReadOnlyThisLogBucketConfiguration"
        Effect = "Allow"
        Action = [
          "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation",
          "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLogging",
          "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketRequestPayment",
          "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketWebsite",
          "s3:GetAccelerateConfiguration", "s3:GetLifecycleConfiguration",
          "s3:GetReplicationConfiguration", "s3:GetEncryptionConfiguration",
          "s3:GetBucketObjectLockConfiguration", "s3:GetBucketOwnershipControls", "s3:GetBucketPublicAccessBlock",
        ]
        Resource = local.vpc_ext_bucket_arn
      },
      {
        # Route 53 Resolver 질의 로그 설정 및 태그를 조회하는 권한입니다.
        Sid       = "ReadQueryLogConfiguration"
        Effect    = "Allow"
        Action    = ["route53resolver:GetResolverQueryLogConfig", "route53resolver:GetResolverQueryLogConfigPolicy", "route53resolver:ListTagsForResource"]
        Resource  = local.vpc_ext_query_arn
        Condition = local.vpc_ci_region
      },
      {
        # Route 53 Resolver 질의 로그와 VPC 간의 연결 상태를 조회하는 권한입니다.
        Sid       = "ReadQueryLogAssociations"
        Effect    = "Allow"
        Action    = ["route53resolver:GetResolverQueryLogConfigAssociation", "route53resolver:ListResolverQueryLogConfigAssociations", "route53resolver:ListResolverQueryLogConfigs"]
        Resource  = "*"
        Condition = local.vpc_ci_region
      },
    ]
  })
}

# Apply 역할에만 추가로 부여할 BU03 생성·수정·삭제(Write) 관리형 정책입니다.
resource "aws_iam_policy" "vpc_extension_write" {
  name        = "gha-infra-${var.environment}-vpc-extension-write"
  description = "BU03 reviewed endpoint, reservation and network logging lifecycle"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # CIDR 예약, VPC 엔드포인트, 엔드포인트 전용 보안 그룹, Flow Log를 생성·관리하는 권한입니다.
        Sid    = "ManageVpcExtensions"
        Effect = "Allow"
        Action = [
          "ec2:CreateSubnetCidrReservation",
          "ec2:CreateVpcEndpoint", "ec2:ModifyVpcEndpoint", "ec2:DeleteVpcEndpoints",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ec2:ModifySecurityGroupRules",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress", "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:CreateFlowLogs", "ec2:DeleteFlowLogs", "ec2:CreateTags", "ec2:DeleteTags",
        ]
        Resource  = local.vpc_ext_resources
        Condition = local.vpc_ci_region
      },
      {
        # 서브넷 CIDR 예약 삭제 API는 리소스 ARN 지정을 지원하지 않으므로 리전 조건으로 제한하여 허용합니다.
        Sid       = "DeleteSubnetReservationInRegion"
        Effect    = "Allow"
        Action    = "ec2:DeleteSubnetCidrReservation"
        Resource  = "*"
        Condition = local.vpc_ci_region
      },
      {
        # 지정된 리전에 네트워크 로그 보존용 S3 버킷을 생성하는 권한입니다.
        Sid      = "CreateOnlyThisRegionalLogBucket"
        Effect   = "Allow"
        Action   = "s3:CreateBucket"
        Resource = local.vpc_ext_bucket_arn
        Condition = {
          StringEquals = { "s3:LocationConstraint" = var.region }
        }
      },
      {
        # 네트워크 로그 보존용 S3 버킷의 정책, 암호화, 버전 관리, 수명주기 설정을 변경하는 권한입니다.
        Sid    = "ManageOnlyThisLogBucketConfiguration"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPolicy", "s3:PutBucketTagging", "s3:TagResource", "s3:PutBucketVersioning",
          "s3:PutBucketOwnershipControls", "s3:PutBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration",
        ]
        Resource = local.vpc_ext_bucket_arn
      },
      {
        # Write 정책에서도 보존용 로그 버킷과 내부 객체 삭제는 명시적으로 거부(Deny)하여 실수를 방지합니다.
        Sid      = "NeverDeleteRetainedNetworkLogs"
        Effect   = "Deny"
        Action   = ["s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = [local.vpc_ext_bucket_arn, "${local.vpc_ext_bucket_arn}/*"]
      },
      {
        # Route 53 Resolver 질의 로그 설정을 생성하고 VPC에 연결·해제하는 권한입니다.
        Sid    = "ManageQueryLogging"
        Effect = "Allow"
        Action = [
          "route53resolver:CreateResolverQueryLogConfig", "route53resolver:DeleteResolverQueryLogConfig",
          "route53resolver:AssociateResolverQueryLogConfig", "route53resolver:DisassociateResolverQueryLogConfig",
          "route53resolver:TagResource", "route53resolver:UntagResource",
        ]
        Resource  = local.vpc_ext_query_arn
        Condition = local.vpc_ci_region
      },
      {
        # VPC Flow Log를 S3 버킷으로 전달(Delivery)하도록 구성하는 데 필요한 로그 서비스 권한입니다.
        Sid       = "ManageS3FlowLogDelivery"
        Effect    = "Allow"
        Action    = ["logs:CreateLogDelivery", "logs:DeleteLogDelivery"]
        Resource  = "*"
        Condition = local.vpc_ci_region
      },
      {
        # Route 53 Resolver가 VPC에 처음 연결될 때 필요한 AWS 서비스 연결 역할(SLR) 1개만 생성을 허용합니다.
        Sid      = "CreateOnlyResolverServiceLinkedRole"
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "arn:aws:iam::${var.expected_account_id}:role/aws-service-role/route53resolver.amazonaws.com/AWSServiceRoleForRoute53Resolver"
        Condition = {
          StringEquals = { "iam:AWSServiceName" = "route53resolver.amazonaws.com" }
        }
      },
    ]
  })
}

# 기존 BU02 정책을 유지한 채, plan 역할과 apply 역할 모두에 BU03 읽기(Read) 정책을 연결합니다.
resource "aws_iam_role_policy_attachment" "vpc_extension_read" {
  for_each = toset(["plan", "apply"])

  role       = aws_iam_role.ci[each.key].name
  policy_arn = aws_iam_policy.vpc_extension_read.arn
}

# apply 역할에만 BU03 쓰기(Write) 정책을 추가로 연결합니다.
resource "aws_iam_role_policy_attachment" "vpc_extension_write" {
  role       = aws_iam_role.ci["apply"].name
  policy_arn = aws_iam_policy.vpc_extension_write.arn
}

# 생성된 확장 정책의 ARN을 출력값으로 남깁니다.
output "vpc_extension_permission_policy_arns" {
  value = {
    read  = aws_iam_policy.vpc_extension_read.arn
    write = aws_iam_policy.vpc_extension_write.arn
  }
}