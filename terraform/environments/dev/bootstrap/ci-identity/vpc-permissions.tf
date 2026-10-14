# vpc-permissions.tf — 기존 bootstrap/ci-identity 루트에 추가합니다.
# BU02의 IPv4 VPC, IGW, 서브넷, NAT/EIP, 라우팅, 기본 SG/NACL을 다룹니다.
locals {
  vpc_ci_ec2_prefix = "arn:aws:ec2:${var.region}:${var.expected_account_id}"
  vpc_ci_resources = [
    for kind in [
      "vpc", "subnet", "internet-gateway", "elastic-ip", "natgateway",
      "route-table", "network-acl", "security-group", "security-group-rule",
    ] : "${local.vpc_ci_ec2_prefix}:${kind}/*"
  ]
  vpc_ci_region = { StringEquals = { "aws:RequestedRegion" = var.region } }
}

# 조회 API는 리소스 ARN 제한을 지원하지 않는 항목이 있어 Action과 리전으로 제한합니다.
resource "aws_iam_policy" "vpc_read" {
  name        = "gha-infra-${var.environment}-vpc-read"
  description = "BU02 VPC refresh and data source reads"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadVpcTopology"
      Effect = "Allow"
      Action = [
        "ec2:DescribeAccountAttributes", "ec2:DescribeAddresses",
        "ec2:DescribeAvailabilityZones", "ec2:DescribeDhcpOptions",
        "ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls", "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules", "ec2:DescribeSubnets",
        "ec2:DescribeTags", "ec2:DescribeVpcAttribute", "ec2:DescribeVpcs", "ec2:DescribeAddressesAttribute",
      ]
      Resource  = "*"
      Condition = local.vpc_ci_region
    }]
  })
}

# 생성 시점부터 태그를 전달하는 VPC와 EIP에만 요청 태그 조건을 둡니다.
# AWS가 자동 생성한 기본 SG/NACL/라우팅 테이블에는 최초 채택 전 태그가 없을 수 있습니다.
resource "aws_iam_policy" "vpc_write" {
  name        = "gha-infra-${var.environment}-vpc-write"
  description = "BU02 reviewed VPC lifecycle changes"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CreateTaggedVpcAndEip"
        Effect   = "Allow"
        Action   = ["ec2:CreateVpc", "ec2:AllocateAddress"]
        Resource = ["${local.vpc_ci_ec2_prefix}:vpc/*", "${local.vpc_ci_ec2_prefix}:elastic-ip/*"]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion"        = var.region
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/ManagedBy"   = "Terraform"
            "aws:RequestTag/Component"   = "vpc"
          }
        }
      },
      {
        # 지정 리전에서 EIP 연결 해제를 허용합니다.
        Sid       = "DisassociateVpcElasticIp"
        Effect    = "Allow"
        Action    = ["ec2:DisassociateAddress"]
        Resource  = "*"
        Condition = local.vpc_ci_region
      },
      {
        Sid    = "ManageVpcTopology"
        Effect = "Allow"
        Action = [
          "ec2:ModifyVpcAttribute", "ec2:DeleteVpc",
          "ec2:CreateSubnet", "ec2:ModifySubnetAttribute", "ec2:DeleteSubnet",
          "ec2:CreateInternetGateway", "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway", "ec2:DeleteInternetGateway",
          "ec2:CreateNatGateway", "ec2:DeleteNatGateway", "ec2:ReleaseAddress",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable", "ec2:ReplaceRouteTableAssociation",
          "ec2:CreateRoute", "ec2:ReplaceRoute", "ec2:DeleteRoute",
          "ec2:CreateNetworkAcl", "ec2:DeleteNetworkAcl", "ec2:ReplaceNetworkAclAssociation",
          "ec2:CreateNetworkAclEntry", "ec2:ReplaceNetworkAclEntry", "ec2:DeleteNetworkAclEntry",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateTags", "ec2:DeleteTags",
        ]
        Resource  = local.vpc_ci_resources
        Condition = local.vpc_ci_region
      },
    ]
  })
}

# plan은 조회만, apply는 조회와 쓰기를 함께 받습니다. 기존 추가 정책 목록은 유지합니다.
resource "aws_iam_role_policy_attachment" "vpc_read" {
  for_each = toset(["plan", "apply"])

  role       = aws_iam_role.ci[each.key].name
  policy_arn = aws_iam_policy.vpc_read.arn
}

resource "aws_iam_role_policy_attachment" "vpc_write" {
  role       = aws_iam_role.ci["apply"].name
  policy_arn = aws_iam_policy.vpc_write.arn
}

# 실제 생성한 ARN을 조회할 때 사용합니다. ARN 문자열을 임의로 입력하지 않습니다.
output "vpc_permission_policy_arns" {
  value = {
    read  = aws_iam_policy.vpc_read.arn
    write = aws_iam_policy.vpc_write.arn
  }
}