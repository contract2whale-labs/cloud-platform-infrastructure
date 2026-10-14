# main.tf — modules/gateway (dev · prod 루트 모듈이 공유하는 모듈)
# NLB · Target Group 은 이 파일이 만들지 않습니다. AWS Load Balancer Controller 가 Gateway 의 Service 를 보고 만들고, Terraform 은 그 controller 의 신원과 권한만 소유합니다.
# 노출 경계(private zone · Security Group · 규칙)는 exposure.tf(exposure_mode 와 zone · NLB Security Group), 출력은 outputs.tf(exposure_mode 와 zone · NLB Security Group) 에 있습니다.

# 실제 plan 에서는 AWS 로 클러스터 · VPC · zone · 서브넷을 조회합니다. mock 테스트(tests/contracts.tftest.hcl)는 override_data 로 같은 모양의 응답을 줍니다.
data "aws_eks_cluster" "this" {
  name = var.cluster_contract.name # 예: "contract2whale-dev-eks" (계약에 적힌 클러스터 이름)
}

data "aws_vpc" "this" {
  id = var.cluster_contract.vpc_id # 예: "vpc-0123456789abcdef0" (계약에 적힌 VPC; cidr_block 은 exposure.tf 의 송신 규칙이 씀)
}

data "aws_route53_zone" "public" {
  name         = var.public_zone.name # 예: "dev.playdevops.click" (위임이 끝난 공개 zone 이름)
  private_zone = false                # 예: false (같은 이름의 private zone 을 제외하고 공개 zone 만 고름)
}

data "aws_route53_zone" "private" {
  count        = contains(["internal", "waf"], var.exposure_mode) && var.existing_private_zone_id != null ? 1 : 0 # 예: internal + 재사용 ID → 1, 그 밖에는 0
  name         = var.public_zone.name                                                                             # 예: "dev.playdevops.click" (public zone 과 같은 이름)
  private_zone = true                                                                                             # 예: true (VPC 에 연결된 private zone 만 찾음)
  vpc_id       = var.cluster_contract.vpc_id                                                                      # 예: "vpc-0123456789abcdef0" (이 VPC 에 연결된 zone 으로 한정)
}

data "aws_subnet" "nlb" {
  for_each = var.nlb_subnet_ids # 예: 서브넷 ID 3개 집합 (원소마다 조회 1개)
  id       = each.value         # 예: "subnet-00000000000000001"
}

resource "terraform_data" "contract" {
  lifecycle {
    precondition {
      condition     = alltrue([for s in data.aws_subnet.nlb : s.vpc_id == var.cluster_contract.vpc_id]) # 예: 서브넷 3개가 모두 계약의 VPC 에 있을 때만 참
      error_message = "NLB subnets must belong to the intended VPC."
    }

    precondition {
      condition     = length(toset([for s in data.aws_subnet.nlb : s.availability_zone])) == 3 && alltrue([for s in data.aws_subnet.nlb : contains(["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"], s.availability_zone)])
      error_message = "NLB subnets must sit in three distinct Seoul AZs."
    }

    precondition {
      condition     = terraform.workspace == "default" # 예: workspace 로 환경을 나누지 않음 (backend key 로 구분)
      error_message = "Use default workspace and a distinct backend key."
    }

    precondition {
      condition     = data.aws_eks_cluster.this.arn == var.cluster_contract.arn # 예: 이름으로 조회한 ARN 과 계약 ARN 이 글자 하나까지 같아야 통과
      error_message = "The EKS cluster looked up by name must match cluster_contract.arn (intended same-account cluster)."
    }

    precondition {
      condition     = split(":", var.cluster_contract.arn)[4] == var.expected_account_id # 예: ARN 의 5번째 항목(계정 12자리) == expected_account_id
      error_message = "cluster_contract.arn must belong to expected_account_id."
    }

    precondition {
      condition     = data.aws_eks_cluster.this.vpc_config[0].vpc_id == var.cluster_contract.vpc_id # 예: 클러스터가 보고하는 VPC 와 계약의 vpc_id 가 같아야 통과
      error_message = "The cluster must run in cluster_contract.vpc_id."
    }

    precondition {
      condition     = data.aws_route53_zone.public.zone_id == var.public_zone.id # 예: 이름으로 조회한 공개 zone ID 와 입력 ID 를 대조
      error_message = "The public zone name and ID must match."
    }

    precondition {
      # 예: 재사용 ID 를 넣은 internal · waf 모드에서만 조회 결과와 입력 ID 를 비교 (그 밖에는 항상 참)
      condition     = var.existing_private_zone_id == null || !contains(["internal", "waf"], var.exposure_mode) ? true : data.aws_route53_zone.private[0].zone_id == var.existing_private_zone_id
      error_message = "The private zone must match the name, ID and VPC association."
    }

    precondition {
      condition     = var.exposure_mode != "waf" || length(var.allowed_client_cidrs) == 0 # 예: waf 모드가 아니거나, waf 모드에서 허용 CIDR 이 비어 있을 때만 참
      error_message = "WAF mode only accepts CloudFront origin traffic; do not add bypass client CIDRs."
    }
  }
}

locals {
  # ExternalDNS 가 레코드를 쓸 zone 입니다. internal · waf 는 private zone ID(재사용 또는 exposure.tf 가 만든 것), public 은 공개 zone ID 입니다.
  dns_zone_id = contains(["internal", "waf"], var.exposure_mode) ? (var.existing_private_zone_id != null ? var.existing_private_zone_id : aws_route53_zone.internal[0].zone_id) : var.public_zone.id # 예: "Z0PRIVATE00000000000"

  # controller 마다 Role 1 + Pod Identity 연결 1. waf 모드는 앱 DNS 를 Edge Terraform 이 소유하므로 ExternalDNS 신원을 만들지 않습니다.
  controllers = merge(
    { lbc = { namespace = "kube-system", sa = "aws-load-balancer-controller" } },                  # 예: Helm values 의 serviceAccount.name 과 같은 이름
    var.exposure_mode != "waf" ? { dns = { namespace = "kube-system", sa = "external-dns" } } : {} # 예: waf 가 아니면 항목 2개(lbc, dns), waf 면 1개(lbc)
  )
}

# Pod Identity 의 namespace · ServiceAccount · 클러스터 세션 태그를 모두 고정합니다 (DNS01 최소 권한과 Pod Identity 의 cert-manager Role 과 같은 신뢰 조건).
resource "aws_iam_role" "controller" {
  for_each = local.controllers                               # 예: { lbc = {...}, dns = {...} } (항목마다 Role 1개)
  name     = "${var.cluster_contract.name}-${each.value.sa}" # 예: "contract2whale-dev-eks-aws-load-balancer-controller" · "contract2whale-dev-eks-external-dns"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" } # 예: Pod Identity 서비스만 이 Role 을 맡음
      Action    = ["sts:AssumeRole", "sts:TagSession"]   # 예: 세션 태그를 붙이려면 TagSession 도 필요
      Condition = {
        StringEquals = {
          "aws:RequestTag/kubernetes-namespace"       = each.value.namespace     # 예: "kube-system"
          "aws:RequestTag/kubernetes-service-account" = each.value.sa            # 예: "aws-load-balancer-controller"
          "aws:RequestTag/eks-cluster-arn"            = var.cluster_contract.arn # 예: "arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks"
        }
      }
    }]
  })

  depends_on = [terraform_data.contract] # 예: 계약 검사를 통과한 뒤에 만듭니다
}

# 공식 LBC v3.5.0 정책 원문입니다. EC2 조회와 ELB 생성에는 Resource = * 가 필요한 항목이 있습니다.
resource "aws_iam_policy" "lbc" {
  name   = "${var.cluster_contract.name}-load-balancer-controller"                  # 예: "contract2whale-dev-eks-load-balancer-controller"
  policy = file("${path.module}/policies/aws-load-balancer-controller-v3.5.0.json") # 예: 모듈 안의 정책 파일(문장 16개)을 그대로 읽음
}

resource "aws_iam_role_policy_attachment" "lbc" {
  role       = aws_iam_role.controller["lbc"].name # 예: "contract2whale-dev-eks-aws-load-balancer-controller"
  policy_arn = aws_iam_policy.lbc.arn              # 예: "arn:aws:iam::111111111111:policy/contract2whale-dev-eks-load-balancer-controller"
}

# ExternalDNS의 이 IAM 정책은 선택 zone의 A·AAAA·CNAME·TXT 변경을 허용합니다. DNS01 challenge TXT의 실제 생성·정리는 cert-manager solver가 담당하며, 별도로 승인한 core 신원·ClusterIssuer source를 대조합니다. 이 정책은 레코드 이름별 소유권 검사가 아닙니다.
resource "aws_iam_role_policy" "dns" {
  count = var.exposure_mode != "waf" ? 1 : 0 # 예: waf 모드가 아니면 1개, waf 모드면 0개
  role  = aws_iam_role.controller["dns"].id  # 예: "contract2whale-dev-eks-external-dns"
  name  = "route53-records"                  # 예: "route53-records" (Role 안에 붙는 inline 정책 이름)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["route53:ListHostedZones", "route53:ListHostedZonesByName"] # 예: zone 목록 조회는 계정 전체 대상
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["route53:ListResourceRecordSets"]                    # 예: 레코드 조회는 선택한 zone 하나만
        Resource = ["arn:aws:route53:::hostedzone/${local.dns_zone_id}"] # 예: "arn:aws:route53:::hostedzone/Z0PRIVATE00000000000"
      },
      {
        Effect   = "Allow"
        Action   = ["route53:ChangeResourceRecordSets"] # 예: 레코드 변경은 선택한 zone 에서 A · AAAA · CNAME · TXT 만
        Resource = ["arn:aws:route53:::hostedzone/${local.dns_zone_id}"]
        Condition = {
          "ForAllValues:StringEquals" = {
            "route53:ChangeResourceRecordSetsRecordTypes" = ["A", "AAAA", "CNAME", "TXT"] # 예: NS · SOA · MX 등은 거부
          }
        }
      }
    ]
  })
}

resource "aws_eks_pod_identity_association" "controller" {
  for_each        = local.controllers                     # 예: 항목마다 연결 1개
  cluster_name    = var.cluster_contract.name             # 예: "contract2whale-dev-eks"
  namespace       = each.value.namespace                  # 예: "kube-system"
  service_account = each.value.sa                         # 예: "aws-load-balancer-controller" · "external-dns"
  role_arn        = aws_iam_role.controller[each.key].arn # 예: "arn:aws:iam::111111111111:role/contract2whale-dev-eks-external-dns"

  depends_on = [aws_iam_role_policy_attachment.lbc, aws_iam_role_policy.dns] # 예: 권한이 붙은 뒤에 연결합니다
}
