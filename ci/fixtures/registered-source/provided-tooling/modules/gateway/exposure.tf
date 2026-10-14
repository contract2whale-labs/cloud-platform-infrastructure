# exposure.tf — modules/gateway (dev · prod 루트 모듈이 공유하는 모듈)
# exposure_mode 와 zone · NLB Security Group: exposure_mode 하나가 DNS zone 과 인바운드 경계에 함께 반영됩니다. private zone 0~1 · Security Group 1 · 인바운드 규칙 0~N(clients) + 0~1(cloudfront) · 아웃바운드 규칙 1 · data 1(prefix list).
# Security Group 은 NLB 생성 전에 있어야 합니다 (NLB 를 Security Group 없이 만든 뒤 붙이는 방식은 지원되지 않음). 생성기(Gateway와 인증서의 native 선언)가 이 SG ID 를 Service annotation 으로 넘깁니다.

# VPC 의 DNS support · hostnames 는 앞 구성(network/vpc)에서 켜져 있습니다. 이름이 같은 public zone 과 private zone 은 별개 리소스입니다.
resource "aws_route53_zone" "internal" {
  count         = contains(["internal", "waf"], var.exposure_mode) && var.existing_private_zone_id == null ? 1 : 0 # 예: internal · waf 이면서 재사용 ID 가 없을 때만 1개
  name          = var.public_zone.name                                                                             # 예: "dev.playdevops.click" (public zone 과 같은 이름)
  comment       = "Private application DNS for ${var.cluster_contract.name}"                                       # 예: "Private application DNS for contract2whale-dev-eks"
  force_destroy = true                                                                                             # 예: true (승인된 saved destroy plan 적용 시 zone 안의 레코드도 삭제 가능; 현재 사용·보존·삭제 승인은 별도 확인)

  vpc {
    vpc_id     = var.cluster_contract.vpc_id # 예: "vpc-0123456789abcdef0" (이 VPC 안에서만 응답)
    vpc_region = var.cluster_contract.region # 예: "ap-northeast-2"
  }

  depends_on = [terraform_data.contract] # 예: 계약 검사를 통과한 뒤에 만듭니다
}

resource "aws_security_group" "nlb" {
  name        = "${var.cluster_contract.name}-gateway-nlb" # 예: "contract2whale-dev-eks-gateway-nlb"
  description = "Explicit gateway exposure boundary"       # 예: 콘솔에서 용도를 알아보게 하는 설명 (변경 시 교체)
  vpc_id      = var.cluster_contract.vpc_id                # 예: "vpc-0123456789abcdef0"

  depends_on = [terraform_data.contract] # 예: 계약 검사를 통과한 뒤에 만듭니다
}

resource "aws_vpc_security_group_ingress_rule" "clients" {
  for_each          = var.exposure_mode == "waf" ? toset([]) : var.allowed_client_cidrs # 예: waf 면 빈 집합, 그 밖에는 허용 CIDR 집합
  security_group_id = aws_security_group.nlb.id                                         # 예: "sg-0123456789abcdef0"
  ip_protocol       = "tcp"                                                             # 예: "tcp"
  from_port         = 443                                                               # 예: 443 (시작 포트)
  to_port           = 443                                                               # 예: 443 (끝 포트, 한 포트만 열림)
  cidr_ipv4         = each.value                                                        # 예: "203.0.113.7/32"
  description       = "Approved HTTPS clients"                                          # 예: 규칙 목록에서 용도를 알아보게 하는 설명
}

# AWS 관리 prefix list 는 CloudFront 의 원본 접속 주소 목록을 AWS 가 갱신합니다.
data "aws_ec2_managed_prefix_list" "cloudfront" {
  count = var.exposure_mode == "waf" ? 1 : 0              # 예: waf 모드에서만 1개
  name  = "com.amazonaws.global.cloudfront.origin-facing" # 예: AWS 가 관리하는 목록 이름
}

resource "aws_vpc_security_group_ingress_rule" "cloudfront" {
  count             = var.exposure_mode == "waf" ? 1 : 0                # 예: waf 모드에서만 1개
  security_group_id = aws_security_group.nlb.id                         # 예: "sg-0123456789abcdef0"
  ip_protocol       = "tcp"                                             # 예: "tcp"
  from_port         = 443                                               # 예: 443
  to_port           = 443                                               # 예: 443
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront[0].id # 예: "pl-0123456789abcdef0"
  description       = "CloudFront VPC origin bootstrap connectivity"    # 예: 규칙의 용도 설명 (운영 환경 에서 VPC Origin 의 service-managed SG 로 대체 검토)
}

# NLB 에서 VPC 안의 Envoy 대상과 상태 검사로 나가는 트래픽입니다. 외부 목적지는 열지 않습니다.
resource "aws_vpc_security_group_egress_rule" "vpc" {
  security_group_id = aws_security_group.nlb.id    # 예: "sg-0123456789abcdef0"
  ip_protocol       = "-1"                         # 예: "-1" (모든 프로토콜)
  cidr_ipv4         = data.aws_vpc.this.cidr_block # 예: "172.20.0.0/16" (조회한 VPC 대역)
}
