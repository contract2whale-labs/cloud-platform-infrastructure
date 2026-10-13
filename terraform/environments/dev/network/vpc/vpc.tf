# vpc.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 계산한 서브넷 주소와 AZ 별 Egress 구성을 공개 VPC 모듈에 전달하고, NAT 와 Private 기본 경로는 이 파일의 리소스가 관리합니다.

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws" # 예: 공개 레지스트리의 VPC 모듈
  version = "6.7.2"                         # 예: "6.7.2" (정확한 버전; = 6.7.2 도 같은 의미)

  name = local.vpc_name         # 예: "cp-dev" (VPC 와 모든 서브넷 이름의 접두사)
  cidr = var.vpc_cidr           # 예: "172.20.0.0/16"
  azs  = var.availability_zones # 예: ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"]

  public_subnets  = local.public_subnets  # 예: ["172.20.0.0/22", "172.20.4.0/22", "172.20.8.0/22"]
  private_subnets = local.private_subnets # 예: ["172.20.32.0/19", "172.20.64.0/19", "172.20.96.0/19"]
  intra_subnets   = local.intra_subnets   # 예: ["172.20.12.0/28", "172.20.12.16/28", "172.20.12.32/28"]

  # VPC DNS 를 켜고 이 단계의 네트워크를 IPv4 전용으로 제한합니다.
  enable_dns_hostnames = true  # 예: true (공인 IPv4 인스턴스의 공인 DNS 이름; Endpoint private DNS 전제 조건)
  enable_dns_support   = true  # 예: true (VPC 내부 DNS 해석; Endpoint private DNS 전제 조건)
  enable_ipv6          = false # 예: false (IPv4 전용; IPv6 규칙을 한 벌 더 만들지 않음)
  enable_vpn_gateway   = false # 예: false (온프레미스 연결은 이 구성의 범위 밖)

  # public 서브넷의 기본 경로는 IGW 를 사용합니다.
  # EC2 의 공인 IP 자동 할당은 꺼도 NAT Gateway 의 EIP 와 IGW 경로는 별개로 동작합니다.
  create_igw                          = true  # 예: true (Internet Gateway 1개 생성)
  map_public_ip_on_launch             = false # 예: false (Public 서브넷 EC2 에 공인 IP 자동 부여 안 함)
  create_multiple_public_route_tables = true  # 예: true (AZ 마다 Public 라우팅 테이블 1개)
  create_multiple_intra_route_tables  = true  # 예: true (AZ 마다 Intra 라우팅 테이블 1개)

  # NAT 와 Private 기본 경로는 아래 루트 리소스가 관리합니다.
  # 이 조합은 모듈의 Private RT 를 AZ 별 3개로 유지합니다.
  enable_nat_gateway               = false # 예: false (모듈이 NAT 를 만들지 않음)
  single_nat_gateway               = false # 예: false
  one_nat_gateway_per_az           = true  # 예: true (Private RT 를 AZ 마다 1개로 유지)
  reuse_nat_ips                    = false # 예: false
  create_private_nat_gateway_route = false # 예: false (기본 경로는 aws_route.private_nat 이 관리)

  # default SG 의 inbound/outbound 규칙을 비웁니다. 워크로드는 별도 SG 가 필요합니다.
  manage_default_security_group  = true # 예: true (기본 SG 를 관리 대상에 포함)
  default_security_group_ingress = []   # 예: [] (인바운드 규칙 없음)
  default_security_group_egress  = []   # 예: [] (아웃바운드 규칙 없음)

  # default NACL 은 private · intra 서브넷이 사용하며 IPv4 허용 규칙을 명시합니다.
  manage_default_network_acl    = true                         # 예: true (기본 NACL 을 관리 대상에 포함)
  default_network_acl_ingress   = local.default_acl_allow_ipv4 # 예: rule_no 100 allow 전체
  default_network_acl_egress    = local.default_acl_allow_ipv4 # 예: 같은 목록을 반대 방향에도 적용
  private_dedicated_network_acl = false                        # 예: false (Private 은 기본 NACL 공유)
  intra_dedicated_network_acl   = false                        # 예: false (Intra 는 기본 NACL 공유)

  # public 서브넷은 전용 NACL 에 연결합니다. 이 구성은 양방향 IPv4 허용입니다.
  public_dedicated_network_acl = true                        # 예: true (Public 전용 NACL 1개 생성)
  public_inbound_acl_rules     = local.public_acl_allow_ipv4 # 예: rule_number 100 allow 전체
  public_outbound_acl_rules    = local.public_acl_allow_ipv4 # 예: 같은 목록을 반대 방향에도 적용

  # default route table 에 사용자 정의 경로를 추가하지 않습니다.
  # 각 서브넷은 위에서 생성한 전용 route table 에 명시적으로 연결됩니다.
  manage_default_route_table = true # 예: true (기본 라우팅 테이블을 관리 대상에 포함)
  default_route_table_routes = []   # 예: [] (사용자 정의 경로 없음)

  # Flow Logs 의 목적지 · 권한 · 보존 기간은 eks-network 에서 직접 설계합니다.
  enable_flow_log = false # 예: false (모듈 기본 구성 대신 직접 설계)

  # 컨트롤러가 용도별 서브넷을 찾을 때 사용하는 태그입니다. LB 생성 명령이 아닙니다.
  public_subnet_tags = {
    SubnetType               = "Public" # 예: "Public" (CLI 조회 시 필터 키)
    "kubernetes.io/role/elb" = "1"      # 예: "1" (외부용 로드밸런서 배치 대상 표시)
  }
  private_subnet_tags = {
    SubnetType                        = "Private" # 예: "Private"
    "kubernetes.io/role/internal-elb" = "1"       # 예: "1" (내부용 로드밸런서 배치 대상 표시)
  }
  intra_subnet_tags = {
    SubnetType = "Intra" # 예: "Intra" (로드밸런서 배치 대상 아님)
  }

  tags = local.common_tags # 예: {ManagedBy="Terraform", Environment="dev", Component="vpc"}
}

# 첫 두 AZ 에 NAT 를 만들고 세 번째 AZ 는 첫 NAT 를 공유합니다 (실습 비용 절감 설계).
locals {
  lab_nat_azs = slice(var.availability_zones, 0, 2) # 예: ["ap-northeast-2a", "ap-northeast-2b"]
}

resource "aws_eip" "lab_nat" {
  for_each = toset(local.lab_nat_azs)                                                 # 예: AZ 이름이 키 (목록 순서가 바뀌어도 주소가 유지됨)
  domain   = "vpc"                                                                    # 예: "vpc"
  tags     = merge(local.common_tags, { Name = "${local.vpc_name}-nat-${each.key}" }) # 예: "cp-dev-nat-ap-northeast-2a"
}

resource "aws_nat_gateway" "lab" {
  for_each      = toset(local.lab_nat_azs)                                                 # 예: AZ 이름이 키 (목록 순서가 바뀌어도 주소가 유지됨)
  allocation_id = aws_eip.lab_nat[each.key].id                                             # 예: 같은 AZ 키의 EIP
  subnet_id     = module.vpc.public_subnets[index(var.availability_zones, each.key)]       # 예: 같은 AZ 의 Public 서브넷
  tags          = merge(local.common_tags, { Name = "${local.vpc_name}-nat-${each.key}" }) # 예: "cp-dev-nat-ap-northeast-2a"

  depends_on = [module.vpc] # 예: IGW 와 Public 경로가 먼저 준비되어야 NAT 가 외부와 통신
}

resource "aws_route" "private_nat" {
  for_each               = { for i, az in var.availability_zones : az => i }         # 예: {"ap-northeast-2a" = 0, ...}
  route_table_id         = module.vpc.private_route_table_ids[each.value]            # 예: 같은 인덱스의 Private RT
  destination_cidr_block = "0.0.0.0/0"                                               # 예: 인터넷 기본 경로
  nat_gateway_id         = aws_nat_gateway.lab[local.lab_nat_azs[each.value % 2]].id # 예: index 2 (AZ-c) 는 AZ-a 의 NAT 공유
}
