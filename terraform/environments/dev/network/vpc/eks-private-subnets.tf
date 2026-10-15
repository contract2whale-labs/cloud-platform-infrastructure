# eks-private-subnets.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# /19 구획 4 · 5 · 6 의 주소를 vpc_cidr 에서 동적으로 계산합니다. AZ 이름을 for_each 키로 써서 리소스 주소의 의미를 고정합니다.
# AZ 목록을 재정렬하면 해당 AZ 의 CIDR 이 바뀌므로 기존 환경에서는 순서를 변경하지 않습니다.

locals {
  eks_subnet_plan_by_az = {
    for az in distinct(var.availability_zones) : az => {
      index = index(var.availability_zones, az)                                  # 예: 0 / 1 / 2 (AZ a, b, c 의 목록 내 위치)
      cidr  = cidrsubnet(var.vpc_cidr, 3, index(var.availability_zones, az) + 4) # 예: "172.20.128.0/19" / "172.20.160.0/19" / "172.20.192.0/19"
    }
  }
  # 예: 결과는 { "ap-northeast-2a" = { index = 0, cidr = "172.20.128.0/19" }, ... } 형태의 map 3개 항목
}

# EKS 워커 노드와 Pod 가 사용할 전용 서브넷입니다. 클러스터와 노드는 이 파일에서 생성하지 않습니다.
resource "aws_subnet" "eks_private" {
  for_each = local.eks_subnet_plan_by_az # 예: AZ a/b/c 를 키로 가진 map, 기본 입력에서 3회 반복

  vpc_id                  = module.vpc.vpc_id # 예: "vpc-0123456789abcdef0" (배포 대상 VPC ID)
  availability_zone       = each.key          # 예: "ap-northeast-2a" (현재 반복 중인 가용영역)
  cidr_block              = each.value.cidr   # 예: "172.20.128.0/19" (해당 AZ 에 배정된 /19 대역)
  map_public_ip_on_launch = false             # 예: false (이 서브넷의 EC2 에 공인 IP 자동 부여 안 함)

  tags = merge(local.common_tags, {
    Name                              = "${local.vpc_name}-eks-private-${each.key}" # 예: "cp-dev-eks-private-ap-northeast-2a"
    SubnetType                        = "EKS-Private"                               # 예: "EKS-Private" (CLI 조회 시 필터 키)
    "kubernetes.io/role/internal-elb" = "1"                                         # 예: "1" (내부 LB 배치 대상 표시)
  })
}

# 기존 일반 Private 서브넷과 같은 AZ 의 라우팅 테이블 · NAT 를 공유합니다. 추가 NAT 는 생성하지 않습니다.
resource "aws_route_table_association" "eks_private" {
  for_each = local.eks_subnet_plan_by_az # 예: AZ a/b/c 를 키로 가진 map, 기본 입력에서 3회 반복

  subnet_id      = aws_subnet.eks_private[each.key].id                  # 예: "subnet-0abc123def4567890" (해당 AZ 의 EKS 서브넷 ID)
  route_table_id = module.vpc.private_route_table_ids[each.value.index] # 예: "rtb-0123456789abcdef0" (같은 AZ 의 기존 Private RT ID)
}
