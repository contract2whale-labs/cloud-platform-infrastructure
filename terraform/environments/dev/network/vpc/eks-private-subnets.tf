# eks-private-subnets.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# /19 구획 4 · 5 · 6 의 주소를 vpc_cidr 에서 동적으로 계산합니다. AZ 이름을 for_each 키로 써서 리소스 주소의 의미를 고정합니다.
# AZ 목록을 재정렬하면 해당 AZ 의 CIDR 이 바뀌므로 기존 환경에서는 순서를 변경하지 않습니다.

locals {
  # 가용 영역(AZ) 이름을 Key로 고정하고, 각 AZ의 목록 내 위치(index)와 할당할 /19 CIDR을 계산하는 Map입니다.
  eks_subnet_plan_by_az = {
    for az in distinct(var.availability_zones) : az => {
      # var.availability_zones 리스트(["ap-northeast-2a", "2b", "2c"])에서 현재 AZ의 순서 번호를 찾습니다.
      index = index(var.availability_zones, az) # 예: 0 / 1 / 2 (AZ a, b, c 의 목록 내 위치)

      # vpc_cidr("172.20.0.0/16")에서 프리픽스를 3비트 늘려(/19) 4번, 5번, 6번 블록의 주소를 계산합니다.
      cidr = cidrsubnet(var.vpc_cidr, 3, index(var.availability_zones, az) + 4) # 예: "172.20.128.0/19" / "172.20.160.0/19" / "172.20.192.0/19"
    }
  }
  # 예: 결과는 { "ap-northeast-2a" = { index = 0, cidr = "172.20.128.0/19" }, ... } 형태의 map 3개 항목
}

# EKS 워커 노드와 Pod 가 사용할 전용 서브넷입니다. 클러스터와 노드는 이 파일에서 생성하지 않습니다.
resource "aws_subnet" "eks_private" {
  # 위에서 만든 AZ 기준 Map을 순회하여 3개의 서브넷 리소스를 생성합니다.
  # 생성되는 테라폼 리소스 주소 예: aws_subnet.eks_private["ap-northeast-2a"]
  for_each = local.eks_subnet_plan_by_az # 예: AZ a/b/c 를 키로 가진 map, 기본 입력에서 3회 반복

  # 앞 챕터(BU02)에서 생성한 VPC의 ID를 참조합니다.
  vpc_id = module.vpc.vpc_id # 예: "vpc-0123456789abcdef0" (배포 대상 VPC ID)

  # Map의 Key인 가용 영역 이름을 그대로 지정합니다.
  availability_zone = each.key # 예: "ap-northeast-2a" (현재 반복 중인 가용영역)

  # Map의 Value에 계산해 둔 /19 CIDR 대역을 지정합니다.
  cidr_block = each.value.cidr # 예: "172.20.128.0/19" (해당 AZ 에 배정된 /19 대역)

  # Private 서브넷이므로 이 서브넷에 뜨는 인스턴스에 공인 IPv4를 자동 할당하지 않습니다.
  map_public_ip_on_launch = false # 예: false (이 서브넷의 EC2 에 공인 IP 자동 부여 안 함)

  # 공통 태그(local.common_tags)에 EKS 전용 서브넷 식별용 태그 3개를 병합(merge)합니다.
  tags = merge(local.common_tags, {
    # 콘솔에서 식별하기 쉬운 서브넷 이름을 지정합니다.
    Name = "${local.vpc_name}-eks-private-${each.key}" # 예: "cp-dev-eks-private-ap-northeast-2a"

    # CLI 조회 및 다음 루트 모듈에서 EKS 서브넷만 필터링할 때 사용할 구분 태그입니다.
    SubnetType = "EKS-Private" # 예: "EKS-Private" (CLI 조회 시 필터 키)

    # AWS Load Balancer Controller가 내부용 로드밸런서(Internal ELB) 생성 시 서브넷을 자동 탐색하는 표준 태그입니다.
    "kubernetes.io/role/internal-elb" = "1" # 예: "1" (내부 LB 배치 대상 표시)
  })
}

# 기존 일반 Private 서브넷과 같은 AZ 의 라우팅 테이블 · NAT 를 공유합니다. 추가 NAT 는 생성하지 않습니다.
resource "aws_route_table_association" "eks_private" {
  # 서브넷과 동일한 AZ Map을 순회하여 3개의 라우팅 연결 리소스를 생성합니다.
  # 생성되는 테라폼 리소스 주소 예: aws_route_table_association.eks_private["ap-northeast-2a"]
  for_each = local.eks_subnet_plan_by_az # 예: AZ a/b/c 를 키로 가진 map, 기본 입력에서 3회 반복

  # 방금 위에서 생성한 같은 AZ의 EKS 전용 서브넷 ID를 참조합니다.
  subnet_id = aws_subnet.eks_private[each.key].id # 예: "subnet-0abc123def4567890" (해당 AZ 의 EKS 서브넷 ID)

  # 앞 챕터 VPC 모듈의 출력 리스트(private_route_table_ids)에서 each.value.index(0, 1, 2)로 같은 AZ의 라우팅 테이블 ID를 찾아 연결합니다.
  route_table_id = module.vpc.private_route_table_ids[each.value.index] # 예: "rtb-0123456789abcdef0" (같은 AZ 의 기존 Private RT ID)
}