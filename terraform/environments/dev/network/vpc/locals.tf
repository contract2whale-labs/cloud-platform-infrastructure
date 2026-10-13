# locals.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 계산한 이름 · 태그 · 주소를 이 구성 안의 여러 블록이 공유합니다. NACL 규칙은 network-acl.tf, NAT 배치는 vpc.tf 에 있습니다.

locals {
  vpc_name = "cp-${var.environment}" # 예: "cp-dev" (VPC 와 모든 서브넷 이름의 접두사)

  common_tags = {
    ManagedBy   = "Terraform"     # 예: "Terraform" (수동 생성 리소스와 구분)
    Environment = var.environment # 예: "dev" (환경 구분; 비용 배분 태그)
    Component   = "vpc"           # 예: "vpc" (어느 구성이 만든 것인지 표시)
  }

  # cidrsubnet(부모 CIDR, 추가 prefix 비트, 서브넷 번호)
  # /16 + 6 = /22: 첫 세 범위를 public 서브넷에 할당합니다.
  public_subnets = [
    for index, az in var.availability_zones :
    cidrsubnet(var.vpc_cidr, 6, index) # 예: index 0 → "172.20.0.0/22", 1 → "172.20.4.0/22", 2 → "172.20.8.0/22"
  ]

  # /16 + 3 = /19: 서브넷 번호 1, 2, 3 을 private 서브넷에 할당합니다.
  # 번호 0 은 Public · Intra 와 겹치므로 1 부터 시작합니다.
  private_subnets = [
    for index, az in var.availability_zones :
    cidrsubnet(var.vpc_cidr, 3, index + 1) # 예: index 0 → "172.20.32.0/19", 1 → "172.20.64.0/19", 2 → "172.20.96.0/19"
  ]

  # /16 + 12 = /28: 서브넷 번호 192, 193, 194 를 intra 서브넷에 할당합니다.
  # 192 x 16 = 3072 = 12 x 256 이므로 172.20.12.0 부터 시작합니다.
  # 이 범위의 라우팅 테이블에는 인터넷 기본 경로를 만들지 않습니다.
  intra_subnets = [
    for index, az in var.availability_zones :
    cidrsubnet(var.vpc_cidr, 12, index + 192) # 예: index 0 → "172.20.12.0/28", 1 → "172.20.12.16/28", 2 → "172.20.12.32/28"
  ]

  # 리소스 ID 가 아직 없어도 AZ 와 주소 배치를 검토할 수 있는 주소·AZ 배치를 보여 주는 값입니다.
  subnet_plan = {
    public = [
      for index, az in var.availability_zones : {
        az   = az                          # 예: "ap-northeast-2a"
        cidr = local.public_subnets[index] # 예: "172.20.0.0/22"
      }
    ]
    private = [
      for index, az in var.availability_zones : {
        az   = az                           # 예: "ap-northeast-2b" (index 1)
        cidr = local.private_subnets[index] # 예: "172.20.64.0/19" (index 1)
      }
    ]
    intra = [
      for index, az in var.availability_zones : {
        az   = az                         # 예: "ap-northeast-2c" (index 2)
        cidr = local.intra_subnets[index] # 예: "172.20.12.32/28" (index 2)
      }
    ]
  }
}
