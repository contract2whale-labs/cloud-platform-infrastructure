# outputs.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# VPC 관련 출력 11개입니다. 같은 루트의 EKS 서브넷 파일은 module.vpc를 직접 참조하며, 독립 EKS 루트는 필요한 출력을 terraform_remote_state로 읽습니다. Transit은 뒤에서 추가하는 vpc_contract를 사용합니다.

# 후속 EKS 와 네트워크 구성이 참조할 VPC ID 입니다. AWS 태그 재조회에 의존하지 않습니다.
output "vpc_id" {
  description = "ID of the VPC created by this root."
  value       = module.vpc.vpc_id # 예: "vpc-0123456789abcdef0"
}

# 입력 CIDR 과 실제 모듈 출력의 연결을 확인합니다.
output "vpc_cidr_block" {
  description = "IPv4 CIDR of the VPC."
  value       = module.vpc.vpc_cidr_block # 예: "172.20.0.0/16" (SG 규칙의 출발지 CIDR 로 사용)
}

# 순서가 subnet 및 route 목록의 의미를 결정하므로 그대로 공개합니다.
output "availability_zones" {
  description = "Ordered AZs used to allocate all three subnet groups."
  value       = var.availability_zones # 예: ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"]
}

# public 서브넷은 IGW 경로와 NAT Gateway 배치에 사용합니다.
output "public_subnet_ids" {
  description = "Public subnet IDs in availability_zones order."
  value       = module.vpc.public_subnets # 예: ["subnet-0pa...", "subnet-0pb...", "subnet-0pc..."]
}

# private 서브넷은 AZ 별 NAT 기본 경로를 사용합니다.
output "private_subnet_ids" {
  description = "Private subnet IDs in availability_zones order."
  value       = module.vpc.private_subnets # 예: ["subnet-0ra...", "subnet-0rb...", "subnet-0rc..."]
}

# intra 서브넷에는 이 구성에서 인터넷 기본 경로를 만들지 않습니다.
output "intra_subnet_ids" {
  description = "Intra subnet IDs in availability_zones order."
  value       = module.vpc.intra_subnets # 예: ["subnet-0ia...", "subnet-0ib...", "subnet-0ic..."]
}

# 후속 경로 구성에서 ID 를 사용하고 route table 을 중복 생성하지 않게 합니다.
output "public_route_table_ids" {
  description = "Public route table IDs, one per AZ."
  value       = module.vpc.public_route_table_ids # 예: ["rtb-0pa...", "rtb-0pb...", "rtb-0pc..."]
}

output "private_route_table_ids" {
  description = "Private route table IDs, one per AZ."
  value       = module.vpc.private_route_table_ids # 예: ["rtb-0ra...", "rtb-0rb...", "rtb-0rc..."] (EKS 서브넷 연결에 재사용)
}

output "intra_route_table_ids" {
  description = "Intra route table IDs, one per AZ."
  value       = module.vpc.intra_route_table_ids # 예: ["rtb-0ia...", "rtb-0ib...", "rtb-0ic..."] (Endpoint 경로 주입 대상)
}

# 각 NAT Gateway 의 EIP 입니다. egress 출발 IP 확인 등에 사용합니다.
output "nat_public_ips" {
  description = "Public NAT Gateway IPs in the first two availability_zones order."
  value       = [for az in local.lab_nat_azs : aws_eip.lab_nat[az].public_ip] # 예: ["3.35.1.10", "3.35.1.11"]
}

# 생성 전부터 사람이 주소 · AZ 배치를 검토할 수 있는 plan입니다.
output "subnet_plan" {
  description = "Public, private and intra subnet plans containing az and cidr."
  value       = local.subnet_plan # 예: {public=[{az,cidr} x3], private=[...], intra=[...]} (plan 단계에서 값 확정)
}
