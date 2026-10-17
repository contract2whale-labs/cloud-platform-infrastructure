# outputs-eks-network.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# eks-network 이 추가한 출력 6개입니다. outputs.tf 의 vpc 출력 11개는 그대로 유지합니다.

# 기존 private_subnet_ids 는 일반 Private 3개를 그대로 유지합니다. EKS 3개는 별도 계약입니다.
output "eks_subnet_ids" {
  description = "EKS private subnet IDs in availability_zones order."
  value       = [for az in var.availability_zones : aws_subnet.eks_private[az].id]
}

# AZ 키로 후속 구성이 의미를 식별할 수 있습니다. map 순회의 정렬 순서에 의존하지 않습니다.
output "eks_subnets_by_az" {
  description = "Map of AZ names to EKS private subnet IDs."
  value       = { for az, subnet in aws_subnet.eks_private : az => subnet.id }
}

output "eks_subnet_cidrs" {
  description = "EKS private subnet CIDRs in availability_zones order."
  value       = [for az in var.availability_zones : aws_subnet.eks_private[az].cidr_block]
}

# 보존 root의 출력을 기존 이름으로 다시 내보내 후속 소비자와의 계약을 유지합니다.
output "network_logs_bucket_name" {
  description = "Name of the S3 bucket used for flow/ and dns/ logs."
  value       = data.terraform_remote_state.network_log_storage.outputs.network_logs_bucket_name
}

output "network_logs_bucket_arn" {
  description = "ARN of the network logs S3 bucket."
  value       = data.terraform_remote_state.network_log_storage.outputs.network_logs_bucket_arn
}

# 후속 구성(transit Transit Gateway)이 이 객체를 입력받아 같은 VPC 와 transit 서브넷에 연결합니다.
# Private RT 3개 + Intra RT 3개입니다. EKS 는 Private RT 를 공유하므로 다시 더하지 않습니다.
output "vpc_contract" {
  description = "VPC, CIDR, transit subnet AZ map and private/intra route table IDs for downstream roots."
  value = {
    vpc_id = module.vpc.vpc_id
    cidr   = module.vpc.vpc_cidr_block
    transit_subnet_ids_by_az = {
      for az in distinct(var.availability_zones) : az => module.vpc.intra_subnets[index(var.availability_zones, az)]
    }
    route_table_ids = concat(module.vpc.private_route_table_ids, module.vpc.intra_route_table_ids)
  }
}