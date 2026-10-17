# Gateway 방식은 ENI·Security Group 없이 라우팅 테이블에 S3 prefix list 경로를 추가합니다.

locals {
  # EKS 서브넷은 Private RT 를 공유하므로 따로 더하지 않습니다.
  # Private RT 3개 + Intra RT 3개 = 6개
  endpoint_route_table_ids = concat(
    module.vpc.private_route_table_ids, # AZ a, b, c
    module.vpc.intra_route_table_ids    # AZ a, b, c
  )
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3" # dev·prod 같은 코드
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.endpoint_route_table_ids

  tags = merge(local.common_tags, {
    Name = "${local.vpc_name}-s3-vpce" # cp-dev-s3-vpce
  })
}