# tests/eks-network.tftest.hcl — network/vpc 루트 모듈 (dev · prod 공통 코드)
# eks-network 이 추가한 EKS 서브넷 · 예약 · Endpoint · NACL · 로그 계약을 확인합니다. tests/network.tftest.hcl (vpc, 7개) 와 함께 실행됩니다.
# mock provider 는 실제 AWS API 를 호출하지 않습니다. ID 연결이 필요한 검사는 로컬 mock apply 로 확인합니다 (실제 AWS apply 가 아닙니다).
# 테스트 통과는 실제 DNS · 통신 · 로그 전달의 증거가 아닙니다. 아래 가짜 ARN 은 테스트 fixture 입니다.

mock_provider "aws" {
  override_during = apply
}

# AWS mock과 별도로 원격 State도 대체하여 실제 S3에 접근하지 않습니다.
override_data {
  target = data.terraform_remote_state.network_log_storage
  values = {
    outputs = {
      network_logs_bucket_name = "cp-testnet-network-logs-111111111111-ap-northeast-2"
      network_logs_bucket_arn  = "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2"
    }
  }
}

# 테스트 fixture 입니다. provider 가 mock 이므로 이 계정에 접근하지 않습니다.
variables {
  state_bucket_name   = "test-state-bucket-111111111111"
  state_region        = "ap-northeast-2"
  expected_account_id = "111111111111"
  region              = "ap-northeast-2"
  environment         = "testnet"
  vpc_cidr            = "172.20.0.0/16"
  availability_zones  = ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"]
}

# 기존 일반 private 3개는 유지하면서 EKS 3개와 해당 AZ 의 기존 RT 를 연결합니다.
run "eks_subnets_reservations_and_downstream_contract" {
  command = apply # 예: mock 생성값 확인 (모듈의 depends_on 때문에 plan 에서 unknown 인 ID 연결을 mock state 로 확인)

  assert {
    condition = (
      length(output.private_subnet_ids) == 3 &&
      length(output.eks_subnet_ids) == 3 &&
      length(aws_route_table_association.eks_private) == 3 &&
      join(",", output.eks_subnet_cidrs) == "172.20.128.0/19,172.20.160.0/19,172.20.192.0/19" &&
      output.eks_subnets_by_az["ap-northeast-2b"] == output.eks_subnet_ids[1] &&
      alltrue([
        for index, az in var.availability_zones :
        aws_route_table_association.eks_private[az].route_table_id == output.private_route_table_ids[index]
      ])
    )
    error_message = "Three EKS subnets must retain AZ order and reuse the matching existing private route tables."
  }

  assert {
    condition = (
      length(aws_ec2_subnet_cidr_reservation.eks_prefix) == 3 &&
      aws_ec2_subnet_cidr_reservation.eks_prefix["ap-northeast-2a"].cidr_block == "172.20.144.0/20" &&
      aws_ec2_subnet_cidr_reservation.eks_prefix["ap-northeast-2b"].cidr_block == "172.20.176.0/20" &&
      aws_ec2_subnet_cidr_reservation.eks_prefix["ap-northeast-2c"].cidr_block == "172.20.208.0/20" &&
      alltrue([
        for reservation in aws_ec2_subnet_cidr_reservation.eks_prefix :
        reservation.reservation_type == "prefix"
      ])
    )
    error_message = "The second /20 of each EKS /19 must be reserved for prefixes."
  }

  assert {
    condition = (
      output.vpc_contract.vpc_id == output.vpc_id &&
      output.vpc_contract.cidr == "172.20.0.0/16" &&
      length(output.vpc_contract.route_table_ids) == 6 &&
      output.vpc_contract.transit_subnet_ids_by_az["ap-northeast-2c"] == output.intra_subnet_ids[2]
    )
    error_message = "The downstream contract must expose the same VPC, three transit subnet mappings and six private/intra route tables."
  }
}

# 기본 endpoint 개수와 실제 연결 대상을 검증합니다. mock 에서는 DNS 나 TLS 연결을 시험하지 않습니다.
run "default_private_endpoint_contract" {
  command = apply # 예: mock 생성값 확인 (모듈의 depends_on 때문에 plan 에서 unknown 인 ID 연결을 mock state 로 확인)

  assert {
    condition = (
      length(aws_vpc_endpoint.interface) == length(var.interface_endpoint_services) &&
      !contains(keys(aws_vpc_endpoint.interface), "guardduty-data") &&
      length(aws_security_group.interface_endpoints) == 1 &&
      aws_vpc_security_group_ingress_rule.interface_https[0].cidr_ipv4 == "172.20.0.0/16" &&
      aws_vpc_security_group_ingress_rule.interface_https[0].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.interface_https[0].to_port == 443 &&
      aws_vpc_security_group_ingress_rule.interface_https[0].ip_protocol == "tcp" &&
      alltrue([
        for endpoint in aws_vpc_endpoint.interface :
        endpoint.vpc_endpoint_type == "Interface" && endpoint.private_dns_enabled &&
        toset(endpoint.subnet_ids) == toset(slice(output.eks_subnet_ids, 0, 2))
      ])
    )
    error_message = "The selected services must use HTTPS and private DNS on the two EKS subnets; GuardDuty is opt-in."
  }

  assert {
    condition = (
      aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" &&
      aws_vpc_endpoint.s3.service_name == "com.amazonaws.ap-northeast-2.s3" &&
      toset(aws_vpc_endpoint.s3.route_table_ids) == toset(output.vpc_contract.route_table_ids) &&
      length(aws_vpc_endpoint.s3.route_table_ids) == 6
    )
    error_message = "The S3 Gateway must cover exactly the six private and intra route tables."
  }
}

# JSON 에 서비스 principal, 계정/Region 조건, flow/dns prefix 가 모두 들어가는지 확인합니다.
# 실제 AWS의 로그 전달 성공은 별도 실측입니다. S3 정책 검사는 보존 root에 있습니다.
run "network_log_storage_and_destinations" {
  command = apply # 예: mock 생성값 확인 (모듈의 depends_on 때문에 plan 에서 unknown 인 ID 연결을 mock state 로 확인)

  assert {
    condition = (
      output.network_logs_bucket_name == "cp-testnet-network-logs-111111111111-ap-northeast-2" &&
      aws_flow_log.vpc.traffic_type == "ALL" &&
      aws_flow_log.vpc.max_aggregation_interval == 60 &&
      aws_flow_log.vpc.log_destination ==
      "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2/flow/" &&
      aws_route53_resolver_query_log_config.vpc.destination_arn ==
      "arn:aws:s3:::cp-testnet-network-logs-111111111111-ap-northeast-2/dns/" &&
      aws_route53_resolver_query_log_config_association.vpc.resource_id == output.vpc_id
    )
    error_message = "Flow and Resolver logs must use separate prefixes in the new account-specific S3 bucket."
  }

}

# 선택 리소스를 꺼도 VPC · EKS subnet · S3 gateway 및 로그는 유지됩니다.
run "optional_prefix_and_interface_resources_disabled" {
  command = apply # 예: mock 생성값 확인 (모듈의 depends_on 때문에 plan 에서 unknown 인 ID 연결을 mock state 로 확인)

  variables {
    prefix_reservations_enabled = false
    interface_endpoint_services = []
    enable_guardduty_endpoint   = false
  }

  assert {
    condition = (
      length(aws_ec2_subnet_cidr_reservation.eks_prefix) == 0 &&
      length(aws_vpc_endpoint.interface) == 0 &&
      length(aws_security_group.interface_endpoints) == 0 &&
      length(aws_vpc_security_group_ingress_rule.interface_https) == 0 &&
      length(output.eks_subnet_ids) == 3 &&
      aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway"
    )
    error_message = "Disabled optional resources must not remove the core EKS subnet or S3 Gateway contract."
  }
}

# 선택적인 GuardDuty endpoint 와 명시한 긴급 deny 의 각 방향을 함께 검증합니다.
run "opt_in_guardduty_and_emergency_denies" {
  command = apply # 예: mock 생성값 확인 (모듈의 depends_on 때문에 plan 에서 unknown 인 ID 연결을 mock state 로 확인)

  variables {
    interface_endpoint_services = []
    enable_guardduty_endpoint   = true
    emergency_denied_ipv4 = {
      incident_one = { cidr = "203.0.113.10/32", rule_number = 10 }
      incident_two = { cidr = "198.51.100.0/24", rule_number = 20 }
    }
  }

  assert {
    condition = (
      length(aws_vpc_endpoint.interface) == 1 &&
      aws_vpc_endpoint.interface["guardduty-data"].service_name == "com.amazonaws.ap-northeast-2.guardduty-data" &&
      jsondecode(aws_vpc_endpoint.interface["guardduty-data"].policy).Statement[1].Effect == "Deny" &&
      jsondecode(
        aws_vpc_endpoint.interface["guardduty-data"].policy
      ).Statement[1].Condition.StringNotEquals["aws:PrincipalAccount"] == "111111111111" &&
      length(aws_network_acl_rule.emergency_ingress) == 2 &&
      length(aws_network_acl_rule.emergency_egress) == 2 &&
      !aws_network_acl_rule.emergency_ingress["incident_one"].egress &&
      aws_network_acl_rule.emergency_egress["incident_one"].egress &&
      aws_network_acl_rule.emergency_ingress["incident_two"].rule_number == 20 &&
      aws_network_acl_rule.emergency_ingress["incident_two"].rule_action == "deny"
    )
    error_message = "Only explicit GuardDuty and emergency inputs may add the selected endpoint and bidirectional deny rules."
  }
}

# 두 CIDR 이 달라도 같은 NACL 방향 안의 rule number 는 중복될 수 없습니다.
run "reject_duplicate_emergency_rule_numbers" {
  command = plan

  variables {
    emergency_denied_ipv4 = {
      first  = { cidr = "203.0.113.10/32", rule_number = 10 }
      second = { cidr = "198.51.100.0/24", rule_number = 10 }
    }
  }

  expect_failures = [var.emergency_denied_ipv4]
}

# CIDR host bit 를 묵시적으로 버리면 사용자가 의도한 차단 범위가 달라질 수 있습니다.
run "reject_emergency_cidr_host_bits" {
  command = plan

  variables {
    emergency_denied_ipv4 = {
      invalid = { cidr = "198.51.100.10/24", rule_number = 10 }
    }
  }

  expect_failures = [var.emergency_denied_ipv4]
}
# Interface Endpoint 목록에 Gateway 서비스인 s3를 섞으면 입력 단계에서 거부합니다.
run "reject_gateway_service_in_interface_endpoints" {
  command = plan

  variables {
    interface_endpoint_services = ["s3"]
  }

  expect_failures = [var.interface_endpoint_services]
}