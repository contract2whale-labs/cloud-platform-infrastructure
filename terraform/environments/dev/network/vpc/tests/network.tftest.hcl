# tests/network.tftest.hcl — network/vpc 루트 모듈 (dev · prod 공통 코드)
# mock provider 로 AWS API 호출 없이 plan 만 실행해 주소 계산 · 생성 개수 · 입력 거부 계약을 확인합니다.
# init 은 모듈 · provider 다운로드가 필요하지만 apply 는 수행하지 않습니다.

mock_provider "aws" {}

# 테스트 fixture 입니다. provider 가 mock 이므로 이 계정에 접근하지 않습니다.
variables {
  expected_account_id = "111111111111"
  region              = "ap-northeast-2"
  environment         = "testnet"
  vpc_cidr            = "172.20.0.0/16"
  availability_zones  = ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"]
}

run "three_az_network_contract" {
  command = plan

  # 서로 겹치지 않는 세 subnet 그룹의 9개 주소를 리터럴 기대값으로 검증합니다.
  assert {
    condition = (
      join(",", [for subnet in output.subnet_plan.public : subnet.cidr]) ==
      "172.20.0.0/22,172.20.4.0/22,172.20.8.0/22" &&
      join(",", [for subnet in output.subnet_plan.private : subnet.cidr]) ==
      "172.20.32.0/19,172.20.64.0/19,172.20.96.0/19" &&
      join(",", [for subnet in output.subnet_plan.intra : subnet.cidr]) ==
      "172.20.12.0/28,172.20.12.16/28,172.20.12.32/28"
    )
    error_message = "The nine subnet CIDRs must match the /16 allocation contract."
  }

  assert {
    condition = (
      join(",", [for subnet in output.subnet_plan.public : subnet.az]) ==
      "ap-northeast-2a,ap-northeast-2b,ap-northeast-2c" &&
      output.subnet_plan.private[1].az == "ap-northeast-2b" &&
      output.subnet_plan.intra[2].az == "ap-northeast-2c"
    )
    error_message = "Subnet positions must retain the configured AZ order."
  }

  # 실제 모듈의 plan 출력을 읽어 subnet · route · NAT 생성 개수를 검증합니다.
  assert {
    condition = (
      length(output.public_subnet_ids) == 3 &&
      length(output.private_subnet_ids) == 3 &&
      length(output.intra_subnet_ids) == 3 &&
      length(output.public_route_table_ids) == 3 &&
      length(output.private_route_table_ids) == 3 &&
      length(output.intra_route_table_ids) == 3 &&
      length(output.nat_public_ips) == 2 &&
      length(aws_nat_gateway.lab) == 2 &&
      length(aws_eip.lab_nat) == 2 &&
      length(aws_route.private_nat) == 3
    )
    error_message = "The stack must plan three subnets and route tables per group and two NAT public IPs."
  }
}

run "explicit_environment_and_address_input" {
  command = plan

  variables {
    environment        = "secondnet"
    vpc_cidr           = "10.80.0.0/16"
    availability_zones = ["ap-northeast-2c", "ap-northeast-2a", "ap-northeast-2b"]
  }

  # 명시적 CIDR 과 AZ 목록의 순서가 계산 결과에 반영되는지 검사합니다.
  assert {
    condition = (
      local.vpc_name == "cp-secondnet" &&
      output.subnet_plan.public[0].az == "ap-northeast-2c" &&
      output.subnet_plan.public[0].cidr == "10.80.0.0/22" &&
      output.subnet_plan.private[1].cidr == "10.80.64.0/19" &&
      output.subnet_plan.intra[2].cidr == "10.80.12.32/28"
    )
    error_message = "Explicit environment, CIDR and AZ order must drive the subnet plan."
  }
}

# CIDR 문법이 올바르더라도 공인 범위는 이 입력 계약에서 거부합니다.
run "reject_public_cidr" {
  command = plan

  variables {
    vpc_cidr = "8.8.0.0/16"
  }

  expect_failures = [var.vpc_cidr]
}

# 네트워크 시작 주소가 아닌 입력을 임의로 정규화해 채택하지 않습니다.
run "reject_cidr_with_host_bits" {
  command = plan

  variables {
    vpc_cidr = "172.20.1.0/16"
  }

  expect_failures = [var.vpc_cidr]
}

# /16 이외의 prefix 에는 이 챕터의 subnet 계산식 계약을 적용하지 않습니다.
run "reject_non_16_prefix" {
  command = plan

  variables {
    vpc_cidr = "172.20.0.0/20"
  }

  expect_failures = [var.vpc_cidr]
}

# 목록 길이가 3 이어도 AZ 가 중복되면 세 AZ 구성이 아닙니다.
run "reject_duplicate_az" {
  command = plan

  variables {
    availability_zones = ["ap-northeast-2a", "ap-northeast-2a", "ap-northeast-2c"]
  }

  expect_failures = [var.availability_zones]
}

# provider region 과 다른 AZ 를 같은 네트워크에 전달하지 않습니다.
run "reject_foreign_region_az" {
  command = plan

  variables {
    availability_zones = ["ap-northeast-2a", "ap-northeast-2b", "eu-west-1c"]
  }

  expect_failures = [var.availability_zones]
}
