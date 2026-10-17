# network-logs.tf — network/vpc에는 VPC에 연결되는 로그 자원만 둡니다.
# 보존용 network/log-storage를 먼저 적용한 뒤 그 State 출력으로 목적지를 정합니다.
variable "state_bucket_name" {
  description = "Existing state bucket containing network/log-storage/terraform.tfstate."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be the existing S3 state bucket name."
  }
}
variable "state_region" {
  description = "Region of the existing state bucket."
  type        = string
  default     = "ap-northeast-2"
  nullable    = false
  validation {
    condition     = var.state_region == "ap-northeast-2"
    error_message = "This course uses the Seoul state bucket."
  }
}

data "terraform_remote_state" "network_log_storage" {
  backend = "s3"
  config = {
    bucket              = var.state_bucket_name
    key                 = "network/log-storage/terraform.tfstate"
    region              = var.state_region
    encrypt             = true
    allowed_account_ids = [var.expected_account_id]
  }
  lifecycle {
    postcondition {
      condition = try(
        self.outputs.network_logs_bucket_name == "cp-${var.environment}-network-logs-${var.expected_account_id}-${var.region}" &&
        self.outputs.network_logs_bucket_arn == "arn:aws:s3:::cp-${var.environment}-network-logs-${var.expected_account_id}-${var.region}",
        false
      )
      error_message = "Apply the retained log-storage root first and verify its account, environment and bucket outputs."
    }
  }
}
locals {
  network_logs_bucket_name = data.terraform_remote_state.network_log_storage.outputs.network_logs_bucket_name
  network_logs_bucket_arn  = data.terraform_remote_state.network_log_storage.outputs.network_logs_bucket_arn
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = module.vpc.vpc_id                        # 예: "vpc-0123456789abcdef0" (관측 대상 VPC)
  traffic_type             = "ALL"                                    # 예: "ALL" (ACCEPT 와 REJECT 를 모두 수집)
  max_aggregation_interval = 60                                       # 예: 60 (최대 집계 간격 초; S3 도착 시각 보장이 아님)
  log_destination_type     = "s3"                                     # 예: "s3" (CloudWatch Logs 가 아닌 S3 직접 전달)
  log_destination          = "${local.network_logs_bucket_arn}/flow/" # 예: "arn:aws:s3:::cp-dev-network-logs-.../flow/"

  # $${...} 는 Terraform 보간을 피하고 AWS 플레이스홀더를 그대로 전달합니다.
  log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}", "$${srcaddr}",             # 예: 버전, 계정, ENI, 출발지 주소
    "$${dstaddr}", "$${srcport}", "$${dstport}", "$${protocol}",                    # 예: 목적지 주소, 포트 2개, 프로토콜 번호
    "$${packets}", "$${bytes}", "$${start}", "$${end}",                             # 예: 패킷 수, 바이트 수, 시작 · 종료 시각
    "$${action}", "$${log-status}", "$${az-id}", "$${flow-direction}",              # 예: ACCEPT/REJECT, 기록 상태, AZ, 방향
    "$${instance-id}", "$${pkt-srcaddr}", "$${pkt-dstaddr}", "$${region}",          # 예: 인스턴스, 실제 패킷 주소 2개, 리전
    "$${sublocation-id}", "$${sublocation-type}", "$${subnet-id}", "$${tcp-flags}", # 예: 서브로케이션 2개, 서브넷, TCP 플래그
    "$${type}", "$${vpc-id}",                                                       # 예: 트래픽 유형, VPC
  ])                                                                                # 예: 결과는 공백으로 이어진 26개 필드 단일 문자열

  # 버킷 정책의 AWSLogs/<계정> 경로와 일치시키기 위해 Hive 접두사를 사용하지 않습니다.
  destination_options {
    file_format                = "plain-text" # 예: "plain-text" (parquet 로 바꾸면 파일 형식과 분석 도구 설정이 달라짐)
    hive_compatible_partitions = false        # 예: false (true 면 경로 구조가 바뀌어 버킷 정책과 어긋남)
    per_hour_partition         = false        # 예: false (시간 단위 하위 경로를 만들지 않음)
  }

  tags = merge(local.common_tags, {
    Name = "${local.vpc_name}-flow-logs" # 예: "cp-dev-flow-logs"
  })

}

resource "aws_route53_resolver_query_log_config" "vpc" {
  name            = "${local.vpc_name}-resolver-queries"    # 예: "cp-dev-resolver-queries" (설정 식별 이름)
  destination_arn = "${local.network_logs_bucket_arn}/dns/" # 예: "arn:aws:s3:::cp-dev-network-logs-.../dns/"

  tags = merge(local.common_tags, {
    Name = "${local.vpc_name}-resolver-queries" # 예: "cp-dev-resolver-queries"
  })

}

resource "aws_route53_resolver_query_log_config_association" "vpc" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.vpc.id # 예: "rqlc-0123456789abcdef0" (위 config 의 ID)
  resource_id                  = module.vpc.vpc_id                            # 예: "vpc-0123456789abcdef0" (질의를 수집할 VPC)
}