# variables.tf — modules/alerting (dev · prod 루트 모듈이 공유하는 모듈)

variable "expected_account_id" {
  # 예: Dev 111111111111 / Prod 222222222222. 사용자의 실제 로그인 계정으로 치환합니다.
  description = "알림 리소스를 관리할 실제 AWS 계정 ID."
  type        = string # 예: string (계정 번호를 문자열로 받습니다)
  nullable    = false  # 예: false (값을 비울 수 없습니다)

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과, "123" 거부
    error_message = "expected_account_id must contain exactly 12 digits."
  }
}

variable "environment" {
  # 예: dev. 이 값이 topic · alarm 이름과 계약의 환경 경계를 정합니다.
  description = "Environment name that prefixes every alerting resource name (contract2whale-<environment>-…)."
  type        = string # 예: string (환경 이름을 문자열로 받습니다)
  nullable    = false  # 예: false (값을 비울 수 없습니다)

  validation {
    condition     = contains(["dev", "prod"], var.environment) # 예: "dev" 통과, "stage" 거부
    error_message = "environment must be dev or prod."
  }
}

variable "region" {
  # 예: ap-northeast-2 (서울). cluster ARN 의 리전도 같아야 합니다.
  description = "AWS region; only ap-northeast-2 is supported."
  type        = string           # 예: string (리전 이름을 문자열로 받습니다)
  default     = "ap-northeast-2" # 예: "ap-northeast-2" (서울 리전)
  nullable    = false            # 예: false (값을 비울 수 없습니다)

  validation {
    condition     = var.region == "ap-northeast-2" # 예: "us-east-1" 거부
    error_message = "This course alerting module supports ap-northeast-2 only."
  }
}

variable "cluster_contract" {
  # 예: { name="contract2whale-dev-eks", arn="arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks", region="ap-northeast-2" }.
  description = "같은 환경의 EKS cluster_contract output. 필요한 필드만 읽는다."
  type        = object({ name = string, arn = string, region = string }) # 예: 필드 세 개를 가진 object (나머지 항목은 타입 변환에서 제외)
  nullable    = false                                                    # 예: false (값을 비울 수 없습니다)

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$", var.cluster_contract.name)) # 예: "contract2whale-dev-eks" 통과
    error_message = "cluster_contract.name must be a valid EKS cluster name."
  }
}

variable "platform_log_group_name" {
  # 예: /platform/contract2whale-dev-eks/application. 운영 기반 구성이 이미 만든 플랫폼 컨테이너 로그 그룹입니다.
  description = "같은 환경 operations_contract의 platform_log_group_name."
  type        = string # 예: string (로그 그룹 이름을 문자열로 받습니다)
  nullable    = false  # 예: false (값을 비울 수 없습니다)
}

variable "receiver_email" {
  # 예: ops-alerts@example.com. 메일 주소를 바꾸면 새 구독 확인이 필요합니다.
  description = "SNS 확인 이메일을 수신하고 구독을 직접 승인할 주소."
  type        = string                   # 예: string (주소를 문자열로 받습니다)
  default     = "ops-alerts@example.com" # 예: 실습자가 자기 주소로 바꾸는 자리
  nullable    = false                    # 예: null 이면 위 기본 주소를 사용합니다

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.receiver_email)) # 예: "not-an-email" 거부
    error_message = "receiver_email must be an email address without whitespace."
  }
}

variable "sample_delete_validation_run_id" {
  # 예: 평소 null, Dev 노드 점검 직전에만 verify-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
  description = "Dev 노드 점검 감지만 명시적으로 무장하는 단일 validation run ID. null이면 생성하지 않는다."
  type        = string # 예: string (식별자를 문자열로 받습니다)
  default     = null   # 예: null (감지를 만들지 않는 기본 상태)

  validation {
    # 예: null 통과, "verify-0123456789abcdef0123456789abcdef" 통과, "verify-all" 거부
    condition     = var.sample_delete_validation_run_id == null ? true : can(regex("^verify-[0-9a-f]{32}$", var.sample_delete_validation_run_id))
    error_message = "Use null or verify- followed by exactly 32 lowercase hex characters."
  }
}
