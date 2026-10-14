# variables.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)
# 대신 state_bucket_name 을 받습니다. receiver_email 은 실습자가 terraform.tfvars 에서 자기 주소로 바꿉니다.

variable "expected_account_id" {
  description = "AWS account that owns the cluster and the alerting resources; 12 digits."
  type        = string # 예: string (앞자리 0 이 사라지지 않도록 문자열)
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과, "123" 거부
    error_message = "expected_account_id must contain exactly 12 digits."
  }
}

# main.tf 의 environment_boundary 가 이 디렉터리에서는 "dev" 만 허용합니다. 모듈은 dev · prod 만 받습니다.
variable "environment" {
  description = "Environment name; this directory accepts dev only (prod is prod/platform/alerting, 운영 환경)."
  type        = string # 예: string (환경 이름을 문자열로 받습니다)
  nullable    = false

  validation {
    condition     = contains(["dev", "prod"], var.environment) # 예: "dev" 통과, "stage" 거부
    error_message = "environment must be dev or prod."
  }
}

variable "region" {
  description = "AWS region for this root; only ap-northeast-2 is supported."
  type        = string
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2"
  nullable    = false

  validation {
    condition     = var.region == "ap-northeast-2" # 예: "us-east-1" 거부
    error_message = "This root supports ap-northeast-2 only."
  }
}

# 앞 루트 모듈(eks · platform/operations)의 State 가 있는 버킷입니다. backend.hcl 의 bucket 과 같은 값입니다.
variable "state_bucket_name" {
  description = "S3 bucket holding the eks and platform/operations states read by terraform_remote_state."
  type        = string # 예: "company-dev-tfstate-111111111111" (work/lab.env 의 DEV_STATE_BUCKET)
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name)) # 예: S3 버킷 이름 규칙
    error_message = "state_bucket_name must be a valid S3 bucket name."
  }
}

variable "receiver_email" {
  description = "SNS 확인 이메일을 수신하고 구독을 직접 승인할 주소."
  type        = string                   # 예: string (주소를 문자열로 받습니다)
  default     = "ops-alerts@example.com" # 예: 실습자가 자기 주소로 바꾸는 자리 (terraform.tfvars)
  nullable    = false

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.receiver_email)) # 예: "not-an-email" 거부
    error_message = "receiver_email must be an email address without whitespace."
  }
}

variable "sample_delete_validation_run_id" {
  description = "Dev 노드 점검 감지만 명시적으로 무장하는 단일 validation run ID. null이면 생성하지 않는다."
  type        = string # 예: string (식별자를 문자열로 받습니다)
  default     = null   # 예: null (감지를 만들지 않는 기본 상태; 장애 대응 장애 실습에서만 값을 넣음)

  validation {
    # 예: null 통과, "verify-0123456789abcdef0123456789abcdef" 통과, "verify-all" 거부
    condition     = var.sample_delete_validation_run_id == null ? true : can(regex("^verify-[0-9a-f]{32}$", var.sample_delete_validation_run_id))
    error_message = "Use null or verify- followed by exactly 32 lowercase hex characters."
  }
}
