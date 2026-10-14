# variables.tf — identity 루트 모듈 (dev · prod 공통 코드)

variable "expected_account_id" {
  description = "AWS account that owns the cluster, the roles and the data resources; 12 digits."
  type        = string # 예: "111111111111"
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "Account ID must be 12 digits."
  }
}

variable "region" {
  description = "AWS region for this root; only ap-northeast-2 is supported."
  type        = string
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2"
  nullable    = false

  validation {
    condition     = var.region == "ap-northeast-2" # 예: 단일 값 비교
    error_message = "This root supports ap-northeast-2 only."
  }
}

# main.tf 의 environment_boundary 가 이 디렉터리에서는 "dev" 만 허용합니다 (prod 는 prod/identity).
variable "environment" {
  description = "Explicit environment name: dev or prod (must match the data contract)."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["dev", "prod"], var.environment) # 예: "dev" 통과 / "staging" 거부
    error_message = "environment must be dev or prod."
  }
}

# 앞 루트 모듈(data · eks)의 State 가 있는 버킷입니다. backend.hcl 의 bucket 과 같은 값입니다.
variable "state_bucket_name" {
  description = "S3 bucket holding the data and eks states read by terraform_remote_state."
  type        = string # 예: "company-dev-tfstate-111111111111" (work/lab.env 의 DEV_STATE_BUCKET)
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name)) # 예: S3 버킷 이름 규칙
    error_message = "state_bucket_name must be a valid S3 bucket name."
  }
}

variable "operator_image_digest" {
  description = "Published operator ECR image digest, reviewed after the image build; never a mutable tag."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.operator_image_digest == null ? true : can(regex("^sha256:[0-9a-f]{64}$", var.operator_image_digest))
    error_message = "operator_image_digest must be a complete immutable ECR sha256 digest or null before image publication."
  }
}
