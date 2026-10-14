# variables.tf — platform/dev-app-access 루트 모듈 (dev 전용)

variable "expected_account_id" {
  description = "AWS account that owns the relay instance, the NLB and the session role; 12 digits."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "Account ID must be 12 digits."
  }
}

variable "region" {
  description = "AWS region of the relay instance and the NLB; only ap-northeast-2 is supported."
  type        = string
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2"
  nullable    = false

  validation {
    condition     = var.region == "ap-northeast-2" # 예: 단일 값 비교
    error_message = "This root supports ap-northeast-2 only."
  }
}

variable "environment" {
  description = "Explicit environment name; this directory accepts dev only."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.environment)) # 예: "dev" 통과
    error_message = "Use a 2-20 character lowercase environment name."
  }
}

variable "state_bucket_name" {
  description = "S3 bucket holding the platform/private-api and platform/gateway states read by terraform_remote_state."
  type        = string # 예: "company-dev-tfstate-111111111111" (work/lab.env 의 DEV_STATE_BUCKET)
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name)) # 예: S3 버킷 이름 규칙
    error_message = "state_bucket_name must be a valid S3 bucket name."
  }
}

# Identity Center 가 Dev 계정에 만든 개발자 Permission Set 의 실제 IAM Role ARN 입니다 (AWSReservedSSO_…). 이 Role 만 전용 세션 Role 을 맡을 수 있습니다.
variable "approved_identity_center_role_arn" {
  description = "IAM role ARN of the approved developer permission set (AWSReservedSSO_*) allowed to assume the session role."
  type        = string # 예: "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/ap-northeast-2/AWSReservedSSO_CommerceDeveloper_0123456789abcdef"
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+AWSReservedSSO_[A-Za-z0-9_-]+$", var.approved_identity_center_role_arn)) # 예: Identity Center 가 만든 Role 형식만
    error_message = "approved_identity_center_role_arn must be an Identity Center permission set role (…/AWSReservedSSO_<name>_<hash>)."
  }
}

# 로컬에서 여는 포트입니다. 인증서 SAN 은 포트 없는 Dev 이름이므로 브라우저 URL 은 https://dev.<PARENT_DOMAIN>:<local_port>/ 입니다.
variable "local_port" {
  description = "Local port of the fixed port-forwarding session (the UI origin uses https://<host>:<local_port>)."
  type        = number
  default     = 8443 # 기본값: 8443
  nullable    = false

  validation {
    condition     = var.local_port >= 1024 && var.local_port <= 65535 && var.local_port == floor(var.local_port) # 예: 비특권 포트 정수
    error_message = "local_port must be an integer between 1024 and 65535."
  }
}
