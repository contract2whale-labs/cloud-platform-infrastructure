# variables.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)

variable "expected_account_id" {
  description = "AWS account that owns the NLB, the public zone and the CloudFront distribution; 12 digits."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "Account ID must be 12 digits."
  }
}

variable "region" {
  description = "AWS region of the NLB and the public zone; only ap-northeast-2 is supported (CloudFront/WAF use the fixed us-east-1 alias)."
  type        = string
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2"
  nullable    = false

  validation {
    condition     = var.region == "ap-northeast-2" # 예: 단일 값 비교
    error_message = "This root supports ap-northeast-2 only."
  }
}

variable "environment" {
  description = "Explicit environment name, 2-20 lowercase letters, digits or hyphens."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.environment)) # 예: "dev" 통과 / "Dev" 거부
    error_message = "Use a 2-20 character lowercase environment name."
  }
}

# Gateway 루트 모듈의 State 가 있는 버킷입니다. backend.hcl 의 bucket 과 같은 값입니다.
variable "state_bucket_name" {
  description = "S3 bucket holding the platform/gateway state read by terraform_remote_state."
  type        = string # 예: "company-dev-tfstate-111111111111" (work/lab.env 의 DEV_STATE_BUCKET)
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name)) # 예: S3 버킷 이름 규칙
    error_message = "state_bucket_name must be a valid S3 bucket name."
  }
}

# Dev 는 false 로 둡니다 (Dev 노출은 internal; CloudFront + WAF 공개는 Prod 의 CloudFront 와 WAF 로 공개 서비스 완성).
variable "enabled" {
  description = "Create CloudFront, WAF, viewer certificate and app DNS records; false keeps the root at the environment marker only."
  type        = bool
  default     = false # 기본값: false
  nullable    = false
}

variable "nlb_arn" {
  description = "ARN of the internal NLB that the controller created for the Gateway Service; empty while disabled."
  type        = string
  default     = "" # 기본값: "" (비활성)
  nullable    = false
}

variable "hostnames" {
  description = "Explicit public hostnames served by CloudFront (also the ACM viewer certificate SANs)."
  type        = set(string)
  default     = [] # 기본값: [] (비활성)
  nullable    = false

  validation {
    condition     = alltrue([for h in var.hostnames : can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", h))]) # 예: 소문자 이름만
    error_message = "Use lowercase explicit DNS names without wildcard or trailing dot."
  }
}

variable "origin_tls_ready" {
  description = "Operator confirmation that the Envoy origin certificate is issued by the production CA."
  type        = bool
  default     = false # 기본값: false
  nullable    = false
}

variable "rate_limit_per_5min" {
  description = "Requests per source IP allowed in a 5-minute window before WAF blocks."
  type        = number
  default     = 2000 # 기본값: 2000
  nullable    = false

  validation {
    condition     = var.rate_limit_per_5min >= 10 && var.rate_limit_per_5min == floor(var.rate_limit_per_5min) # 예: 10 이상의 정수
    error_message = "Use an integer rate limit of at least 10."
  }
}
