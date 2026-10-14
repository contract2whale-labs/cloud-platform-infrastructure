# variables.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)
# 대신 region · environment · state_bucket_name 을 받습니다. expected_account_id · exposure_mode · allowed_client_cidrs · existing_private_zone_id 는 모듈과 같은 검사식으로 그대로 전달합니다.

variable "expected_account_id" {
  description = "AWS account that owns the cluster, the zones and the security group; 12 digits."
  type        = string # 예: string (앞자리 0 이 사라지지 않도록 문자열)
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "Account ID must be 12 digits."
  }
}

# 클러스터 · zone 이 서울 리전에 있으므로 리전도 고정합니다. 모듈은 cluster_contract.region 이 같은 값인지 따로 검사합니다.
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

# main.tf 의 environment_boundary 가 이 디렉터리에서는 "dev" 만 허용합니다.
variable "environment" {
  description = "Explicit environment name, 2-20 lowercase letters, digits or hyphens."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.environment)) # 예: "dev" 통과 / "Dev" 거부
    error_message = "Use a 2-20 character lowercase environment name."
  }
}

# 앞 루트 모듈(eks · account-baseline-dns · network/vpc)의 State 가 있는 버킷입니다. backend.hcl 의 bucket 과 같은 값입니다.
variable "state_bucket_name" {
  description = "S3 bucket holding the eks, account-baseline-dns and network/vpc states read by terraform_remote_state."
  type        = string # 예: "company-dev-tfstate-111111111111" (work/lab.env 의 DEV_STATE_BUCKET)
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name)) # 예: S3 버킷 이름 규칙
    error_message = "state_bucket_name must be a valid S3 bucket name."
  }
}

# 최종 Dev 는 internal 입니다. locals.tf 가 이 값으로 NLB 서브넷(public ↔ private)을 고릅니다.
variable "exposure_mode" {
  description = "internal (private NLB + private zone), public (internet-facing NLB + public zone) or waf (private NLB behind CloudFront)."
  type        = string
  default     = "internal" # 기본값: "internal"
  nullable    = false

  validation {
    condition     = contains(["internal", "public", "waf"], var.exposure_mode) # 예: 세 값 중 하나
    error_message = "Use internal, public, or waf."
  }
}

# 최종 Dev 는 빈 목록입니다 (승인된 접속은 승인된 개발자의 Private Dev 접근 의 SG 출발지 규칙; CIDR 우회는 두지 않음).
variable "allowed_client_cidrs" {
  description = "Approved client IPv4 CIDRs allowed to reach the NLB on TCP 443; empty means no CIDR rule."
  type        = set(string)
  default     = [] # 기본값: [] (인바운드 CIDR 규칙 0개)
  nullable    = false

  validation {
    condition     = alltrue([for c in var.allowed_client_cidrs : can(cidrnetmask(c))]) # 예: IPv4 CIDR 형식만
    error_message = "Use valid IPv4 CIDRs."
  }
}

variable "existing_private_zone_id" {
  description = "Existing private hosted zone ID to reuse (already associated with the VPC); null creates a new one."
  type        = string
  default     = null # 기본값: null (모듈이 VPC 전용 private zone 을 새로 만듦)
  nullable    = true
}
