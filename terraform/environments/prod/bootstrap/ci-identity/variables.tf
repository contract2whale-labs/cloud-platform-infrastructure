# variables.tf — bootstrap/ci-identity 루트 모듈 (dev · prod 공통 코드)

variable "expected_account_id" {
  description = "Resources may be managed only in this user-supplied 12-digit AWS account."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "expected_account_id must contain exactly 12 digits."
  }
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "ap-northeast-2"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.region)) # 예: "ap-northeast-2" 통과
    error_message = "region must be an AWS region name such as ap-northeast-2."
  }
}

variable "environment" {
  description = "Environment name used in role names and GitHub Environment names."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["dev", "prod"], var.environment) # 예: "dev" 통과 / "staging" 거부
    error_message = "environment must be dev or prod."
  }
}

variable "state_bucket_name" {
  description = "Name of the existing Terraform state bucket in this account."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.state_bucket_name)) # 예: "company-dev-tfstate-111111111111" 통과
    error_message = "state_bucket_name must be a valid lowercase S3 bucket name."
  }
}

variable "state_keys" {
  description = "Exact state object keys that CI may use. Add a key only when a root is registered in ci/roots.json."
  type        = list(string)
  default     = ["bootstrap/state/terraform.tfstate"] # 예: ["bootstrap/state/terraform.tfstate"]
  nullable    = false

  validation {
    condition     = alltrue([for k in var.state_keys : can(regex("^[A-Za-z0-9/_.-]+\\.tfstate$", k))]) # 예: 와일드카드(*) 거부
    error_message = "Each state key must be an exact object key ending in .tfstate (no wildcards)."
  }
}

variable "github_org" {
  description = "GitHub organization or user that owns the repository."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.github_org)) # 예: "my-org" 통과
    error_message = "github_org must contain only letters, digits and hyphens."
  }
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.github_repo)) # 예: "infrastructure" 통과
    error_message = "github_repo must contain only letters, digits, dots, underscores and hyphens."
  }
}

variable "github_subject_prefix" {
  description = "OIDC subject prefix of the repository from the GitHub API (actions/oidc/customization/sub). Null means repo:<org>/<repo>."
  type        = string
  default     = null

  validation {
    condition     = var.github_subject_prefix == null || can(regex("^repo:[A-Za-z0-9@._/-]+$", var.github_subject_prefix)) # 예: "repo:my-org@111/infrastructure@222" 통과
    error_message = "github_subject_prefix must look like repo:<owner>[@<id>]/<repo>[@<id>]."
  }
}

variable "create_oidc_provider" {
  description = "true creates the GitHub OIDC provider in this account. false reuses existing_oidc_provider_arn."
  type        = bool
  default     = true
  nullable    = false
}

variable "existing_oidc_provider_arn" {
  description = "ARN of an existing GitHub OIDC provider. Required when create_oidc_provider is false."
  type        = string
  default     = null

  validation {
    condition     = var.create_oidc_provider ? var.existing_oidc_provider_arn == null : can(regex("^arn:aws:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.existing_oidc_provider_arn))
    error_message = "Set existing_oidc_provider_arn (the token.actions.githubusercontent.com provider ARN) only when create_oidc_provider is false."
  }
}

variable "plan_additional_policy_arns" {
  description = "Extra managed policy ARNs for the plan role (add when a new root needs more read access)."
  type        = list(string)
  default     = []
  nullable    = false
}

variable "apply_additional_policy_arns" {
  description = "Extra managed policy ARNs for the apply role (add when a new root needs more AWS permissions)."
  type        = list(string)
  default     = []
  nullable    = false
}