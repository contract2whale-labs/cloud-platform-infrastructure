variable "expected_account_id" {
  description = "AWS account that owns the retained network log bucket."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must contain 12 digits."
  }
}
variable "region" {
  description = "Region used by this course and the log delivery service."
  type        = string
  default     = "ap-northeast-2"
  nullable    = false
  validation {
    condition     = var.region == "ap-northeast-2"
    error_message = "This root supports the Seoul Region only."
  }
}
variable "environment" {
  description = "Environment name used in the existing bucket naming contract."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,15}$", var.environment))
    error_message = "environment must be a lowercase name of 1 through 16 characters."
  }
}