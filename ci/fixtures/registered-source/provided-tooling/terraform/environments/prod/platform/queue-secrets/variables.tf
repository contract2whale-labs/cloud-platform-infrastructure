variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Expected account must be a 12-digit account ID."
  }
}
variable "region" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = var.environment == "prod"
    error_message = "This root accepts prod; use the prod root for prod."
  }
}
variable "state_bucket_name" { type = string }
