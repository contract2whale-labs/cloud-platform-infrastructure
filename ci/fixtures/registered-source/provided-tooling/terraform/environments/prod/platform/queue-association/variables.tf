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
variable "credentials_receipt" {
  description = "Noncredential receipt verified against current AWS version metadata by the protected runner."
  type = object({
    request_id         = string
    environment        = string
    account_id         = string
    region             = string
    secret_version_ids = map(string)
  })
  validation {
    condition     = toset(keys(var.credentials_receipt.secret_version_ids)) == toset(["reader", "writer"])
    error_message = "The verified receipt must contain the reader and writer version IDs."
  }
}
