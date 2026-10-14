provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { ManagedBy = "Terraform", Environment = var.environment, Component = "queue-secrets" }
  }
}
