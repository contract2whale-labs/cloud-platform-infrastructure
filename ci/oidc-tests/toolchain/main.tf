# Installation-only fixture: no backend, resources, provider configuration, or AWS calls.
terraform {
  required_version = "= 1.16.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.62.0"
    }
  }
}
