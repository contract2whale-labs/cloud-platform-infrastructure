data "terraform_remote_state" "queue" {
  backend = "s3"
  config = {
    bucket = var.state_bucket_name
    key    = "platform/queue/terraform.tfstate"
    region = var.region
  }
}
resource "aws_msk_scram_secret_association" "queue_user" {
  cluster_arn     = data.terraform_remote_state.queue.outputs.queue_managed_contract.cluster_arn
  secret_arn_list = [for key in ["reader", "writer"] : data.terraform_remote_state.queue.outputs.queue_managed_contract.secret_arns[key]]
  lifecycle {
    precondition {
      condition     = var.credentials_receipt.environment == var.environment && var.credentials_receipt.account_id == var.expected_account_id && var.credentials_receipt.region == var.region
      error_message = "The verified credential receipt belongs to another deployment boundary."
    }
  }
}

resource "terraform_data" "environment_boundary" {
  input = var.environment
  lifecycle {
    precondition {
      condition     = terraform.workspace == "default"
      error_message = "Use distinct backend keys and the default workspace."
    }
  }
}
