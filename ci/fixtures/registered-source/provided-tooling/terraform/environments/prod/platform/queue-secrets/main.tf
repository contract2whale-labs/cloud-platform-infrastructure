data "terraform_remote_state" "queue" {
  backend = "s3"
  config  = { bucket = var.state_bucket_name, key = "platform/queue/terraform.tfstate", region = var.region }
}
data "terraform_remote_state" "operations" {
  backend = "s3"
  config  = { bucket = var.state_bucket_name, key = "platform/operations/terraform.tfstate", region = var.region }
}
locals {
  queue           = data.terraform_remote_state.queue.outputs.queue_managed_contract
  controller_role = data.terraform_remote_state.operations.outputs.external_secrets_role_arn
}
resource "aws_iam_role" "queue_secret_reader" {
  name = "contract2whale-${var.environment}-eks-queue-secret-reader"
  path = "/platform/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { AWS = local.controller_role }, Action = ["sts:AssumeRole", "sts:TagSession"]
      Condition = { StringEquals = {
        "aws:PrincipalTag/kubernetes-namespace"       = "external-secrets"
        "aws:PrincipalTag/kubernetes-service-account" = "external-secrets"
      } }
    }]
  })
}
resource "aws_iam_role_policy" "read_queue_credentials" {
  name = "read-managed-queue-only"
  role = aws_iam_role.queue_secret_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], Resource = values(local.queue.secret_arns) },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [local.queue.kms_key_arn], Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } }
    ]
  })
}
resource "aws_iam_role_policy" "controller_assume_queue_reader" {
  name = "assume-queue-secret-reader"
  role = element(reverse(split("/", local.controller_role)), 0)
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["sts:AssumeRole", "sts:TagSession"], Resource = [aws_iam_role.queue_secret_reader.arn]
  }] })
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
