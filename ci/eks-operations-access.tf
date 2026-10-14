# Merge into existing modules/eks; never into bootstrap/ci-identity.
# Reuses aws_eks_cluster.this, var.environment, var.expected_account_id,
# var.admin_principal_arns. Operational identities must exist before EKS creation.
locals {
  operations_access_groups = {
    gitops-bootstrap = "cp:${var.environment}:gitops-bootstrap"
    gitops-apply     = "cp:${var.environment}:gitops-apply"
    incident-plan    = "cp:${var.environment}:incident-plan"
    incident-apply   = "cp:${var.environment}:incident-apply"
  }
  lifecycle_access_groups = {
    plan    = "cp:${var.environment}:lifecycle-plan"
    apply   = "cp:${var.environment}:lifecycle-apply"
    destroy = "cp:${var.environment}:lifecycle-destroy"
  }
  lifecycle_access_arns = {
    plan    = "arn:aws:iam::${var.expected_account_id}:role/gha-infra-${var.environment}-plan"
    apply   = "arn:aws:iam::${var.expected_account_id}:role/gha-infra-${var.environment}-apply"
    destroy = "arn:aws:iam::${var.expected_account_id}:role/gha-infra-${var.environment}-lifecycle-destroy"
  }
}
resource "aws_eks_access_entry" "operations" {
  for_each          = local.operations_access_groups
  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = "arn:aws:iam::${var.expected_account_id}:role/cp-${var.environment}-${each.key}"
  type              = "STANDARD"
  kubernetes_groups = [each.value]
  lifecycle {
    precondition {
      condition     = !contains(var.admin_principal_arns, "arn:aws:iam::${var.expected_account_id}:role/cp-${var.environment}-${each.key}")
      error_message = "Operational principals cannot also be instructor/admin principals."
    }
  }
}
resource "aws_eks_access_entry" "lifecycle" {
  for_each          = local.lifecycle_access_groups
  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = local.lifecycle_access_arns[each.key]
  type              = "STANDARD"
  kubernetes_groups = [each.value]
  lifecycle {
    precondition {
      condition     = !contains(var.admin_principal_arns, local.lifecycle_access_arns[each.key])
      error_message = "Lifecycle principals must not duplicate existing admin access entries. Migrate the existing entry through reviewed Terraform before adding this mapping."
    }
  }
}
# Enable only once Dev's existing AWS fixed-operation roles have been created by
# identity-admin. The retained EKS input re-creates these entries on later Up.
variable "aws_fixed_operations_enabled" {
  type    = bool
  default = false
}
resource "aws_eks_access_entry" "aws_fixed" {
  for_each          = var.environment == "dev" && var.aws_fixed_operations_enabled ? toset(["plan", "apply"]) : toset([])
  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = "arn:aws:iam::${var.expected_account_id}:role/gha-aws-ops-dev-${each.key}"
  type              = "STANDARD"
  kubernetes_groups = ["cp:dev:aws-fixed-${each.key}"]
  lifecycle {
    precondition {
      condition     = !contains(var.admin_principal_arns, "arn:aws:iam::${var.expected_account_id}:role/gha-aws-ops-dev-${each.key}")
      error_message = "AWS fixed-operation roles cannot have duplicate admin access."
    }
  }
}
# Persistent privileged bootstrap boundary, deliberately NOT ordinary infra apply.
# The sole OIDC Environment gitops-<env>-bootstrap requires review. Its workflow
# admits only a fresh cluster incarnation with no started/completed install receipt.
# Terraform recreates this association with the cluster before the paused Up handoff.
resource "aws_eks_access_policy_association" "operations_bootstrap" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.operations["gitops-bootstrap"].principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}
output "operations_access_contract" {
  value = {
    cluster_arn            = aws_eks_cluster.this.arn
    cluster_created_at     = aws_eks_cluster.this.created_at
    aws_fixed_principals   = { for k, v in aws_eks_access_entry.aws_fixed : k => v.principal_arn }
    operational_principals = { for k, v in aws_eks_access_entry.operations : k => v.principal_arn }
    lifecycle_principals   = { for k, v in aws_eks_access_entry.lifecycle : k => v.principal_arn }
    groups                 = merge(local.operations_access_groups, { for k, v in local.lifecycle_access_groups : "lifecycle-${k}" => v })
    bootstrap_principal    = aws_eks_access_entry.operations["gitops-bootstrap"].principal_arn
  }
  depends_on = [aws_eks_access_entry.operations, aws_eks_access_entry.lifecycle, aws_eks_access_entry.aws_fixed, aws_eks_access_policy_association.operations_bootstrap]
}
