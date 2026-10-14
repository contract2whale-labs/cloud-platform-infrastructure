# outputs.tf — identity 루트 모듈 (dev · prod 공통 코드)

output "identity_contract" {
  description = "Environment, cluster, namespace, the three identities (role ARN, service account, association ID) and the secrets reader role."
  value       = module.component.identity_contract # 예: 7개 키를 담은 object
}

output "operator_image" {
  description = "Noncredential immutable operator image reference from the data contract and verified publication digest."
  value       = var.operator_image_digest == null ? null : "${data.terraform_remote_state.data.outputs.data_contract.operator.repository_url}@${var.operator_image_digest}"
}
