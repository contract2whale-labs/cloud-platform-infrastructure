# outputs.tf — modules/tenant-pod-identity (dev · prod 루트 모듈이 공유하는 모듈)

output "identity_contract" {
  description = "Environment, cluster, namespace, the three identities (role ARN, service account, association ID) and the secrets reader role."
  value = {
    environment  = var.environment             # 예: "dev"
    cluster_name = var.cluster_contract.name   # 예: "contract2whale-dev-eks"
    namespace    = var.data_contract.namespace # 예: "contract2whale-demo"

    runtime = {
      role_arn        = aws_iam_role.runtime.arn                                # 예: "arn:aws:iam::…:role/platform/contract2whale-dev-eks-app-runtime"
      service_account = var.data_contract.service_accounts.runtime              # 예: "commerce-api"
      association_id  = aws_eks_pod_identity_association.runtime.association_id # 예: "a-abcdefghij1234567"
    }

    operator = {
      role_arn        = aws_iam_role.operator.arn                                # 예: "arn:aws:iam::…:role/platform/contract2whale-dev-eks-app-database-operator"
      service_account = var.data_contract.service_accounts.operator              # 예: "database-operator"
      association_id  = aws_eks_pod_identity_association.operator.association_id # 예: "a-bcdefghij12345678"
    }

    migration = {
      role_arn        = var.migration_role_arn                                    # 예: 배포 플랫폼이 만든 Role (이 모듈은 정책 · 연결만 더함)
      service_account = var.data_contract.service_accounts.migration              # 예: "delivery-migration"
      association_id  = aws_eks_pod_identity_association.migration.association_id # 예: "a-cdefghij123456789"
    }

    secrets_reader = {
      role_arn = aws_iam_role.secrets_reader.arn # 예: "arn:aws:iam::…:role/platform/contract2whale-dev-eks-data-app-secrets" (SecretStore spec.provider.aws.role)
    }
  }
}
