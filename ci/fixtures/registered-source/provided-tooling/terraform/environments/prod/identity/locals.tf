# locals.tf — identity 루트 모듈 (dev · prod 공통 코드)

locals {
  cluster_contract = {
    name = data.terraform_remote_state.eks.outputs.cluster_contract.name # 예: "contract2whale-prod-eks"
    arn  = data.terraform_remote_state.eks.outputs.cluster_contract.arn  # 예: "arn:aws:eks:ap-northeast-2:222222222222:cluster/contract2whale-prod-eks"
  }

  contract = data.terraform_remote_state.data.outputs.data_contract # 예: 데이터베이스 · KMS 키 · 시크릿 · 미디어 버킷 의 12키 계약

  # 앱 비밀 읽기 Role 이 신뢰할 운영 도구 External Secrets controller Role 입니다.
  external_secrets_role_arn = data.terraform_remote_state.operations.outputs.external_secrets_role_arn # 예: "arn:aws:iam::222222222222:role/contract2whale-prod-eks-external-secrets"

  # 모듈이 요구하는 모양으로 추린 데이터 계약입니다 (Role 이름 · 태그처럼 쓰지 않는 값은 넘기지 않습니다).
  data_contract = {
    environment  = local.contract.environment  # 예: "prod"
    account_id   = local.contract.account_id   # 예: "222222222222"
    region       = local.contract.region       # 예: "ap-northeast-2"
    cluster_name = local.contract.cluster_name # 예: "contract2whale-prod-eks"
    namespace    = local.contract.namespace    # 예: "contract2whale-demo"

    service_accounts = {
      runtime   = local.contract.service_accounts.runtime   # 예: "commerce-api" (스토어프런트 commerce-web 은 AWS 를 부르지 않아 신원이 없습니다)
      operator  = local.contract.service_accounts.operator  # 예: "database-operator"
      migration = local.contract.service_accounts.migration # 예: "delivery-migration"
    }

    credentials = {
      master_secret_arn    = local.contract.credentials.master_secret_arn    # 예: RDS 관리 Secret
      migration_secret_arn = local.contract.credentials.migration_secret_arn # 예: 스키마 변경 계정 시크릿
      runtime_secret_arn   = local.contract.credentials.runtime_secret_arn   # 예: 앱 실행 계정 시크릿
      app_secret_arn       = local.contract.credentials.app_secret_arn       # 예: Medusa JWT_SECRET · COOKIE_SECRET 비밀 (runtime · migration 이 함께 읽음)
    }

    export = {
      bucket_arn = local.contract.export.bucket_arn # 예: "arn:aws:s3:::cp-prod-app-exports-…" (이름은 내보내기 그대로, 쓰임은 미디어)
      prefix     = local.contract.export.prefix     # 예: "media/prod/commerce-api/" (Medusa file-s3 의 S3_PREFIX)
    }

    kms_key_arn = local.contract.kms_key_arn # 예: "arn:aws:kms:…:key/…"
  }
}
