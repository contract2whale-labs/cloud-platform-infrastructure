# variables.tf — modules/tenant-pod-identity (dev · prod 루트 모듈이 공유하는 모듈)

variable "expected_account_id" {
  description = "AWS account that owns the cluster, the secrets and the export bucket; 12 digits."
  type        = string # 예: "111111111111"
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "Account ID must be 12 digits."
  }
}

variable "region" {
  description = "AWS region for this module; only ap-northeast-2 is supported in this course."
  type        = string
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2"
  nullable    = false

  validation {
    condition     = var.region == "ap-northeast-2" # 예: 단일 값 비교
    error_message = "This module supports ap-northeast-2 only."
  }
}

variable "environment" {
  description = "Environment name that must match the data contract: dev or prod."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["dev", "prod"], var.environment) # 예: "dev" 통과 / "staging" 거부
    error_message = "environment must be dev or prod."
  }
}

# Pod Identity 신뢰 정책의 세션 태그(eks-cluster-arn)에 쓰는 값입니다 (E3).
variable "cluster_contract" {
  description = "Cluster name and ARN used for the association and the trust policy session tags."
  type = object({
    name = string # 예: "contract2whale-dev-eks"
    arn  = string # 예: "arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks"
  })
  nullable = false

  validation {
    condition     = can(regex("^arn:aws:eks:[a-z0-9-]+:[0-9]{12}:cluster/", var.cluster_contract.arn)) # 예: EKS 클러스터 ARN 형식
    error_message = "cluster_contract.arn must be an EKS cluster ARN."
  }
}

variable "data_contract" {
  description = "Environment, account, cluster, namespace, service accounts, secret ARNs, media location and KMS key from the data root."
  type = object({
    environment  = string # 예: "dev"
    account_id   = string # 예: "111111111111"
    region       = string # 예: "ap-northeast-2"
    cluster_name = string # 예: "contract2whale-dev-eks"
    namespace    = string # 예: "contract2whale-demo"

    service_accounts = object({
      runtime   = string # 예: "commerce-api" (스토어프런트 commerce-web 은 AWS 를 부르지 않아 여기에 없습니다)
      operator  = string # 예: "database-operator"
      migration = string # 예: "delivery-migration"
    })

    credentials = object({
      master_secret_arn    = string           # 예: "arn:aws:secretsmanager:…:secret:rds!db-…" (운영자만 읽음)
      migration_secret_arn = string           # 예: 스키마 변경 계정 시크릿
      runtime_secret_arn   = string           # 예: 앱 실행 계정 시크릿
      app_secret_arn       = optional(string) # 예: Medusa 의 JWT_SECRET · COOKIE_SECRET 비밀 (계약에 없으면 null — 권한에서도 빠집니다)
    })

    # 상품 이미지 같은 미디어 파일이 올라가는 곳입니다. 애플리케이션 데이터 내보내기 버킷을 그대로 쓰고 이름만 계약에 남았습니다.
    export = object({
      bucket_arn = string # 예: "arn:aws:s3:::cp-dev-app-exports-111111111111-ap-northeast-2" (미디어 버킷)
      prefix     = string # 예: "media/dev/commerce-api/" (Medusa file-s3 의 S3_PREFIX · commerce-api 만 씁니다)
    })

    kms_key_arn = string # 예: "arn:aws:kms:ap-northeast-2:111111111111:key/…"
  })
  nullable = false

  validation {
    condition = alltrue([
      for arn in concat([var.data_contract.credentials.master_secret_arn, var.data_contract.credentials.migration_secret_arn, var.data_contract.credentials.runtime_secret_arn], compact([var.data_contract.credentials.app_secret_arn])) :
      can(regex("^arn:aws:secretsmanager:", arn)) # 예: 주어진 값 모두 Secrets Manager ARN
    ])
    error_message = "credentials must be Secrets Manager ARNs (the data root outputs them)."
  }

  validation {
    condition     = endswith(var.data_contract.export.prefix, "/") && !startswith(var.data_contract.export.prefix, "/") # 예: "media/dev/commerce-api/" 통과 / "/media/dev" 거부
    error_message = "export.prefix must be a relative key prefix ending with a slash."
  }
}

# 배포 플랫폼 delivery 모듈이 만든 migration Role 입니다. 이 모듈은 Role 을 만들지 않고 데이터 권한(인라인 정책)과 Pod Identity 연결만 더합니다.
variable "migration_role_arn" {
  description = "ARN of the delivery migration role created in 배포 플랫폼; this module attaches the migration secret policy and the association to it."
  type        = string # 예: "arn:aws:iam::111111111111:role/platform/contract2whale-dev-eks-delivery-migration"
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/", var.migration_role_arn)) # 예: IAM Role ARN 형식
    error_message = "migration_role_arn must be an IAM role ARN."
  }
}

# 운영 도구 운영 기반의 External Secrets controller Role 입니다. 앱 비밀 읽기 Role(secrets_reader)이 이 Role 만 신뢰합니다 (assume-role chaining).
variable "external_secrets_role_arn" {
  description = "ARN of the cluster-wide External Secrets controller role (operations root output external_secrets_role_arn); the only principal the application secrets reader role trusts."
  type        = string # 예: "arn:aws:iam::111111111111:role/contract2whale-dev-eks-external-secrets"
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/", var.external_secrets_role_arn)) # 예: IAM Role ARN 형식
    error_message = "external_secrets_role_arn must be an IAM role ARN."
  }
}
