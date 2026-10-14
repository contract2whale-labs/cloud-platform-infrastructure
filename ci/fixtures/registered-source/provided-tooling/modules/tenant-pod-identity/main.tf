# main.tf — modules/tenant-pod-identity (dev · prod 루트 모듈이 공유하는 모듈)
# 세 신원의 경계: runtime(commerce-api) 은 실행 계정 · 앱 비밀과 자기 미디어 접두사, operator 는 관리 시크릿 · 앱 비밀 읽기와 앱 자격 증명 발행, migration 은 스키마 변경 계정 · 앱 비밀입니다.
# 앱 비밀 읽기 Role(secrets_reader)은 Pod 신원이 아니라 External Secrets controller 가 SecretStore 로 맡는 읽기 전용 Role 입니다 (assume-role chaining).
# 스토어프런트(commerce-web) 는 AWS API 를 부르지 않습니다. 그래서 Role 도 Pod Identity 연결도 만들지 않고, 이 모듈의 Pod 신원은 셋 그대로입니다.
# IAM 이 열어 주는 것은 AWS API 뿐입니다. 데이터베이스 안의 SQL 권한(GRANT)은 데이터베이스 초기화 Job 이 따로 만듭니다.

locals {
  name_prefix       = "${var.cluster_contract.name}-app"                                                # 예: "contract2whale-dev-eks-app" (이 모듈이 만드는 Role 이름 접두사)
  migration_role_id = regex("^arn:aws:iam::[0-9]{12}:role/(?:.*/)?([^/]+)$", var.migration_role_arn)[0] # 예: "contract2whale-dev-eks-delivery-migration" (경로가 있어도 마지막 이름만)
  export_resource   = "${var.data_contract.export.bucket_arn}/${var.data_contract.export.prefix}*"      # 예: "arn:aws:s3:::cp-dev-app-exports-…/media/dev/commerce-api/*" (미디어 객체가 올라가는 곳)

  # 앱 비밀(Medusa 의 JWT_SECRET · COOKIE_SECRET)은 계약에 있을 때만 권한에 들어갑니다. 없으면 목록에서 빠집니다 (compact).
  runtime_secrets   = compact([var.data_contract.credentials.runtime_secret_arn, var.data_contract.credentials.app_secret_arn])                                                     # 예: 실행 계정 비밀 + 앱 비밀
  migration_secrets = compact([var.data_contract.credentials.migration_secret_arn, var.data_contract.credentials.app_secret_arn])                                                   # 예: 스키마 변경 계정 비밀 + 앱 비밀 (db:migrate 도 설정을 읽습니다)
  reader_secrets    = compact([var.data_contract.credentials.runtime_secret_arn, var.data_contract.credentials.migration_secret_arn, var.data_contract.credentials.app_secret_arn]) # 예: ExternalSecret 두 개(commerce-api-runtime · commerce-api-migration)가 읽는 세 비밀
  contract_arns     = concat([var.data_contract.credentials.master_secret_arn, var.data_contract.credentials.migration_secret_arn, var.data_contract.credentials.runtime_secret_arn, var.data_contract.kms_key_arn], compact([var.data_contract.credentials.app_secret_arn]))

  # Pod Identity 는 세션 태그 세 개로 "이 클러스터의 이 namespace 의 이 ServiceAccount" 를 증명합니다 (E3).
  pod_identity_trust = {
    for key, service_account in var.data_contract.service_accounts : key => jsonencode({
      Version = "2012-10-17" # 예: "2012-10-17" (정책 문법 버전, 날짜가 아닙니다)
      Statement = [{
        Sid       = "PodIdentityAssumes${title(key)}"      # 예: "PodIdentityAssumesRuntime" (사람이 읽는 Statement 식별자)
        Effect    = "Allow"                                # 예: "Allow" (조건에 맞는 요청을 허용합니다)
        Principal = { Service = "pods.eks.amazonaws.com" } # 예: EKS Pod Identity 에이전트만
        Action    = ["sts:AssumeRole", "sts:TagSession"]   # 예: Pod Identity 는 두 동작이 모두 필요
        Condition = {
          StringEquals = {
            "aws:RequestTag/kubernetes-namespace"       = var.data_contract.namespace # 예: "contract2whale-demo"
            "aws:RequestTag/kubernetes-service-account" = service_account             # 예: "commerce-api" · "database-operator" · "delivery-migration"
            "aws:RequestTag/eks-cluster-arn"            = var.cluster_contract.arn    # 예: 이 클러스터의 Pod 만
          }
        }
      }]
    })
  }
}

resource "terraform_data" "guard" {
  input = "${var.environment}:${var.data_contract.namespace}" # 예: "dev:contract2whale-demo" (State 에 남는 표식)

  lifecycle {
    precondition {
      condition     = var.data_contract.environment == var.environment && var.data_contract.account_id == var.expected_account_id && var.data_contract.region == var.region # 예: 데이터 계약과 이 루트 모듈의 환경 · 계정 · 리전이 같아야 함
      error_message = "data_contract must describe the same environment, account and region as this root (an environment mix-up)."
    }

    precondition {
      condition     = var.data_contract.cluster_name == var.cluster_contract.name # 예: 다른 클러스터의 계약을 쓰지 않음
      error_message = "data_contract.cluster_name must equal cluster_contract.name."
    }

    precondition {
      condition = alltrue([
        for arn in local.contract_arns :
        split(":", arn)[4] == var.expected_account_id && split(":", arn)[3] == var.region # 예: 시크릿 · 키가 같은 계정 · 같은 리전에 있어야 함 (이름만 Dev 인 Prod ARN 거부)
      ])
      error_message = "Secrets and the KMS key must live in expected_account_id and region (name says dev, ARN says prod is the mistake this catches)."
    }

    precondition {
      condition     = startswith(var.data_contract.export.prefix, "media/${var.environment}/") # 예: "media/dev/commerce-api/" 통과 / "media/prod/commerce-api/" 거부
      error_message = "export.prefix must start with media/<environment>/ (the media prefix of the data contract)."
    }

    precondition {
      condition     = split(":", var.migration_role_arn)[4] == var.expected_account_id && endswith(local.migration_role_id, "-delivery-migration") # 예: 같은 계정의 배포 플랫폼 migration Role 인지
      error_message = "migration_role_arn must be the delivery migration role of this account (배포 플랫폼 execution contract)."
    }
  }
}

# runtime: 앱 Pod(commerce-api) 의 신원입니다. 실행 계정과 선택적 앱 비밀을 읽고, 자기 미디어 접두사 아래의 객체만 다룹니다.
resource "aws_iam_role" "runtime" {
  name               = "${local.name_prefix}-runtime"      # 예: "contract2whale-dev-eks-app-runtime"
  path               = "/platform/"                        # 예: "/platform/" (배포 플랫폼 Role 과 같은 경로 규칙)
  assume_role_policy = local.pod_identity_trust["runtime"] # 예: namespace/ServiceAccount/클러스터 조건이 붙은 신뢰 정책

  depends_on = [terraform_data.guard] # 예: 계약 검사를 통과한 뒤에 만듭니다
}

resource "aws_iam_role_policy" "runtime" {
  name = "application-data" # 예: Role 안에 붙는 인라인 정책 이름
  role = aws_iam_role.runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RuntimeSecret" # 예: 자기 실행 계정 시크릿과 앱 비밀만 읽기 (관리자 · 스키마 변경 시크릿은 없음)
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = local.runtime_secrets
      },
      {
        Sid      = "OwnExportObjects" # 예: 자기 접두사 아래의 객체만 읽고 쓰고 지움 (관리자 화면의 미디어 업로드 · 삭제)
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload"]
        Resource = [local.export_resource]
      },
      {
        Sid      = "ListOwnExportPrefix" # 예: 목록 조회도 접두사로 제한 (버킷 전체 목록 금지)
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [var.data_contract.export.bucket_arn]
        Condition = {
          StringLike = { "s3:prefix" = ["${var.data_contract.export.prefix}*"] }
        }
      },
      {
        Sid      = "ExportKeyViaS3" # 예: 키 사용은 S3 를 거치는 호출로만 (직접 복호화 금지)
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
        Resource = [var.data_contract.kms_key_arn]
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        }
      },
      {
        Sid      = "RuntimeSecretKey" # 예: 시크릿 복호화는 Secrets Manager 를 거치는 호출로만
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.data_contract.kms_key_arn]
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        }
      },
    ]
  })
}

# operator: 초기화 · 진단 Job 의 신원입니다. 관리 시크릿과 앱 비밀을 읽고, 후보 비밀번호를 만들어 앱 시크릿 두 개를 발행합니다. 내보내기 버킷 권한은 없습니다.
resource "aws_iam_role" "operator" {
  name               = "${local.name_prefix}-database-operator" # 예: "contract2whale-dev-eks-app-database-operator"
  path               = "/platform/"                             # 예: "/platform/"
  assume_role_policy = local.pod_identity_trust["operator"]     # 예: database-operator ServiceAccount 만

  depends_on = [terraform_data.guard] # 예: 계약 검사를 통과한 뒤에 만듭니다
}

resource "aws_iam_role_policy" "operator" {
  name = "database-bootstrap" # 예: Role 안에 붙는 인라인 정책 이름
  role = aws_iam_role.operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "MasterSecret" # 예: RDS 가 관리하는 관리자 시크릿 읽기 (앱 · migration 에는 없는 권한)
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [var.data_contract.credentials.master_secret_arn]
      },
      {
        Sid    = "PublishApplicationCredentials" # 예: 앱 시크릿 두 개에 후보 값을 올리고 현재 버전으로 승격
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:ListSecretVersionIds",
        ]
        Resource = [var.data_contract.credentials.migration_secret_arn, var.data_contract.credentials.runtime_secret_arn]
      },
      {
        Sid      = "GeneratePasswords" # 예: 후보 비밀번호 생성 (리소스를 지정할 수 없는 동작이라 "*")
        Effect   = "Allow"
        Action   = ["secretsmanager:GetRandomPassword"]
        Resource = ["*"]
      },
      {
        Sid      = "OperatorSecretKey" # 예: 시크릿 암복호화는 Secrets Manager 를 거치는 호출로만
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.data_contract.kms_key_arn]
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        }
      },
      ], var.data_contract.credentials.app_secret_arn == null ? [] : [
      {
        Sid      = "ReadApplicationSecret" # 예: 앱 비밀(jwt_secret · cookie_secret)을 읽어 실행 계정 비밀에 옮겨 적음 (쓰기 없음)
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [var.data_contract.credentials.app_secret_arn]
      },
    ])
  })
}

# migration: 배포 플랫폼이 만든 Role 에 데이터 권한만 더합니다. Role · 신뢰 정책은 배포 플랫폼 소유이고 여기서 다시 만들지 않습니다.
# Argo CD PreSync Job 이 앱 이미지로 medusa db:migrate 를 돌리므로, 이 신원이 읽는 것은 스키마 변경 계정 비밀과 앱 비밀 둘뿐입니다.
resource "aws_iam_role_policy" "migration" {
  name = "migration-secret"      # 예: Role 안에 붙는 인라인 정책 이름 (배포 플랫폼 의 정책과 이름이 겹치지 않음)
  role = local.migration_role_id # 예: "contract2whale-dev-eks-delivery-migration" (ARN 에서 뽑은 Role 이름)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "MigrationSecret" # 예: 스키마 변경 계정 시크릿과 앱 비밀만 읽기 (medusa db:migrate 도 설정을 읽어 JWT_SECRET · COOKIE_SECRET 을 요구)
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = local.migration_secrets
      },
      {
        Sid      = "MigrationSecretKey" # 예: 시크릿 복호화는 Secrets Manager 를 거치는 호출로만
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.data_contract.kms_key_arn]
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        }
      },
    ]
  })

  depends_on = [terraform_data.guard] # 예: migration Role 이 이 계정의 배포 플랫폼 Role 인지 확인한 뒤에
}

# 앱 비밀 읽기: 운영 도구 External Secrets controller 가 SecretStore(spec.provider.aws.role)로 맡는 읽기 전용 Role 입니다 (assume-role chaining).
# ExternalSecret 두 개(commerce-api-runtime · commerce-api-migration)가 같은 SecretStore 를 쓰므로 실행 계정 · 스키마 변경 계정 · 앱 비밀을 읽습니다. 관리자 시크릿은 없습니다.
resource "aws_iam_role" "secrets_reader" {
  name = "${var.cluster_contract.name}-data-app-secrets" # 예: "contract2whale-dev-eks-data-app-secrets" (gitops overlay 의 SecretStore role 과 같은 이름)
  path = "/platform/"                                    # 예: "/platform/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ExternalSecretsControllerChaining"
      Effect    = "Allow"
      Principal = { AWS = var.external_secrets_role_arn } # 예: 운영 도구 controller Role (platform/operations 루트 모듈 출력 external_secrets_role_arn)
      Action    = ["sts:AssumeRole", "sts:TagSession"]    # 예: 역할 사용 + 세션 태그 전달
      Condition = {
        StringEquals = {
          "aws:PrincipalTag/kubernetes-namespace"       = "external-secrets" # 예: controller 가 도는 네임스페이스 (운영 도구)
          "aws:PrincipalTag/kubernetes-service-account" = "external-secrets" # 예: controller ServiceAccount (운영 도구 values serviceAccount.name)
        }
      }
    }]
  })

  depends_on = [terraform_data.guard] # 예: 계약 검사를 통과한 뒤에 만듭니다
}

resource "aws_iam_role_policy" "secrets_reader" {
  name = "read-application-secrets"     # 예: Role 안에 붙는 인라인 정책 이름
  role = aws_iam_role.secrets_reader.id # 예: 위 Role

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadApplicationSecrets" # 예: 실행 계정 · 스키마 변경 계정 · 앱 비밀 읽기 2동작 (관리자 시크릿 · 쓰기 없음)
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = local.reader_secrets
      },
      {
        Sid      = "ReaderSecretKey" # 예: 시크릿 복호화는 Secrets Manager 를 거치는 호출로만
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.data_contract.kms_key_arn]
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        }
      },
    ]
  })
}

resource "aws_eks_pod_identity_association" "runtime" {
  cluster_name    = var.cluster_contract.name                  # 예: "contract2whale-dev-eks"
  namespace       = var.data_contract.namespace                # 예: "contract2whale-demo"
  service_account = var.data_contract.service_accounts.runtime # 예: "commerce-api"
  role_arn        = aws_iam_role.runtime.arn                   # 예: "arn:aws:iam::…:role/platform/contract2whale-dev-eks-app-runtime"

  depends_on = [aws_iam_role_policy.runtime] # 예: 권한이 붙은 뒤에 연결을 만듭니다
}

resource "aws_eks_pod_identity_association" "operator" {
  cluster_name    = var.cluster_contract.name                   # 예: "contract2whale-dev-eks"
  namespace       = var.data_contract.namespace                 # 예: "contract2whale-demo"
  service_account = var.data_contract.service_accounts.operator # 예: "database-operator"
  role_arn        = aws_iam_role.operator.arn                   # 예: "arn:aws:iam::…:role/platform/contract2whale-dev-eks-app-database-operator"

  depends_on = [aws_iam_role_policy.operator] # 예: 권한이 붙은 뒤에 연결을 만듭니다
}

# 배포 플랫폼 는 migration Role 과 신뢰 정책만 만들고 연결은 만들지 않습니다 (배포 플랫폼 사양의 인계 항목). 그래서 이 연결의 소유자는 애플리케이션 데이터 입니다.
resource "aws_eks_pod_identity_association" "migration" {
  cluster_name    = var.cluster_contract.name                    # 예: "contract2whale-dev-eks"
  namespace       = var.data_contract.namespace                  # 예: "contract2whale-demo"
  service_account = var.data_contract.service_accounts.migration # 예: "delivery-migration" (gitops/platform/tenant-baseline/overlays/dev/serviceaccount-delivery-migration.yaml)
  role_arn        = var.migration_role_arn                       # 예: 배포 플랫폼이 만든 Role

  depends_on = [aws_iam_role_policy.migration] # 예: 데이터 권한이 붙은 뒤에 연결을 만듭니다
}
