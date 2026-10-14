# main.tf — identity 루트 모듈 (dev · prod 공통 코드)
# 데이터 자원(130)과 State 를 나눠 두었기 때문에 권한만 고쳐 다시 적용해도 데이터베이스 계획이 나오지 않습니다.

module "component" {
  source = "../../../../modules/tenant-pod-identity" # 예: 이 루트 모듈에서 모듈까지의 상대 경로

  expected_account_id = var.expected_account_id         # 예: "222222222222"
  region              = var.region                      # 예: "ap-northeast-2"
  environment         = var.environment                 # 예: "prod"
  cluster_contract    = local.cluster_contract          # 예: eks State 의 이름 · ARN
  data_contract       = local.data_contract             # 예: data State 의 계약에서 추린 9키
  migration_role_arn  = data.aws_iam_role.migration.arn # 예: 이름으로 조회한 배포 플랫폼 Role 의 ARN

  external_secrets_role_arn = local.external_secrets_role_arn # 예: platform/operations State 의 ESO controller Role (앱 비밀 읽기 Role 의 신뢰 주체)
}

# 이 디렉터리는 prod 만 받습니다. input 은 State 에 남는 marker 이며 AWS 자원을 만들지 않습니다.
resource "terraform_data" "environment_boundary" {
  input = var.environment # 예: "prod"

  lifecycle {
    precondition {
      condition     = var.environment == "prod" # 예: "prod" 통과 / "dev" 거부 (dev는 dev/identity 디렉터리)
      error_message = "This directory accepts only the prod environment."
    }

    precondition {
      condition     = terraform.workspace == "default" # 예: workspace 로 환경을 나누지 않음
      error_message = "Use default workspace and a distinct backend key."
    }
  }
}
