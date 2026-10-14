# main.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)

module "component" {
  source = "../../../../../modules/alerting" # 예: 이 루트 모듈에서 모듈까지의 상대 경로 (다섯 단계 위가 저장소 최상위)

  expected_account_id             = var.expected_account_id             # 예: "111111111111"
  environment                     = var.environment                     # 예: "dev"
  region                          = var.region                          # 예: "ap-northeast-2"
  cluster_contract                = local.cluster_contract              # 예: eks State 출력으로 조립한 {name, arn, region}
  platform_log_group_name         = local.platform_log_group_name       # 예: platform/operations State 의 "/platform/contract2whale-dev-eks/application"
  receiver_email                  = var.receiver_email                  # 예: "ops-alerts@example.com"
  sample_delete_validation_run_id = var.sample_delete_validation_run_id # 예: null (감지를 켜지 않은 상태)

  depends_on = [terraform_data.environment_boundary] # 예: 환경 경계를 통과한 뒤에 호출합니다
}

# 이 디렉터리는 dev 만 받습니다. input 은 State 에 남는 marker 이며 AWS 자원을 만들지 않습니다.
resource "terraform_data" "environment_boundary" {
  input = var.environment # 예: "dev" (input 변경은 in-place 갱신)

  lifecycle {
    precondition {
      condition     = var.environment == "dev" # 예: "dev" 통과 / "prod" 거부 (prod 는 prod/platform/alerting 디렉터리 — 운영 환경)
      error_message = "This directory accepts only the dev environment."
    }

    precondition {
      condition     = terraform.workspace == "default" # 예: workspace 로 환경을 나누지 않음 (backend key 로 구분)
      error_message = "Use default workspace and a distinct backend key."
    }
  }
}
