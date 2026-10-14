# main.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)

module "component" {
  source = "../../../../../modules/gateway" # 예: 이 루트 모듈에서 모듈까지의 상대 경로 (다섯 단계 위가 저장소 최상위)

  cluster_contract         = local.cluster_contract       # 예: eks State 출력으로 조립한 {name, arn, region, vpc_id}
  expected_account_id      = var.expected_account_id      # 예: "111111111111"
  public_zone              = local.public_zone            # 예: account-baseline-dns State 출력으로 조립한 {id, name}
  exposure_mode            = var.exposure_mode            # 예: "internal" (기본값)
  allowed_client_cidrs     = var.allowed_client_cidrs     # 예: [] (최종 Dev)
  existing_private_zone_id = var.existing_private_zone_id # 예: null (없으면 새로 만듦)
  nlb_subnet_ids           = local.nlb_subnet_ids         # 예: network/vpc State 의 서브넷 3개 (모드에 따라 public · private)
}

# 이 디렉터리는 dev 만 받습니다. input 은 State 에 남는 marker 이며 AWS 자원을 만들지 않습니다.
resource "terraform_data" "environment_boundary" {
  input = var.environment # 예: "dev" (input 변경은 in-place 갱신)

  lifecycle {
    precondition {
      condition     = var.environment == "dev" # 예: "dev" 통과 / "prod" 거부 (prod 는 prod/platform/gateway 디렉터리)
      error_message = "This directory accepts only the dev environment."
    }

    precondition {
      condition     = terraform.workspace == "default" # 예: workspace 로 환경을 나누지 않음 (backend key 로 구분)
      error_message = "Use default workspace and a distinct backend key."
    }
  }
}
