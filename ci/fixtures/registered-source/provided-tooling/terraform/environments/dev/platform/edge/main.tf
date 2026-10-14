# main.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)

module "component" {
  source = "../../../../../modules/edge" # 예: 이 루트 모듈에서 모듈까지의 상대 경로 (다섯 단계 위가 저장소 최상위)

  providers = {
    aws        = aws        # 예: 왼쪽은 모듈 안의 이름, 오른쪽은 루트 모듈의 provider (서울)
    aws.global = aws.global # 예: us-east-1 provider (ACM · WAF)
  }

  enabled             = var.enabled             # 예: false (Dev 기본)
  expected_account_id = var.expected_account_id # 예: "111111111111"
  gateway_contract    = local.gateway_contract  # 예: Gateway State 출력에서 고른 6개 항목
  nlb_arn             = var.nlb_arn             # 예: "" (비활성 상태의 기본값)
  hostnames           = var.hostnames           # 예: [] (비활성 상태의 기본값)
  origin_tls_ready    = var.origin_tls_ready    # 예: false (원본 인증서를 확인한 뒤 true)
  rate_limit_per_5min = var.rate_limit_per_5min # 예: 2000
}

# 이 디렉터리는 dev 만 받습니다. input 은 State 에 남는 marker 이며 AWS 자원을 만들지 않습니다.
resource "terraform_data" "environment_boundary" {
  input = var.environment # 예: "dev" (input 변경은 in-place 갱신)

  lifecycle {
    precondition {
      condition     = var.environment == "dev" # 예: "dev" 통과 / "prod" 거부 (prod 는 prod/platform/edge 디렉터리, 운영 환경)
      error_message = "This directory accepts only the dev environment."
    }

    precondition {
      condition     = terraform.workspace == "default" # 예: workspace 로 환경을 나누지 않음
      error_message = "Use default workspace and a distinct backend key."
    }
  }
}
