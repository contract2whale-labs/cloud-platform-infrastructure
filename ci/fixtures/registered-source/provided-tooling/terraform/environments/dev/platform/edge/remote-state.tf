# remote-state.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)
# 읽는 쪽에는 State 객체 전체의 s3:GetObject 권한이 필요합니다 (관련 구성 의 State 역할 key 목록과 대조).

data "terraform_remote_state" "gateway" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name                # 예: "company-dev-tfstate-111111111111"
    key    = "platform/gateway/terraform.tfstate" # 예: Gateway 루트 모듈의 key
    region = var.region                           # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition = alltrue([
        for name in ["cluster_name", "vpc_id", "exposure_mode", "nlb_security_group_id", "public_zone_id", "dns_zone_name"] :
        contains(keys(try(self.outputs.gateway_contract, {})), name) # 예: 6개 모두 gateway_contract 에 존재
      ])
      error_message = "platform/gateway state must expose gateway_contract with cluster_name, vpc_id, exposure_mode, nlb_security_group_id, public_zone_id and dns_zone_name (apply 계약 테스트와 controller 설치 first)."
    }
  }
}
