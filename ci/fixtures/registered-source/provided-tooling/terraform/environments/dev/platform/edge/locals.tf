# locals.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)

locals {
  gateway_contract = {
    cluster_name          = data.terraform_remote_state.gateway.outputs.gateway_contract.cluster_name          # 예: "contract2whale-dev-eks"
    vpc_id                = data.terraform_remote_state.gateway.outputs.gateway_contract.vpc_id                # 예: "vpc-0123456789abcdef0"
    exposure_mode         = data.terraform_remote_state.gateway.outputs.gateway_contract.exposure_mode         # 예: "internal" (Dev; edge 를 켜려면 "waf")
    nlb_security_group_id = data.terraform_remote_state.gateway.outputs.gateway_contract.nlb_security_group_id # 예: "sg-0123456789abcdef0"
    public_zone_id        = data.terraform_remote_state.gateway.outputs.gateway_contract.public_zone_id        # 예: "ZPUBLIC"
    dns_zone_name         = data.terraform_remote_state.gateway.outputs.gateway_contract.dns_zone_name         # 예: "dev.playdevops.click"
  }
}
