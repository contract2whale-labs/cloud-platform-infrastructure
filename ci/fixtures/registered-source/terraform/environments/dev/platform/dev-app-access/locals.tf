# locals.tf — platform/dev-app-access 루트 모듈 (dev 전용)
# 승인된 개발자의 Private Dev 접근: State 에서 읽은 출력과 고정 이름을 한곳에 모읍니다.

locals {
  instance_id       = data.terraform_remote_state.private_api.outputs.session_contract.instance_id       # 예: "i-0123456789abcdef0" (SSM 중계 인스턴스)
  relay_sg_id       = data.terraform_remote_state.private_api.outputs.session_contract.security_group_id # 예: "sg-0relay…" (인스턴스 SG)
  nlb_sg_id         = data.terraform_remote_state.gateway.outputs.gateway_contract.nlb_security_group_id # 예: "sg-0123456789abcdef0" (Gateway NLB SG)
  cluster_name      = data.terraform_remote_state.gateway.outputs.gateway_contract.cluster_name          # 예: "contract2whale-dev-eks"
  gateway_namespace = data.terraform_remote_state.gateway.outputs.gateway_contract.namespace             # 예: "platform-gateway"
  exposure_mode     = data.terraform_remote_state.gateway.outputs.gateway_contract.exposure_mode         # 예: "internal" (이 경로는 internal 에서만 의미가 있음)

  document_name = "CommerceDevelopmentAppHttps"   # 예: 고정 세션 문서 이름 (aws ssm start-session --document-name)
  role_name     = "CommerceDevelopmentAppSession" # 예: 전용 세션 Role 이름 (~/.aws/config 의 role_arn)
  remote_port   = 443                             # 예: NLB listener 포트 (Envoy HTTPS)
}
