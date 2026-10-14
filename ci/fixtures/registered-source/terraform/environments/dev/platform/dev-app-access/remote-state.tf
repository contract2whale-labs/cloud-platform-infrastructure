# remote-state.tf — platform/dev-app-access 루트 모듈 (dev 전용)
# 승인된 개발자의 Private Dev 접근: 앞 루트 모듈 두 곳(private-api · gateway)의 root 출력을 State 에서 직접 읽습니다. terraform.tfvars.json 에 인스턴스 ID · SG ID 를 옮겨 적지 않습니다.
# 읽는 쪽에는 State 객체 전체의 s3:GetObject 권한이 필요합니다 (관련 구성 의 State 역할 key 목록과 대조).

# Private API 접속 경로 준비 의 SSM 중계 인스턴스 루트 모듈입니다. 세션 대상 인스턴스와 그 SG(NLB 출발지 규칙의 referenced SG)를 읽습니다.
data "terraform_remote_state" "private_api" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name                    # 예: "company-dev-tfstate-111111111111"
    key    = "platform/private-api/terraform.tfstate" # 예: private-api 루트 모듈의 key (Private API 접속 경로 준비)
    region = var.region                               # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = alltrue([for name in ["instance_id", "security_group_id"] : contains(keys(try(self.outputs.session_contract, {})), name)]) # 예: 두 항목 모두 session_contract 에 존재
      error_message = "platform/private-api state must expose session_contract with instance_id and security_group_id (apply Private API 접속 경로 준비 first)."
    }
  }
}

data "terraform_remote_state" "gateway" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name                # 예: 같은 버킷
    key    = "platform/gateway/terraform.tfstate" # 예: Gateway 루트 모듈의 key
    region = var.region                           # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = alltrue([for name in ["cluster_name", "nlb_security_group_id", "exposure_mode", "namespace"] : contains(keys(try(self.outputs.gateway_contract, {})), name)]) # 예: 4개 모두 gateway_contract 에 존재
      error_message = "platform/gateway state must expose gateway_contract with cluster_name, nlb_security_group_id, exposure_mode and namespace (apply 계약 테스트와 controller 설치 first)."
    }
  }
}
