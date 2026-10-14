# remote-state.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)
# 알림 루트 모듈과 설치 검사: 앞 루트 모듈 두 곳(eks · platform/operations)의 root 출력을 State 에서 직접 읽습니다 (P1). .local/alerting/dev/*.json · terraform.tfvars.json 같은 입력 파일을 만들지 않습니다.
# 읽는 쪽에는 State 객체의 s3:GetObject 권한이 필요합니다 (관련 구성 의 State 역할 key 목록과 대조: eks/terraform.tfstate · platform/operations/terraform.tfstate).
# 적용 후 alerting_contract의 실제 SNS ARN을 operations의 alerts_topic_arn 입력에 설정하고, fresh saved plan을 검토·적용해 계약에 전달합니다. 후속 변경에서도 이 입력을 유지합니다.

data "terraform_remote_state" "eks" {
  backend = "s3" # 예: "s3" (앞 루트 모듈이 State 를 둔 방식)

  config = {
    bucket = var.state_bucket_name   # 예: "company-dev-tfstate-111111111111"
    key    = "eks/terraform.tfstate" # 예: eks 루트 모듈의 key (클러스터 입력과 네트워크 계약)
    region = var.region              # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition = alltrue([
        for name in ["name", "arn", "region"] :
        contains(keys(try(self.outputs.cluster_contract, {})), name) # 예: 3개 모두 cluster_contract 에 존재
      ])
      error_message = "eks state must expose cluster_contract with name, arn and region (apply 생성 계획과 private API 검증 first)."
    }
  }
}

# 운영 기반 루트 모듈과 계약 의 운영 기반 루트 모듈입니다. 로그 그룹 이름만 읽습니다 (fluent_bit 을 끈 State 는 null 이라 거부).
data "terraform_remote_state" "operations" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name                   # 예: "company-dev-tfstate-111111111111" (같은 버킷)
    key    = "platform/operations/terraform.tfstate" # 예: platform/operations 루트 모듈의 key (운영 기반 루트 모듈과 계약)
    region = var.region                              # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = try(self.outputs.operations_contract.platform_log_group_name != null, false) # 예: "/platform/contract2whale-dev-eks/application" (null 이면 거부)
      error_message = "platform/operations state must expose operations_contract.platform_log_group_name (apply 운영 기반 루트 모듈과 계약 with fluent_bit enabled first)."
    }
  }
}
