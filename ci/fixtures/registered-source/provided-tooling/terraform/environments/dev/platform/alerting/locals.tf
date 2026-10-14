# locals.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)
# 알림 루트 모듈과 설치 검사: State 에서 읽은 출력을 모듈 입력 모양으로 조립합니다. 두 값 모두 이 루트 모듈이 직접 입력받지 않습니다.

locals {
  cluster_contract = {
    name   = data.terraform_remote_state.eks.outputs.cluster_contract.name   # 예: "contract2whale-dev-eks"
    arn    = data.terraform_remote_state.eks.outputs.cluster_contract.arn    # 예: "arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks"
    region = data.terraform_remote_state.eks.outputs.cluster_contract.region # 예: "ap-northeast-2"
  }

  platform_log_group_name = data.terraform_remote_state.operations.outputs.operations_contract.platform_log_group_name # 예: "/platform/contract2whale-dev-eks/application" (운영 기반 루트 모듈과 계약 출력)
}
