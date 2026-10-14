# locals.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)
# 환경 root 두 개 연결: State 에서 읽은 출력을 모듈 입력 모양으로 조립합니다. 세 값 모두 이 루트 모듈이 직접 입력받지 않습니다.

locals {
  cluster_contract = {
    name   = data.terraform_remote_state.eks.outputs.cluster_contract.name   # 예: "contract2whale-dev-eks"
    arn    = data.terraform_remote_state.eks.outputs.cluster_contract.arn    # 예: "arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks"
    region = data.terraform_remote_state.eks.outputs.cluster_contract.region # 예: "ap-northeast-2"
    vpc_id = data.terraform_remote_state.eks.outputs.cluster_contract.vpc_id # 예: "vpc-0123456789abcdef0"
  }

  public_zone = {
    id   = data.terraform_remote_state.dns.outputs.public_zone_id   # 예: "Z0123456789ABCDEFGHIJ" (계정 옵션과 공개 자식 DNS 루트 모듈 출력)
    name = data.terraform_remote_state.dns.outputs.public_zone_name # 예: "dev.playdevops.click" (끝의 점 없음)
  }

  # public 은 IGW 경로가 있는 public 서브넷, internal · waf 는 NAT 뒤의 일반 Private 서브넷(관련 구성)입니다. EKS 서브넷(관련 구성)은 노드 · Pod 전용으로 남깁니다.
  nlb_subnet_ids = toset(var.exposure_mode == "public" ? data.terraform_remote_state.network.outputs.public_subnet_ids : data.terraform_remote_state.network.outputs.private_subnet_ids) # 예: ["subnet-0pri1...", "subnet-0pri2...", "subnet-0pri3..."]
}
