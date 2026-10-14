# versions.tf — modules/gateway (dev · prod 루트 모듈이 공유하는 모듈)
# controller 권한과 소유권: controller 신원(IAM Role · Pod Identity 연결)과 노출 경계(SG · private zone)만 Terraform 으로 관리합니다. NLB 자체는 controller 가 만듭니다.
# 과정 내부 전용 모듈이라 루트 모듈과 같은 값을 등호로 고정합니다. provider 블록은 두지 않습니다 (인증 · 리전 · default_tags 는 루트 모듈의 providers.tf 가 담당).

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source  = "hashicorp/aws" # 예: "hashicorp/aws" (공식 레지스트리 경로)
      version = "= 6.62.0"      # 예: "= 6.62.0" (aws_eks_pod_identity_association · aws_vpc_security_group_*_rule 을 검증한 버전; 루트 모듈과 같은 값)
    }
  }
}
