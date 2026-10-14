# providers.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)
# 환경 root 두 개 연결: provider 두 개. 기본 provider 는 워크로드 리전(NLB 조회 · Route 53 · VPC origin), aws.global 은 us-east-1(CloudFront viewer 인증서 · CLOUDFRONT scope WAF · WAF 로그 그룹)입니다.
# 두 provider 모두 같은 계정으로 제한하고 같은 default_tags 를 씁니다. 모듈은 providers = { aws = aws, aws.global = aws.global } 로 둘을 받습니다.

provider "aws" {
  region              = var.region                # 예: "ap-northeast-2" (서울 리전)
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"]

  default_tags {
    tags = {
      ManagedBy   = "Terraform"     # 예: "Terraform"
      Environment = var.environment # 예: "dev"
      Component   = "platform-edge" # 예: "platform-edge"
    }
  }
}

# CloudFront viewer 인증서와 CLOUDFRONT 범위 WAF 를 만들 provider 입니다.
provider "aws" {
  alias               = "global"                  # 예: "global" (모듈이 aws.global 로 받음)
  region              = "us-east-1"               # 예: "us-east-1" (전역 서비스의 API 리전; 변수로 바꾸지 않음)
  allowed_account_ids = [var.expected_account_id] # 예: ["111111111111"] (기본 provider 와 같은 계정)

  default_tags {
    tags = {
      ManagedBy   = "Terraform"     # 예: 같은 태그
      Environment = var.environment # 예: "dev"
      Component   = "platform-edge" # 예: "platform-edge"
    }
  }
}
