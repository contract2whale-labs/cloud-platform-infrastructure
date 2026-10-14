# versions.tf — modules/edge (dev · prod 루트 모듈이 공유하는 모듈)
# Prod 공개 Edge 모듈: CloudFront · WAF · viewer 인증서는 Gateway 와 별도 State 를 씁니다. Gateway 와 NLB 를 만든 뒤 enabled = true 로 명시적으로 켭니다.
# CloudFront viewer 인증서(ACM)와 CLOUDFRONT scope WAF 는 us-east-1 API 에서 만들므로 루트 모듈에서 aws.global provider 를 추가로 받습니다. provider 블록은 두지 않습니다.

terraform {
  required_version = "= 1.16.0" # 예: "= 1.16.0" (등호로 정확한 버전 고정)

  required_providers {
    aws = {
      source                = "hashicorp/aws" # 예: "hashicorp/aws"
      version               = "= 6.62.0"      # 예: "= 6.62.0" (aws_cloudfront_vpc_origin 을 검증한 버전; 루트 모듈과 같은 값)
      configuration_aliases = [aws.global]    # 예: [aws.global] (루트 모듈의 providers = { aws.global = aws.global } 로 받음)
    }
  }
}
