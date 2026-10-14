# outputs.tf — platform/edge 루트 모듈 (dev · prod 공통 코드)
# 환경 root 두 개 연결: child module 의 출력을 같은 이름으로 루트 모듈 밖에 전달합니다. 비활성이면 null 입니다.

output "edge_contract" {
  description = "CloudFront distribution, domain, WAF ARN and hostnames when enabled; null while disabled."
  value       = module.component.edge_contract # 예: null (Dev 기본)
}
