# outputs.tf — modules/edge (dev · prod 루트 모듈이 공유하는 모듈)

output "edge_contract" {
  description = "CloudFront distribution, domain, WAF ARN and hostnames when enabled; null while disabled."
  value = var.enabled ? {
    distribution_id = aws_cloudfront_distribution.app[0].id          # 예: "E1ABCDEFGHIJKL"
    domain_name     = aws_cloudfront_distribution.app[0].domain_name # 예: "d111111abcdef8.cloudfront.net"
    waf_arn         = aws_wafv2_web_acl.edge[0].arn                  # 예: Web ACL 의 ARN
    hostnames       = sort(tolist(var.hostnames))                    # 예: ["dev.playdevops.click"]
  } : null                                                           # 예: 비활성이면 null
}
