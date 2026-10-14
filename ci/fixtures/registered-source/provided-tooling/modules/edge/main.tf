# main.tf — modules/edge (dev · prod 루트 모듈이 공유하는 모듈)
# 모든 data · 리소스가 var.enabled 로 개수를 0 또는 1(hostnames 만큼)로 정하므로 기본값(false)에서는 아무것도 만들지 않습니다.
# 읽기 조회에서 internet-facing NLB · TLS listener · 다른 VPC 의 원본을 거부합니다. 이 모듈의 최종 사용처는 Prod(CloudFront 와 WAF 로 공개 서비스 완성) 이며 Dev 루트 모듈은 비활성 상태로 코드만 검증합니다.

data "aws_lb" "origin" {
  count = var.enabled ? 1 : 0 # 예: 비활성이면 조회하지 않음
  arn   = var.nlb_arn         # 예: controller 가 만든 NLB 의 ARN
}

data "aws_lb_listener" "https_tcp" {
  count             = var.enabled ? 1 : 0 # 예: 비활성이면 조회하지 않음
  load_balancer_arn = var.nlb_arn         # 예: 같은 NLB 의 ARN
  port              = 443                 # 예: 443 (Envoy 로 전달하는 listener)
}

# VPC origin 은 VPC 에 IGW 가 연결돼 있어야 합니다 (private 서브넷에 IGW 기본 route 를 추가하는 것이 아님).
data "aws_internet_gateway" "attached" {
  count = var.enabled ? 1 : 0 # 예: 비활성이면 조회하지 않음

  filter {
    name   = "attachment.vpc-id"           # 예: VPC 에 붙은 IGW 를 찾는 필터
    values = [var.gateway_contract.vpc_id] # 예: ["vpc-0123456789abcdef0"]
  }
}

resource "terraform_data" "contract" {
  count = var.enabled ? 1 : 0 # 예: 비활성이면 검사 리소스도 만들지 않음

  lifecycle {
    precondition {
      condition     = terraform.workspace == "default" && var.gateway_contract.exposure_mode == "waf" # 예: 기본 workspace + Gateway 가 waf 모드일 때만 참
      error_message = "Enable only behind a WAF-mode internal Gateway in the default workspace."
    }

    precondition {
      condition     = var.origin_tls_ready && length(var.hostnames) > 0 # 예: 원본 인증서 확인 선언 + 이름 1개 이상
      error_message = "Enable only after the WAF-mode internal Gateway has a production TLS certificate and explicit hostnames."
    }

    precondition {
      # 예: zone apex 자체 또는 점으로 구분한 하위 도메인만 허용 ("evildev.playdevops.click" 같은 유사 접미사 거부)
      condition     = alltrue([for h in var.hostnames : h == trimsuffix(var.gateway_contract.dns_zone_name, ".") || endswith(h, ".${trimsuffix(var.gateway_contract.dns_zone_name, ".")}")])
      error_message = "Every hostname must equal the delegated zone apex or be its proper subdomain."
    }

    precondition {
      # 예: 조회한 NLB 가 internal · network · 같은 VPC · 계약 SG 를 가질 때만 참
      condition     = data.aws_lb.origin[0].internal && data.aws_lb.origin[0].load_balancer_type == "network" && data.aws_lb.origin[0].vpc_id == var.gateway_contract.vpc_id && contains(data.aws_lb.origin[0].security_groups, var.gateway_contract.nlb_security_group_id)
      error_message = "CloudFront VPC origin must use the same-VPC internal NLB with the contract security group."
    }

    precondition {
      condition     = data.aws_lb_listener.https_tcp[0].protocol == "TCP" # 예: NLB 가 TLS 를 끝내지 않고 Envoy 로 전달할 때만 참
      error_message = "The NLB 443 listener must be TCP; TLS terminates at Envoy."
    }
  }
}

# ACM 공개 인증서는 viewer TLS 만 담당하며 Envoy 원본 인증서는 cert-manager 가 따로 발급합니다.
resource "aws_acm_certificate" "viewer" {
  count                     = var.enabled ? 1 : 0                                          # 예: 비활성이면 0개
  provider                  = aws.global                                                   # 예: aws.global (us-east-1)
  domain_name               = sort(tolist(var.hostnames))[0]                               # 예: "dev.playdevops.click" (정렬된 첫 이름)
  subject_alternative_names = slice(sort(tolist(var.hostnames)), 1, length(var.hostnames)) # 예: 나머지 이름 목록
  validation_method         = "DNS"                                                        # 예: "DNS" (ACM 이 제공한 CNAME 레코드로 소유를 증명)

  lifecycle {
    create_before_destroy = true # 예: true (새 인증서를 먼저 만들고 바꿈)
  }

  depends_on = [terraform_data.contract] # 예: 계약 검사를 먼저 지나갑니다
}

# provider 가 domain_validation_options 를 만든 뒤 각 DNS 검증 레코드를 생성합니다. 주소 키는 사용자가 전달한 hostname 으로 확정합니다.
resource "aws_route53_record" "validation" {
  for_each = var.enabled ? var.hostnames : toset([])                                                                                          # 예: 이름마다 레코드 1개
  zone_id  = var.gateway_contract.public_zone_id                                                                                              # 예: "Z0123456789ABCDEFGHIJ"
  name     = one([for d in aws_acm_certificate.viewer[0].domain_validation_options : d.resource_record_name if d.domain_name == each.key])    # 예: "_abc123.dev.playdevops.click."
  type     = one([for d in aws_acm_certificate.viewer[0].domain_validation_options : d.resource_record_type if d.domain_name == each.key])    # 예: "CNAME"
  records  = [one([for d in aws_acm_certificate.viewer[0].domain_validation_options : d.resource_record_value if d.domain_name == each.key])] # 예: ["_def456.acm-validations.aws."]
  ttl      = 60                                                                                                                               # 예: 60 (초)
}

resource "aws_acm_certificate_validation" "viewer" {
  count                   = var.enabled ? 1 : 0                               # 예: 비활성이면 0개
  provider                = aws.global                                        # 예: aws.global (인증서와 같은 리전)
  certificate_arn         = aws_acm_certificate.viewer[0].arn                 # 예: 요청한 인증서의 ARN
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn] # 예: 위에서 만든 레코드의 전체 이름 목록
}

# VPC origin 전용 ENI 는 CloudFront 가 만듭니다. 내부 NLB 는 TCP 로 Envoy 의 HTTPS 를 전달합니다.
resource "aws_cloudfront_vpc_origin" "gateway" {
  count = var.enabled ? 1 : 0 # 예: 비활성이면 0개

  vpc_origin_endpoint_config {
    name                   = "${var.gateway_contract.cluster_name}-gateway" # 예: "contract2whale-dev-eks-gateway"
    arn                    = data.aws_lb.origin[0].arn                      # 예: 조회한 NLB 의 ARN
    http_port              = 80                                             # 예: 80 (쓰지 않지만 값이 필요)
    https_port             = 443                                            # 예: 443 (실제로 쓰는 포트)
    origin_protocol_policy = "https-only"                                   # 예: "https-only" (평문 경로를 만들지 않음)

    origin_ssl_protocols {
      items    = ["TLSv1.2"] # 예: ["TLSv1.2"]
      quantity = 1           # 예: 1 (items 의 개수)
    }
  }

  depends_on = [terraform_data.contract, data.aws_internet_gateway.attached] # 예: 검사와 IGW 조회 뒤에 만듭니다
}

# 세션과 로그인 응답은 공유 캐시하지 않습니다 (TTL 0). Host · cookie · Authorization · query 는 원본으로 보냅니다.
resource "aws_cloudfront_cache_policy" "disabled" {
  count       = var.enabled ? 1 : 0                             # 예: 비활성이면 0개
  name        = "${var.gateway_contract.cluster_name}-no-cache" # 예: "contract2whale-dev-eks-no-cache"
  default_ttl = 0                                               # 예: 0 (기본 보관 시간 없음)
  max_ttl     = 0                                               # 예: 0 (최대 보관 시간 없음)
  min_ttl     = 0                                               # 예: 0 (최소 보관 시간 없음)

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false # 예: false
    enable_accept_encoding_gzip   = false # 예: false

    cookies_config {
      cookie_behavior = "none" # 예: "none" (캐시 키에 쿠키를 넣지 않음)
    }

    headers_config {
      header_behavior = "none" # 예: "none" (캐시 키에 헤더를 넣지 않음)
    }

    query_strings_config {
      query_string_behavior = "none" # 예: "none" (캐시 키에 query 를 넣지 않음)
    }
  }
}

resource "aws_cloudfront_origin_request_policy" "viewer" {
  count = var.enabled ? 1 : 0                               # 예: 비활성이면 0개
  name  = "${var.gateway_contract.cluster_name}-all-viewer" # 예: "contract2whale-dev-eks-all-viewer"

  cookies_config {
    cookie_behavior = "all" # 예: "all" (쿠키를 원본으로 전달)
  }

  headers_config {
    header_behavior = "allViewer" # 예: "allViewer" (요청자가 보낸 Host · Authorization 을 전달 → Envoy 의 hostname route 와 JWT 유지)
  }

  query_strings_config {
    query_string_behavior = "all" # 예: "all" (query 를 원본으로 전달)
  }
}

resource "aws_wafv2_web_acl" "edge" {
  count    = var.enabled ? 1 : 0                         # 예: 비활성이면 0개
  provider = aws.global                                  # 예: aws.global (CLOUDFRONT scope 는 us-east-1)
  name     = "${var.gateway_contract.cluster_name}-edge" # 예: "contract2whale-dev-eks-edge"
  scope    = "CLOUDFRONT"                                # 예: "CLOUDFRONT" (CloudFront 에 붙이는 범위)

  default_action {
    allow {} # 예: 규칙에 걸리지 않은 요청은 허용
  }

  dynamic "rule" {
    for_each = {
      AWSManagedRulesCommonRuleSet         = 10 # 예: 규칙 이름 → 평가 순서
      AWSManagedRulesKnownBadInputsRuleSet = 20
      AWSManagedRulesSQLiRuleSet           = 30
    }

    content {
      name     = rule.key   # 예: "AWSManagedRulesCommonRuleSet"
      priority = rule.value # 예: 10 (숫자가 작을수록 먼저 평가)

      override_action {
        none {} # 예: 룰 그룹의 동작을 그대로 씀
      }

      statement {
        managed_rule_group_statement {
          name        = rule.key # 예: 관리 룰 그룹 이름
          vendor_name = "AWS"    # 예: "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true     # 예: true (지표를 남김)
        metric_name                = rule.key # 예: 규칙 이름을 지표 이름으로 사용
        sampled_requests_enabled   = false    # 예: false (요청 표본을 저장하지 않음)
      }
    }
  }

  rule {
    name     = "request-rate" # 예: "request-rate"
    priority = 40             # 예: 40 (관리 규칙 뒤에 평가)

    action {
      block {} # 예: rate 규칙이 매칭한 요청을 차단; 정확한 N번째 요청·반영 시각 보장은 아님
    }

    statement {
      rate_based_statement {
        limit                 = var.rate_limit_per_5min # 예: 2000
        aggregate_key_type    = "IP"                    # 예: "IP" (요청 IP 로 셈)
        evaluation_window_sec = 300                     # 예: 300 (5분 창)
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true           # 예: true
      metric_name                = "request-rate" # 예: "request-rate"
      sampled_requests_enabled   = false          # 예: false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true                                        # 예: true
    metric_name                = "${var.gateway_contract.cluster_name}-edge" # 예: "contract2whale-dev-eks-edge"
    sampled_requests_enabled   = false                                       # 예: false
  }
}

# WAF 의 전체 요청 로그를 보존하되 Authorization · Cookie · query 는 가립니다. 로그 그룹 이름은 aws-waf-logs- 로 시작해야 합니다.
resource "aws_cloudwatch_log_group" "waf" {
  count             = var.enabled ? 1 : 0                                 # 예: 비활성이면 0개
  provider          = aws.global                                          # 예: aws.global (Web ACL 과 같은 리전)
  name              = "aws-waf-logs-${var.gateway_contract.cluster_name}" # 예: "aws-waf-logs-contract2whale-dev-eks"
  retention_in_days = 30                                                  # 예: 30 (보존 기간)
}

resource "aws_wafv2_web_acl_logging_configuration" "edge" {
  count                   = var.enabled ? 1 : 0                   # 예: 비활성이면 0개
  provider                = aws.global                            # 예: aws.global
  resource_arn            = aws_wafv2_web_acl.edge[0].arn         # 예: 위에서 만든 Web ACL 의 ARN
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn] # 예: 위에서 만든 로그 그룹의 ARN

  redacted_fields {
    single_header {
      name = "authorization" # 예: "authorization" (헤더 값을 가림)
    }
  }

  redacted_fields {
    single_header {
      name = "cookie" # 예: "cookie" (헤더 값을 가림)
    }
  }

  redacted_fields {
    query_string {} # 예: query 문자열 전체를 가림
  }
}

resource "aws_cloudfront_distribution" "app" {
  count               = var.enabled ? 1 : 0                    # 예: 비활성이면 0개
  enabled             = true                                   # 예: true (배포를 켬)
  is_ipv6_enabled     = true                                   # 예: true (IPv6 주소도 제공)
  http_version        = "http2and3"                            # 예: "http2and3"
  aliases             = var.hostnames                          # 예: ["dev.playdevops.click"]
  comment             = "WAF protected internal Envoy Gateway" # 예: 콘솔에서 보이는 설명
  price_class         = "PriceClass_100"                       # 예: "PriceClass_100" (사용할 edge 위치 범위)
  wait_for_deployment = true                                   # 예: true (배포가 끝날 때까지 기다림)
  web_acl_id          = aws_wafv2_web_acl.edge[0].arn          # 예: 위에서 만든 Web ACL 의 ARN

  origin {
    origin_id   = "gateway"                      # 예: "gateway" (아래 동작이 가리킬 이름)
    domain_name = data.aws_lb.origin[0].dns_name # 예: 내부 NLB 의 DNS 이름 (전달 Host 는 viewer 의 app 이름)

    vpc_origin_config {
      vpc_origin_id            = aws_cloudfront_vpc_origin.gateway[0].id # 예: 위에서 만든 VPC origin
      origin_read_timeout      = 60                                      # 예: 60 (초)
      origin_keepalive_timeout = 5                                       # 예: 5 (초)
    }
  }

  default_cache_behavior {
    target_origin_id         = "gateway"                                                    # 예: 위 origin 의 이름
    viewer_protocol_policy   = "redirect-to-https"                                          # 예: HTTP 요청을 HTTPS 로 보냄
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"] # 예: 앱이 쓰는 메서드 전부
    cached_methods           = ["GET", "HEAD"]                                              # 예: 저장을 고려할 메서드
    cache_policy_id          = aws_cloudfront_cache_policy.disabled[0].id                   # 예: TTL 0 정책
    origin_request_policy_id = aws_cloudfront_origin_request_policy.viewer[0].id            # 예: 전달 정책
    compress                 = true                                                         # 예: true (응답 압축)
  }

  restrictions {
    geo_restriction {
      restriction_type = "none" # 예: "none" (지역 제한 없음)
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.viewer[0].certificate_arn # 예: 검증이 끝난 인증서
    ssl_support_method       = "sni-only"                                               # 예: "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"                                           # 예: "TLSv1.2_2021"
  }

  depends_on = [aws_wafv2_web_acl_logging_configuration.edge] # 예: 로그 연결 뒤에 배포합니다
}

# 이 모드에서 앱 DNS 는 Terraform 만 소유합니다. ExternalDNS 가 같은 이름을 쓰게 하지 않습니다 (waf 모드는 ExternalDNS 신원이 없음).
resource "aws_route53_record" "app_ipv4" {
  for_each = var.enabled ? var.hostnames : toset([]) # 예: 이름마다 A 레코드 1개
  zone_id  = var.gateway_contract.public_zone_id     # 예: "Z0123456789ABCDEFGHIJ"
  name     = each.value                              # 예: "dev.playdevops.click"
  type     = "A"                                     # 예: "A" (IPv4 alias)

  alias {
    name                   = aws_cloudfront_distribution.app[0].domain_name    # 예: "d111111abcdef8.cloudfront.net"
    zone_id                = aws_cloudfront_distribution.app[0].hosted_zone_id # 예: CloudFront 의 고정 zone ID
    evaluate_target_health = false                                             # 예: false (alias 상태 검사를 쓰지 않음)
  }
}

resource "aws_route53_record" "app_ipv6" {
  for_each = var.enabled ? var.hostnames : toset([]) # 예: 이름마다 AAAA 레코드 1개
  zone_id  = var.gateway_contract.public_zone_id     # 예: "Z0123456789ABCDEFGHIJ"
  name     = each.value                              # 예: "dev.playdevops.click"
  type     = "AAAA"                                  # 예: "AAAA" (IPv6 alias)

  alias {
    name                   = aws_cloudfront_distribution.app[0].domain_name    # 예: "d111111abcdef8.cloudfront.net"
    zone_id                = aws_cloudfront_distribution.app[0].hosted_zone_id # 예: CloudFront 의 고정 zone ID
    evaluate_target_health = false                                             # 예: false
  }
}
