# variables.tf — modules/edge (dev · prod 루트 모듈이 공유하는 모듈)

variable "enabled" {
  description = "Create CloudFront, WAF, viewer certificate and app DNS records; false keeps the root at zero AWS resources."
  type        = bool  # 예: bool
  default     = false # 기본값: false (기본은 만들지 않음)
  nullable    = false
}

variable "expected_account_id" {
  description = "AWS account that owns the NLB, the public zone and the CloudFront distribution; 12 digits."
  type        = string # 예: "111111111111"
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: 숫자 12자리만 통과
    error_message = "Use a 12-digit account ID."
  }
}

variable "gateway_contract" {
  description = "Six items of the gateway root output: cluster_name, vpc_id, exposure_mode, nlb_security_group_id, public_zone_id, dns_zone_name."
  type = object({
    cluster_name          = string # 예: "contract2whale-dev-eks"
    vpc_id                = string # 예: "vpc-0123456789abcdef0"
    exposure_mode         = string # 예: "waf" (edge 를 켤 수 있는 유일한 모드)
    nlb_security_group_id = string # 예: "sg-0123456789abcdef0"
    public_zone_id        = string # 예: "Z0123456789ABCDEFGHIJ"
    dns_zone_name         = string # 예: "dev.playdevops.click"
  })
  nullable = false
}

# NLB Service 가 Active 가 된 뒤 aws elbv2 describe-load-balancers 로 확인한 ARN 을 전달합니다.
variable "nlb_arn" {
  description = "ARN of the internal NLB that the controller created for the Gateway Service; empty while disabled."
  type        = string # 예: "arn:aws:elasticloadbalancing:ap-northeast-2:111111111111:loadbalancer/net/k8s-platfor-platform-0123456789/abcdef0123456789"
  default     = ""     # 기본값: "" (비활성 상태에서는 쓰지 않음)
  nullable    = false
}

# 와일드카드 대신 실제 공개 FQDN 목록입니다. Gateway Certificate 와 HTTPRoute 의 이름과 같아야 합니다.
variable "hostnames" {
  description = "Explicit public hostnames served by CloudFront (also the ACM viewer certificate SANs)."
  type        = set(string) # 예: ["dev.playdevops.click"]
  default     = []          # 기본값: [] (비활성 상태의 기본값)
  nullable    = false

  validation {
    condition     = alltrue([for h in var.hostnames : can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", h))]) # 예: 소문자 이름만 통과 (와일드카드 · 끝의 점 거부)
    error_message = "Use lowercase explicit DNS names without wildcard or trailing dot."
  }
}

# 승인한 hostname의 Gateway 원본 인증서·체인·실제 TLS 응답을 확인한 뒤 운영자가 입력하는 선언입니다. Terraform의 true 검사나 mock 테스트가 인증서 발급·TLS 성공을 실측하지 않습니다.
variable "origin_tls_ready" {
  description = "Operator confirmation that the Envoy origin certificate is issued by the production CA."
  type        = bool  # 예: bool
  default     = false # 기본값: false (원본 인증서를 확인한 뒤 true 로 바꿈)
  nullable    = false
}

variable "rate_limit_per_5min" {
  description = "Per-source-IP WAF rate threshold over a 300-second evaluation window; not an exact request allowance or immediate blocking guarantee."
  type        = number # 예: 2000
  default     = 2000   # 기본값: 2000 (300초 평가 창의 IP별 rate 기준; 정확한 요청 허용량·즉시 차단 보장이 아님)
  nullable    = false

  validation {
    condition     = var.rate_limit_per_5min >= 10 && var.rate_limit_per_5min == floor(var.rate_limit_per_5min) # 예: 10 이상의 정수
    error_message = "Use an integer rate limit of at least 10."
  }
}
