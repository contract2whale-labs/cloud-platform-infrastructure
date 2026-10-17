# public-nacl-rules.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 비상 Deny 규칙은 사용자가 명시한 입력이 있을 때만 생성됩니다. 기본값 {} 에서는 리소스가 0개입니다.
# NACL 은 stateless 이므로 들어오는 방향과 나가는 방향을 따로 설정합니다. 대상은 Public 서브넷 전용 NACL 입니다.

# map 의 키는 운영자가 차단 사유를 식별하기 위한 이름입니다.
# 0.0.0.0/0 을 입력하면 Public NACL 의 필터링 대상 IPv4 통신이 차단되므로 범위를 신중히 정합니다.
variable "emergency_denied_ipv4" {
  description = "Explicit emergency public NACL denies, with canonical IPv4 CIDRs and unique integer rule numbers 10-90."
  type = map(object({
    cidr        = string # 예: "203.0.113.10/32" (단일 호스트) 또는 "198.51.100.0/24" (대역 전체)
    rule_number = number # 예: 10 (10~90 구간의 정수, 항목마다 서로 달라야 함)
  }))
  default  = {}    # 기본값: {} (평상시 상태, 생성되는 규칙 0개)
  nullable = false # 예: false (null 입력은 기본값 {} 로 대체)

  validation {
    condition = alltrue([
      for rule in values(var.emergency_denied_ipv4) : try(
        cidrnetmask(rule.cidr) != "" &&                                                 # 예: "203.0.113.10/32" → "255.255.255.255" (IPv6 입력은 오류로 걸러짐)
        rule.cidr == "${cidrhost(rule.cidr, 0)}/${tonumber(split("/", rule.cidr)[1])}", # 예: "198.51.100.0/24" 통과 / "198.51.100.10/24" 거부
        false                                                                           # 예: false (평가 중 오류 발생 시 검증 실패로 처리)
      )
    ])
    error_message = "Every emergency deny must use a canonical IPv4 network CIDR, such as 203.0.113.10/32."
  }

  validation {
    condition = try(
      alltrue([
        for rule in values(var.emergency_denied_ipv4) :
        rule.rule_number >= 10 &&                   # 예: 10 이상 (1~9 는 여유 구간으로 남김)
        rule.rule_number <= 90 &&                   # 예: 90 이하 (기존 Allow 100 보다 먼저 평가되도록)
        floor(rule.rule_number) == rule.rule_number # 예: 10 통과 / 10.5 거부 (AWS 규칙 번호는 정수 필드)
      ]) &&
      length(distinct([
        for rule in values(var.emergency_denied_ipv4) : rule.rule_number # 예: [10, 20] → distinct 후에도 2개면 중복 없음
      ])) == length(var.emergency_denied_ipv4),
      false # 예: false (평가 중 오류 발생 시 검증 실패로 처리)
    )
    error_message = "Emergency deny rule numbers must be unique integers from 10 through 90, before allow rule 100."
  }
}

resource "aws_network_acl_rule" "emergency_ingress" {
  for_each = var.emergency_denied_ipv4 # 예: {} 이면 0회, 항목 2개면 2회 반복

  network_acl_id = module.vpc.public_network_acl_id # 예: "acl-0123456789abcdef0" (Public 서브넷에 연결된 NACL ID)
  rule_number    = each.value.rule_number           # 예: 10 (이 방향 안에서 유일한 정수)
  egress         = false                            # 예: false (들어오는 방향; cidr_block 이 출발지로 해석됨)
  protocol       = "-1"                             # 예: "-1" (모든 IP 프로토콜; TCP · UDP · ICMP 전부 포함)
  rule_action    = "deny"                           # 예: "deny" (일치하면 즉시 차단하고 평가 종료)
  cidr_block     = each.value.cidr                  # 예: "203.0.113.10/32" (이 주소에서 오는 패킷을 차단)
  from_port      = 0                                # 예: 0 (protocol 이 "-1" 이면 포트 범위는 의미가 없어 0 으로 둠)
  to_port        = 0                                # 예: 0 (위와 동일)
}

# 같은 번호를 반대 방향에서 다시 사용하는 것은 허용됩니다. 번호는 각 방향 안에서만 유일하면 됩니다.
# 10~90 번은 기존 Allow 100 보다 먼저 평가됩니다. 이 방향에서 입력 CIDR 은 목적지입니다.
resource "aws_network_acl_rule" "emergency_egress" {
  for_each = var.emergency_denied_ipv4 # 예: ingress 와 동일한 map 을 순회

  network_acl_id = module.vpc.public_network_acl_id # 예: "acl-0123456789abcdef0" (ingress 와 같은 NACL)
  rule_number    = each.value.rule_number           # 예: 10 (ingress 의 10 번과 충돌하지 않음)
  egress         = true                             # 예: true (나가는 방향; cidr_block 이 목적지로 해석됨)
  protocol       = "-1"                             # 예: "-1" (모든 IP 프로토콜)
  rule_action    = "deny"                           # 예: "deny" (일치하면 즉시 차단)
  cidr_block     = each.value.cidr                  # 예: "203.0.113.10/32" (이 주소로 나가는 패킷을 차단)
  from_port      = 0                                # 예: 0
  to_port        = 0                                # 예: 0
}