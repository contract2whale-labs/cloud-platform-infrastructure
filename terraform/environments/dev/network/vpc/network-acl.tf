# network-acl.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 기본값에 의존하지 않고 NACL 허용 규칙을 코드에 명시합니다. 두 목록은 뜻이 같지만 모듈 입력 스키마의 키 이름이 다릅니다.

locals {
  # 기본 NACL 인자는 AWS 기본 ACL 리소스의 rule_no/action 키를 사용합니다.
  # IPv4 전체 허용이며 세밀한 통신 제한은 별도 SG 와 후속 정책에서 설계합니다.
  default_acl_allow_ipv4 = [
    {
      rule_no    = 100         # 예: 100 (eks-network 의 비상 차단 10~90 보다 뒤에 평가됨)
      action     = "allow"     # 예: "allow" (기본 ACL 인자의 키 이름)
      from_port  = 0           # 예: 0 (protocol 이 "-1" 이면 포트는 평가에 쓰이지 않음)
      to_port    = 0           # 예: 0
      protocol   = "-1"        # 예: "-1" (모든 IP 프로토콜)
      cidr_block = "0.0.0.0/0" # 예: "0.0.0.0/0" (IPv4 전체)
    }
  ]

  # public 전용 NACL 인자는 별도 ACL rule 리소스의 rule_number/rule_action 키입니다.
  # 뜻은 같아도 두 모듈 입력 스키마의 속성 이름을 혼용하지 않습니다.
  public_acl_allow_ipv4 = [
    {
      rule_number = 100         # 예: 100 (위의 rule_no 와 같은 뜻, 다른 키 이름)
      rule_action = "allow"     # 예: "allow" (위의 action 과 같은 뜻, 다른 키 이름)
      from_port   = 0           # 예: 0
      to_port     = 0           # 예: 0
      protocol    = "-1"        # 예: "-1"
      cidr_block  = "0.0.0.0/0" # 예: "0.0.0.0/0"
    }
  ]
}
