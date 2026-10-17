# vpc-endpoints-interface.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 서비스 1개당 Interface Endpoint 1개, Endpoint 1개당 EKS 서브넷 2곳(AZ a · b)에 ENI 1개씩 생성됩니다.
# private DNS 가 AWS 서비스 도메인을 이 ENI 의 사설 주소로 해석합니다.

# 서비스 코드는 com.amazonaws.<Region>. 뒤에 붙는 접미사입니다.
# s3 는 Gateway 방식으로, guardduty-data 는 별도 스위치로 관리하므로 이 목록에서 제외합니다.
variable "interface_endpoint_services" {
  description = "Regional AWS interface endpoint service suffixes; each selected service uses the two selected EKS subnet AZs."
  type        = set(string)            # 예: set(string) (중복 없는 집합; for_each 키로 그대로 사용)
  default     = ["ecr.api", "ecr.dkr"] # 기본값: 2개 서비스 접미사 (Endpoint 2개 → ENI 4개)
  nullable    = false                  # 예: false (null 입력은 기본 2개 목록으로 대체)

  validation {
    condition = alltrue([
      for service in var.interface_endpoint_services :
      try(
        can(regex("^[a-z][a-z0-9-]*(\\.[a-z0-9-]+)*$", service)) && # 예: "ecr.api" 통과 / "ECR_API" 거부 (소문자 · 숫자 · 하이픈 · 점만 허용)
        !startswith(service, "com.amazonaws.") &&
        !contains(["s3", "guardduty-data"], service), # 예: "s3" 입력 시 false (별도 관리 대상 혼입 차단)
        false                                         # 예: false (평가 중 오류가 나면 안전하게 실패 처리)
      )
    ])
    error_message = "Use regional interface service suffixes such as ecr.api; s3 and guardduty-data are managed separately."
  }
}

# 이 엔드포인트는 GuardDuty 데이터 전달 경로만 만듭니다. detector 나 runtime agent 를 활성화하는 스위치가 아닙니다.
variable "enable_guardduty_endpoint" {
  description = "Add the guardduty-data interface endpoint; configure GuardDuty and its agent separately."
  type        = bool  # 예: bool (true/false 두 값만 허용)
  default     = false # 기본값: false (생성 안 함; GuardDuty ENI 2개 추가 생략)
  nullable    = false # 예: false (null 입력은 default=false 로 대체)
}

locals {
  # 기본 서비스 목록과 GuardDuty 선택 항목의 합집합입니다.
  effective_interface_endpoint_services = setunion(
    var.interface_endpoint_services,                                      # 예: ["ecr.api", "ecr.dkr"] (2개)
    var.enable_guardduty_endpoint ? toset(["guardduty-data"]) : toset([]) # 예: false 이면 빈 집합, true 이면 ["guardduty-data"]
  )                                                                       # 예: 기본 실행 결과는 2개 집합, GuardDuty 활성화 시 3개 집합

  # GuardDuty 엔드포인트에만 붙일 접근 정책입니다.
  # Allow * 는 엔드포인트 통과를 허용하는 선언이며 서비스 API 의 IAM 권한을 부여하지 않습니다.
  guardduty_endpoint_policy = jsonencode({
    Version = "2012-10-17" # 예: "2012-10-17" (IAM 정책 문법 버전; 고정값)
    Statement = [
      {
        Effect    = "Allow" # 예: "Allow" (엔드포인트 통과 자체는 허용)
        Principal = "*"     # 예: "*" (호출 주체를 여기서 제한하지 않음)
        Action    = "*"     # 예: "*" (동작 제한은 호출자 IAM Role 이 담당)
        Resource  = "*"     # 예: "*" (리소스 제한은 대상 서비스 정책이 담당)
      },
      {
        Effect    = "Deny" # 예: "Deny" (명시적 Deny 는 Allow 보다 항상 우선)
        Principal = "*"    # 예: "*" (모든 주체를 평가 대상으로)
        Action    = "*"    # 예: "*" (모든 동작에 조건을 적용)
        Resource  = "*"    # 예: "*" (모든 리소스에 조건을 적용)
        Condition = {
          StringNotEquals = { "aws:PrincipalAccount" = var.expected_account_id } # 예: {"aws:PrincipalAccount" = "111111111111"} (이 계정이 아니면 차단)
        }
      }
    ]
  })
}

# Interface Endpoint ENI 가 공유하는 공통 Security Group 입니다.
# 인라인 ingress/egress 와 별도 rule 리소스를 혼용하지 않습니다. aws_security_group 은 AWS 기본 allow-all egress 를 제거합니다.
resource "aws_security_group" "interface_endpoints" {
  count = length(local.effective_interface_endpoint_services) > 0 ? 1 : 0 # 예: 2 > 0 이므로 1 (SG 1개 생성; 목록이 비면 0개)

  name        = "${local.vpc_name}-interface-vpce"               # 예: "cp-dev-interface-vpce" (계정 · VPC 내 식별용 SG 이름)
  description = "HTTPS from this VPC to interface endpoint ENIs" # 예: 콘솔에 표시되는 설명 (생성 후 변경 시 교체 발생)
  vpc_id      = module.vpc.vpc_id                                # 예: "vpc-0123456789abcdef0" (SG 가 소속될 VPC ID)

  tags = merge(local.common_tags, {
    Name = "${local.vpc_name}-interface-vpce" # 예: "cp-dev-interface-vpce" (콘솔 목록 식별용 Name 태그)
  })
}

# 네트워크 도달성만 허용합니다. 이 규칙이 ECR · STS · SSM API 의 IAM 권한을 부여하지 않습니다.
resource "aws_vpc_security_group_ingress_rule" "interface_https" {
  count = length(local.effective_interface_endpoint_services) > 0 ? 1 : 0 # 예: 1 (SG 와 동일 조건; 인덱스 [0] 참조 오류 방지)

  security_group_id = aws_security_group.interface_endpoints[0].id # 예: "sg-0123456789abcdef0" (위에서 만든 공통 SG 의 ID)
  description       = "VPC clients to AWS service endpoint HTTPS"  # 예: 규칙 목록에서 용도를 구분하기 위한 설명
  cidr_ipv4         = var.vpc_cidr                                 # 예: "172.20.0.0/16" (이 VPC 내부 출발지만 허용)
  ip_protocol       = "tcp"                                        # 예: "tcp" (프로토콜 번호 6)
  from_port         = 443                                          # 예: 443 (HTTPS 시작 포트)
  to_port           = 443                                          # 예: 443 (단일 포트이므로 from 과 동일)
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.effective_interface_endpoint_services # 예: 2개 서비스 집합 (원소 값이 곧 리소스 주소 키)

  vpc_id              = module.vpc.vpc_id                                                               # 예: "vpc-0123456789abcdef0" (엔드포인트가 소속될 VPC)
  service_name        = "com.amazonaws.${var.region}.${each.key}"                                       # 예: "com.amazonaws.ap-northeast-2.ecr.api" (리전 + 서비스 접미사)
  vpc_endpoint_type   = "Interface"                                                                     # 예: "Interface" (서브넷에 ENI 생성 방식; Gateway 와 구분)
  ip_address_type     = "ipv4"                                                                          # 예: "ipv4" (ENI 에 IPv4 주소만 부여)
  private_dns_enabled = true                                                                            # 예: true (서비스 도메인을 ENI 사설 IP 로 해석)
  subnet_ids          = [for az in slice(var.availability_zones, 0, 2) : aws_subnet.eks_private[az].id] # 예: ["subnet-0aaa...", "subnet-0bbb..."] (AZ a/b EKS 서브넷 2개)
  security_group_ids  = [aws_security_group.interface_endpoints[0].id]                                  # 예: ["sg-0123456789abcdef0"] (공통 SG 1개를 모든 Endpoint 가 공유)

  # 일반 서비스는 AWS 기본 엔드포인트 정책을 사용하고, GuardDuty 만 계정 제한 정책을 붙입니다.
  policy = each.key == "guardduty-data" ? local.guardduty_endpoint_policy : null # 예: 일반 서비스는 null (기본 Allow *), guardduty-data 만 JSON 문자열

  tags = merge(local.common_tags, {
    Name = "${local.vpc_name}-${each.key}-vpce" # 예: "cp-dev-ecr.api-vpce" (서비스별 콘솔 식별용 이름)
  })

  # ENI 가 예약 대상 구역의 IP 를 먼저 점유하지 않도록 subnet → reservation → ENI 순서를 고정합니다.
  # 예약을 비활성화하면 대상이 빈 컬렉션이므로 이 의존성이 생성을 차단하지 않습니다.
  depends_on = [aws_ec2_subnet_cidr_reservation.eks_prefix] # 예: 예약 3개 완료 후 ENI 4개 생성 시작
}