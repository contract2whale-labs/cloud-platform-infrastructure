# cidr-reservations.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# EKS /19 의 뒤쪽 절반 /20 을 연속 prefix 할당용으로 남깁니다. 기본 입력에서는 AZ 별 예약이 1개씩, 총 3개 생성됩니다.
# 이 예약은 이미 할당된 IP 를 회수하거나 CNI 설정을 변경하지 않습니다 (CNI 설정은 nodes).

variable "prefix_reservations_enabled" {
  description = "Reserve the second /20 of each EKS /19 subnet for prefix delegation."
  type        = bool  # 예: bool (true 또는 false 만 허용)
  default     = true  # 기본값: true (AZ 별 예약 1개씩, 총 3개 생성)
  nullable    = false # 예: false (null 입력은 default=true 로 대체)
}

resource "aws_ec2_subnet_cidr_reservation" "eks_prefix" {
  # 스위치가 true 이면 01편에서 정의한 AZ별 주소 계획 Map(3개 항목)을 순회하고, false 이면 빈 Map을 반환합니다.
  for_each = var.prefix_reservations_enabled ? local.eks_subnet_plan_by_az : {} # 예: true → 항목 3개 map / false → 빈 map {}

  # 01편에서 생성한 같은 AZ의 EKS 전용 서브넷 ID를 참조합니다.
  subnet_id = aws_subnet.eks_private[each.key].id # 예: "subnet-0abc123def4567890" (해당 AZ 의 EKS 서브넷 ID)

  # 부모 서브넷(/19)에 1비트를 더해 나눈 두 개의 /20 블록(0번 앞쪽, 1번 뒤쪽) 중 1번(뒤쪽 /20)을 계산합니다.
  cidr_block = cidrsubnet(each.value.cidr, 1, 1) # 예: "172.20.144.0/20" / "172.20.176.0/20" / "172.20.208.0/20"

  # 단일 IP 자동 할당을 막고 연속된 prefix(/28) 할당 전용으로 비워 두는 예약 유형을 지정합니다.
  reservation_type = "prefix" # 예: "prefix" (연속 prefix 할당 용도로 예약; explicit 과 구분)

  # AWS 콘솔이나 CLI 조회 시 예약 목적과 대상 AZ를 바로 식별할 수 있도록 설명을 남깁니다.
  description = "Preserve contiguous EKS prefix space in ${each.key}" # 예: "Preserve contiguous EKS prefix space in ap-northeast-2a"
}