# variables.tf — modules/gateway (dev · prod 루트 모듈이 공유하는 모듈)
# 루트 모듈은 cluster_contract · public_zone · nlb_subnet_ids 를 앞 루트 모듈 State 에서 읽어 넘기고, exposure_mode · allowed_client_cidrs · existing_private_zone_id 만 terraform.tfvars 로 받습니다.

variable "cluster_contract" {
  description = "Cluster identity (name, arn, region, vpc_id) taken from the eks root output."
  type = object({
    name   = string # 예: "contract2whale-dev-eks"
    arn    = string # 예: "arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks"
    region = string # 예: "ap-northeast-2"
    vpc_id = string # 예: "vpc-0123456789abcdef0"
  })
  nullable = false

  validation {
    condition     = var.cluster_contract.region == "ap-northeast-2" # 예: 서울 리전일 때만 참
    error_message = "This implementation is verified for the Seoul region."
  }

  validation {
    condition     = can(regex("^arn:aws:eks:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_-]+$", var.cluster_contract.arn)) # 예: split(":")[4] 로 계정을 꺼낼 수 있는 형식
    error_message = "cluster_contract.arn must be an EKS cluster ARN."
  }
}

variable "expected_account_id" {
  description = "AWS account that owns the cluster, the zones and the security group; 12 digits."
  type        = string # 예: "111111111111" (앞자리 0 이 사라지지 않도록 문자열)
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: 숫자 12자리만 참
    error_message = "Use a 12-digit AWS account ID."
  }
}

# 인증서 구성(클러스터 보안 기반)과 같은 위임된 public zone 입니다. DNS01 은 공개 TXT 로 private 서비스의 인증서도 검증합니다.
variable "public_zone" {
  description = "Delegated public zone (id, name) shared with the cert-manager DNS01 solver."
  type = object({
    id   = string # 예: "Z0123456789ABCDEFGHIJ"
    name = string # 예: "dev.playdevops.click"
  })
  nullable = false
}

# internal 이 기본이며 입력 없이 인터넷 공개를 하지 않습니다.
variable "exposure_mode" {
  description = "internal (private NLB + private zone), public (internet-facing NLB + public zone) or waf (private NLB behind CloudFront)."
  type        = string     # 예: "internal" (세 갈래 중 하나를 고르는 문자열)
  default     = "internal" # 기본값: "internal" (값을 적지 않으면 비공개 경로)
  nullable    = false

  validation {
    condition     = contains(["internal", "public", "waf"], var.exposure_mode) # 예: 세 값 중 하나일 때만 참
    error_message = "Use internal, public, or waf."
  }
}

# internal · public의 IPv4 CIDR 규칙 입력입니다. 빈 목록은 이 모듈의 clients 규칙만 0개로 만듭니다. 별도 SG 출발지 규칙과 NLB에 연결된 모든 SG의 현재 규칙은 따로 대조합니다.
variable "allowed_client_cidrs" {
  description = "Approved client IPv4 CIDRs allowed to reach the NLB on TCP 443; empty means no CIDR rule."
  type        = set(string) # 예: ["203.0.113.7/32"] (승인된 접속망 목록)
  default     = []          # 기본값: [] (이 모듈의 clients CIDR 규칙 0개)
  nullable    = false

  validation {
    condition     = alltrue([for c in var.allowed_client_cidrs : can(cidrnetmask(c))]) # 예: 모든 원소가 IPv4 CIDR 형식일 때만 참
    error_message = "Use valid IPv4 CIDRs."
  }
}

# 기존 private zone 을 재사용할 때만 지정합니다. null 이면 internal · waf 모드에서 VPC 전용 zone 을 새로 만듭니다.
variable "existing_private_zone_id" {
  description = "Existing private hosted zone ID to reuse (already associated with the VPC); null creates a new one."
  type        = string # 예: "Z0PRIVATE00000000000"
  default     = null   # 기본값: null (재사용하지 않고 새로 만듭니다)
  nullable    = true   # 예: true (null 을 정상 값으로 받습니다)
}

variable "nlb_subnet_ids" {
  description = "Exactly three subnet IDs (one per Seoul AZ) where the controller places the NLB."
  type        = set(string) # 예: ["subnet-00000000000000001", "subnet-00000000000000002", "subnet-00000000000000003"]
  nullable    = false

  validation {
    condition     = length(var.nlb_subnet_ids) == 3 && alltrue([for s in var.nlb_subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", s))])
    error_message = "Supply three distinct subnet IDs from the workload VPC."
  }
}
