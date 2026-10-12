# variables.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)

# 실제 대상 계정 ID 를 받아 잘못된 계정에서 실행하지 않게 합니다.
variable "expected_account_id" {
  description = "AWS account allowed by this VPC provider configuration."
  type        = string # 예: string (앞자리 0 이 사라지지 않도록)
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과
    error_message = "expected_account_id must contain exactly 12 digits."
  }
}

# 이 구성은 서울의 AZ 세 개를 명시적으로 사용합니다.
# 다른 리전으로 옮기려면 리전과 AZ 입력 계약을 함께 변경해야 합니다.
variable "region" {
  description = "AWS region for this chapter; only ap-northeast-2 is supported."
  type        = string # 예: "ap-northeast-2" 리전 코드 문자열
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2"
  nullable    = false

  validation {
    condition     = var.region == "ap-northeast-2" # 예: 단일 값 비교 (AZ 검증과 짝을 이룸)
    error_message = "This VPC chapter requires region ap-northeast-2."
  }
}

# workspace 에서 환경명을 추론하지 않습니다. 같은 값이 VPC 이름과 태그로 전달됩니다.
variable "environment" {
  description = "Explicit environment name, 3-20 lowercase letters, digits or hyphens."
  type        = string # 예: "dev" 환경 이름 문자열
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.environment)) # 예: "dev" 통과 / "Dev" 거부 / "d" 거부
    error_message = "environment must be 3-20 lowercase letters, digits or hyphens, start with a letter and end with a letter or digit."
  }
}

# /16 기반 서브넷 계산식을 입력한 VPC CIDR 에 적용합니다.
# 실제 CIDR 은 연결할 다른 네트워크와 겹치지 않게 정합니다.
variable "vpc_cidr" {
  description = "Canonical RFC1918 IPv4 /16 network used by the chapter's subnet formulas."
  type        = string # 예: "172.20.0.0/16" CIDR 문자열
  nullable    = false

  validation {
    # cidrhost(..., 0) 은 네트워크 시작 주소를 계산합니다.
    # 시작 주소가 아닌 입력, IPv6, 다른 prefix, 공인 범위는 허용하지 않습니다.
    # 잘못된 CIDR 의 함수 오류는 try 가 false 로 바꿔 입력 오류로 표시합니다.
    condition = try(
      cidrnetmask(var.vpc_cidr) == "255.255.0.0" &&        # 예: "172.20.0.0/16" 통과 / "/20" 거부
      var.vpc_cidr == "${cidrhost(var.vpc_cidr, 0)}/16" && # 예: "172.20.1.0/16" 거부 (호스트 비트)
      (
        startswith(cidrhost(var.vpc_cidr, 0), "10.") ||                             # 예: "10.80.0.0/16" 통과
        can(regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.", cidrhost(var.vpc_cidr, 0))) || # 예: "172.20.0.0/16" 통과 / "172.32..." 거부
        startswith(cidrhost(var.vpc_cidr, 0), "192.168.")                           # 예: "192.168.0.0/16" 통과
      ),
      false # 예: false (IPv6 등 함수 오류를 검증 실패로 처리)
    )
    error_message = "vpc_cidr must be a canonical RFC1918 IPv4 /16 network, such as 172.20.0.0/16; host bits, public ranges and other prefixes are rejected."
  }
}

# 3개 AZ 의 목록 순서가 서브넷 번호와 CIDR 을 연결합니다.
# 같은 집합이라도 순서를 바꾸면 AZ/CIDR 매핑이 바뀌므로 운영 중 재정렬하지 않습니다.
variable "availability_zones" {
  description = "Exactly ap-northeast-2a, ap-northeast-2b and ap-northeast-2c; list order determines subnet allocation."
  type        = list(string)                                              # 예: list(string) (순서가 의미를 가지므로 set 이 아님)
  default     = ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"] # 기본값: 서울 AZ 3개
  nullable    = false

  validation {
    condition = (
      length(var.availability_zones) == 3 &&           # 예: 정확히 3개
      length(distinct(var.availability_zones)) == 3 && # 예: 중복 제거 후에도 3개 (중복 입력 차단)
      alltrue([
        for az in var.availability_zones :
        contains(["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c"], az) # 예: 서울 AZ 만 허용
      ])
    )
    error_message = "availability_zones must contain ap-northeast-2a, ap-northeast-2b and ap-northeast-2c exactly once each."
  }
}
