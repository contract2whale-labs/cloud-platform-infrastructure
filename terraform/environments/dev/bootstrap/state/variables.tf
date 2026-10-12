# variables.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# 실제 대상 계정은 실행자가 입력합니다. 기본값으로 임의 계정에 적용되지 않게 합니다.

variable "expected_account_id" {
  description = "Resources may be managed only in this user-supplied 12-digit AWS account."
  type        = string # 예: string (앞자리 0 이 사라지지 않도록 number 가 아닌 string)
  nullable    = false  # 예: false (null 입력 차단)

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 예: "111111111111" 통과 / "1111-1111-1111" 거부
    error_message = "expected_account_id must contain exactly 12 digits."
  }
}

# bootstrap 버킷과 뒤 구성들의 backend 가 사용할 리전을 하나의 입력으로 관리합니다.
variable "region" {
  description = "AWS region for the bootstrap state bucket."
  type        = string           # 예: "ap-northeast-2" (리전 코드 문자열)
  default     = "ap-northeast-2" # 기본값: "ap-northeast-2" (서울 리전)
  nullable    = false            # 예: false (null 입력 차단)

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.region)) # 예: "ap-northeast-2" 통과 / "seoul" 거부
    error_message = "region must be an AWS region name such as ap-northeast-2."
  }
}

# 뒤 구성들의 backend.hcl 에 문자열 그대로 적을 전체 버킷 이름입니다.
variable "state_bucket_name" {
  description = "Bucket name unique in the shared namespace of this AWS partition; reuse literally in backend.hcl."
  type        = string # 예: "company-dev-tfstate-111111111111" (소문자 버킷 이름 문자열)
  nullable    = false  # 예: false (null 입력 차단)

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.state_bucket_name)) && # 예: "company-dev-tfstate-111111111111" 통과 / "Company_Dev" 거부
      !startswith(var.state_bucket_name, "xn--") &&                             # 예: 국제화 도메인 인코딩 접두사 차단
      !startswith(var.state_bucket_name, "sthree-") &&                          # 예: AWS 내부 예약 접두사 차단
      !startswith(var.state_bucket_name, "amzn-s3-demo-") &&                    # 예: AWS 문서 예제용 예약 접두사 차단
      !endswith(var.state_bucket_name, "--x-s3") &&                             # 예: 디렉터리 버킷 전용 접미사 차단
      !endswith(var.state_bucket_name, "--table-s3") &&                         # 예: 테이블 버킷 전용 접미사 차단
      !endswith(var.state_bucket_name, "-s3alias") &&                           # 예: Access Point alias 접미사 차단
      !endswith(var.state_bucket_name, "--ol-s3") &&                            # 예: Object Lambda alias 접미사 차단
      !endswith(var.state_bucket_name, "-an")                                   # 예: account regional namespace 전용 접미사 차단
    )
    error_message = "Use a 3-63 character lowercase S3 bucket name without reserved prefixes or suffixes."
  }
}
