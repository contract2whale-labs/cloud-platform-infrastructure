# remote-state.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)
# 환경 root 두 개 연결: 앞 루트 모듈 세 곳(eks · account-baseline-dns · network/vpc)의 root 출력을 State 에서 직접 읽습니다. input.auto.tfvars.json 같은 입력 파일을 만들지 않습니다.
# 읽는 쪽에는 State 객체 전체의 s3:GetObject 권한이 필요합니다 (관련 구성 의 State 역할 key 목록과 대조).

data "terraform_remote_state" "eks" {
  backend = "s3" # 예: "s3" (앞 루트 모듈이 State 를 둔 방식)

  config = {
    bucket = var.state_bucket_name   # 예: "company-dev-tfstate-111111111111"
    key    = "eks/terraform.tfstate" # 예: eks 루트 모듈의 key (클러스터 입력과 네트워크 계약)
    region = var.region              # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition = alltrue([
        for name in ["name", "arn", "region", "vpc_id"] :
        contains(keys(try(self.outputs.cluster_contract, {})), name) # 예: 4개 모두 cluster_contract 에 존재
      ])
      error_message = "eks state must expose cluster_contract with name, arn, region and vpc_id (apply 생성 계획과 private API 검증 first)."
    }
  }
}

# 계정 옵션과 공개 자식 DNS 루트 모듈 의 공개 자식 Zone 루트 모듈입니다 (steps.tsv 에서 retain). cert-manager DNS01 과 같은 zone 입니다.
data "terraform_remote_state" "dns" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name                    # 예: 같은 버킷
    key    = "account-baseline-dns/terraform.tfstate" # 예: account-baseline-dns 루트 모듈의 key (관련 구성 결정)
    region = var.region                               # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = try(self.outputs.public_zone_id != null && self.outputs.public_zone_name != null, false) # 예: "Z…" · "dev.playdevops.click" (null 이면 거부)
      error_message = "account-baseline-dns state must expose a non-null public_zone_id and public_zone_name (apply 계정 옵션과 공개 자식 DNS 루트 모듈 with the zone enabled first)."
    }
  }
}

data "terraform_remote_state" "network" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name           # 예: 같은 버킷
    key    = "network/vpc/terraform.tfstate" # 예: network/vpc 루트 모듈의 key (출력 계약과 계약 테스트)
    region = var.region                      # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = length(try(self.outputs.public_subnet_ids, [])) == 3 && length(try(self.outputs.private_subnet_ids, [])) == 3 # 예: 두 목록 모두 AZ 3개
      error_message = "network/vpc state must expose three public_subnet_ids and three private_subnet_ids (apply 출력 계약과 계약 테스트 first)."
    }
  }
}
