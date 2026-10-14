# remote-state.tf — identity 루트 모듈 (dev · prod 공통 코드)
# 데이터 루트 모듈과 PostgreSQL 버전 고정: 앞 루트 모듈 세 곳(data · eks · platform/operations)의 root 출력을 State 에서 읽고, 배포 플랫폼이 만든 migration Role 은 이름으로 IAM 을 조회합니다 (P1 · P3).
# 배포 전달 State 는 여기서 읽지 않습니다 — migration Role 은 루트 모듈과 적용 의 적용에서 이미 만들어졌으므로 이름으로만 조회합니다.

# 데이터 루트 모듈과 PostgreSQL 버전 고정 의 데이터 루트 모듈입니다. 시크릿 ARN · 내보내기 위치 · 키 · ServiceAccount 이름이 모두 여기서 옵니다.
data "terraform_remote_state" "data" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name    # 예: "company-dev-tfstate-111111111111"
    key    = "data/terraform.tfstate" # 예: data 루트 모듈의 key (데이터 루트 모듈과 PostgreSQL 버전 고정)
    region = var.region               # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition = alltrue([
        for name in ["environment", "account_id", "region", "cluster_name", "namespace", "service_accounts", "credentials", "export", "kms_key_arn"] :
        contains(keys(try(self.outputs.data_contract, {})), name) # 예: 9개 모두 data_contract 에 존재
      ])
      error_message = "data state must expose data_contract with the namespace, service accounts, credentials, export and KMS key (apply dev/data first)."
    }
  }
}

# 클러스터 접속 의 EKS 루트 모듈입니다. Pod Identity 신뢰 정책의 세션 태그에 쓸 클러스터 ARN 하나를 읽습니다.
data "terraform_remote_state" "eks" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name   # 예: 같은 버킷
    key    = "eks/terraform.tfstate" # 예: eks 루트 모듈의 key (클러스터 입력과 네트워크 계약)
    region = var.region              # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = can(regex("^arn:aws:eks:", try(self.outputs.cluster_contract.arn, ""))) && try(self.outputs.cluster_contract.name, "") != "" # 예: 클러스터 ARN · 이름
      error_message = "eks state must expose cluster_contract with name and arn (apply 생성 계획과 private API 검증 first)."
    }
  }
}

# 운영 도구 의 운영 기반 루트 모듈입니다. 클러스터 전체 External Secrets controller 의 Role ARN 을 읽어 앱 비밀 읽기 Role 이 신뢰할 주체로 넣습니다 (assume-role chaining).
data "terraform_remote_state" "operations" {
  backend = "s3" # 예: "s3"

  config = {
    bucket = var.state_bucket_name                   # 예: 같은 버킷
    key    = "platform/operations/terraform.tfstate" # 예: operations 루트 모듈의 key (운영 기반 루트 모듈과 계약)
    region = var.region                              # 예: "ap-northeast-2"
  }

  lifecycle {
    postcondition {
      condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$", try(self.outputs.external_secrets_role_arn, ""))) # 예: IAM Role ARN 형식
      error_message = "operations state must expose external_secrets_role_arn (apply 운영 도구 with external_secrets enabled first)."
    }
  }
}

# 배포 플랫폼 delivery 모듈이 만든 migration Role 입니다. ARN 을 State 에서 받지 않고 이름 규약(<cluster>-delivery-migration)으로 조회해 실제 존재까지 확인합니다.
data "aws_iam_role" "migration" {
  name = "${data.terraform_remote_state.eks.outputs.cluster_contract.name}-delivery-migration" # 예: "contract2whale-dev-eks-delivery-migration"

  lifecycle {
    postcondition {
      condition     = self.path == "/platform/" && strcontains(self.assume_role_policy, "pods.eks.amazonaws.com") # 예: 배포 플랫폼이 만든 Pod Identity 전용 Role 인지 (조회 결과의 정책 문서는 URL 인코딩되지만 서비스 주체 문자열은 그대로 남습니다)
      error_message = "The delivery migration role must be the 배포 플랫폼 role under /platform/ that trusts pods.eks.amazonaws.com (apply dev/delivery first — 루트 모듈과 적용)."
    }
  }
}
