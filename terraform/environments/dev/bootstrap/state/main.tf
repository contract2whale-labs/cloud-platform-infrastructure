# main.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# State 버킷 1개와 보호 설정 5개를 선언합니다. state 는 Terraform 안에서만 쓰는 리소스 이름입니다.

resource "aws_s3_bucket" "state" {
  bucket        = local.state_bucket_name # 예: "company-dev-tfstate-111111111111" (변경 시 교체 발생)
  force_destroy = true                    # 예: true (버킷을 명시적으로 destroy할 때 잔여 객체·버전 정리; 일반 down에서는 retain)

  lifecycle {
    prevent_destroy = false # 예: false (실습 삭제 기본값 — 삭제·교체 계획을 허용)

    precondition {
      condition     = terraform.workspace == "default" # 예: "default" 통과 / "drill" 거부
      error_message = "Bootstrap must use the default workspace; use distinct state keys for other roots."
    }

    precondition {
      condition     = length(local.state_bucket_name) <= 63 # 예: 32 → 통과 (S3 버킷 이름 63자 제한)
      error_message = "The combined state bucket name must be at most 63 characters."
    }
  }
}

# 같은 State 객체를 덮어써도 이전 버전을 보관합니다.
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id # 예: "company-dev-tfstate-111111111111" (S3 는 이름이 곧 ID)

  versioning_configuration {
    status = "Enabled" # 예: "Enabled" (Suspended 는 새 업로드에 고유한 버전 ID 를 부여하지 않음)
  }
}

# 새 객체의 기본 저장 암호화를 S3 관리 키(SSE-S3)로 명시합니다.
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id # 예: 버킷 이름

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # 예: "AES256" (SSE-S3; 별도 KMS 키 권한 관리 불필요)
    }
  }
}

# 공개 ACL 과 공개 버킷 정책 관련 경로를 네 항목 모두 차단합니다.
resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id # 예: 버킷 이름

  block_public_acls       = true # 예: true (공개 ACL 설정 요청 자체를 거부)
  block_public_policy     = true # 예: true (공개로 판정되는 버킷 정책 등록을 거부)
  ignore_public_acls      = true # 예: true (이미 붙어 있는 공개 ACL 을 무시)
  restrict_public_buckets = true # 예: true (공개 정책이 있어도 익명·교차 계정 접근을 제한)
}

# ACL 을 비활성화하고 모든 객체를 버킷 소유자가 소유하게 합니다.
resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id # 예: 버킷 이름

  rule {
    object_ownership = "BucketOwnerEnforced" # 예: "BucketOwnerEnforced" (ACL 기능 비활성화)
  }
}

# Allow 문장 없이 비TLS 전송만 거부합니다. 권한 부여는 각 주체의 IAM 정책이 담당합니다.
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id # 예: 버킷 이름

  policy = jsonencode({
    Version = "2012-10-17" # 예: "2012-10-17" (IAM 정책 문법 버전; 고정값)
    Statement = [
      {
        Sid       = "DenyInsecureTransport" # 예: 정책 안에서 이 문장을 구분하는 식별자
        Effect    = "Deny"                  # 예: "Deny" (명시적 거부는 Allow 보다 우선)
        Principal = "*"                     # 예: "*" (모든 주체를 평가 대상으로)
        Action    = "s3:*"                  # 예: "s3:*" (모든 S3 작업)
        Resource = [
          aws_s3_bucket.state.arn,        # 예: "arn:aws:s3:::company-dev-tfstate-111111111111" (버킷 수준 작업)
          "${aws_s3_bucket.state.arn}/*", # 예: ".../*" (객체 수준 작업)
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false" # 예: "false" (HTTPS 가 아닌 연결일 때 조건 성립)
          }
        }
      },
    ]
  })
}
