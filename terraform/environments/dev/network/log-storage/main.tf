# VPC Down/Up과 별개로 버킷·객체·설정을 보존하는 root입니다.
# 로그 객체와 이전 버전을 지우는 동작은 이 root에 없습니다.

# 버킷 이름과 전달 정책은 VPC ID를 사용하지 않습니다.
locals {
  common_tags = {
    ManagedBy   = "Terraform"
    Environment = var.environment
    Component   = "network-log-storage"
  }
  network_logs_bucket_name = "cp-${var.environment}-network-logs-${var.expected_account_id}-${var.region}" # 예: "cp-dev-network-logs-111111111111-ap-northeast-2"
  # 상용 AWS 서울 리전으로 한정된 구성이므로 arn:aws 파티션을 명시합니다.
  network_logs_bucket_arn = "arn:aws:s3:::${local.network_logs_bucket_name}"          # 예: "arn:aws:s3:::cp-dev-network-logs-111111111111-ap-northeast-2"
  log_delivery_source_arn = "arn:aws:logs:${var.region}:${var.expected_account_id}:*" # 예: "arn:aws:logs:ap-northeast-2:111111111111:*" (aws:SourceArn 비교용 패턴)

  # jsonencode 가 HCL 객체를 AWS 가 받는 JSON 문자열로 변환합니다.
  # source 조건은 flow-log 리소스 자체가 아니라 AWS 로그 전달 서비스의 ARN 입니다.
  network_logs_bucket_policy = {
    Version = "2012-10-17" # 예: "2012-10-17" (IAM 정책 문법 버전; 고정값)
    Statement = [
      {
        Sid       = "AWSLogDeliveryAclCheck"                    # 예: 정책에서 문장을 식별하는 이름
        Effect    = "Allow"                                     # 예: "Allow" (조회 허용)
        Principal = { Service = "delivery.logs.amazonaws.com" } # 예: AWS 로그 전달 서비스 주체
        Action    = "s3:GetBucketAcl"                           # 예: "s3:GetBucketAcl" (버킷 수준 작업)
        Resource  = local.network_logs_bucket_arn               # 예: "arn:aws:s3:::cp-dev-network-logs-..." (객체 경로 /* 를 붙이지 않음)
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.expected_account_id }   # 예: "111111111111" (타 계정 로그 유입 차단)
          ArnLike      = { "aws:SourceArn" = local.log_delivery_source_arn } # 예: "arn:aws:logs:ap-northeast-2:111111111111:*"
        }
      },
      {
        Sid       = "AWSLogDeliveryWrite"                       # 예: 실제 로그 객체 쓰기 문장
        Effect    = "Allow"                                     # 예: "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" } # 예: 위와 동일한 서비스 주체
        Action    = "s3:PutObject"                              # 예: "s3:PutObject" (객체 업로드만 허용)
        Resource = [
          "${local.network_logs_bucket_arn}/flow/AWSLogs/${var.expected_account_id}/*", # 예: ".../flow/AWSLogs/111111111111/*" (Flow Log 저장 경로)
          "${local.network_logs_bucket_arn}/dns/AWSLogs/${var.expected_account_id}/*"   # 예: ".../dns/AWSLogs/111111111111/*" (질의 로그 저장 경로)
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.expected_account_id     # 예: "111111111111"
            "s3:x-amz-acl"      = "bucket-owner-full-control" # 예: 로그 전달 요청의 ACL 헤더 검사
          }
          ArnLike = { "aws:SourceArn" = local.log_delivery_source_arn } # 예: "arn:aws:logs:ap-northeast-2:111111111111:*"
        }
      },
      {
        Sid       = "DenyInsecureTransportForNonServicePrincipals"                        # 예: 비암호화 접근 차단 문장
        Effect    = "Deny"                                                                # 예: "Deny" (명시적 거부는 Allow 보다 우선)
        Principal = "*"                                                                   # 예: "*" (모든 주체를 평가 대상으로)
        Action    = "s3:*"                                                                # 예: "s3:*" (모든 S3 작업)
        Resource  = [local.network_logs_bucket_arn, "${local.network_logs_bucket_arn}/*"] # 예: 버킷과 그 안의 모든 객체
        Condition = {
          Bool = {
            "aws:SecureTransport"       = "false" # 예: "false" (HTTPS 가 아닌 연결일 때 조건 성립)
            "aws:PrincipalIsAWSService" = "false" # 예: "false" (AWS 서비스 주체는 이 Deny 대상에서 제외)
          }
        }
      },
      {
        Sid       = "DenyNetworkLogDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = [local.network_logs_bucket_arn, "${local.network_logs_bucket_arn}/*"]
      }
    ]
  }
}

resource "aws_s3_bucket" "network_logs" {
  bucket        = local.network_logs_bucket_name # 예: "cp-dev-network-logs-111111111111-ap-northeast-2"
  force_destroy = false                          # 버킷이 비어 있어도 삭제하지 않습니다.

  tags = merge(local.common_tags, {
    Name    = local.network_logs_bucket_name   # 예: "cp-dev-network-logs-111111111111-ap-northeast-2"
    Purpose = "network-flow-and-resolver-logs" # 예: 용도 구분용 태그 (비용 배분과 검색에 사용)
  })

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = length(local.network_logs_bucket_name) <= 63 # 예: 47자 → 통과 (S3 버킷 이름 63자 제한)
      error_message = "The network logs bucket name must fit the S3 63-character limit."
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "network_logs" {
  bucket = aws_s3_bucket.network_logs.id # 예: "cp-dev-network-logs-111111111111-ap-northeast-2" (S3 는 이름이 곧 ID)

  rule {
    object_ownership = "BucketOwnerEnforced" # 예: "BucketOwnerEnforced" (ACL 기능 비활성화, 소유권 고정)
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "network_logs" {
  bucket = aws_s3_bucket.network_logs.id # 예: 버킷 이름

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # 예: "AES256" (SSE-S3; 별도 키 관리 불필요)
    }
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "network_logs" {
  bucket = aws_s3_bucket.network_logs.id # 예: 버킷 이름

  block_public_acls       = true # 예: true (공개 ACL 설정 요청 자체를 거부)
  block_public_policy     = true # 예: true (공개로 판정되는 버킷 정책 등록을 거부)
  ignore_public_acls      = true # 예: true (이미 붙어 있는 공개 ACL 을 무시)
  restrict_public_buckets = true # 예: true (공개 정책이 있어도 익명 · 교차 계정 접근을 제한)
  lifecycle {
    prevent_destroy = true
  }
}

# 같은 key가 덮어써져도 이전 버전을 남기며, 이전 버전 만료 규칙도 만들지 않습니다.
resource "aws_s3_bucket_versioning" "network_logs" {
  bucket = aws_s3_bucket.network_logs.id
  versioning_configuration {
    status = "Enabled"
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "network_logs" {
  bucket = aws_s3_bucket.network_logs.id # 예: 버킷 이름

  rule {
    id     = "expire-network-logs" # 예: "expire-network-logs" (규칙 식별자; 콘솔 표시명)
    status = "Disabled"            # 만료·미완료 업로드 정리를 실행하지 않습니다.

    filter {
      prefix = "" # 예: "" (버킷 전체가 로그 전용이므로 접두사 제한 없음)
    }

    expiration {
      days = 90 # 비활성 규칙의 형식만 유지합니다. 자동 만료를 켜지 않습니다.
    }

  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_policy" "network_logs" {
  bucket = aws_s3_bucket.network_logs.id                # 예: 버킷 이름
  policy = jsonencode(local.network_logs_bucket_policy) # 예: 위 locals 의 객체를 JSON 문자열로 변환한 값

  depends_on = [aws_s3_bucket_public_access_block.network_logs] # 예: 공개 차단 완료 후 정책 부착
  lifecycle {
    prevent_destroy = true
  }
}