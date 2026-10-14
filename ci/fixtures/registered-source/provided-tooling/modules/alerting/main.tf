# main.tf — modules/alerting (dev · prod 루트 모듈이 공유하는 모듈)
# 이메일 구독은 수신자가 확인 링크를 눌러야 전달됩니다 (Terraform 이 확인할 수 없음). Alertmanager 자체는 관측 파이프라인 가 설치하며 여기서는 신원과 게시 권한만 만듭니다 (E3).

locals {
  # 예: environment=dev 이면 이름 접두사는 contract2whale-dev 입니다.
  prefix                       = "contract2whale-${var.environment}"                                     # 예: "contract2whale-dev" (모든 이름의 앞부분)
  namespace                    = "monitoring"                                                            # 예: "monitoring" (경보를 묶는 Pod 의 네임스페이스; 관측 파이프라인 kube-prometheus-stack)
  alertmanager_service_account = "platform-alertmanager"                                                 # 예: 그 Pod 의 ServiceAccount 이름 (알림 루트 모듈과 설치 검사 overlay 의 serviceAccount.name)
  metric_namespace             = "contract2whale/Incidents/${var.environment}"                           # 예: "contract2whale/Incidents/dev" (지표를 담는 네임스페이스)
  sample_deletion_armed        = var.environment == "dev" && var.sample_delete_validation_run_id != null # 예: false (기본 상태)
}

resource "terraform_data" "contract" {
  input = {
    account_id   = var.expected_account_id   # 예: "111111111111" (값이 바뀌면 검사를 다시 실행합니다)
    environment  = var.environment           # 예: "dev"
    cluster_name = var.cluster_contract.name # 예: "contract2whale-dev-eks"
  }

  lifecycle {
    precondition {
      # 예: 다른 계정의 ARN 이나 다른 리전의 계약을 넣으면 거부합니다
      condition     = var.cluster_contract.region == var.region && var.cluster_contract.arn == "arn:aws:eks:${var.region}:${var.expected_account_id}:cluster/${var.cluster_contract.name}"
      error_message = "cluster_contract must match the expected account, Seoul region and cluster name."
    }
    precondition {
      condition     = var.cluster_contract.name == "contract2whale-${var.environment}-eks" # 예: Prod 이름을 Dev 입력에 넣으면 거부
      error_message = "cluster_contract.name must match contract2whale-<environment>-eks."
    }
    precondition {
      condition     = var.platform_log_group_name == "/platform/${var.cluster_contract.name}/application" # 예: 다른 클러스터의 로그 그룹을 넣으면 거부
      error_message = "platform_log_group_name must belong to this cluster's operations contract."
    }
    precondition {
      condition     = var.sample_delete_validation_run_id == null || var.environment == "dev" # 예: Prod 에서 감지를 켜면 거부
      error_message = "Sample deletion detection can be armed only in dev."
    }
  }
}

resource "aws_sns_topic" "alerts" {
  # 예: contract2whale-dev-alerts (Prod 는 별도 계정의 contract2whale-prod-alerts).
  name       = "${local.prefix}-alerts" # 예: "contract2whale-dev-alerts"
  fifo_topic = false                    # 예: false (이메일 구독을 지원하는 Standard 토픽)

  depends_on = [terraform_data.contract] # 예: 소유권 검사를 통과한 뒤에 만듭니다
}

# email endpoint 의 소유자가 받은 확인 링크를 직접 승인해야 알림이 전달됩니다.
resource "aws_sns_topic_subscription" "email" {
  # 예: 같은 환경 topic ARN 과 ops-alerts@example.com. 확인 링크는 수신자가 승인합니다.
  topic_arn              = aws_sns_topic.alerts.arn # 예: 위에서 만든 토픽 하나
  protocol               = "email"                  # 예: "email" (메일로 받습니다)
  endpoint               = var.receiver_email       # 예: "ops-alerts@example.com"
  endpoint_auto_confirms = false                    # 예: false (endpoint 의 자동 확인 처리를 가정하지 않습니다)
}

resource "aws_iam_role" "alertmanager" {
  # 예: contract2whale-dev-alertmanager. 노드 역할에 SNS 권한을 추가하지 않습니다.
  name = "${local.prefix}-alertmanager" # 예: "contract2whale-dev-alertmanager"
  assume_role_policy = jsonencode({
    Version = "2012-10-17" # 예: 정책 문서 형식의 버전 번호
    Statement = [{
      Effect    = "Allow"                                # 예: "Allow" (허용)
      Principal = { Service = "pods.eks.amazonaws.com" } # 예: Pod 별 신원 경로의 주체
      Action    = ["sts:AssumeRole", "sts:TagSession"]   # 예: 역할을 맡고 세션 태그를 전달합니다
      Condition = {
        StringEquals = {
          # 예: arn:aws:eks:ap-northeast-2:111111111111:cluster/contract2whale-dev-eks.
          "aws:RequestTag/eks-cluster-arn"            = var.cluster_contract.arn           # 예: 이 클러스터여야 합니다
          "aws:RequestTag/kubernetes-namespace"       = local.namespace                    # 예: "monitoring"
          "aws:RequestTag/kubernetes-service-account" = local.alertmanager_service_account # 예: "platform-alertmanager"
        }
      }
    }]
  })

  depends_on = [terraform_data.contract] # 예: 소유권 검사를 통과한 뒤에 만듭니다
}

resource "aws_iam_role_policy" "publish" {
  name = "publish-environment-alerts" # 예: 역할에 붙는 인라인 정책 이름
  role = aws_iam_role.alertmanager.id # 예: 위에서 만든 역할
  policy = jsonencode({
    Version = "2012-10-17" # 예: 정책 문서 형식의 버전 번호
    Statement = [{
      Effect = "Allow"       # 예: "Allow" (허용)
      Action = "sns:Publish" # 예: 게시 동작 하나만 허용합니다
      # 예: arn:aws:sns:ap-northeast-2:111111111111:contract2whale-dev-alerts 하나만 허용합니다.
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

resource "aws_eks_pod_identity_association" "alertmanager" {
  # 예: contract2whale-dev-eks 의 monitoring/platform-alertmanager 에만 역할을 연결합니다.
  cluster_name    = var.cluster_contract.name          # 예: "contract2whale-dev-eks"
  namespace       = local.namespace                    # 예: "monitoring"
  service_account = local.alertmanager_service_account # 예: "platform-alertmanager"
  role_arn        = aws_iam_role.alertmanager.arn      # 예: 위에서 만든 역할의 ARN

  depends_on = [aws_iam_role_policy.publish] # 예: 정책 부착 이후에 연결 (modules/operations 와 같은 순서)
}

# EC2 state-change 이벤트에는 태그 필터를 넣지 않습니다. 계정 · 리전 내 모든 EC2 가 대상입니다.
resource "aws_cloudwatch_event_rule" "ec2_state_change" {
  # 예: contract2whale-dev-ec2-state-change. EKS 태그가 아닌 계정 · 리전으로 범위를 고정합니다.
  name           = "${local.prefix}-ec2-state-change"                             # 예: "contract2whale-dev-ec2-state-change"
  description    = "EC2 instance state changes in this account and Seoul region." # 예: 규칙의 설명 문구
  event_bus_name = "default"                                                      # 예: "default" (계정 기본 이벤트 버스)
  event_pattern = jsonencode({
    source        = ["aws.ec2"]                                                                   # 예: 인스턴스가 내는 이벤트만
    "detail-type" = ["EC2 Instance State-change Notification"]                                    # 예: 상태 변화 알림만
    account       = [var.expected_account_id]                                                     # 예: ["111111111111"]
    region        = [var.region]                                                                  # 예: ["ap-northeast-2"]
    detail        = { state = ["stopping", "stopped", "shutting-down", "terminated", "running"] } # 예: 다섯 상태
  })

  depends_on = [terraform_data.contract] # 예: 소유권 검사를 통과한 뒤에 만듭니다
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn # 예: 정책을 붙일 토픽 하나
  policy = jsonencode({
    Version = "2012-10-17" # 예: 정책 문서 형식의 버전 번호
    Statement = [
      {
        Sid       = "EventBridgePublish"                 # 예: 첫 번째 문장의 레이블
        Effect    = "Allow"                              # 예: "Allow" (허용)
        Principal = { Service = "events.amazonaws.com" } # 예: 이벤트 규칙이 서비스로서 호출합니다
        Action    = "sns:Publish"                        # 예: 게시 동작 하나만 허용합니다
        Resource  = aws_sns_topic.alerts.arn             # 예: 이 토픽 하나만
      },
      {
        Sid       = "EnvironmentCloudWatchAlarmsPublish"     # 예: 두 번째 문장의 레이블
        Effect    = "Allow"                                  # 예: "Allow" (허용)
        Principal = { Service = "cloudwatch.amazonaws.com" } # 예: 경보가 서비스로서 호출합니다
        Action    = "sns:Publish"                            # 예: 게시 동작 하나만 허용합니다
        Resource  = aws_sns_topic.alerts.arn                 # 예: 이 토픽 하나만
        Condition = {
          # 예: 서울 Dev 계정의 contract2whale-dev-* CloudWatch alarm 만 게시할 수 있습니다.
          StringEquals = { "aws:SourceAccount" = var.expected_account_id }                                                           # 예: 이 계정의 경보만
          ArnLike      = { "aws:SourceArn" = "arn:aws:cloudwatch:${var.region}:${var.expected_account_id}:alarm:${local.prefix}-*" } # 예: 이름 접두사가 맞는 경보만
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "ec2_state_change" {
  # 예: 메일 본문의 detail.instance-id=i-0123456789abcdef0 로 실제 EC2 를 구별합니다.
  rule           = aws_cloudwatch_event_rule.ec2_state_change.name # 예: 위에서 만든 규칙
  event_bus_name = "default"                                       # 예: "default" (계정 기본 이벤트 버스)
  target_id      = "environment-alerts"                            # 예: 규칙 안에서 이 대상을 가리키는 이름
  arn            = aws_sns_topic.alerts.arn                        # 예: 게시할 토픽
  # input / input_path / input_transformer 를 생략해 detail.instance-id 를 포함한 원문을 전달합니다.

  depends_on = [aws_sns_topic_policy.alerts] # 예: 토픽 정책이 먼저 붙도록 순서를 고정합니다
}
