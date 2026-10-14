# alarms.tf — modules/alerting (dev · prod 루트 모듈이 공유하는 모듈)
# 이 로그 그룹은 앱 네임스페이스을 뺀 컨테이너 기록만 받습니다 (플랫폼 컨테이너 로그 수집 Exclude_Path). 노드 수준 사건만 봅니다. 필터 패턴은 정확 일치 조건만 쓰며 메시지 문구는 읽지 않습니다.

resource "aws_cloudwatch_log_metric_filter" "pool_acquire_timeout" {
  # 예: /platform/contract2whale-dev-eks/application 의 kube-system/aws-node 표준 오류 기록.
  name           = "${local.prefix}-pool-acquire-timeout" # 예: "contract2whale-dev-pool-acquire-timeout"
  log_group_name = var.platform_log_group_name            # 예: "/platform/contract2whale-dev-eks/application"
  # 예: 세 항등 조건이 모두 맞는 기록만 고릅니다. 메시지 문구는 읽지 않습니다 (scripts/check-log-filters.sh 가 aws logs test-metric-filter 로 확인).
  pattern = "{ $.kubernetes.namespace_name = \"kube-system\" && $.kubernetes.container_name = \"aws-node\" && $.stream = \"stderr\" }"

  metric_transformation {
    # 예: contract2whale/Incidents/dev 안의 NodeNetworkAgentErrors 에 일치 기록마다 1 을 기록합니다.
    name          = "NodeNetworkAgentErrors" # 예: 지표 이름
    namespace     = local.metric_namespace   # 예: "contract2whale/Incidents/dev"
    value         = "1"                      # 예: "1" (일치하는 기록마다 더할 값)
    default_value = 0                        # 예: 0 (로그를 받은 분에 일치가 없을 때의 값)
  }

  depends_on = [terraform_data.contract] # 예: 소유권 검사를 통과한 뒤에 만듭니다
}

resource "aws_cloudwatch_metric_alarm" "pool_acquire_timeout" {
  # 예: contract2whale-dev-pool-acquire-timeout; 60초 안의 일치 기록 1건으로 ALARM.
  alarm_name          = "${local.prefix}-pool-acquire-timeout"                                              # 예: "contract2whale-dev-pool-acquire-timeout"
  alarm_description   = "The node network agent container wrote an error-stream line on a node."            # 예: 경보의 설명 문구
  namespace           = local.metric_namespace                                                              # 예: "contract2whale/Incidents/dev"
  metric_name         = aws_cloudwatch_log_metric_filter.pool_acquire_timeout.metric_transformation[0].name # 예: "NodeNetworkAgentErrors"
  statistic           = "Sum"                                                                               # 예: "Sum" (구간 안의 합계)
  period              = 60                                                                                  # 예: 60 (60초 구간)
  comparison_operator = "GreaterThanOrEqualToThreshold"                                                     # 예: 기준값 이상이면 경보
  threshold           = 1                                                                                   # 예: 1 (한 건이면 경보)
  evaluation_periods  = 1                                                                                   # 예: 1 (구간 하나만 봅니다)
  datapoints_to_alarm = 1                                                                                   # 예: 1 (그 구간에서 한 번이면 경보)
  treat_missing_data  = "notBreaching"                                                                      # 예: 값이 없는 구간은 정상으로 봅니다
  # 예: 환경별 SNS topic 으로 ALARM/OK 전이를 알립니다. OK 는 노드 복구 판정이 아닙니다.
  alarm_actions = [aws_sns_topic.alerts.arn] # 예: 경보로 바뀔 때 게시할 토픽
  ok_actions    = [aws_sns_topic.alerts.arn] # 예: 정상으로 돌아올 때 게시할 토픽

  depends_on = [aws_sns_topic_policy.alerts] # 예: 토픽 정책이 먼저 붙도록 순서를 고정합니다
}

# 이 optional 필터는 별도 점검기가 발행한 정확한 Dev JSON 만 받습니다. 이 코드에 점검기 배포는 포함되지 않습니다 (장애 대응 장애 실습).
resource "aws_cloudwatch_log_metric_filter" "armed_sample_deletion" {
  # 예: verify-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 하나를 지정한 Dev 점검 때만 생성합니다.
  count          = local.sample_deletion_armed ? 1 : 0     # 예: 0 (기본 상태에서는 만들지 않습니다)
  name           = "${local.prefix}-armed-sample-deletion" # 예: "contract2whale-dev-armed-sample-deletion"
  log_group_name = var.platform_log_group_name             # 예: "/platform/contract2whale-dev-eks/application"
  # 예: 네 항등 조건이 모두 맞는 기록만 고릅니다. 지정한 점검 실행 하나만 일치합니다.
  pattern = "{ $.kubernetes.namespace_name = \"kube-system\" && $.event = \"node_drain_probe\" && $.phase = \"not_ready\" && $.validation_run_id = \"${var.sample_delete_validation_run_id}\" }"

  metric_transformation {
    name          = "ArmedNodeDrainProbe"  # 예: 지표 이름
    namespace     = local.metric_namespace # 예: "contract2whale/Incidents/dev"
    value         = "1"                    # 예: "1" (일치하는 기록마다 더할 값)
    default_value = 0                      # 예: 0 (로그를 받은 분에 일치가 없을 때의 값)
  }

  depends_on = [terraform_data.contract] # 예: 소유권 검사를 통과한 뒤에 만듭니다
}

resource "aws_cloudwatch_metric_alarm" "armed_sample_deletion" {
  # 예: contract2whale-dev-armed-sample-deletion. Prod 에서는 이 리소스를 만들 수 없습니다.
  count               = local.sample_deletion_armed ? 1 : 0                                                     # 예: 0 (기본 상태에서는 만들지 않습니다)
  alarm_name          = "${local.prefix}-armed-sample-deletion"                                                 # 예: "contract2whale-dev-armed-sample-deletion"
  alarm_description   = "The explicitly armed Dev drain probe reported a node as not ready."                    # 예: 경보의 설명 문구
  namespace           = local.metric_namespace                                                                  # 예: "contract2whale/Incidents/dev"
  metric_name         = aws_cloudwatch_log_metric_filter.armed_sample_deletion[0].metric_transformation[0].name # 예: "ArmedNodeDrainProbe"
  statistic           = "Sum"                                                                                   # 예: "Sum" (구간 안의 합계)
  period              = 60                                                                                      # 예: 60 (60초 구간)
  comparison_operator = "GreaterThanOrEqualToThreshold"                                                         # 예: 기준값 이상이면 경보
  threshold           = 1                                                                                       # 예: 1 (한 건이면 경보)
  evaluation_periods  = 1                                                                                       # 예: 1 (구간 하나만 봅니다)
  datapoints_to_alarm = 1                                                                                       # 예: 1 (그 구간에서 한 번이면 경보)
  treat_missing_data  = "notBreaching"                                                                          # 예: 값이 없는 구간은 정상으로 봅니다
  alarm_actions       = [aws_sns_topic.alerts.arn]                                                              # 예: 경보로 바뀔 때 게시할 토픽
  ok_actions          = [aws_sns_topic.alerts.arn]                                                              # 예: 정상으로 돌아올 때 게시할 토픽

  depends_on = [aws_sns_topic_policy.alerts] # 예: 토픽 정책이 먼저 붙도록 순서를 고정합니다
}
