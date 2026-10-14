# outputs.tf — modules/alerting (dev · prod 루트 모듈이 공유하는 모듈)

output "alerting_contract" {
  description = "Secret 없이 Alertmanager overlay 렌더와 실습 확인에 전달하는 환경별 알림 계약."
  value = {
    account_id   = var.expected_account_id   # 예: "111111111111"
    environment  = var.environment           # 예: "dev"
    region       = var.region                # 예: "ap-northeast-2"
    cluster_name = var.cluster_contract.name # 예: "contract2whale-dev-eks"
    topic_arn    = aws_sns_topic.alerts.arn  # 예: "arn:aws:sns:ap-northeast-2:111111111111:contract2whale-dev-alerts"
    # 예: 수신자와 monitoring/platform-alertmanager 는 서로 다른 책임의 식별자입니다.
    receiver_email               = var.receiver_email                              # 예: "ops-alerts@example.com"
    alertmanager_service_account = local.alertmanager_service_account              # 예: "platform-alertmanager"
    event_rule_name              = aws_cloudwatch_event_rule.ec2_state_change.name # 예: "contract2whale-dev-ec2-state-change"
    namespace                    = local.namespace                                 # 예: "monitoring"
    metric_namespace             = local.metric_namespace                          # 예: "contract2whale/Incidents/dev"
    alarm_names = merge(
      # 예: 기본은 pool_acquire_timeout 만, Dev 점검 감지를 켠 경우에만 두 번째 키를 추가합니다.
      { pool_acquire_timeout = aws_cloudwatch_metric_alarm.pool_acquire_timeout.alarm_name },
      { for alarm in aws_cloudwatch_metric_alarm.armed_sample_deletion : "armed_sample_deletion" => alarm.alarm_name }
    )
  }
}
