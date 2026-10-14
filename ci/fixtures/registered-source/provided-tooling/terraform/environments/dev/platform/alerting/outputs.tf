# outputs.tf — platform/alerting 루트 모듈 (dev · prod 공통 코드)

output "alerting_contract" {
  description = "Environment alerting contract (topic, receiver, Alertmanager service account, event rule, metric namespace, alarm names); no secrets."
  value       = module.component.alerting_contract # 예: 열한 필드를 담은 map
}
