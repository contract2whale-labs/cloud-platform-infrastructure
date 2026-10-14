# outputs.tf — platform/dev-app-access 루트 모듈 (dev 전용)

output "session_contract" {
  description = "Instance, document, role and ports of the fixed developer session; the browser origin is https://<hostname>:<local_port>."
  value = {
    instance_id   = local.instance_id                   # 예: "i-0123456789abcdef0" (--target)
    document_name = aws_ssm_document.dev_app_https.name # 예: "CommerceDevelopmentAppHttps" (--document-name)
    role_arn      = aws_iam_role.dev_app_session.arn    # 예: "arn:aws:iam::111111111111:role/CommerceDevelopmentAppSession" (~/.aws/config role_arn)
    nlb_dns_name  = data.aws_lb.gateway.dns_name        # 예: "k8s-platfor-platform-…elb.ap-northeast-2.amazonaws.com" (kubectl get svc platform-envoy 와 대조)
    remote_port   = local.remote_port                   # 예: 443
    local_port    = var.local_port                      # 예: 8443
  }
}
