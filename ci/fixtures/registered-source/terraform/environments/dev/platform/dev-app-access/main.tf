# main.tf — platform/dev-app-access 루트 모듈 (dev 전용)
# 승인된 SSO 역할 → 전용 Role → 고정 문서 → 한 인스턴스 → NLB 443 만 허용합니다. 범용 문서(AWS-StartPortForwardingSessionToRemoteHost) 와 shell 세션은 이 Role 로 열 수 없습니다.

# LBC 는 Gateway Service 의 NLB 에 태그 두 개를 붙입니다. 이름이 아니라 태그로 찾으므로 NLB 가 다시 만들어져도 입력을 고칠 필요가 없습니다.
data "aws_lb" "gateway" {
  tags = {
    "elbv2.k8s.aws/cluster" = local.cluster_name                          # 예: "contract2whale-dev-eks"
    "service.k8s.aws/stack" = "${local.gateway_namespace}/platform-envoy" # 예: "platform-gateway/platform-envoy" (EnvoyProxy envoyService.name)
  }
}

data "aws_instance" "relay" {
  instance_id = local.instance_id # 예: "i-0123456789abcdef0"
}

resource "terraform_data" "contract" {
  lifecycle {
    precondition {
      condition     = terraform.workspace == "default" && local.exposure_mode == "internal" # 예: Dev 는 internal 노출일 때만 이 경로를 만듦
      error_message = "Approved developer access applies to the internal exposure mode in the default workspace."
    }

    precondition {
      condition     = data.aws_lb.gateway.internal && data.aws_lb.gateway.load_balancer_type == "network" # 예: 조회한 NLB 가 internal · network
      error_message = "The Gateway load balancer must be an internal NLB (kubectl get svc platform-envoy shows its DNS name)."
    }

    precondition {
      condition     = contains(data.aws_lb.gateway.security_groups, local.nlb_sg_id) # 예: 조회한 NLB 에 Gateway 계약의 SG 가 붙어 있음
      error_message = "The NLB must carry the gateway_contract security group."
    }

    precondition {
      condition     = contains(data.aws_instance.relay.vpc_security_group_ids, local.relay_sg_id) # 예: 인스턴스에 private-api 계약의 SG 가 붙어 있음
      error_message = "The relay instance must carry the private-api session security group."
    }

    precondition {
      condition     = split(":", var.approved_identity_center_role_arn)[4] == var.expected_account_id # 예: 승인 Role 이 같은 계정
      error_message = "approved_identity_center_role_arn must belong to expected_account_id."
    }
  }
}

# 고정 포트 포워딩 문서입니다. host · 포트가 default 이자 유일한 allowedValues 라 호출자가 다른 대상을 넣을 수 없습니다.
resource "aws_ssm_document" "dev_app_https" {
  name            = local.document_name # 예: "CommerceDevelopmentAppHttps"
  document_type   = "Session"           # 예: Session (start-session 전용 문서)
  document_format = "YAML"

  content = yamlencode({
    schemaVersion = "1.0"
    description   = "Fixed port forwarding from the SSM relay to the Dev Gateway NLB on TCP 443."
    sessionType   = "Port"
    parameters = {
      host            = { type = "String", default = data.aws_lb.gateway.dns_name, allowedValues = [data.aws_lb.gateway.dns_name] } # 예: NLB DNS 이름 하나만
      portNumber      = { type = "String", default = tostring(local.remote_port), allowedValues = [tostring(local.remote_port)] }   # 예: "443"
      localPortNumber = { type = "String", default = tostring(var.local_port), allowedValues = [tostring(var.local_port)] }         # 예: "8443"
    }
    properties = {
      type            = "LocalPortForwarding"
      host            = "{{ host }}"
      portNumber      = "{{ portNumber }}"
      localPortNumber = "{{ localPortNumber }}"
    }
  })

  depends_on = [terraform_data.contract] # 예: 계약 검사를 통과한 뒤에 만듦
}

# 승인된 Identity Center Role 만 이 Role 을 맡습니다 (~/.aws/config 의 role_arn · source_profile). 세션은 1시간.
resource "aws_iam_role" "dev_app_session" {
  name                 = local.role_name # 예: "CommerceDevelopmentAppSession"
  max_session_duration = 3600            # 예: 3600 (1시간)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.approved_identity_center_role_arn } # 예: AWSReservedSSO_CommerceDeveloper_… Role 만
      Action    = "sts:AssumeRole"
    }]
  })

  depends_on = [terraform_data.contract]
}

# StartSession 은 이 인스턴스 + 이 문서에만 허용합니다. SessionDocumentAccessCheck 로 문서 권한 없는 세션 시작을 막습니다.
resource "aws_iam_role_policy" "dev_app_session" {
  role = aws_iam_role.dev_app_session.id # 예: "CommerceDevelopmentAppSession"
  name = "fixed-https-session"           # 예: inline 정책 이름

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StartFixedSessionOnRelay"
        Effect   = "Allow"
        Action   = ["ssm:StartSession"]
        Resource = ["arn:aws:ec2:${var.region}:${var.expected_account_id}:instance/${local.instance_id}"] # 예: 중계 인스턴스 하나
        Condition = {
          BoolIfExists = { "ssm:SessionDocumentAccessCheck" = "true" } # 예: 문서 권한도 함께 검사
        }
      },
      {
        Sid      = "UseFixedDocumentOnly"
        Effect   = "Allow"
        Action   = ["ssm:StartSession"]
        Resource = [aws_ssm_document.dev_app_https.arn] # 예: arn:aws:ssm:ap-northeast-2:111111111111:document/CommerceDevelopmentAppHttps (범용 문서 · shell 문서 없음)
      },
      {
        Sid      = "ManageOwnSessions"
        Effect   = "Allow"
        Action   = ["ssm:TerminateSession", "ssm:ResumeSession"]
        Resource = ["arn:aws:ssm:*:*:session/$${aws:userid}-*"] # 예: 자기 세션만
      }
    ]
  })
}

# NLB SG 에 CIDR 대신 중계 인스턴스 SG 를 출발지로 한 443 규칙 하나를 더합니다 (Gateway 루트 모듈의 allowed_client_cidrs 는 빈 목록 유지).
resource "aws_vpc_security_group_ingress_rule" "relay_to_nlb" {
  security_group_id            = local.nlb_sg_id                         # 예: "sg-0123456789abcdef0" (Gateway NLB SG; 규칙만 이 루트 모듈 소유)
  referenced_security_group_id = local.relay_sg_id                       # 예: "sg-0relay…" (중계 인스턴스 SG)
  ip_protocol                  = "tcp"                                   # 예: "tcp"
  from_port                    = local.remote_port                       # 예: 443
  to_port                      = local.remote_port                       # 예: 443
  description                  = "Approved SSM relay to the Gateway NLB" # 예: 규칙 설명

  depends_on = [terraform_data.contract]
}

# 이 디렉터리는 dev 만 받습니다. input 은 State 에 남는 marker 이며 AWS 자원을 만들지 않습니다.
resource "terraform_data" "environment_boundary" {
  input = var.environment # 예: "dev"

  lifecycle {
    precondition {
      condition     = var.environment == "dev" # 예: Prod 에는 이 경로가 없음 (Prod 접근은 CloudFront + WAF, 운영 환경)
      error_message = "This directory accepts only the dev environment."
    }
  }
}
