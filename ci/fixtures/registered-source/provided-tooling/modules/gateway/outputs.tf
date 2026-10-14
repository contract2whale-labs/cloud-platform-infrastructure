# outputs.tf — modules/gateway (dev · prod 루트 모듈이 공유하는 모듈)

output "gateway_contract" {
  description = "Cluster, VPC, exposure mode, NLB subnets/SG, DNS zones and the fixed Gateway names that the platform publisher and the edge root rely on."
  value = {
    cluster_name          = var.cluster_contract.name             # 예: "contract2whale-dev-eks"
    region                = var.cluster_contract.region           # 예: "ap-northeast-2"
    vpc_id                = var.cluster_contract.vpc_id           # 예: "vpc-0123456789abcdef0"
    exposure_mode         = var.exposure_mode                     # 예: "internal"
    nlb_subnet_ids        = sort(tolist(var.nlb_subnet_ids))      # 예: ["subnet-...1", "subnet-...2", "subnet-...3"] (정렬한 목록; annotation 순서 고정)
    nlb_security_group_id = aws_security_group.nlb.id             # 예: "sg-0123456789abcdef0"
    dns_zone_id           = local.dns_zone_id                     # 예: "Z0PRIVATE00000000000" (ExternalDNS 가 쓰는 zone)
    dns_zone_name         = trimsuffix(var.public_zone.name, ".") # 예: "dev.playdevops.click" (끝의 점 없음)
    public_zone_id        = var.public_zone.id                    # 예: "ZPUBLIC" (cert-manager DNS01 TXT 용)
    external_dns_enabled  = var.exposure_mode != "waf"            # 예: true (waf 만 false)
    namespace             = "platform-gateway"                    # 예: "platform-gateway" (Envoy Gateway · Gateway 객체 namespace)
    gateway_name          = "platform"                            # 예: "platform" (tenant HTTPRoute 의 parentRefs.name)
    listener_name         = "https"                               # 예: "https" (parentRefs.sectionName)
  }
}
