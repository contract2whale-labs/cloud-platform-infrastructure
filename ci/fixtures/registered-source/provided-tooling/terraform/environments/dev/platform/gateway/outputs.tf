# outputs.tf — platform/gateway 루트 모듈 (dev · prod 공통 코드)

output "gateway_contract" {
  description = "Cluster, VPC, exposure mode, NLB subnets/SG, DNS zones and fixed Gateway names for the platform publisher and later roots."
  value       = module.component.gateway_contract
}



output "platform_input_values" {
  description = "Typed noncredential fields consumed by the reviewed native platform input publisher."
  value = {
    cluster_name           = module.component.gateway_contract.cluster_name
    region                 = module.component.gateway_contract.region
    vpc_id                 = module.component.gateway_contract.vpc_id
    nlb_scheme             = var.exposure_mode == "public" ? "internet-facing" : "internal"
    nlb_subnet_ids_csv     = join(",", module.component.gateway_contract.nlb_subnet_ids)
    nlb_security_group_id  = module.component.gateway_contract.nlb_security_group_id
    dns_zone_id            = module.component.gateway_contract.dns_zone_id
    dns_zone_name          = module.component.gateway_contract.dns_zone_name
    dashboard_hostname     = "grafana.${trimsuffix(module.component.gateway_contract.dns_zone_name, ".")}"
    dns_zone_type          = var.exposure_mode == "public" ? "public" : "private"
    dns_zone_id_argument   = "--zone-id-filter=${module.component.gateway_contract.dns_zone_id}"
    dns_zone_type_argument = var.exposure_mode == "public" ? "--aws-zone-type=public" : "--aws-zone-type=private"
  }
}
