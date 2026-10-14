"""Offline adversarial tests for exact BU05 inspection ownership."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("_firewall_fixtures", Path(__file__).with_name("test_network_topology_guard.py"))
base = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(base)
guard = base.guard
ACCOUNT, REGION = base.ACCOUNT, base.REGION
resource, state_of, plan_of = base.resource, base.state_of, base.plan_of


def identity(prefix, number): return prefix + "-" + format(number, "017x")


IVPC = identity("vpc", 200)
IATT = identity("tgw-attach", 200)
ITABLE = identity("tgw-rtb", 200)
ISG = identity("sg", 200)
IACL = identity("acl", 200)
DEFAULT_TABLE = identity("rtb", 200)
SUBNETS = [identity("subnet", 300 + i) for i in range(6)]
TABLES = [identity("rtb", 300 + i) for i in range(6)]
ENDPOINTS = [identity("vpce", 400 + i) for i in range(3)]
FENIS = [identity("eni", 400 + i) for i in range(3)]
TENIS = [identity("eni", 500 + i) for i in range(3)]
FIREWALL = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/course-inspection"
POLICY = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall-policy/course-inspection"
GROUP = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:stateful-rulegroup/course-inspection"
LOGS = {kind: "/aws/network-firewall/course-inspection/" + kind.lower() for kind in ("ALERT", "FLOW")}


class InspectionFixture(base.Fixture):
    def __init__(self):
        super().__init__()
        rows = self.state["resources"]
        rows[0]["instances"][0]["attributes"]["input"] = {"mode": "inspection"}
        rows[1]["instances"][0]["attributes"]["input"] = "inspection"
        for row in rows:
            if row["type"] == "aws_ec2_transit_gateway_route":
                row["name"] += "_inspected"
                row["instances"][0]["attributes"]["transit_gateway_attachment_id"] = IATT
        rows += [resource("aws_vpc", "inspection", IVPC, 0, owner_id=ACCOUNT, cidr_block="10.90.0.0/16",
                          default_network_acl_id=IACL, default_route_table_id=DEFAULT_TABLE),
                 resource("aws_default_security_group", "inspection", ISG, 0, vpc_id=IVPC),
                 resource("aws_ec2_transit_gateway_vpc_attachment", "inspection", IATT, 0, vpc_id=IVPC,
                          transit_gateway_id=base.TGW, subnet_ids=SUBNETS[:3], appliance_mode_support="enable", dns_support="enable", ipv6_support="disable",
                          transit_gateway_default_route_table_association=False, transit_gateway_default_route_table_propagation=False),
                 resource("aws_ec2_transit_gateway_route_table", "after_inspection", ITABLE, 0, transit_gateway_id=base.TGW),
                 resource("aws_ec2_transit_gateway_route_table_association", "inspection", ITABLE + "_" + IATT, 0,
                          transit_gateway_attachment_id=IATT, transit_gateway_route_table_id=ITABLE)]
        for i in range(6):
            az = REGION + "abc"[i % 3]
            suffix = "inspection_transit" if i < 3 else "inspection_firewall"
            rows += [resource("aws_subnet", suffix, SUBNETS[i], az, vpc_id=IVPC, availability_zone=az),
                     resource("aws_route_table", suffix, TABLES[i], az, vpc_id=IVPC),
                     resource("aws_route_table_association", suffix, identity("rtbassoc", 300 + i), az, subnet_id=SUBNETS[i], route_table_id=TABLES[i])]
            for n, key in enumerate(("workload", "lab")):
                target = {"vpc_endpoint_id": ENDPOINTS[i]} if i < 3 else {"transit_gateway_id": base.TGW}
                rows.append(resource("aws_route", "inspection_in" if i < 3 else "inspection_out", "route-" + str(i) + "-" + key, az + "/" + key,
                                     route_table_id=TABLES[i], destination_cidr_block=base.CIDRS[n], **target))
        for i, key in enumerate(("workload", "lab")):
            rows.append(resource("aws_ec2_transit_gateway_route", "after_inspection", ITABLE + "_" + base.CIDRS[i], key,
                                 destination_cidr_block=base.CIDRS[i], transit_gateway_attachment_id=base.ATTACHMENTS[i], transit_gateway_route_table_id=ITABLE))
        rows += [resource("aws_networkfirewall_rule_group", "this", GROUP, 0, arn=GROUP, type="STATEFUL"),
                 resource("aws_networkfirewall_firewall_policy", "this", POLICY, 0, arn=POLICY,
                          firewall_policy=[{"stateful_rule_group_reference": [{"resource_arn": GROUP, "priority": 1}]}]),
                 resource("aws_networkfirewall_firewall", "this", FIREWALL, 0, arn=FIREWALL, vpc_id=IVPC, firewall_policy_arn=POLICY,
                          delete_protection=False, subnet_mapping=[{"subnet_id": s, "ip_address_type": "IPV4"} for s in SUBNETS[3:]],
                          firewall_status=[{"sync_states": [{"availability_zone": REGION + "abc"[i], "attachment": [{"endpoint_id": ENDPOINTS[i], "subnet_id": SUBNETS[i+3]}]} for i in range(3)]}]),
                 resource("aws_networkfirewall_logging_configuration", "this", FIREWALL, 0, firewall_arn=FIREWALL,
                          logging_configuration=[{"log_destination_config": [{"log_type": kind, "log_destination_type": "CloudWatchLogs", "log_destination": {"logGroup": name}} for kind, name in LOGS.items()]}])]
        for kind, name in LOGS.items():
            rows.append(resource("aws_cloudwatch_log_group", "firewall", name, kind, name=name,
                                 arn=f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{name}:*", retention_in_days=30, skip_destroy=False))
        self.original = guard.normalize_resources(self.state)
        r = self.responses
        r["describe-vpcs"]["Vpcs"].append({"VpcId": IVPC, "OwnerId": ACCOUNT, "State": "available", "IsDefault": False, "CidrBlock": "10.90.0.0/16"})
        r["describe-subnets"]["Subnets"] += [{"SubnetId": s, "VpcId": IVPC, "OwnerId": ACCOUNT, "State": "available", "AvailabilityZone": REGION + "abc"[i % 3]} for i, s in enumerate(SUBNETS)]
        r["describe-transit-gateway-attachments"]["TransitGatewayAttachments"].append({"TransitGatewayAttachmentId": IATT, "TransitGatewayId": base.TGW,
            "ResourceType": "vpc", "ResourceOwnerId": ACCOUNT, "TransitGatewayOwnerId": ACCOUNT, "ResourceId": IVPC, "State": "available", "Association": {"TransitGatewayRouteTableId": ITABLE, "State": "associated"}})
        r["describe-transit-gateway-vpc-attachments"]["TransitGatewayVpcAttachments"].append({"TransitGatewayAttachmentId": IATT, "TransitGatewayId": base.TGW,
            "VpcId": IVPC, "VpcOwnerId": ACCOUNT, "SubnetIds": SUBNETS[:3], "State": "available", "Options": {"ApplianceModeSupport": "enable", "DnsSupport": "enable", "Ipv6Support": "disable"}})
        r["describe-transit-gateway-route-tables"]["TransitGatewayRouteTables"].append({"TransitGatewayRouteTableId": ITABLE, "TransitGatewayId": base.TGW, "State": "available", "DefaultAssociationRouteTable": False, "DefaultPropagationRouteTable": False})
        for table in base.TGTABLES:
            route = r[("search-transit-gateway-routes", table)]["Routes"][0]
            route["TransitGatewayAttachments"] = [{"TransitGatewayAttachmentId": IATT, "ResourceType": "vpc", "ResourceId": IVPC}]
        r[("get-transit-gateway-route-table-associations", ITABLE)] = {"Associations": [{"TransitGatewayAttachmentId": IATT, "ResourceType": "vpc", "ResourceId": IVPC, "State": "associated"}]}
        r[("search-transit-gateway-routes", ITABLE)] = {"AdditionalRoutesAvailable": False, "Routes": [{"DestinationCidrBlock": base.CIDRS[i], "Type": "static", "State": "active",
            "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": base.ATTACHMENTS[i], "ResourceType": "vpc", "ResourceId": base.VPCS[i]}]} for i in range(2)]}
        r["describe-route-tables"]["RouteTables"].append({"RouteTableId": DEFAULT_TABLE, "VpcId": IVPC, "OwnerId": ACCOUNT,
            "Routes": [{"GatewayId": "local", "State": "active", "DestinationCidrBlock": "10.90.0.0/16"}], "Associations": []})
        for i, table in enumerate(TABLES):
            target = {"GatewayId": ENDPOINTS[i]} if i < 3 else {"TransitGatewayId": base.TGW}
            r["describe-route-tables"]["RouteTables"].append({"RouteTableId": table, "VpcId": IVPC, "OwnerId": ACCOUNT,
                "Routes": [{"GatewayId": "local", "State": "active", "DestinationCidrBlock": "10.90.0.0/16"}] +
                          [dict(DestinationCidrBlock=cidr, State="active", **target) for cidr in base.CIDRS], "Associations": [{"SubnetId": SUBNETS[i]}]})
        r.update({
            "list-firewalls": {"Firewalls": [{"FirewallArn": FIREWALL}]},
            "list-firewall-policies": {"FirewallPolicies": [{"Arn": POLICY}]},
            "list-rule-groups": {"RuleGroups": [{"Arn": GROUP}]},
            "describe-resource-policy": {"Policy": json.dumps({"Version": "2012-10-17", "Statement": []})},
            "list-vpc-endpoint-associations": {"VpcEndpointAssociations": []},
            ("describe-firewall", FIREWALL): {"UpdateToken": "firewall-version", "Firewall": {"FirewallArn": FIREWALL, "VpcId": IVPC, "FirewallPolicyArn": POLICY,
                "DeleteProtection": False, "NumberOfAssociations": 0, "SubnetMappings": [{"SubnetId": s, "IPAddressType": "IPV4"} for s in SUBNETS[3:]]},
                "FirewallStatus": {"Status": "READY", "ConfigurationSyncStateSummary": "IN_SYNC", "SyncStates": {REGION + "abc"[i]: {"Attachment": {"EndpointId": ENDPOINTS[i], "SubnetId": SUBNETS[i+3], "Status": "READY"}} for i in range(3)}}},
            ("describe-firewall-policy", POLICY): {"UpdateToken": "policy-version", "FirewallPolicyResponse": {"FirewallPolicyArn": POLICY, "FirewallPolicyStatus": "ACTIVE", "NumberOfAssociations": 1},
                "FirewallPolicy": {"StatefulRuleGroupReferences": [{"ResourceArn": GROUP, "Priority": 1}]}},
            ("describe-rule-group", GROUP): {"UpdateToken": "group-version", "RuleGroupResponse": {"RuleGroupArn": GROUP, "RuleGroupStatus": "ACTIVE", "Type": "STATEFUL", "NumberOfAssociations": 1}},
            "describe-vpc-endpoints": {"VpcEndpoints": [{"VpcEndpointId": ENDPOINTS[i], "VpcId": IVPC, "OwnerId": ACCOUNT, "State": "available",
                "VpcEndpointType": "GatewayLoadBalancer", "RequesterManaged": True, "SubnetIds": [SUBNETS[i+3]], "NetworkInterfaceIds": [FENIS[i]], "Groups": [], "RouteTableIds": []} for i in range(3)]},
            "describe-network-interfaces": {"NetworkInterfaces": [dict(NetworkInterfaceId=eni, VpcId=IVPC, OwnerId=ACCOUNT, RequesterManaged=True, Status="in-use", Groups=[],
                SubnetId=SUBNETS[(i if kind == "transit_gateway" else i+3)], InterfaceType=kind) for kind, ids in (("transit_gateway", TENIS), ("gateway_load_balancer_endpoint", FENIS)) for i, eni in enumerate(ids)]},
            "describe-logging-configuration": {"FirewallArn": FIREWALL, "LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": kind, "LogDestinationType": "CloudWatchLogs", "LogDestination": {"logGroup": name}} for kind, name in LOGS.items()]}},
            "describe-log-groups": {"logGroups": [{"logGroupName": name, "arn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{name}:*", "retentionInDays": 30} for name in LOGS.values()]},
            "describe-security-groups": {"SecurityGroups": [{"GroupId": ISG, "VpcId": IVPC, "OwnerId": ACCOUNT}]},
            "describe-network-acls": {"NetworkAcls": [{"NetworkAclId": IACL, "VpcId": IVPC, "OwnerId": ACCOUNT, "Associations": [{"SubnetId": s} for s in SUBNETS]}]},
            "describe-internet-gateways": {"InternetGateways": []}, "describe-nat-gateways": {"NatGateways": []},
            "describe-instances": {"Reservations": []}, "describe-vpc-peering-connections": {"VpcPeeringConnections": []},
            "describe-vpn-gateways": {"VpnGateways": []}, "describe-egress-only-internet-gateways": {"EgressOnlyInternetGateways": []},
            ("elb", "describe-load-balancers"): {"LoadBalancerDescriptions": []}, ("elbv2", "describe-load-balancers"): {"LoadBalancers": []},
            "list-clusters": {"clusters": []}, "list-hosted-zones-by-vpc": {"HostedZoneSummaries": []}, "list-profile-associations": {"ProfileAssociations": []},
            "describe-flow-logs": {"FlowLogs": []}, "list-resolver-query-log-config-associations": {"ResolverQueryLogConfigAssociations": []},
            "get-subnet-cidr-reservations": {"SubnetIpv4CidrReservations": [], "SubnetIpv6CidrReservations": []},
        })

    def aws(self, service, operation, *args):
        self.calls.append((service, operation, args))
        key = operation
        if operation in ("describe-firewall", "describe-firewall-policy", "describe-rule-group"):
            key = (operation, args[1])
        elif operation in ("get-transit-gateway-route-table-associations", "search-transit-gateway-routes"):
            key = (operation, args[args.index("--transit-gateway-route-table-id") + 1])
        elif operation == "describe-load-balancers": key = (service, operation)
        response = self.responses[key]
        if isinstance(response, Exception): raise response
        response = copy.deepcopy(response)
        filter_fields = {"vpc-id": "VpcId", "subnet-id": "SubnetId", "network-interface-id": "NetworkInterfaceId"}
        if "--filters" in args:
            value = args[args.index("--filters") + 1]
            name, values = value.removeprefix("Name=").split(",Values=", 1)
            if name in filter_fields:
                for key, rows in response.items():
                    if isinstance(rows, list): response[key] = [r for r in rows if r.get(filter_fields[name]) in values.split(",")]
        return response

    def full(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); (path / "ci").mkdir()
            (path / "ci/deploy-roots.json").write_text(json.dumps({"dependencies": {guard.TRANSIT: []}}))
            return guard.guard_destroy(tmp, self.context, self.state, plan_of(self.state), self.original, self.upstream,
                                       aws_call=self.aws, load_state=lambda key: {"state": None, "fingerprint": {"exists": False}})


class FirewallTests(unittest.TestCase):
    def setUp(self): self.fx = InspectionFixture()

    def test_full_inspection_guard_proves_exact_service_chain_and_no_writes(self):
        result = self.fx.full()
        self.assertEqual(set(result["firewall"]["endpoints"]), set(ENDPOINTS))
        self.assertEqual(result["firewall"]["log_policy"], "owned-disposable")
        self.assertTrue(all((s, o) in guard.READ_OPERATIONS for s, o, args in self.fx.calls))

    def test_same_vpc_extra_tgw_attachment_and_eni_block(self):
        for kind in ("attachment", "eni", "workload", "duplicate_subnet"):
            self.fx = InspectionFixture()
            if kind == "attachment":
                self.fx.responses["describe-transit-gateway-vpc-attachments"]["TransitGatewayVpcAttachments"].append({"TransitGatewayAttachmentId": identity("tgw-attach", 999), "VpcId": IVPC, "State": "available"})
            elif kind == "eni":
                self.fx.responses["describe-network-interfaces"]["NetworkInterfaces"].append(dict(self.fx.responses["describe-network-interfaces"]["NetworkInterfaces"][0], NetworkInterfaceId=identity("eni", 999)))
            elif kind == "workload":
                self.fx.responses["describe-network-interfaces"]["NetworkInterfaces"].append({"NetworkInterfaceId": identity("eni", 999), "VpcId": IVPC, "OwnerId": ACCOUNT, "InterfaceType": "interface", "SubnetId": SUBNETS[0], "Groups": []})
            else:
                self.fx.responses["describe-network-interfaces"]["NetworkInterfaces"][1]["SubnetId"] = SUBNETS[0]
            with self.subTest(kind=kind), self.assertRaises(guard.SafeError): self.fx.full()

    def test_firewall_protection_shared_policy_and_endpoint_associations_block(self):
        mutations = [lambda r: r[("describe-firewall", FIREWALL)]["Firewall"].update(DeleteProtection=True),
                     lambda r: r[("describe-firewall-policy", POLICY)]["FirewallPolicyResponse"].update(NumberOfAssociations=2),
                     lambda r: r[("describe-rule-group", GROUP)]["RuleGroupResponse"].update(NumberOfAssociations=2),
                     lambda r: r["list-vpc-endpoint-associations"]["VpcEndpointAssociations"].append({"VpcEndpointAssociationArn": "foreign"}),
                     lambda r: r["describe-resource-policy"].update(Policy=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*"}]}))]
        for change in mutations:
            self.fx = InspectionFixture(); change(self.fx.responses)
            with self.assertRaises(guard.SafeError): self.fx.full()

    def test_firewall_endpoint_or_eni_identity_mismatch_blocks(self):
        mutations = [lambda r: r[("describe-firewall", FIREWALL)]["FirewallStatus"]["SyncStates"][REGION + "a"]["Attachment"].update(EndpointId=identity("vpce", 999)),
                     lambda r: r["describe-vpc-endpoints"]["VpcEndpoints"][0].update(NetworkInterfaceIds=[identity("eni", 999)]),
                     lambda r: r["describe-network-interfaces"]["NetworkInterfaces"][-1].update(OwnerId="999999999999"),
                     lambda r: r["describe-vpc-endpoints"]["VpcEndpoints"][0].update(VpcEndpointType="Interface"),
                     lambda r: r[("describe-firewall", FIREWALL)]["FirewallStatus"].update(Status="DELETING")]
        for change in mutations:
            self.fx = InspectionFixture(); change(self.fx.responses)
            with self.assertRaises(guard.SafeError): self.fx.full()

    def test_unowned_endpoint_route_and_log_configuration_block(self):
        self.fx.responses["describe-route-tables"]["RouteTables"][-1]["Routes"].append({"GatewayId": ENDPOINTS[0], "DestinationCidrBlock": "10.99.0.0/16", "State": "active"})
        with self.assertRaises(guard.SafeError): self.fx.full()
        self.fx = InspectionFixture()
        self.fx.responses["describe-logging-configuration"]["LoggingConfiguration"]["LogDestinationConfigs"][0]["LogDestination"] = {"logGroup": "foreign"}
        with self.assertRaises(guard.SafeError): self.fx.full()

    def test_firewall_pagination_read_denial_and_unknown_status_block(self):
        for op, value in (("list-firewalls", {"Firewalls": [], "NextToken": "more"}), ("describe-resource-policy", {}), ("list-rule-groups", PermissionError("private error"))):
            self.fx = InspectionFixture(); self.fx.responses[op] = value
            with self.subTest(op=op), self.assertRaises(guard.SafeError): self.fx.full()

    def test_unknown_inspection_logging_and_reservations_block(self):
        for op, field in (("describe-flow-logs", "FlowLogs"), ("list-resolver-query-log-config-associations", "ResolverQueryLogConfigAssociations"), ("get-subnet-cidr-reservations", "SubnetIpv4CidrReservations")):
            self.fx = InspectionFixture(); self.fx.responses[op][field] = [{"Id": "unknown"}]
            with self.subTest(op=op), self.assertRaises(guard.SafeError): self.fx.full()

    def test_typed_resource_policy_absence_is_distinct_from_generic_read_denial(self):
        self.fx.responses["describe-resource-policy"] = guard.ResourcePolicyAbsent("no policy")
        self.fx.full()
        self.fx.responses["describe-resource-policy"] = guard.SafeError("permission denied")
        with self.assertRaises(guard.SafeError): self.fx.full()


class FirewallPlanAndRetryTests(unittest.TestCase):
    def setUp(self): self.fx = InspectionFixture()

    def up_plan(self):
        plan = plan_of(self.fx.state)
        plan["planned_values"] = copy.deepcopy(plan["prior_state"]["values"])
        plan["variables"] = {"enable_inspection": {"value": True}}
        for row in plan["resource_changes"]:
            row["change"] = {"actions": ["no-op"], "before": row["change"]["before"], "after": copy.deepcopy(row["change"]["before"]), "after_unknown": {}}
        return plan

    def absent(self):
        for operation, key in (("describe-vpcs", "Vpcs"), ("describe-subnets", "Subnets"), ("describe-security-groups", "SecurityGroups"),
                               ("describe-network-acls", "NetworkAcls"), ("describe-route-tables", "RouteTables"),
                               ("describe-transit-gateways", "TransitGateways"), ("describe-transit-gateway-attachments", "TransitGatewayAttachments"),
                               ("describe-transit-gateway-vpc-attachments", "TransitGatewayVpcAttachments"), ("describe-transit-gateway-route-tables", "TransitGatewayRouteTables"),
                               ("list-firewalls", "Firewalls"), ("list-firewall-policies", "FirewallPolicies"), ("list-rule-groups", "RuleGroups"),
                               ("describe-log-groups", "logGroups"), ("describe-vpc-endpoints", "VpcEndpoints"), ("describe-network-interfaces", "NetworkInterfaces")):
            self.fx.responses[operation][key] = []

    def test_inspection_source_plan_accepts_exact_owned_cw_and_mode(self):
        result = guard.validate_plan_contracts(self.fx.context, self.up_plan(), self.fx.upstream)
        self.assertEqual(result["mode"], "inspection")
        self.assertEqual(result["cloudwatch_policy"], "owned-disposable")

    def test_inspection_restore_from_empty_state_allows_owned_computed_links(self):
        plan = self.up_plan()
        own_ids = {row["values"]["id"] for row in plan["planned_values"]["root_module"]["resources"]}
        changed = {}
        for change in plan["resource_changes"]:
            value = change["change"]["after"]
            unknown = {"id": True}
            value.pop("id", None)
            if value.get("arn"):
                value.pop("arn"); unknown["arn"] = True
            for field in ("vpc_id", "subnet_id", "route_table_id", "transit_gateway_id", "transit_gateway_attachment_id", "transit_gateway_route_table_id", "firewall_arn", "firewall_policy_arn"):
                if value.get(field) in own_ids:
                    value.pop(field); unknown[field] = True
            if change["address"] == "aws_ec2_transit_gateway_vpc_attachment.inspection[0]":
                value.pop("subnet_ids"); unknown["subnet_ids"] = True
            if change["type"] == "aws_networkfirewall_firewall":
                for item in value["subnet_mapping"]: item.pop("subnet_id")
                unknown["subnet_mapping"] = [{"subnet_id": True} for _ in range(3)]
                value.pop("firewall_status"); unknown["firewall_status"] = True
            if change["type"] == "aws_networkfirewall_firewall_policy":
                value["firewall_policy"][0]["stateful_rule_group_reference"][0].pop("resource_arn")
                unknown["firewall_policy"] = [{"stateful_rule_group_reference": [{"resource_arn": True}]}]
            if change["address"].startswith("aws_route.inspection_in"):
                value.pop("vpc_endpoint_id"); unknown["vpc_endpoint_id"] = True
            change["change"] = {"actions": ["create"], "before": None, "after": value, "after_unknown": unknown}
            changed[change["address"]] = value
        for row in plan["planned_values"]["root_module"]["resources"]:
            row["values"] = copy.deepcopy(changed[row["address"]])
        result = guard.validate_plan_contracts(self.fx.context, plan, self.fx.upstream)
        self.assertEqual(result["mode"], "inspection")

    def test_foreign_firewall_plan_policy_subnet_and_protection_block(self):
        mutations = [("aws_networkfirewall_firewall", lambda v: v.update(delete_protection=True)),
                     ("aws_networkfirewall_firewall", lambda v: v.update(firewall_policy_arn="foreign")),
                     ("aws_networkfirewall_firewall", lambda v: v["subnet_mapping"][0].update(subnet_id="foreign")),
                     ("aws_networkfirewall_firewall_policy", lambda v: v["firewall_policy"][0]["stateful_rule_group_reference"][0].update(resource_arn="foreign")),
                     ("aws_cloudwatch_log_group", lambda v: v.update(skip_destroy=True))]
        for kind, change in mutations:
            plan = self.up_plan()
            row = next(r for r in plan["resource_changes"] if r["type"] == kind)
            change(row["change"]["after"])
            with self.subTest(kind=kind), self.assertRaises(guard.SafeError):
                guard.validate_plan_contracts(self.fx.context, plan, self.fx.upstream)

    def test_empty_inspection_retry_requires_all_original_resources_absent(self):
        self.fx.state = state_of([])
        with self.assertRaises(guard.SafeError): self.fx.full()
        self.absent()
        self.fx.full()
        self.assertTrue(guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)["absent"])
        self.fx.responses["list-firewall-policies"]["FirewallPolicies"] = [{"Arn": POLICY}]
        with self.assertRaises(guard.SafeError): guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)

    def test_original_log_or_service_eni_residual_blocks_absence(self):
        self.absent()
        self.fx.responses["describe-log-groups"]["logGroups"] = [{"logGroupName": LOGS["ALERT"]}]
        with self.assertRaises(guard.SafeError): guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)
        self.fx.responses["describe-log-groups"]["logGroups"] = []
        self.fx.responses["describe-network-interfaces"]["NetworkInterfaces"] = [{"NetworkInterfaceId": TENIS[0], "VpcId": IVPC}]
        with self.assertRaises(guard.SafeError): guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)

    def test_foreign_firewall_and_policy_consumers_block(self):
        foreign = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/foreign"
        self.fx.responses["list-firewalls"]["Firewalls"].append({"FirewallArn": foreign})
        self.fx.responses[("describe-firewall", foreign)] = {"Firewall": {"FirewallArn": foreign, "VpcId": base.VPCS[0], "FirewallPolicyArn": POLICY}}
        with self.assertRaises(guard.SafeError): self.fx.full()
        self.fx = InspectionFixture()
        foreign_policy = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall-policy/foreign"
        self.fx.responses["list-firewall-policies"]["FirewallPolicies"].append({"Arn": foreign_policy})
        self.fx.responses[("describe-firewall-policy", foreign_policy)] = {"FirewallPolicyResponse": {"FirewallPolicyArn": foreign_policy}, "FirewallPolicy": {"StatefulRuleGroupReferences": [{"ResourceArn": GROUP}]}}
        with self.assertRaises(guard.SafeError): self.fx.full()

    def test_resource_policy_error_interpreter_is_exact_and_read_only(self):
        for stderr, expected in ((b"An error occurred (ResourceNotFoundException) when calling the DescribeResourcePolicy operation: private", guard.ResourcePolicyAbsent),
                                 (b"An error occurred (AccessDeniedException) when calling the DescribeResourcePolicy operation: private", guard.SafeError),
                                 (b"An error occurred (ResourceNotFoundException) when calling the DescribeFirewall operation: private", guard.SafeError)):
            with patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", stderr)):
                with self.assertRaises(expected) as caught:
                    guard.aws_read("network-firewall", "describe-resource-policy", "--resource-arn", POLICY)
                self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__": unittest.main()
