"""Offline tests: never call AWS, GitHub, Terraform or a real backend."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("network_topology_guard", HERE / "network-topology-guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
TGW = "tgw-0123456789abcdef0"
VPCS = ["vpc-0123456789abcdef0", "vpc-1123456789abcdef0"]
CIDRS = ["172.20.0.0/16", "10.80.0.0/16"]
TABLES = ["rtb-0123456789abcdef0", "rtb-1123456789abcdef0"]
TGTABLES = ["tgw-rtb-0123456789abcdef0", "tgw-rtb-1123456789abcdef0"]
ATTACHMENTS = ["tgw-attach-0123456789abcdef0", "tgw-attach-1123456789abcdef0"]
SUBNETS = [["subnet-" + str(i) + str(j) + "23456789abcdef0" for j in range(3)] for i in range(2)]


def resource(kind, resource_name, identity, index=None, **values):
    item = {"mode": "managed", "type": kind, "name": resource_name, "instances": [{"attributes": dict(id=identity, **copy.deepcopy(values))}]}
    if index is not None:
        item["instances"][0]["index_key"] = index
    return item


def state_of(rows):
    return {"version": 4, "lineage": "private", "serial": 2, "resources": rows, "outputs": {"private": {"value": "never print"}}}


def plan_of(state):
    rows = guard.managed_resources(state)
    shown = [dict(address=r["address"], mode="managed", type=r["type"], name=r["name"], values=copy.deepcopy(r["values"])) for r in rows]
    return {"format_version": "1.2", "complete": True, "errored": False,
            "prior_state": {"format_version": "1.0", "values": {"root_module": {"resources": shown}}},
            "planned_values": {}, "resource_changes": [dict(address=r["address"], mode="managed", type=r["type"],
            change={"actions": ["delete"], "before": copy.deepcopy(r["values"]), "after": None}) for r in rows]}


def context(root=guard.TRANSIT):
    return {"root": root, "environment": "dev", "workspace": "default", "account": ACCOUNT,
            "backend": {"bucket": "private-state", "key": root.removeprefix("terraform/environments/dev/") + "/terraform.tfstate", "region": REGION}}


class Fixture:
    def __init__(self):
        self.context = context()
        self.upstream = {}
        rows = [resource("terraform_data", "contract", "contract-id", 0, input={"mode": "direct"}), resource("terraform_data", "lifecycle", "lifecycle-id", input="direct"),
                resource("aws_ec2_transit_gateway", "this", TGW, 0, owner_id=ACCOUNT, default_route_table_association="disable",
                         default_route_table_propagation="disable", auto_accept_shared_attachments="disable")]
        for i, (root, key) in enumerate(((guard.VPC, "workload"), (guard.PEER, "lab"))):
            upstream = [resource("aws_vpc", "peer" if i else "this", VPCS[i], owner_id=ACCOUNT, cidr_block=CIDRS[i]),
                        resource("aws_route_table", "peer" if i else "this", TABLES[i], "ap-northeast-2a" if i else 0, vpc_id=VPCS[i])]
            upstream += [resource("aws_subnet", "peer" if i else "this", subnet, REGION + "abc"[j] if i else j,
                                 vpc_id=VPCS[i], availability_zone=REGION + "abc"[j]) for j, subnet in enumerate(SUBNETS[i])]
            self.upstream[root] = state_of(upstream)
            rows += [resource("aws_ec2_transit_gateway_vpc_attachment", "edge", ATTACHMENTS[i], key, vpc_id=VPCS[i],
                              transit_gateway_id=TGW, subnet_ids=SUBNETS[i], transit_gateway_default_route_table_association=False,
                              transit_gateway_default_route_table_propagation=False, appliance_mode_support="disable", dns_support="enable", ipv6_support="disable"),
                     resource("aws_ec2_transit_gateway_route_table", "workload" if i == 0 else "peer", TGTABLES[i], 0, transit_gateway_id=TGW),
                     resource("aws_ec2_transit_gateway_route_table_association", "edge", TGTABLES[i] + "_" + ATTACHMENTS[i], key,
                              transit_gateway_attachment_id=ATTACHMENTS[i], transit_gateway_route_table_id=TGTABLES[i]),
                     resource("aws_ec2_transit_gateway_route", "to_peer" if i == 0 else "to_workload", TGTABLES[i] + "_" + CIDRS[1-i], "lab" if i == 0 else 0,
                              destination_cidr_block=CIDRS[1-i], transit_gateway_attachment_id=ATTACHMENTS[1-i], transit_gateway_route_table_id=TGTABLES[i], blackhole=False),
                     resource("aws_route", "edge", "r-" + TABLES[i] + "-hash", key + "/" + TABLES[i] + "/" + ("lab" if i == 0 else "workload"),
                              route_table_id=TABLES[i], destination_cidr_block=CIDRS[1-i], transit_gateway_id=TGW)]
        self.state = state_of(rows)
        self.original = guard.normalize_resources(self.state)
        self.calls = []
        self.responses = {
            "get-caller-identity": {"Account": ACCOUNT},
            "describe-transit-gateways": {"TransitGateways": [{"TransitGatewayId": TGW, "OwnerId": ACCOUNT, "State": "available", "Options": {
                "DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable", "AutoAcceptSharedAttachments": "disable"}}]},
            "describe-transit-gateway-attachments": {"TransitGatewayAttachments": [{"TransitGatewayAttachmentId": ATTACHMENTS[i],
                "TransitGatewayId": TGW, "ResourceType": "vpc", "ResourceOwnerId": ACCOUNT, "TransitGatewayOwnerId": ACCOUNT,
                "ResourceId": VPCS[i], "State": "available", "Association": {"TransitGatewayRouteTableId": TGTABLES[i], "State": "associated"}} for i in range(2)]},
            "describe-transit-gateway-vpc-attachments": {"TransitGatewayVpcAttachments": [{"TransitGatewayAttachmentId": ATTACHMENTS[i],
                "TransitGatewayId": TGW, "VpcId": VPCS[i], "VpcOwnerId": ACCOUNT, "SubnetIds": SUBNETS[i], "State": "available", "Options": {"ApplianceModeSupport": "disable", "DnsSupport": "enable", "Ipv6Support": "disable"}} for i in range(2)]},
            "describe-vpcs": {"Vpcs": [{"VpcId": VPCS[i], "OwnerId": ACCOUNT, "CidrBlock": CIDRS[i], "State": "available", "IsDefault": False} for i in range(2)]},
            "describe-subnets": {"Subnets": [{"SubnetId": subnet, "VpcId": VPCS[i], "OwnerId": ACCOUNT, "State": "available", "AvailabilityZone": REGION + "abc"[j]}
                                            for i in range(2) for j, subnet in enumerate(SUBNETS[i])]},
            "describe-transit-gateway-route-tables": {"TransitGatewayRouteTables": [{"TransitGatewayRouteTableId": table, "TransitGatewayId": TGW,
                "State": "available", "DefaultAssociationRouteTable": False, "DefaultPropagationRouteTable": False} for table in TGTABLES]},
            "get-transit-gateway-route-table-propagations": {"TransitGatewayRouteTablePropagations": []},
            "describe-route-tables": {"RouteTables": [{"RouteTableId": TABLES[i], "VpcId": VPCS[i], "OwnerId": ACCOUNT,
                "Routes": [{"GatewayId": "local", "DestinationCidrBlock": CIDRS[i], "State": "active"},
                           {"TransitGatewayId": TGW, "DestinationCidrBlock": CIDRS[1-i], "State": "active"}]} for i in range(2)]},
        }
        for i, table in enumerate(TGTABLES):
            self.responses[("get-transit-gateway-route-table-associations", table)] = {"Associations": [{"TransitGatewayAttachmentId": ATTACHMENTS[i], "ResourceId": VPCS[i], "ResourceType": "vpc", "State": "associated"}]}
            self.responses[("search-transit-gateway-routes", table)] = {"AdditionalRoutesAvailable": False, "Routes": [{"DestinationCidrBlock": CIDRS[1-i], "Type": "static", "State": "active",
                "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": ATTACHMENTS[1-i], "ResourceType": "vpc", "ResourceId": VPCS[1-i]}]}]}

    def aws(self, service, operation, *args):
        self.calls.append((service, operation, args))
        key = (operation, args[args.index("--transit-gateway-route-table-id") + 1]) if operation in ("get-transit-gateway-route-table-associations", "search-transit-gateway-routes") else operation
        value = self.responses[key]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    def proof(self):
        return guard.prove_selected_transit(self.context, self.state, self.original, self.upstream, aws_call=self.aws)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def validate(self):
        return guard.validate_state(self.fx.context, self.fx.state, self.fx.original, self.fx.upstream)

    def test_direct_shape_and_exact_destroy(self):
        self.assertEqual(len(self.validate()), len(self.fx.original))
        self.assertEqual(len(guard.validate_destroy(self.fx.state, plan_of(self.fx.state), self.fx.original)), len(self.fx.original))

    def test_retained_resources_and_unknown_shapes_block(self):
        for kind in ("aws_s3_bucket", "aws_s3_bucket_policy", "aws_iam_role", "aws_kms_key", "aws_cloudwatch_log_group", "aws_instance", "aws_ec2_transit_gateway_route_table_propagation"):
            fx = Fixture()
            fx.state["resources"].append(resource(kind, "extra", "secret-private-identity"))
            with self.subTest(kind=kind), self.assertRaises(guard.SafeError):
                guard.validate_state(fx.context, fx.state, upstream_states=fx.upstream)
        self.fx.state["resources"][2]["name"] = "foreign"
        with self.assertRaises(guard.SafeError):
            self.validate()

    def test_module_injection_and_wrong_workspace_account_region_block(self):
        for key, value in (("workspace", "prod"), ("environment", "prod"), ("root", guard.VPC), ("account", "not-an-account")):
            fx = Fixture(); fx.context[key] = value
            with self.subTest(key=key), self.assertRaises(guard.SafeError):
                guard.validate_state(fx.context, fx.state, upstream_states=fx.upstream)
        self.fx.state["resources"][2]["module"] = "module.foreign"
        with self.assertRaises(guard.SafeError): self.validate()

    def test_partial_subset_is_pinned_not_type_only(self):
        self.fx.state["resources"].pop(0)
        self.validate()
        self.fx.state["resources"][0]["instances"][0]["attributes"]["id"] = "new-marker"
        with self.assertRaises(guard.SafeError): self.validate()

    def test_duplicate_original_ids_wrong_route_cidr_and_missing_az_block(self):
        duplicate = copy.deepcopy(self.fx.original)
        duplicate[3]["id"] = duplicate[8]["id"]
        with self.assertRaises(guard.SafeError):
            guard.original_resources(duplicate, guard.TRANSIT)
        self.fx.state["resources"][-1]["instances"][0]["attributes"]["destination_cidr_block"] = "10.99.0.0/16"
        with self.assertRaises(guard.SafeError): self.validate()
        self.fx = Fixture()
        self.fx.state["resources"][3]["instances"][0]["attributes"]["subnet_ids"].pop()
        with self.assertRaises(guard.SafeError): self.validate()
        self.fx = Fixture()
        self.fx.upstream[guard.VPC]["resources"][0]["instances"][0]["attributes"].pop("cidr_block")
        with self.assertRaises(guard.SafeError): self.validate()

    def test_unknown_attachment_subnet_and_upstream_output_only_block(self):
        self.fx.state["resources"][3]["instances"][0]["attributes"]["subnet_ids"] = ["subnet-foreign"]
        with self.assertRaises(guard.SafeError): self.validate()
        self.fx = Fixture(); self.fx.upstream[guard.PEER] = state_of([])
        self.fx.upstream[guard.PEER]["outputs"] = {"vpc_contract": {"value": {"vpc_id": VPCS[1]}}}
        with self.assertRaises(guard.SafeError): self.validate()

    def test_automatic_defaults_and_foreign_route_table_block(self):
        for field in ("default_route_table_association", "default_route_table_propagation", "auto_accept_shared_attachments"):
            self.fx = Fixture(); self.fx.state["resources"][2]["instances"][0]["attributes"][field] = "enable"
            with self.subTest(field=field), self.assertRaises(guard.SafeError): self.validate()
        self.fx = Fixture(); self.fx.state["resources"][-1]["instances"][0]["attributes"]["route_table_id"] = "rtb-foreign"
        with self.assertRaises(guard.SafeError): self.validate()

    def test_plan_rejects_identity_relationship_action_and_completeness_changes(self):
        modifications = [lambda p: p.update(complete=False), lambda p: p.update(deferred_changes=[{}]),
                         lambda p: p["resource_changes"][0]["change"].update(actions=["no-op"]),
                         lambda p: p["resource_changes"][0]["change"]["before"].update(id="new"),
                         lambda p: p["resource_changes"][3]["change"]["before"].update(vpc_id="vpc-foreign"),
                         lambda p: p["resource_changes"].pop(), lambda p: p["resource_changes"].append(p["resource_changes"][0]),
                         lambda p: p["resource_changes"][0].update(previous_address="old"),
                         lambda p: p["planned_values"].update(root_module=p["prior_state"]["values"]["root_module"])]
        for mutate in modifications:
            plan = plan_of(self.fx.state); mutate(plan)
            with self.subTest(mutate=mutate), self.assertRaises(guard.SafeError):
                guard.validate_destroy(self.fx.state, plan, self.fx.original)

    def test_empty_retry_still_validates_original_identity_map(self):
        guard.validate_state(self.fx.context, state_of([]), self.fx.original, self.fx.upstream)
        guard.validate_destroy(state_of([]), {"format_version": "1.2", "planned_values": {}}, self.fx.original)
        bad = copy.deepcopy(self.fx.original); bad.append({"address": "aws_s3_bucket.logs", "type": "aws_s3_bucket", "id": "private"})
        with self.assertRaises(guard.SafeError): guard.validate_state(self.fx.context, state_of([]), bad, self.fx.upstream)


class LiveTests(unittest.TestCase):
    def setUp(self): self.fx = Fixture()

    def test_proof_exact_contract_and_read_only_calls(self):
        proof = self.fx.proof()
        self.assertEqual(set(proof["vpcs"]), set(VPCS))
        self.assertEqual(proof["vpcs"][VPCS[0]]["attachment_ids"], [ATTACHMENTS[0]])
        self.assertTrue(proof["requires_unfiltered_apply_recheck"])
        self.assertTrue(all((s, op) in guard.READ_OPERATIONS for s, op, _ in self.fx.calls))
        self.assertTrue(all(args[-2:] == ("--region", REGION) for _, _, args in self.fx.calls))
        self.assertFalse(any(op == "describe-network-interfaces" for _, op, _ in self.fx.calls))

    def test_live_wrong_account_owner_and_options_block(self):
        cases = [("get-caller-identity", None, "Account", "000000000000"),
                 ("describe-transit-gateways", "TransitGateways", "OwnerId", "000000000000"),
                 ("describe-transit-gateway-attachments", "TransitGatewayAttachments", "ResourceType", "vpn"),
                 ("describe-transit-gateway-attachments", "TransitGatewayAttachments", "ResourceOwnerId", "000000000000"),
                 ("describe-transit-gateway-vpc-attachments", "TransitGatewayVpcAttachments", "VpcOwnerId", "000000000000"),
                 ("describe-subnets", "Subnets", "AvailabilityZone", "ap-northeast-2d"),
                 ("describe-vpcs", "Vpcs", "CidrBlock", "10.99.0.0/16")]
        for operation, rows, field, value in cases:
            self.fx = Fixture(); target = self.fx.responses[operation]
            if rows: target = target[rows][0]
            target[field] = value
            with self.subTest(operation=operation, field=field), self.assertRaises(guard.SafeError): self.fx.proof()

    def test_unknown_attachment_missing_owned_attachment_and_duplicate_block(self):
        for mutation in (lambda rows: rows.append(dict(rows[0], TransitGatewayAttachmentId="tgw-attach-unknown")), lambda rows: rows.pop(), lambda rows: rows.append(rows[0])):
            self.fx = Fixture(); mutation(self.fx.responses["describe-transit-gateway-attachments"]["TransitGatewayAttachments"])
            with self.assertRaises(guard.SafeError): self.fx.proof()

    def test_read_failure_pagination_and_malformed_response_block(self):
        for value in ({}, {"TransitGateways": [], "NextToken": "secret"}, PermissionError("private-service-error")):
            self.fx = Fixture(); self.fx.responses["describe-transit-gateways"] = value
            with self.assertRaises(guard.SafeError) as caught: self.fx.proof()
            self.assertNotIn("private-service-error", str(caught.exception))

    def test_partial_association_retry_accepts_only_exact_terminal_disassociation(self):
        self.fx.state["resources"] = [r for r in self.fx.state["resources"] if not (r["type"] == "aws_ec2_transit_gateway_route_table_association" and r["instances"][0].get("index_key") == "workload")]
        self.fx.responses["describe-transit-gateway-attachments"]["TransitGatewayAttachments"][0]["Association"]["State"] = "disassociated"
        self.fx.responses[("get-transit-gateway-route-table-associations", TGTABLES[0])]["Associations"][0]["State"] = "disassociated"
        self.fx.proof()
        self.fx.responses["describe-transit-gateway-attachments"]["TransitGatewayAttachments"][0]["Association"]["State"] = "disassociating"
        with self.assertRaises(guard.SafeError): self.fx.proof()

    def test_live_propagation_and_unknown_route_and_incomplete_search_block(self):
        self.fx.responses["get-transit-gateway-route-table-propagations"]["TransitGatewayRouteTablePropagations"] = [{"State": "enabled"}]
        with self.assertRaises(guard.SafeError): self.fx.proof()
        for field, value in (("AdditionalRoutesAvailable", True), ("AdditionalRoutesAvailable", None)):
            self.fx = Fixture(); self.fx.responses[("search-transit-gateway-routes", TGTABLES[0])][field] = value
            with self.assertRaises(guard.SafeError): self.fx.proof()
        self.fx = Fixture(); self.fx.responses[("search-transit-gateway-routes", TGTABLES[0])]["Routes"][0]["DestinationCidrBlock"] = "10.99.0.0/16"
        with self.assertRaises(guard.SafeError): self.fx.proof()

    def test_global_foreign_route_and_missing_or_blackhole_owned_routes_block(self):
        for mutation in (lambda tables: tables.append({"RouteTableId": "rtb-foreign", "VpcId": "vpc-foreign", "OwnerId": ACCOUNT, "Routes": [{"TransitGatewayId": TGW, "DestinationCidrBlock": CIDRS[0], "State": "active"}]}),
                         lambda tables: tables[0]["Routes"].pop(), lambda tables: tables[0]["Routes"][1].update(State="blackhole")):
            self.fx = Fixture(); mutation(self.fx.responses["describe-route-tables"]["RouteTables"])
            with self.assertRaises(guard.SafeError): self.fx.proof()

    def test_guard_checks_dependencies_and_never_modifies_private_state(self):
        before = copy.deepcopy(self.fx.state)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); (path / "ci").mkdir()
            (path / "ci/deploy-roots.json").write_text(json.dumps({"dependencies": {guard.TRANSIT: [], guard.PEER: [], "terraform/environments/dev/workload": [guard.TRANSIT]}}))
            loader = lambda key: {"state": None, "fingerprint": {"exists": False}}
            result = guard.guard_destroy(tmp, self.fx.context, self.fx.state, plan_of(self.fx.state), self.fx.original, self.fx.upstream, self.fx.aws, loader)
            self.assertIn("dependent_states", result)
            loader = lambda key: {"state": self.fx.state, "fingerprint": {"exists": True, "version": "pinned"}}
            with self.assertRaises(guard.SafeError):
                guard.guard_destroy(tmp, self.fx.context, self.fx.state, plan_of(self.fx.state), self.fx.original, self.fx.upstream, self.fx.aws, loader)
        self.assertEqual(self.fx.state, before)

    def test_absence_requires_all_original_core_ids_and_no_residual_routes(self):
        with self.assertRaises(guard.SafeError): guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)
        for operation, key in (("describe-transit-gateways", "TransitGateways"), ("describe-transit-gateway-attachments", "TransitGatewayAttachments"), ("describe-transit-gateway-route-tables", "TransitGatewayRouteTables")):
            self.fx.responses[operation][key] = []
        with self.assertRaises(guard.SafeError): guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)
        self.fx.responses["describe-route-tables"]["RouteTables"] = []
        self.assertTrue(guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)["absent"])
        self.fx.responses["describe-transit-gateway-attachments"]["TransitGatewayAttachments"] = [{"State": "deleting"}]
        with self.assertRaises(guard.SafeError): guard.verify_absent(self.fx.context, self.fx.original, self.fx.aws)

    def test_aws_read_rejects_write_before_process_and_never_prints_errors(self):
        with patch.object(guard.subprocess, "run") as process:
            with self.assertRaises(guard.SafeError): guard.aws_read("ec2", "delete-transit-gateway")
            process.assert_not_called()


class PlanContractTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.plan = plan_of(self.fx.state)
        self.plan["planned_values"] = copy.deepcopy(self.plan["prior_state"]["values"])
        self.plan["variables"] = {"enable_inspection": {"value": False}}
        for change in self.plan["resource_changes"]:
            change["change"] = {"actions": ["no-op"], "before": change["change"]["before"], "after": copy.deepcopy(change["change"]["before"]), "after_unknown": {}}

    def validate(self):
        return guard.validate_plan_contracts(self.fx.context, self.plan, self.fx.upstream)

    def test_direct_evaluated_source_contract_passes(self):
        self.assertEqual(self.validate()["mode"], "direct-or-disabled")

    def test_creation_mode_allows_own_computed_ids_only(self):
        for row in self.plan["planned_values"]["root_module"]["resources"]:
            row["values"].pop("id", None)
            for key in ("transit_gateway_id", "transit_gateway_attachment_id", "transit_gateway_route_table_id"):
                row["values"].pop(key, None)
        for row in self.plan["resource_changes"]:
            row["change"]["actions"] = ["create"]
            row["change"]["before"] = None
            unknown = {"id": True}
            row["change"]["after"].pop("id", None)
            for key in ("transit_gateway_id", "transit_gateway_attachment_id", "transit_gateway_route_table_id"):
                if key in row["change"]["after"]:
                    row["change"]["after"].pop(key); unknown[key] = True
            row["change"]["after_unknown"] = unknown
        self.validate()

    def test_inspection_flags_shapes_and_unknown_markers_block_without_state(self):
        for value in (None, "false"):
            self.plan["variables"]["enable_inspection"]["value"] = value
            with self.subTest(value=value), self.assertRaises(guard.SafeError): self.validate()
        self.plan["variables"]["enable_inspection"]["value"] = False
        self.plan["resource_changes"].append({"mode": "managed", "type": "aws_networkfirewall_firewall", "address": "aws_networkfirewall_firewall.this[0]",
            "change": {"actions": ["create"], "before": None, "after": {}, "after_unknown": {"id": True}}})
        with self.assertRaises(guard.SafeError): self.validate()

    def test_change_after_cannot_hide_unsafe_fields_behind_planned_values(self):
        self.plan["resource_changes"][2]["change"]["after"]["auto_accept_shared_attachments"] = "enable"
        with self.assertRaises(guard.SafeError): self.validate()

    def test_retained_change_or_unknown_upstream_blocks(self):
        self.plan["resource_changes"][3]["change"]["after_unknown"]["vpc_id"] = True
        with self.assertRaises(guard.SafeError): self.validate()
        self.plan["resource_changes"][3]["change"]["after_unknown"] = {}
        self.plan["resource_changes"].append({"mode": "managed", "type": "aws_cloudwatch_log_group", "address": "aws_cloudwatch_log_group.firewall[\"ALERT\"]",
            "change": {"actions": ["create"], "before": None, "after": {}, "after_unknown": {"id": True}}})
        with self.assertRaises(guard.SafeError): self.validate()


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.state = state_of([
            resource("aws_vpc", "peer", VPCS[1], owner_id=ACCOUNT, default_network_acl_id="acl-1123456789abcdef0", default_route_table_id="rtb-2123456789abcdef0"),
            resource("aws_default_security_group", "peer", "sg-1123456789abcdef0", vpc_id=VPCS[1]),
            resource("aws_subnet", "peer", SUBNETS[1][0], REGION + "a", vpc_id=VPCS[1]),
            resource("aws_route_table", "peer", TABLES[1], REGION + "a", vpc_id=VPCS[1]),
            resource("aws_route_table_association", "peer", "rtbassoc-1123456789abcdef0", REGION + "a", subnet_id=SUBNETS[1][0], route_table_id=TABLES[1]),
        ])

    def test_peer_default_id_proof_is_derived_only_without_mutating_state(self):
        original = copy.deepcopy(self.state)
        rows = guard.validate_state(context(guard.PEER), self.state)
        guarded = guard._peer_resources(rows)
        self.assertEqual(len(guarded), len(rows) + 2)
        self.assertEqual(self.state, original)
        self.state["resources"][0]["instances"][0]["attributes"].pop("default_network_acl_id")
        with self.assertRaises(guard.SafeError): guard._peer_resources(guard.managed_resources(self.state))

    def test_real_peer_inventory_reuses_full_guard_and_blocks_unowned_eni(self):
        spec = importlib.util.spec_from_file_location("_peer_base_fixture", HERE / "test_vpc_lifecycle_guard.py")
        fixture_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture_module)
        fixture = fixture_module.Fixture()
        vpc, subnet, group, acl, default_table = fixture_module.VPC, fixture_module.SUBNET, fixture_module.SG, fixture_module.ACL, fixture_module.RT
        state = state_of([
            resource("aws_vpc", "peer", vpc, owner_id=ACCOUNT, default_network_acl_id=acl, default_route_table_id=default_table),
            resource("aws_default_security_group", "peer", group, vpc_id=vpc),
            resource("aws_subnet", "peer", subnet, REGION + "a", vpc_id=vpc),
            resource("aws_route_table", "peer", TABLES[1], REGION + "a", vpc_id=vpc),
            resource("aws_route_table_association", "peer", "rtbassoc-1123456789abcdef0", REGION + "a", subnet_id=subnet, route_table_id=TABLES[1]),
        ])
        for op, key in (("describe-internet-gateways", "InternetGateways"), ("describe-nat-gateways", "NatGateways"), ("describe-network-interfaces", "NetworkInterfaces")):
            fixture.responses[("ec2", op)][key] = []
        fixture.responses[("ec2", "describe-route-tables")]["RouteTables"] = [
            {"RouteTableId": identity, "VpcId": vpc, "OwnerId": ACCOUNT, "Routes": [{"GatewayId": "local"}], "Associations": []}
            for identity in (default_table, TABLES[1])]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); (path / "ci").mkdir()
            (path / "ci/deploy-roots.json").write_text(json.dumps({"dependencies": {guard.PEER: [], guard.TRANSIT: [guard.PEER]}}))
            def run():
                return guard.guard_destroy(tmp, context(guard.PEER), state, plan_of(state), guard.normalize_resources(state),
                                           aws_call=fixture.aws, load_state=lambda key: {"state": None, "fingerprint": {"exists": False}})
            self.assertEqual(run()["vpc_id"], vpc)
            fixture.responses[("ec2", "describe-network-interfaces")]["NetworkInterfaces"] = [{"NetworkInterfaceId": "eni-unknown", "VpcId": vpc, "OwnerId": ACCOUNT}]
            with self.assertRaises(guard.SafeError): run()
        self.assertTrue(all((s, o) in guard.READ_OPERATIONS for s, o, args in fixture.calls))

    def test_peer_wrong_vpc_route_association_and_igw_block(self):
        self.state["resources"][2]["instances"][0]["attributes"]["vpc_id"] = VPCS[0]
        with self.assertRaises(guard.SafeError): guard.validate_state(context(guard.PEER), self.state)
        self.state["resources"].append(resource("aws_internet_gateway", "peer", "igw-1123456789abcdef0", vpc_id=VPCS[1]))
        with self.assertRaises(guard.SafeError): guard.validate_state(context(guard.PEER), self.state)

    def test_only_exact_course_cloudwatch_addresses_are_allowed(self):
        guard._allowed(guard.TRANSIT, 'aws_cloudwatch_log_group.firewall["ALERT"]', "aws_cloudwatch_log_group")
        with self.assertRaises(guard.SafeError):
            guard._allowed(guard.TRANSIT, 'aws_cloudwatch_log_group.unrelated', "aws_cloudwatch_log_group")


if __name__ == "__main__": unittest.main()
