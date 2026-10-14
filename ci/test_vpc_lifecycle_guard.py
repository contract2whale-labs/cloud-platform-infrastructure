import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("vpc_lifecycle_guard", HERE / "vpc-lifecycle-guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
ACCOUNT = "123456789012"
VPC = "vpc-0123456789abcdef0"
SUBNET = "subnet-0123456789abcdef0"
SG = "sg-0123456789abcdef0"
ACL = "acl-0123456789abcdef0"
RT = "rtb-0123456789abcdef0"
IGW = "igw-0123456789abcdef0"
NAT = "nat-0123456789abcdef0"
EIP = "eipalloc-0123456789abcdef0"
NAT_ENI = "eni-0123456789abcdef0"
ENDPOINT = "vpce-1123456789abcdef0"
EP_ENI = "eni-1123456789abcdef0"
FOREIGN = "foreign-private-resource-DO_NOT_PRINT"


def resource(kind, name, identity, *, module=None, index=None, **values):
    row = {"mode": "managed", "type": kind, "name": name,
           "instances": [{"attributes": dict(id=identity, **values)}]}
    if module:
        row["module"] = module
    if index is not None:
        row["instances"][0]["index_key"] = index
    return row


def state_of(resources):
    return {"version": 4, "lineage": "private-lineage", "serial": 3,
            "resources": resources, "outputs": {"irrelevant_secret": {"value": "DO_NOT_PRINT"}}}


def plan_of(state):
    rows = guard.managed_resources(state)
    shown = [dict(address=r["address"], mode="managed", type=r["type"], name=r["name"], values=copy.deepcopy(r["values"])) for r in rows]
    return {"format_version": "1.2", "complete": True, "errored": False,
            "prior_state": {"format_version": "1.0", "values": {"root_module": {"resources": shown}}},
            "planned_values": {},
            "resource_changes": [dict(address=r["address"], mode="managed", type=r["type"],
                                      change={"actions": ["delete"], "before": copy.deepcopy(r["values"]), "after": None}) for r in rows]}


class Fixture:
    def __init__(self):
        self.state = state_of([
            resource("terraform_data", "workspace_guard", "workspace-id", input="default"),
            resource("aws_vpc", "this", VPC, module="module.vpc", index=0, owner_id=ACCOUNT),
            resource("aws_subnet", "public", SUBNET, module="module.vpc", index=0, vpc_id=VPC),
            resource("aws_default_security_group", "this", SG, module="module.vpc", index=0, vpc_id=VPC),
            resource("aws_default_network_acl", "this", ACL, module="module.vpc", index=0, vpc_id=VPC),
            resource("aws_default_route_table", "this", RT, module="module.vpc", index=0, vpc_id=VPC),
            resource("aws_internet_gateway", "this", IGW, module="module.vpc", index=0, vpc_id=VPC),
            resource("aws_eip", "lab_nat", EIP, index="ap-northeast-2a", domain="vpc"),
            resource("aws_nat_gateway", "lab", NAT, index="ap-northeast-2a", subnet_id=SUBNET,
                     allocation_id=EIP, network_interface_id=NAT_ENI),
            resource("aws_route", "private_nat", "private-route-id", index="ap-northeast-2a",
                     route_table_id=RT, nat_gateway_id=NAT),
        ])
        self.context = {"root": guard.ROOT, "environment": "dev", "workspace": "default", "account": ACCOUNT,
                        "backend": {"bucket": "private-state", "key": guard.STATE_KEY, "region": "ap-northeast-2"}}
        self.calls = []
        self.responses = {
            ("sts", "get-caller-identity"): {"Account": ACCOUNT},
            ("ec2", "describe-vpcs"): {"Vpcs": [{"VpcId": VPC, "OwnerId": ACCOUNT, "State": "available", "IsDefault": False}]},
            ("ec2", "describe-subnets"): {"Subnets": [{"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": ACCOUNT}]},
            ("ec2", "describe-security-groups"): {"SecurityGroups": [{"GroupId": SG, "VpcId": VPC, "OwnerId": ACCOUNT}]},
            ("ec2", "describe-network-acls"): {"NetworkAcls": [{"NetworkAclId": ACL, "VpcId": VPC, "OwnerId": ACCOUNT,
                                                             "Associations": [{"SubnetId": SUBNET}]}]},
            ("ec2", "describe-route-tables"): {"RouteTables": [{"RouteTableId": RT, "VpcId": VPC, "OwnerId": ACCOUNT,
                                                               "Routes": [{"GatewayId": "local"}, {"NatGatewayId": NAT}],
                                                               "Associations": [{"SubnetId": SUBNET}]}]},
            ("ec2", "describe-internet-gateways"): {"InternetGateways": [{"InternetGatewayId": IGW, "OwnerId": ACCOUNT,
                                                                         "Attachments": [{"VpcId": VPC}]}]},
            ("ec2", "describe-nat-gateways"): {"NatGateways": [{"NatGatewayId": NAT, "VpcId": VPC, "State": "available",
                                                               "SubnetId": SUBNET, "NatGatewayAddresses": [
                                                                   {"AllocationId": EIP, "NetworkInterfaceId": NAT_ENI}]}]},
            ("ec2", "describe-vpc-endpoints"): {"VpcEndpoints": []},
            ("ec2", "describe-network-interfaces"): {"NetworkInterfaces": [{"NetworkInterfaceId": NAT_ENI,
                                                                           "VpcId": VPC, "OwnerId": ACCOUNT,
                                                                           "SubnetId": SUBNET, "Groups": []}]},
            ("ec2", "describe-addresses"): {"Addresses": [{"AllocationId": EIP, "Domain": "vpc", "NetworkInterfaceId": NAT_ENI}]},
            ("ec2", "describe-instances"): {"Reservations": []},
            ("ec2", "describe-vpc-peering-connections"): {"VpcPeeringConnections": []},
            ("ec2", "describe-transit-gateway-vpc-attachments"): {"TransitGatewayVpcAttachments": []},
            ("ec2", "describe-vpn-gateways"): {"VpnGateways": []},
            ("ec2", "describe-egress-only-internet-gateways"): {"EgressOnlyInternetGateways": []},
            ("elb", "describe-load-balancers"): {"LoadBalancerDescriptions": []},
            ("elbv2", "describe-load-balancers"): {"LoadBalancers": []},
            ("eks", "list-clusters"): {"clusters": []},
            ("route53", "list-hosted-zones-by-vpc"): {"HostedZoneSummaries": []},
            ("route53profiles", "list-profile-associations"): {"ProfileAssociations": []},
        }

    def aws(self, service, operation, *args):
        self.calls.append((service, operation, args))
        response = self.responses[(service, operation)]
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)

    def endpoint(self):
        self.state["resources"].append(resource("aws_vpc_endpoint", "interface", ENDPOINT, vpc_id=VPC,
                                                network_interface_ids=[EP_ENI]))
        self.responses[("ec2", "describe-vpc-endpoints")]["VpcEndpoints"] = [{
            "VpcEndpointId": ENDPOINT, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available",
            "VpcEndpointType": "Interface", "SubnetIds": [SUBNET], "RouteTableIds": [],
            "NetworkInterfaceIds": [EP_ENI], "Groups": [{"GroupId": SG}],
        }]
        self.responses[("ec2", "describe-network-interfaces")]["NetworkInterfaces"].append({
            "NetworkInterfaceId": EP_ENI, "VpcId": VPC, "OwnerId": ACCOUNT, "SubnetId": SUBNET,
            "Groups": [{"GroupId": SG}], "RequesterManaged": True,
        })


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name)
        (self.workspace / "ci").mkdir()
        self.graph = {guard.ROOT: [], "terraform/environments/dev/platform/private-api": [guard.ROOT],
                      "terraform/environments/dev/eks": ["terraform/environments/dev/platform/private-api"],
                      "terraform/environments/dev/account-baseline": [],
                      "terraform/environments/prod/network/vpc": []}
        self.write_graph()
        self.fixture = Fixture()
        self.loads = []
        self.dependent = {}

    def write_graph(self):
        (self.workspace / "ci/deploy-roots.json").write_text(json.dumps({"dependencies": self.graph}))

    def load(self, key):
        self.loads.append(key)
        return self.dependent.get(key, {"state": None, "fingerprint": {"exists": False}})

    def run_guard(self, *, plan=None, **kwargs):
        return guard.guard_destroy(self.workspace, self.fixture.context, self.fixture.state,
                                   plan or plan_of(self.fixture.state), aws_call=self.fixture.aws, load_state=self.load, **kwargs)

    def test_owned_nat_service_eni_is_allowed_and_calls_are_read_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.run_guard()
        self.assertEqual(result["vpc_id"], VPC)
        self.assertIn("not a universal", result["limits"])
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(set(self.loads), {"platform/private-api/terraform.tfstate", "eks/terraform.tfstate"})
        self.assertTrue(all((s, o) in guard.READ_OPERATIONS for s, o, _ in self.fixture.calls))
        self.assertTrue(all(args[-2:] == ("--region", "ap-northeast-2") for _, _, args in self.fixture.calls))

    def test_owned_interface_endpoint_service_eni_is_allowed(self):
        self.fixture.endpoint()
        self.run_guard()

    def test_direct_private_zone_association_and_route53_read_failures_block(self):
        for response in ({"HostedZoneSummaries": [{"HostedZoneId": "private-zone", "Owner": {"OwningAccount": ACCOUNT}}]},
                         {"HostedZoneSummaries": [{"HostedZoneId": "service-zone", "Owner": {"OwningService": "private-service"}}]},
                         {"HostedZoneSummaries": [], "NextToken": "more-results"}, {}, guard.SafeError("Denied")):
            self.fixture = Fixture()
            self.fixture.responses[("route53", "list-hosted-zones-by-vpc")] = response
            with self.assertRaises(guard.SafeError):
                self.run_guard()

    def test_route53_profile_association_and_unknown_or_incomplete_reads_block(self):
        for response in ({"ProfileAssociations": [{"Id": "rpassoc-private", "ResourceId": VPC, "Status": "COMPLETE"}]},
                         {"ProfileAssociations": [{"Id": "rpassoc-private", "ResourceId": VPC, "Status": "DELETING"}]},
                         {"ProfileAssociations": [], "NextToken": "more-results"}, {}, guard.SafeError("Denied")):
            self.fixture = Fixture()
            self.fixture.responses[("route53profiles", "list-profile-associations")] = response
            with self.assertRaises(guard.SafeError):
                self.run_guard()
        self.fixture = Fixture()
        self.run_guard()
        call = next(args for service, operation, args in self.fixture.calls
                    if (service, operation) == ("route53profiles", "list-profile-associations"))
        self.assertEqual(call, ("--resource-id", VPC, "--region", "ap-northeast-2"))

    def test_absence_verification_uses_exact_id_account_and_complete_success(self):
        self.fixture.responses[("ec2", "describe-vpcs")] = {"Vpcs": []}
        self.assertEqual(guard.verify_vpc_absent(self.fixture.context, VPC, aws_call=self.fixture.aws),
                         {"vpc_id": VPC, "absent": True})
        self.assertIn("Name=vpc-id,Values=" + VPC, self.fixture.calls[-1][2])
        for response in ({"Vpcs": [{"VpcId": VPC}]}, {}, {"Vpcs": [], "NextToken": "token"}, guard.SafeError("Denied")):
            self.fixture.responses[("ec2", "describe-vpcs")] = response
            with self.assertRaises(guard.SafeError):
                guard.verify_vpc_absent(self.fixture.context, VPC, aws_call=self.fixture.aws)
        with self.assertRaises(guard.SafeError):
            guard.verify_vpc_absent(self.fixture.context, "Name=tag:Name", aws_call=self.fixture.aws)

    def test_direct_managed_eni_requires_unattached_non_service_ownership(self):
        self.fixture.state["resources"].append(resource("aws_network_interface", "test", EP_ENI, subnet_id=SUBNET))
        eni = {"NetworkInterfaceId": EP_ENI, "VpcId": VPC, "OwnerId": ACCOUNT, "SubnetId": SUBNET,
               "Groups": [], "RequesterManaged": False, "InterfaceType": "interface"}
        self.fixture.responses[("ec2", "describe-network-interfaces")]["NetworkInterfaces"].append(eni)
        self.run_guard()
        eni["RequesterManaged"] = True
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_owned_gateway_endpoint_without_eni_is_allowed(self):
        self.fixture.state["resources"].append(resource("aws_vpc_endpoint", "s3", ENDPOINT, vpc_id=VPC, network_interface_ids=[]))
        self.fixture.responses[("ec2", "describe-vpc-endpoints")]["VpcEndpoints"] = [{
            "VpcEndpointId": ENDPOINT, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available", "VpcEndpointType": "Gateway",
            "NetworkInterfaceIds": [], "SubnetIds": [], "RouteTableIds": [RT], "Groups": []}]
        self.fixture.responses[("ec2", "describe-route-tables")]["RouteTables"][0]["Routes"].append({"GatewayId": ENDPOINT})
        self.run_guard()

    def test_every_unsupported_managed_type_including_iam_and_logging_blocks(self):
        for kind in ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment", "aws_s3_bucket", "aws_kms_key",
                     "aws_secretsmanager_secret", "aws_flow_log", "aws_cloudwatch_log_group",
                     "aws_route53_resolver_query_log_config", "aws_eks_cluster", "aws_instance", "unknown_resource"):
            with self.subTest(kind=kind):
                self.fixture = Fixture()
                self.fixture.state["resources"].append(resource(kind, "misplaced", FOREIGN))
                with self.assertRaises(guard.SafeError):
                    self.run_guard()
                self.assertEqual(self.fixture.calls, [])

    def test_data_sources_do_not_establish_ownership_or_block_alone(self):
        data = resource("aws_iam_policy_document", "logs", "data-only")
        data["mode"] = "data"
        self.fixture.state["resources"].append(data)
        self.run_guard()
        self.fixture.state["resources"] = [dict(r, mode="data") if r["type"] == "aws_vpc" else r for r in self.fixture.state["resources"]]
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_exact_vpc_identity_cannot_come_from_outputs(self):
        self.fixture.state["outputs"]["vpc_id"] = {"value": VPC}
        self.fixture.state["resources"] = [r for r in self.fixture.state["resources"] if r["type"] != "aws_vpc"]
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_wrong_root_environment_account_and_workspace_block(self):
        for key, value in (("root", "terraform/environments/prod/network/vpc"), ("environment", "prod"),
                           ("account", "1234"), ("account", "１２３４５６７８９０１２"), ("workspace", "other")):
            with self.subTest(key=key):
                self.fixture = Fixture()
                self.fixture.context[key] = value
                with self.assertRaises(guard.SafeError):
                    self.run_guard()
        self.fixture = Fixture()
        self.fixture.responses[("sts", "get-caller-identity")]["Account"] = "999999999999"
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_backend_key_and_resource_arn_account_are_verified(self):
        self.fixture.context["backend"]["key"] = "eks/terraform.tfstate"
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture = Fixture()
        self.fixture.state["resources"][1]["instances"][0]["attributes"]["arn"] = "arn:aws:ec2:ap-northeast-2:999999999999:vpc/" + VPC
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_duplicate_vpc_deposed_and_duplicate_addresses_block(self):
        for change in (lambda s: s["resources"].append(resource("aws_vpc", "other", "vpc-1123456789abcdef0")),
                       lambda s: s["resources"][1]["instances"][0].update(deposed="1234"),
                       lambda s: s["resources"].append(copy.deepcopy(s["resources"][1]))):
            self.fixture = Fixture()
            change(self.fixture.state)
            with self.assertRaises(guard.SafeError):
                self.run_guard()

    def test_managed_reference_outside_vpc_state_blocks(self):
        for kind, field in (("aws_subnet", "vpc_id"), ("aws_nat_gateway", "subnet_id"), ("aws_route", "route_table_id")):
            self.fixture = Fixture()
            next(r for r in self.fixture.state["resources"] if r["type"] == kind)["instances"][0]["attributes"][field] = FOREIGN
            with self.assertRaises(guard.SafeError):
                self.run_guard()

    def test_plan_replace_create_noop_moved_or_missing_delete_blocks(self):
        for action in (["delete", "create"], ["create"], ["no-op"], ["forget"]):
            plan = plan_of(self.fixture.state)
            plan["resource_changes"][0]["change"]["actions"] = action
            with self.subTest(action=action), self.assertRaises(guard.SafeError):
                self.run_guard(plan=plan)
        plan = plan_of(self.fixture.state)
        plan["resource_changes"].pop()
        with self.assertRaises(guard.SafeError):
            self.run_guard(plan=plan)
        plan = plan_of(self.fixture.state)
        plan["resource_changes"][0]["previous_address"] = "terraform_data.old"
        with self.assertRaises(guard.SafeError):
            self.run_guard(plan=plan)

    def test_plan_prior_state_identity_and_remaining_resources_verified(self):
        plan = plan_of(self.fixture.state)
        plan["prior_state"]["values"]["root_module"]["resources"][1]["values"]["id"] = FOREIGN
        with self.assertRaises(guard.SafeError):
            self.run_guard(plan=plan)
        plan = plan_of(self.fixture.state)
        plan["planned_values"] = copy.deepcopy(plan["prior_state"]["values"])
        with self.assertRaises(guard.SafeError):
            self.run_guard(plan=plan)
        plan = plan_of(self.fixture.state)
        plan["complete"] = False
        with self.assertRaises(guard.SafeError):
            self.run_guard(plan=plan)

    def test_live_transitive_dependent_state_blocks_even_without_eni(self):
        self.dependent["eks/terraform.tfstate"] = {"state": state_of([resource("aws_eks_cluster", "cluster", "cluster-id")]),
                                                 "fingerprint": {"exists": True, "version": "v3"}}
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.assertFalse(any(op == "describe-vpcs" for _, op, _ in self.fixture.calls))

    def test_empty_dependent_state_is_allowed_but_unknown_and_denied_fail(self):
        self.dependent["eks/terraform.tfstate"] = {"state": state_of([]), "fingerprint": {"exists": True, "version": "v3"}}
        self.run_guard()
        self.dependent["eks/terraform.tfstate"]["fingerprint"]["version"] = "null"
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        with self.assertRaises(guard.SafeError):
            guard.check_dependents(self.workspace, lambda key: (_ for _ in ()).throw(guard.SafeError("Denied")))

    def test_dependency_registry_closure_handles_cycles_and_new_root(self):
        self.graph["terraform/environments/dev/data"] = ["terraform/environments/dev/eks"]
        self.graph["terraform/environments/dev/eks"].append("terraform/environments/dev/data")
        self.write_graph()
        self.assertIn("terraform/environments/dev/data", guard.dependent_roots(self.workspace))
        self.run_guard()
        self.assertIn("data/terraform.tfstate", self.loads)
        self.graph["terraform/environments/dev/eks"].append("unknown-root")
        self.write_graph()
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_real_registry_contains_indirect_queue_secrets_and_no_prod(self):
        roots = guard.dependent_roots(HERE.parent)
        self.assertIn("terraform/environments/dev/platform/queue-secrets", roots)
        self.assertIn("terraform/environments/dev/account-integrations", roots)
        self.assertFalse(any("/prod/" in r for r in roots))

    def test_foreign_topology_resources_block_despite_terraform_tags(self):
        cases = [("describe-subnets", "Subnets", "SubnetId"), ("describe-security-groups", "SecurityGroups", "GroupId"),
                 ("describe-network-acls", "NetworkAcls", "NetworkAclId"), ("describe-route-tables", "RouteTables", "RouteTableId"),
                 ("describe-internet-gateways", "InternetGateways", "InternetGatewayId"),
                 ("describe-nat-gateways", "NatGateways", "NatGatewayId"),
                 ("describe-network-interfaces", "NetworkInterfaces", "NetworkInterfaceId")]
        for operation, key, field in cases:
            self.fixture = Fixture()
            rows = self.fixture.responses[("ec2", operation)][key]
            foreign = copy.deepcopy(rows[0])
            foreign[field] = FOREIGN
            foreign["Tags"] = [{"Key": "ManagedBy", "Value": "Terraform"}]
            rows.append(foreign)
            with self.subTest(operation=operation), self.assertRaises(guard.SafeError) as error:
                self.run_guard()
            self.assertNotIn(FOREIGN, str(error.exception))

    def test_missing_live_owned_resource_and_unstable_nat_block(self):
        self.fixture.responses[("ec2", "describe-subnets")]["Subnets"] = []
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture = Fixture()
        self.fixture.responses[("ec2", "describe-nat-gateways")]["NatGateways"][0]["State"] = "deleting"
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_foreign_endpoint_and_wrong_nat_or_endpoint_eni_block(self):
        self.fixture.endpoint()
        self.fixture.responses[("ec2", "describe-vpc-endpoints")]["VpcEndpoints"][0]["VpcEndpointId"] = FOREIGN
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture = Fixture()
        self.fixture.responses[("ec2", "describe-nat-gateways")]["NatGateways"][0]["NatGatewayAddresses"][0]["NetworkInterfaceId"] = FOREIGN
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture = Fixture()
        self.fixture.endpoint()
        self.fixture.responses[("ec2", "describe-vpc-endpoints")]["VpcEndpoints"][0]["NetworkInterfaceIds"] = [FOREIGN]
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_owned_eni_attached_to_instance_and_foreign_eip_use_block(self):
        self.fixture.responses[("ec2", "describe-network-interfaces")]["NetworkInterfaces"][0]["Attachment"] = {"InstanceId": "i-foreign"}
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture = Fixture()
        self.fixture.responses[("ec2", "describe-addresses")]["Addresses"][0]["NetworkInterfaceId"] = FOREIGN
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_eks_elb_peer_tgw_vpn_and_ipv6_consumers_block(self):
        cases = [(("eks", "list-clusters"), {"clusters": ["private-cluster"]}),
                 (("elb", "describe-load-balancers"), {"LoadBalancerDescriptions": [{"VPCId": VPC}]}),
                 (("elbv2", "describe-load-balancers"), {"LoadBalancers": [{"VpcId": VPC}]}),
                 (("ec2", "describe-vpc-peering-connections"), {"VpcPeeringConnections": [{"Status": {"Code": "active"}}]}),
                 (("ec2", "describe-transit-gateway-vpc-attachments"), {"TransitGatewayVpcAttachments": [{"State": "pendingAcceptance"}]}),
                 (("ec2", "describe-vpn-gateways"), {"VpnGateways": [{"VpnGatewayId": FOREIGN}]}),
                 (("ec2", "describe-egress-only-internet-gateways"), {"EgressOnlyInternetGateways": [{"Attachments": [{"VpcId": VPC}]}]}),
                 (("ec2", "describe-instances"), {"Reservations": [{"Instances": [{"State": {"Name": "stopped"}}]}]})]
        for key, response in cases:
            self.fixture = Fixture()
            self.fixture.responses[key] = response
            self.fixture.responses[("eks", "describe-cluster")] = {"cluster": {"resourcesVpcConfig": {"vpcId": VPC}}}
            with self.subTest(api=key), self.assertRaises(guard.SafeError):
                self.run_guard()

    def test_deleted_peering_tgw_and_terminated_instances_are_not_live(self):
        self.fixture.responses[("ec2", "describe-vpc-peering-connections")] = {"VpcPeeringConnections": [{"Status": {"Code": "deleted"}}]}
        self.fixture.responses[("ec2", "describe-transit-gateway-vpc-attachments")] = {"TransitGatewayVpcAttachments": [{"State": "deleted"}]}
        self.fixture.responses[("ec2", "describe-instances")] = {"Reservations": [{"Instances": [{"State": {"Name": "terminated"}}]}]}
        self.run_guard()
        filters = [args for _, op, args in self.fixture.calls if op == "describe-vpc-peering-connections"]
        self.assertEqual(len(filters), 2)
        self.assertTrue(any("accepter-vpc-info.vpc-id" in args[1] for args in filters))

    def test_unmanaged_route_and_foreign_default_vpc_block(self):
        self.fixture.responses[("ec2", "describe-route-tables")]["RouteTables"][0]["Routes"].append({"TransitGatewayId": FOREIGN})
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture = Fixture()
        self.fixture.responses[("ec2", "describe-vpcs")]["Vpcs"][0]["IsDefault"] = True
        with self.assertRaises(guard.SafeError):
            self.run_guard()

    def test_api_denial_missing_collection_and_pagination_fail_closed(self):
        for response in (guard.SafeError("A required read was denied."), {}, {"NetworkInterfaces": [], "NextToken": "private-token"}):
            self.fixture = Fixture()
            self.fixture.responses[("ec2", "describe-network-interfaces")] = response
            with self.assertRaises(guard.SafeError):
                self.run_guard()

    def test_normalize_nested_module_and_string_index(self):
        records = guard.normalize_resources(self.fixture.state)
        self.assertIn({"address": 'aws_nat_gateway.lab["ap-northeast-2a"]', "type": "aws_nat_gateway", "id": NAT}, records)
        shown = plan_of(self.fixture.state)["prior_state"]
        rows = shown["values"]["root_module"].pop("resources")
        shown["values"]["root_module"]["child_modules"] = [{"address": "module.nested", "resources": rows}]
        self.assertEqual(guard.normalize_resources(shown), records)

    def test_partial_down_with_vpc_absent_requires_original_map_and_live_absence(self):
        original = guard.normalize_resources(self.fixture.state)
        self.fixture.state = state_of([r for r in self.fixture.state["resources"] if r["type"] == "aws_eip"])
        for key, response in self.fixture.responses.items():
            if key[0] != "sts" and key != ("ec2", "describe-addresses"):
                for field in response:
                    if isinstance(response[field], list):
                        response[field] = []
        self.fixture.responses[("ec2", "describe-addresses")]["Addresses"][0].pop("NetworkInterfaceId")
        self.run_guard(expected_vpc_id=VPC, expected_resources=original)
        with self.assertRaises(guard.SafeError):
            self.run_guard(expected_vpc_id=VPC)
        self.fixture.responses[("ec2", "describe-vpcs")]["Vpcs"] = Fixture().responses[("ec2", "describe-vpcs")]["Vpcs"]
        with self.assertRaises(guard.SafeError):
            self.run_guard(expected_vpc_id=VPC, expected_resources=original)

    def test_partial_down_retains_exact_original_aws_defaults_after_state_forgets_them(self):
        original = guard.normalize_resources(self.fixture.state)
        defaults = {"aws_default_security_group", "aws_default_network_acl", "aws_default_route_table"}
        self.fixture.state["resources"] = [r for r in self.fixture.state["resources"] if r["type"] not in defaults]
        self.run_guard(expected_vpc_id=VPC, expected_resources=original)
        self.fixture.responses[("ec2", "describe-security-groups")]["SecurityGroups"][0]["GroupId"] = FOREIGN
        with self.assertRaises(guard.SafeError):
            self.run_guard(expected_vpc_id=VPC, expected_resources=original)

    def test_partial_down_can_retry_owned_detached_internet_gateway(self):
        original = guard.normalize_resources(self.fixture.state)
        self.fixture.responses[("ec2", "describe-internet-gateways")]["InternetGateways"][0]["Attachments"] = []
        original_call = self.fixture.aws
        def detached(service, operation, *args):
            if operation == "describe-internet-gateways" and "--filters" in args:
                return {"InternetGateways": []}
            return original_call(service, operation, *args)
        self.fixture.aws = detached
        self.run_guard(expected_vpc_id=VPC, expected_resources=original)
        self.assertTrue(any("--internet-gateway-ids" in args for _, operation, args in self.fixture.calls
                            if operation == "describe-internet-gateways"))

    def test_empty_down_noop_requires_pinned_original_identity_and_complete_reads(self):
        original = guard.normalize_resources(self.fixture.state)
        self.fixture.state = state_of([])
        for key, response in self.fixture.responses.items():
            if key[0] != "sts":
                for field in response:
                    if isinstance(response[field], list):
                        response[field] = []
        empty_plan = plan_of(self.fixture.state)
        empty_plan.pop("prior_state")
        empty_plan.pop("resource_changes")
        self.run_guard(plan=empty_plan, expected_vpc_id=VPC, expected_resources=original)
        with self.assertRaises(guard.SafeError):
            self.run_guard()
        self.fixture.responses[("ec2", "describe-vpcs")] = guard.SafeError("Read denied")
        with self.assertRaises(guard.SafeError):
            self.run_guard(expected_vpc_id=VPC, expected_resources=original)

    def test_original_control_map_prevents_new_resources_or_identity_substitution(self):
        original = guard.normalize_resources(self.fixture.state)
        self.fixture.state["resources"][7]["instances"][0]["attributes"]["id"] = FOREIGN
        with self.assertRaises(guard.SafeError):
            self.run_guard(expected_vpc_id=VPC, expected_resources=original)
        self.fixture = Fixture()
        with self.assertRaises(guard.SafeError):
            self.run_guard(expected_vpc_id="vpc-1123456789abcdef0", expected_resources=original)


class StateReaderTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.state = state_of([])
        self.metadata = {"VersionId": "exact-v1", "ETag": "etag", "ContentLength": 120, "ServerSideEncryption": "AES256"}
        self.objects = []
        self.head_calls = 0

    def aws(self, service, operation, *args):
        self.calls.append((service, operation, args))
        if operation == "list-objects-v2":
            return {"KeyCount": 1, "IsTruncated": False, "Contents": [{"Key": "eks/terraform.tfstate"}]}
        self.head_calls += 1
        return copy.deepcopy(self.metadata)

    def read(self, *args):
        self.objects.append(args)
        return self.state, copy.deepcopy(self.metadata)

    def reader(self):
        return guard.VersionedStateReader("private-state", ACCOUNT, "ap-northeast-2", aws_call=self.aws, object_reader=self.read)

    def test_exact_version_expected_owner_and_memory_loader_contract(self):
        result = self.reader()("eks/terraform.tfstate")
        self.assertEqual(result["fingerprint"]["version"], "exact-v1")
        self.assertEqual(self.objects[0][-1], "exact-v1")
        self.assertEqual(self.head_calls, 2)
        self.assertTrue(all("--expected-bucket-owner" in args for _, _, args in self.calls))

    def test_absence_requires_successful_complete_listing(self):
        reader = self.reader()
        reader.aws = lambda *args: {"KeyCount": 0, "IsTruncated": False}
        self.assertEqual(reader("eks/terraform.tfstate"), {"state": None, "fingerprint": {"exists": False}})
        reader.aws = lambda *args: {"IsTruncated": True, "Contents": []}
        with self.assertRaises(guard.SafeError):
            reader("eks/terraform.tfstate")
        reader.aws = lambda *args: {}
        with self.assertRaises(guard.SafeError):
            reader("eks/terraform.tfstate")
        reader.aws = lambda *args: (_ for _ in ()).throw(guard.SafeError("Denied"))
        with self.assertRaises(guard.SafeError):
            reader("eks/terraform.tfstate")

    def test_wrong_version_encryption_and_concurrent_state_change_block(self):
        for key, value in (("VersionId", "null"), ("ServerSideEncryption", None), ("ContentLength", 0)):
            reader = self.reader()
            metadata = copy.deepcopy(self.metadata)
            metadata[key] = value
            reader.object_reader = lambda *args: (self.state, metadata)
            with self.subTest(key=key), self.assertRaises(guard.SafeError):
                reader("eks/terraform.tfstate")
        reader = self.reader()
        def changed(*args):
            result = self.aws(*args)
            if self.head_calls == 2:
                result["VersionId"] = "newer-version"
            return result
        reader.aws = changed
        self.head_calls = 0
        with self.assertRaises(guard.SafeError):
            reader("eks/terraform.tfstate")

    def test_raw_state_and_metadata_stream_through_anonymous_pipe(self):
        original_popen = subprocess.Popen
        calls = []
        def local_process(args, **kwargs):
            calls.append(args)
            path = next(value for value in args if value.startswith("/proc/self/fd/"))
            body = json.dumps(self.state)
            metadata = dict(self.metadata, ContentLength=len(body.encode()))
            program = "from pathlib import Path; Path(" + repr(path) + ").write_text(" + repr(body) + "); print(" + repr(json.dumps(metadata)) + ")"
            return original_popen([sys.executable, "-c", program], **kwargs)
        output = io.StringIO()
        with patch.object(guard.subprocess, "Popen", side_effect=local_process), contextlib.redirect_stdout(output):
            state, metadata = guard.read_object_memory("private-state", ACCOUNT, "ap-northeast-2", "eks/terraform.tfstate", "exact-v1")
        self.assertEqual(state, self.state)
        self.assertEqual(metadata["VersionId"], "exact-v1")
        self.assertIn("--version-id", calls[0])
        self.assertEqual(output.getvalue(), "")

    def test_read_adapter_rejects_mutations_and_suppresses_private_stderr(self):
        with self.assertRaises(guard.SafeError):
            guard.aws_read("ec2", "delete-vpc", "--vpc-id", VPC)
        result = subprocess.CompletedProcess([], 1, stdout=b"PRIVATE_OUTPUT", stderr=b"PRIVATE_ERROR")
        with patch.object(guard.subprocess, "run", return_value=result):
            with self.assertRaises(guard.SafeError) as error:
                guard.aws_read("ec2", "describe-vpcs")
        self.assertNotIn("PRIVATE", str(error.exception))


if __name__ == "__main__":
    unittest.main()
