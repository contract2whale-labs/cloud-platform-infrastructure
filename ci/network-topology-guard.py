#!/usr/bin/env python3
"""Read-only, fail-closed BU05 peer/direct/inspection-transit lifecycle guard.

No output, State edits, AWS mutations, labels-as-authority, or force bypass.
The parent pins source/input/backend identities and calls this immediately before
apply. Original identity records are private. A deferred preplan proof is never
permission to apply a VPC destroy with consumers still present.

Inspection uses exact firewall -> endpoint -> ENI service relationships. TGW
ENIs use the explicitly bounded complete attachment/VPC/subnet/account/type
relationship proof, because AWS does not expose their parent attachment ID.
All S3/KMS/IAM remain protected. Exact owned course CloudWatch groups may be
removed; externally retained log groups are verified and never managed here.

API contracts: docs.aws.amazon.com/cli/latest/reference/ec2/
  describe-transit-gateway-attachments.html
  describe-transit-gateway-vpc-attachments.html
  search-transit-gateway-routes.html (AdditionalRoutesAvailable must be false)
"""
import copy
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess

_SPEC = importlib.util.spec_from_file_location("_network_guard_vpc_private", Path(__file__).with_name("vpc-lifecycle-guard.py"))
_vpc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_vpc)
SafeError = _vpc.SafeError
require = _vpc.require
object_value = _vpc.object_value
array = _vpc.array
managed_resources = _vpc.managed_resources
normalize_resources = _vpc.normalize_resources
complete_list = _vpc.complete_list
VPC = "terraform/environments/dev/network/vpc"
PEER = "terraform/environments/dev/network/peer"
TRANSIT = "terraform/environments/dev/network/transit"
AZ = r'ap-northeast-2[abc]'
KEY = r'[a-zA-Z0-9_/-]+'
INDEX = r'\["' + KEY + r'"\]'
ADDRESS_PATTERNS = {
    PEER: {
        "aws_vpc": r'aws_vpc\.peer',
        "aws_default_security_group": r'aws_default_security_group\.peer',
        "aws_subnet": r'aws_subnet\.peer\["' + AZ + r'"\]',
        "aws_route_table": r'aws_route_table\.peer\["' + AZ + r'"\]',
        "aws_route_table_association": r'aws_route_table_association\.peer\["' + AZ + r'"\]',
    },
    TRANSIT: {
        "terraform_data": r'terraform_data\.(?:contract\[0\]|lifecycle)',
        "aws_ec2_transit_gateway": r'aws_ec2_transit_gateway\.this\[0\]',
        "aws_ec2_transit_gateway_vpc_attachment": r'aws_ec2_transit_gateway_vpc_attachment\.(?:edge' + INDEX + r'|inspection\[0\])',
        "aws_ec2_transit_gateway_route_table": r'aws_ec2_transit_gateway_route_table\.(?:workload|peer|after_inspection)\[0\]',
        "aws_ec2_transit_gateway_route_table_association": r'aws_ec2_transit_gateway_route_table_association\.(?:edge' + INDEX + r'|inspection\[0\])',
        "aws_ec2_transit_gateway_route": r'aws_ec2_transit_gateway_route\.(?:(?:to_peer|to_peer_inspected|after_inspection)' + INDEX + r'|(?:to_workload|to_workload_inspected)\[0\])',
        "aws_route": r'aws_route\.(?:edge|inspection_in|inspection_out)' + INDEX,
        "aws_vpc": r'aws_vpc\.inspection\[0\]',
        "aws_default_security_group": r'aws_default_security_group\.inspection\[0\]',
        "aws_subnet": r'aws_subnet\.inspection_(?:transit|firewall)\["' + AZ + r'"\]',
        "aws_route_table": r'aws_route_table\.inspection_(?:transit|firewall)\["' + AZ + r'"\]',
        "aws_route_table_association": r'aws_route_table_association\.inspection_(?:transit|firewall)\["' + AZ + r'"\]',
        "aws_networkfirewall_rule_group": r'aws_networkfirewall_rule_group\.this\[0\]',
        "aws_networkfirewall_firewall_policy": r'aws_networkfirewall_firewall_policy\.this\[0\]',
        "aws_networkfirewall_firewall": r'aws_networkfirewall_firewall\.this\[0\]',
        "aws_networkfirewall_logging_configuration": r'aws_networkfirewall_logging_configuration\.this\[0\]',
        "aws_cloudwatch_log_group": r'aws_cloudwatch_log_group\.firewall\["(?:ALERT|FLOW)"\]', 
    },
}
ALLOWED_TYPES = {root: frozenset(patterns) for root, patterns in ADDRESS_PATTERNS.items()}
READ_OPERATIONS = _vpc.READ_OPERATIONS | frozenset({
    ("ec2", "describe-transit-gateways"),
    ("ec2", "describe-transit-gateway-attachments"),
    ("ec2", "describe-transit-gateway-route-tables"),
    ("ec2", "get-transit-gateway-route-table-associations"),
    ("ec2", "get-transit-gateway-route-table-propagations"),
    ("ec2", "search-transit-gateway-routes"),
})
ID_PREFIXES = {
    "aws_vpc": "vpc", "aws_subnet": "subnet", "aws_default_security_group": "sg",
    "aws_route_table": "rtb", "aws_route_table_association": "rtbassoc",
    "aws_ec2_transit_gateway": "tgw", "aws_ec2_transit_gateway_vpc_attachment": "tgw-attach",
    "aws_ec2_transit_gateway_route_table": "tgw-rtb",
}
TERMINAL = frozenset({"deleted", "rejected", "failed"})
LIMITS = ("Exact managed BU05 peer/direct/inspection identities and regional topology reads only; "
          "not an account-wide dependency proof. TGW ENIs have bounded complete attachment/"
          "subnet/account/type ownership, not immutable parent IDs. AWS rehearsal is required. "
          "Owned course CloudWatch groups are disposable; S3/KMS/IAM are never accepted. Reads are not atomic; freeze "
          "other writers and rerun the unfiltered guard immediately before apply.")


def aws_read(service, operation, *args):
    require((service, operation) in READ_OPERATIONS, "Only approved read-only topology APIs are allowed.")
    process = subprocess.run(["aws", service, operation, *args, "--output", "json", "--no-cli-pager"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if process.returncode != 0 and (service, operation) == ("network-firewall", "describe-resource-policy"):
        if re.search(rb"^An error occurred \(ResourceNotFoundException\) when calling the DescribeResourcePolicy operation:", process.stderr, re.MULTILINE):
            raise ResourcePolicyAbsent("No resource policy was returned for this exact firewall resource.")
    require(process.returncode == 0, "A topology read failed; destruction is blocked.")
    try:
        return object_value(json.loads(process.stdout))
    except (ValueError, TypeError):
        raise SafeError("A topology read returned invalid JSON.") from None


def validate_context(context):
    context = object_value(context)
    root = context.get("root")
    require(root in ALLOWED_TYPES and context.get("environment") == "dev" and context.get("workspace") == "default",
            "Only the default dev BU05 peer or transit root is supported.")
    account = context.get("account")
    backend = object_value(context.get("backend"))
    require(isinstance(account, str) and re.fullmatch(r"\d{12}", account), "An exact configured dev account is required.")
    require(backend.get("key") == root.removeprefix("terraform/environments/dev/") + "/terraform.tfstate" and
            isinstance(backend.get("bucket"), str) and backend["bucket"] and backend.get("region") == "ap-northeast-2",
            "The BU05 backend identity or course region is invalid.")
    return account, backend["region"]


def _allowed(root, address, kind):
    if isinstance(kind, str) and kind.startswith(("aws_s3_", "aws_kms_", "aws_iam_")):
        raise SafeError("Retained data, IAM, S3 or KMS must be separated before lifecycle use.")
    require(isinstance(kind, str) and kind in ALLOWED_TYPES[root] and isinstance(address, str) and
            re.fullmatch(ADDRESS_PATTERNS[root][kind], address) is not None,
            "An unsupported managed type or resource address exists in network State.")


def original_resources(expected_resources, root=None):
    rows = array(expected_resources)
    seen = set()
    for row in rows:
        row = object_value(row)
        require(set(row) == {"address", "type", "id"} and all(isinstance(row[k], str) and row[k] for k in row),
                "Original network resource identities are invalid.")
        require(row["address"] not in seen, "Duplicate original network resource address.")
        seen.add(row["address"])
        if root is not None:
            _allowed(root, row["address"], row["type"])
        else:
            require(any(row["type"] in kinds and re.fullmatch(ADDRESS_PATTERNS[r][row["type"]], row["address"])
                        for r, kinds in ALLOWED_TYPES.items()), "An original resource is outside the BU05 scope.")
    identities = [(row["type"], row["id"]) for row in rows]
    require(len(identities) == len(set(identities)), "Multiple original addresses claim the same managed identity.")
    for row in rows:
        if row["type"] in ID_PREFIXES:
            require(re.fullmatch(ID_PREFIXES[row["type"]] + r"-(?:[0-9a-f]{8}|[0-9a-f]{17})", row["id"]),
                    "An original AWS network identity has an invalid format.")
    return rows


def _ids(rows, kind):
    return {r["id"] if "id" in r else r["values"]["id"] for r in rows if r["type"] == kind}


def _arn(value, account, region):
    require(isinstance(value, str), "A resource ARN is invalid.")
    pieces = value.split(":", 5)
    require(len(pieces) == 6 and pieces[:2] == ["arn", "aws"] and pieces[3] == region and pieces[4] == account,
            "A resource ARN is outside the approved account or region.")


def _cidr(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError):
        raise SafeError("A managed route has an invalid canonical destination.") from None
    require(network.version == 4, "Only the course IPv4 topology is supported.")
    return str(network)


def _upstream(upstream_states):
    result = []
    upstream_states = object_value(upstream_states or {})
    for root, state in upstream_states.items():
        require(root in (VPC, PEER), "An unregistered upstream network State was supplied.")
        state = object_value(state)
        if "state" in state:
            state = object_value(state["state"])
        rows = managed_resources(state)
        require(len(_ids(rows, "aws_vpc")) == 1, "Each upstream State must own exactly one VPC.")
        for row in rows:
            if row["type"] in ("aws_vpc", "aws_subnet", "aws_route_table", "aws_default_route_table"):
                require(isinstance(row["values"].get("id"), str) and row["values"]["id"],
                        "Upstream managed network identity is missing.")
                if row["type"] == "aws_vpc":
                    _cidr(row["values"].get("cidr_block"))
                result.append(dict(row, root=root))
    require(len({r["values"]["id"] for r in result}) == len(result), "Upstream network ownership is duplicated.")
    return result


def validate_state(context, state, expected_resources=None, upstream_states=None):
    account, region = validate_context(context)
    root = context["root"]
    rows = managed_resources(state)
    for row in rows:
        _allowed(root, row["address"], row["type"])
        value = row["values"]
        require(isinstance(value.get("id"), str) and value["id"], "A managed network object has no exact identity.")
        if value.get("owner_id"):
            require(value["owner_id"] == account, "A managed resource is owned by another account.")
        if value.get("arn"):
            _arn(value["arn"], account, region)
    scope = original_resources(expected_resources, root) if expected_resources is not None else original_resources(normalize_resources(state), root)
    approved = {r["address"]: (r["type"], r["id"]) for r in scope}
    require(all(approved.get(r["address"]) == (r["type"], r["values"]["id"]) for r in rows),
            "Remaining State is not a subset of the original pinned network identities.")
    owned_vpcs = _ids(scope, "aws_vpc")
    require(len(owned_vpcs) <= 1, "Multiple managed VPCs are outside this root's scope.")
    if root == PEER:
        require(not rows or len(owned_vpcs) == 1, "Peer State requires its original managed VPC identity.")
        upstream = []
    else:
        upstream = _upstream(upstream_states)
        require(len(_ids(scope, "aws_ec2_transit_gateway")) <= 1, "Multiple TGWs are outside the course topology.")
        if any(r["type"] not in ("terraform_data",) for r in rows):
            require(len(_ids(scope, "aws_ec2_transit_gateway")) == 1, "Transit resources require the original managed TGW.")
        if any(r["type"] in ("aws_ec2_transit_gateway_vpc_attachment", "aws_route") for r in rows):
            require({r["root"] for r in upstream} == {VPC, PEER}, "Both upstream managed network States are required.")
    vpcs = owned_vpcs | _ids(upstream, "aws_vpc")
    require(len(vpcs) == len(owned_vpcs) + len(_ids(upstream, "aws_vpc")), "Inspection and upstream VPC identities overlap.")
    subnets = _ids(scope, "aws_subnet") | _ids(upstream, "aws_subnet")
    tables = _ids(scope, "aws_route_table") | _ids(upstream, "aws_route_table") | _ids(upstream, "aws_default_route_table")
    subnet_values = {r["values"]["id"]: r["values"] for r in rows + upstream if r["type"] == "aws_subnet"}
    table_values = {r["values"]["id"]: r["values"] for r in rows + upstream if r["type"] in ("aws_route_table", "aws_default_route_table")}
    vpc_values = {r["values"]["id"]: r["values"] for r in rows + upstream if r["type"] == "aws_vpc"}
    attachments = {r["values"]["id"]: r["values"] for r in rows if r["type"] == "aws_ec2_transit_gateway_vpc_attachment"}
    for value in vpc_values.values():
        if value.get("cidr_block"):
            _cidr(value["cidr_block"])
    for row in rows:
        kind, value = row["type"], row["values"]
        if kind in ("aws_subnet", "aws_default_security_group", "aws_route_table", "aws_networkfirewall_firewall"):
            require(value.get("vpc_id") in owned_vpcs, "A managed network object refers to a foreign VPC.")
        if kind == "aws_route_table_association":
            require(value.get("subnet_id") in _ids(scope, "aws_subnet") and value.get("route_table_id") in _ids(scope, "aws_route_table"),
                    "A route association refers to infrastructure outside its root.")
        if kind == "aws_ec2_transit_gateway":
            require(all(value.get(k) == "disable" for k in ("default_route_table_association", "default_route_table_propagation", "auto_accept_shared_attachments")),
                    "TGW automatic association, propagation or sharing must already be disabled.")
        if kind in ("aws_ec2_transit_gateway_vpc_attachment", "aws_ec2_transit_gateway_route_table"):
            require(value.get("transit_gateway_id") in _ids(scope, "aws_ec2_transit_gateway"), "A resource refers to a foreign TGW.")
        if kind == "aws_ec2_transit_gateway_vpc_attachment":
            if row["address"].startswith("aws_ec2_transit_gateway_vpc_attachment.edge"):
                key = json.loads(row["address"].split(".edge", 1)[1])[0]
                upstream_root = VPC if key == "workload" else PEER
                require(value.get("vpc_id") in {r["values"]["id"] for r in upstream if r["root"] == upstream_root and r["type"] == "aws_vpc"},
                        "An edge attachment key refers to the wrong managed upstream VPC.")
            selected = array(value.get("subnet_ids"))
            require(value.get("vpc_id") in vpcs and selected and len(selected) == len(set(selected)) and set(selected) <= subnets,
                    "A TGW attachment has unowned VPC or subnet identities.")
            require(len(selected) == 3 and {subnet_values.get(s, {}).get("availability_zone") for s in selected} ==
                    {region + az for az in "abc"}, "Course TGW attachments require one exact managed subnet in each of the three approved AZs.")
            require(all(s in subnet_values and subnet_values[s].get("vpc_id") == value["vpc_id"] for s in selected),
                    "Attachment subnet ownership differs from managed State.")
            inspection_attachment = row["address"] == "aws_ec2_transit_gateway_vpc_attachment.inspection[0]"
            if inspection_attachment:
                require(set(selected) <= {r["values"]["id"] for r in rows if r["type"] == "aws_subnet" and r["address"].startswith("aws_subnet.inspection_transit")},
                        "Inspection TGW attachment must use only the exact managed transit subnets.")
            require(value.get("appliance_mode_support") == ("enable" if inspection_attachment else "disable") and
                    value.get("dns_support") == "enable" and value.get("ipv6_support") == "disable",
                    "Attachment appliance, DNS or IPv4 course settings differ from State.")
            require(all(value.get(k) is False for k in ("transit_gateway_default_route_table_association", "transit_gateway_default_route_table_propagation")),
                    "Attachment default routing must already be disabled.")
        if kind in ("aws_ec2_transit_gateway_route_table_association", "aws_ec2_transit_gateway_route"):
            require(value.get("transit_gateway_attachment_id") in _ids(scope, "aws_ec2_transit_gateway_vpc_attachment") and
                    value.get("transit_gateway_route_table_id") in _ids(scope, "aws_ec2_transit_gateway_route_table"),
                    "A transit route or association refers outside original managed identities.")
        if kind == "aws_ec2_transit_gateway_route":
            _cidr(value.get("destination_cidr_block"))
            require(value.get("blackhole", False) is False, "Unexpected TGW blackhole routing is not allowed.")
            attachment = attachments.get(value.get("transit_gateway_attachment_id"))
            if attachment is not None and not any(name in row["address"] for name in (".to_peer_inspected", ".to_workload_inspected")):
                require(value["destination_cidr_block"] == vpc_values.get(attachment.get("vpc_id"), {}).get("cidr_block"),
                        "A direct TGW route destination differs from its exact managed target VPC CIDR.")
        if kind == "aws_route":
            require(value.get("route_table_id") in tables, "A route modifies an unowned upstream route table.")
            _cidr(value.get("destination_cidr_block"))
            if row["address"].startswith("aws_route.edge"):
                require(value.get("route_table_id") in _ids(upstream, "aws_route_table") | _ids(upstream, "aws_default_route_table"),
                        "An edge route is not owned by an approved upstream State.")
                source_vpc = table_values[value["route_table_id"]].get("vpc_id")
                parts = json.loads(row["address"].split(".edge", 1)[1])[0].split("/")
                workload_vpcs = {r["values"]["id"] for r in upstream if r["root"] == VPC and r["type"] == "aws_vpc"}
                require(len(parts) == 3 and parts[1] == value["route_table_id"] and
                        ((parts[0] == "workload" and parts[2] != "workload" and source_vpc in workload_vpcs) or
                         (parts[0] != "workload" and parts[2] == "workload" and source_vpc not in workload_vpcs)),
                        "An edge route's exact address does not match its source and destination ownership.")
                require(value["destination_cidr_block"] in {v.get("cidr_block") for identity, v in vpc_values.items() if identity != source_vpc},
                        "An edge route destination is not an exact different managed VPC CIDR.")
            targets = [k for k in ("transit_gateway_id", "vpc_endpoint_id", "gateway_id", "nat_gateway_id", "network_interface_id", "vpc_peering_connection_id", "instance_id", "egress_only_gateway_id", "core_network_arn") if value.get(k)]
            require(targets == ["transit_gateway_id"] or (row["address"].startswith("aws_route.inspection_in") and targets == ["vpc_endpoint_id"]),
                    "A managed route has an unsupported or ambiguous target.")
            if targets == ["transit_gateway_id"]:
                require(value[targets[0]] in _ids(scope, "aws_ec2_transit_gateway"), "A managed route targets a foreign TGW.")
        if kind.startswith("aws_networkfirewall_"):
            require(value["id"] == (value.get("firewall_arn") if kind == "aws_networkfirewall_logging_configuration" else value.get("arn")),
                    "Firewall managed identity differs from its exact ARN relationship.")
        if kind == "aws_networkfirewall_rule_group":
            require(value.get("type") == "STATEFUL", "Only the exact course stateful firewall group is supported.")
        if kind == "aws_networkfirewall_firewall_policy":
            policy = _single_block(value, "firewall_policy")
            refs = array(policy.get("stateful_rule_group_reference"))
            require(len(refs) == 1 and object_value(refs[0]).get("resource_arn") in _ids(scope, "aws_networkfirewall_rule_group") and
                    not policy.get("stateless_rule_group_reference") and not policy.get("tls_inspection_configuration_arn"),
                    "Firewall policy references unowned rules or TLS inspection data.")
        if kind == "aws_networkfirewall_logging_configuration":
            require(value.get("firewall_arn") in _ids(scope, "aws_networkfirewall_firewall"), "Firewall logging references an unowned firewall.")
            _logging_destinations(value)
        if kind == "aws_cloudwatch_log_group":
            require(value.get("name") == value["id"] and value.get("skip_destroy", False) is False,
                    "Course CloudWatch log-group identity or disposal semantics are ambiguous.")
        if kind == "aws_networkfirewall_firewall":
            require(value.get("delete_protection") is False, "Firewall delete protection must be changed in a separately reviewed plan.")
            require(value.get("firewall_policy_arn") in _ids(scope, "aws_networkfirewall_firewall_policy"), "Firewall policy ownership is unknown.")
    return rows


def validate_destroy(state, plan, expected_resources=None):
    rows = managed_resources(state)
    scope = original_resources(expected_resources if expected_resources is not None else normalize_resources(state))
    approved = {r["address"]: (r["type"], r["id"]) for r in scope}
    require(all(approved.get(r["address"]) == (r["type"], r["values"].get("id")) for r in rows),
            "Destroy State differs from original approved network identities.")
    plan = object_value(plan)
    require(str(plan.get("format_version", "")).split(".")[0] == "1" and plan.get("errored", False) is False and
            plan.get("complete", True) is True and not plan.get("deferred_changes"), "The network destroy plan is incomplete.")
    current = {r["address"]: (r["type"], r["values"]) for r in rows}
    prior = [] if not rows and "prior_state" not in plan else managed_resources(object_value(plan.get("prior_state")))
    require({r["address"]: (r["type"], r["values"]) for r in prior} == current, "Destroy prior State differs from current managed State.")
    changes = {}
    for row in array(plan.get("resource_changes", [])):
        row = object_value(row)
        require(row.get("mode") in ("managed", "data"), "A planned resource mode is invalid.")
        if row["mode"] == "data":
            continue
        require(not row.get("deposed") and not row.get("previous_address"), "Moved or deposed network instances are unsupported.")
        detail = object_value(row.get("change"))
        require(detail.get("actions") == ["delete"] and detail.get("after") is None, "Only an exact delete-only network plan is accepted.")
        address = row.get("address")
        require(isinstance(address, str) and address not in changes, "Duplicate or invalid destroy address.")
        changes[address] = (row.get("type"), object_value(detail.get("before")))
    require(changes == current, "The saved plan does not delete every exact managed network object.")
    require(not managed_resources({"format_version": "1.0", "values": object_value(plan.get("planned_values"))}),
            "The destroy plan leaves managed network objects behind.")
    return rows


class Inventory:
    def __init__(self, context, aws_call=None):
        self.account, self.region = validate_context(context)
        self.aws = aws_call or aws_read
        self.counts = {}
        require(object_value(self.call("sts", "get-caller-identity")).get("Account") == self.account,
                "AWS caller differs from the configured account.")

    def call(self, service, operation, *args):
        require((service, operation) in READ_OPERATIONS, "Unapproved topology read.")
        try:
            return object_value(self.aws(service, operation, *args, "--region", self.region))
        except SafeError:
            raise
        except Exception:
            raise SafeError("A required topology read failed; destruction is blocked.") from None

    def rows(self, operation, key, *args):
        rows = complete_list(self.call("ec2", operation, *args), key)
        require(all(isinstance(row, dict) for row in rows), "A topology inventory is malformed.")
        self.counts[operation] = self.counts.get(operation, 0) + len(rows)
        return rows

    def filtered(self, operation, key, field, ids):
        require(bool(ids), "An exact nonempty inventory filter is required.")
        return self.rows(operation, key, "--filters", "Name=" + field + ",Values=" + ",".join(sorted(ids)))


def _exact(rows, field, expected, message):
    found = [r.get(field) for r in rows]
    require(all(isinstance(v, str) and v for v in found) and len(found) == len(set(found)) and set(found) == set(expected), message)


def _active(rows):
    require(all(isinstance(r.get("State"), str) for r in rows), "A live topology resource has unknown status.")
    return [r for r in rows if r["State"] not in TERMINAL]


def _transit_inventory(context, rows, scope, upstream_states, inventory):
    upstream = _upstream(upstream_states)
    network_rows = upstream + [r for r in rows if r["type"] in ("aws_vpc", "aws_subnet", "aws_route_table", "aws_default_route_table")]
    by_kind = {}
    for row in rows:
        by_kind.setdefault(row["type"], []).append(row)
    gateways = _ids(scope, "aws_ec2_transit_gateway")
    if not gateways:
        require(not any(r["type"] != "terraform_data" for r in rows), "Transit State has infrastructure without a pinned TGW.")
        return {}
    live = _active(inventory.filtered("describe-transit-gateways", "TransitGateways", "transit-gateway-id", gateways))
    _exact(live, "TransitGatewayId", _ids(rows, "aws_ec2_transit_gateway"), "Live TGW identity differs from current managed State.")
    for gateway in live:
        require(gateway.get("OwnerId") == inventory.account and gateway.get("State") == "available", "TGW ownership or availability is unverified.")
        options = object_value(gateway.get("Options"))
        require(all(options.get(k) == "disable" for k in ("DefaultRouteTableAssociation", "DefaultRouteTablePropagation", "AutoAcceptSharedAttachments")),
                "TGW live defaults differ from the explicit course routing model.")
    attachment_rows = by_kind.get("aws_ec2_transit_gateway_vpc_attachment", [])
    attachments = {r["values"]["id"]: r["values"] for r in attachment_rows}
    all_attachments = _active(inventory.filtered("describe-transit-gateway-attachments", "TransitGatewayAttachments", "transit-gateway-id", gateways))
    _exact(all_attachments, "TransitGatewayAttachmentId", attachments, "Unknown, shared or missing TGW attachments block destruction.")
    association_values = by_kind.get("aws_ec2_transit_gateway_route_table_association", [])
    associated = {r["values"]["transit_gateway_attachment_id"]: r["values"]["transit_gateway_route_table_id"] for r in association_values}
    require(len(associated) == len(association_values), "Duplicate managed TGW attachment associations.")
    for row in all_attachments:
        state = attachments[row["TransitGatewayAttachmentId"]]
        require(row.get("ResourceType") == "vpc" and row.get("ResourceOwnerId") == inventory.account and
                row.get("TransitGatewayOwnerId") == inventory.account and row.get("ResourceId") == state["vpc_id"] and
                row.get("TransitGatewayId") == state["transit_gateway_id"] and row.get("State") == "available",
                "TGW attachment live ownership or relationship is unverified.")
        association = row.get("Association")
        if row["TransitGatewayAttachmentId"] in associated:
            require(isinstance(association, dict) and association.get("TransitGatewayRouteTableId") == associated[row["TransitGatewayAttachmentId"]] and association.get("State") == "associated",
                    "Live TGW attachment association differs from managed State.")
        else:
            require(not association or (isinstance(association, dict) and association.get("State") == "disassociated" and
                    association.get("TransitGatewayRouteTableId") in _ids(scope, "aws_ec2_transit_gateway_route_table")),
                    "An unmanaged TGW attachment association exists.")
    vpc_attachments = _active(inventory.filtered("describe-transit-gateway-vpc-attachments", "TransitGatewayVpcAttachments", "transit-gateway-id", gateways))
    _exact(vpc_attachments, "TransitGatewayAttachmentId", attachments, "TGW VPC attachment inventory differs from managed State.")
    proof = {}
    for row in vpc_attachments:
        state = attachments[row["TransitGatewayAttachmentId"]]
        require(row.get("VpcOwnerId") == inventory.account and row.get("VpcId") == state["vpc_id"] and
                row.get("TransitGatewayId") == state["transit_gateway_id"] and row.get("State") == "available" and
                set(array(row.get("SubnetIds"))) == set(state["subnet_ids"]), "TGW VPC attachment ownership or subnets differ from State.")
        options = object_value(row.get("Options"))
        require(options.get("ApplianceModeSupport") == state.get("appliance_mode_support") and
                options.get("DnsSupport") == state.get("dns_support") and options.get("Ipv6Support") == state.get("ipv6_support"),
                "Attachment appliance or IP settings differ from managed State.")
        entry = proof.setdefault(state["vpc_id"], {"attachment_ids": [], "transit_gateway_ids": [], "subnet_ids": [], "routes": []})
        entry["attachment_ids"].append(state["id"])
        entry["transit_gateway_ids"].append(state["transit_gateway_id"])
        entry["subnet_ids"].extend(state["subnet_ids"])
    # Prove upstream VPC, subnet and route-table ownership from managed State and
    # live owner/VPC/AZ fields, never from remote-state output contracts.
    needed_vpcs = {v["vpc_id"] for v in attachments.values()}
    needed_subnets = set().union(*(set(v["subnet_ids"]) for v in attachments.values())) if attachments else set()
    subnet_values = {r["values"]["id"]: r["values"] for r in network_rows if r["type"] == "aws_subnet"}
    vpc_values = {r["values"]["id"]: r["values"] for r in network_rows if r["type"] == "aws_vpc"}
    if needed_vpcs:
        vpcs = inventory.filtered("describe-vpcs", "Vpcs", "vpc-id", needed_vpcs)
        _exact(vpcs, "VpcId", needed_vpcs, "An upstream attachment VPC is absent or duplicated.")
        for row in vpcs:
            require(row.get("OwnerId") == inventory.account and row.get("State") == "available" and row.get("IsDefault") is False and
                    row.get("CidrBlock") == vpc_values[row["VpcId"]].get("cidr_block"), "Upstream live VPC identity or CIDR is unverified.")
        # Every live TGW attachment in these selected VPCs must belong to this
        # selected transit State. A second TGW is not silently exempted.
        in_vpcs = _active(inventory.filtered("describe-transit-gateway-vpc-attachments", "TransitGatewayVpcAttachments", "vpc-id", needed_vpcs))
        _exact(in_vpcs, "TransitGatewayAttachmentId", attachments, "An upstream VPC has an unknown transit attachment.")
    if needed_subnets:
        subnets = inventory.filtered("describe-subnets", "Subnets", "subnet-id", needed_subnets)
        _exact(subnets, "SubnetId", needed_subnets, "An attachment subnet is absent or duplicated.")
        for row in subnets:
            state = subnet_values[row["SubnetId"]]
            require(row.get("OwnerId") == inventory.account and row.get("VpcId") == state.get("vpc_id") and
                    row.get("AvailabilityZone") == state.get("availability_zone") and row.get("State") == "available",
                    "An attachment subnet's live account, VPC or AZ is unverified.")
    table_rows = _active(inventory.filtered("describe-transit-gateway-route-tables", "TransitGatewayRouteTables", "transit-gateway-id", gateways))
    _exact(table_rows, "TransitGatewayRouteTableId", _ids(rows, "aws_ec2_transit_gateway_route_table"), "Unknown or missing TGW route tables block destruction.")
    for table in table_rows:
        table_id = table["TransitGatewayRouteTableId"]
        require(table.get("TransitGatewayId") in gateways and table.get("State") == "available" and
                table.get("DefaultAssociationRouteTable") is False and table.get("DefaultPropagationRouteTable") is False,
                "TGW route-table identity or defaults are unverified.")
        associations = inventory.rows("get-transit-gateway-route-table-associations", "Associations", "--transit-gateway-route-table-id", table_id)
        inactive = [r for r in associations if r.get("State") == "disassociated"]
        require(all(r.get("TransitGatewayAttachmentId") in _ids(scope, "aws_ec2_transit_gateway_vpc_attachment") and
                    r.get("ResourceType") == "vpc" for r in inactive), "An unknown inactive TGW association exists.")
        associations = [r for r in associations if r.get("State") != "disassociated"]
        expected = {attachment for attachment, route_table in associated.items() if route_table == table_id}
        _exact(associations, "TransitGatewayAttachmentId", expected, "Unknown or missing TGW route-table association.")
        for association in associations:
            require(association.get("ResourceType") == "vpc" and association.get("State") == "associated" and
                    association.get("ResourceId") == attachments[association["TransitGatewayAttachmentId"]]["vpc_id"],
                    "TGW association resource identity is unverified.")
        require(not inventory.rows("get-transit-gateway-route-table-propagations", "TransitGatewayRouteTablePropagations", "--transit-gateway-route-table-id", table_id),
                "TGW route propagation exists outside the explicit course model.")
        response = inventory.call("ec2", "search-transit-gateway-routes", "--transit-gateway-route-table-id", table_id,
                                  "--filters", "Name=type,Values=static,propagated", "--max-results", "1000")
        require(response.get("AdditionalRoutesAvailable") is False, "TGW route search was incomplete or has unknown completeness.")
        routes = complete_list(response, "Routes")
        expected_routes = {(r["values"]["destination_cidr_block"], r["values"]["transit_gateway_attachment_id"])
                           for r in by_kind.get("aws_ec2_transit_gateway_route", []) if r["values"]["transit_gateway_route_table_id"] == table_id}
        found = []
        for route in routes:
            route = object_value(route)
            targets = array(route.get("TransitGatewayAttachments"))
            require(route.get("Type") == "static" and route.get("State") == "active" and len(targets) == 1, "An unmanaged or unstable TGW route exists.")
            target = object_value(targets[0])
            attachment = target.get("TransitGatewayAttachmentId")
            require(attachment in attachments and target.get("ResourceType") == "vpc" and target.get("ResourceId") == attachments[attachment]["vpc_id"],
                    "A TGW route's target ownership is unverified.")
            found.append((_cidr(route.get("DestinationCidrBlock")), attachment))
        require(len(found) == len(set(found)) and set(found) == expected_routes, "TGW routes differ from exact managed routes.")
    # A global regional route-table inventory detects foreign VPCs routing to the
    # selected TGW, including stale blackhole routes after a partial destroy.
    route_tables = inventory.rows("describe-route-tables", "RouteTables")
    managed_routes = [r for r in by_kind.get("aws_route", []) if r["values"].get("transit_gateway_id")]
    expected_routes = {(r["values"]["route_table_id"], r["values"]["destination_cidr_block"], r["values"]["transit_gateway_id"]) for r in managed_routes}
    require(len(expected_routes) == len(managed_routes), "Duplicate managed VPC route destinations.")
    found = []
    state_tables = {r["values"]["id"]: r["values"] for r in network_rows if r["type"] in ("aws_route_table", "aws_default_route_table")}
    for table in route_tables:
        for route in array(table.get("Routes")):
            route = object_value(route)
            if route.get("TransitGatewayId") not in gateways:
                continue
            targets = [field for field in ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
                       "NetworkInterfaceId", "InstanceId", "EgressOnlyInternetGatewayId", "LocalGatewayId",
                       "CarrierGatewayId", "CoreNetworkArn", "VpcEndpointId") if route.get(field)]
            require(targets == ["TransitGatewayId"] and not route.get("DestinationIpv6CidrBlock") and
                    not route.get("DestinationPrefixListId"), "A VPC transit route has an ambiguous target or destination.")
            identity = (table.get("RouteTableId"), route.get("DestinationCidrBlock"), route.get("TransitGatewayId"))
            require(identity in expected_routes and table.get("OwnerId") == inventory.account and
                    table["RouteTableId"] in state_tables and table.get("VpcId") == state_tables[table["RouteTableId"]].get("vpc_id") and
                    route.get("State") == "active", "An unknown, unowned or stale VPC route targets the selected TGW.")
            found.append(identity)
            entry = proof.setdefault(table["VpcId"], {"attachment_ids": [], "transit_gateway_ids": [], "subnet_ids": [], "routes": []})
            entry["routes"].append({"route_table_id": identity[0], "destination_cidr_block": identity[1], "transit_gateway_id": identity[2]})
    require(len(found) == len(set(found)) and set(found) == expected_routes, "Live VPC routes differ from managed transit routes.")
    for entry in proof.values():
        for key in ("attachment_ids", "transit_gateway_ids", "subnet_ids"):
            entry[key] = sorted(set(entry[key]))
        entry["routes"].sort(key=lambda r: (r["route_table_id"], r["destination_cidr_block"]))
    return proof


def prove_selected_transit(context, state, expected_resources, upstream_states, aws_call=None):
    """PRIVATE preplan facts, not an ENI exemption or apply authorization.

    Caller must run the full unfiltered VPC consumer guard after transit absence.
    This cannot link individual TGW ENI IDs to immutable parent attachment IDs.
    Inspection uses the separately documented bounded complete relationship proof;
    upstream VPC applies still require an unfiltered post-transit consumer check.
    """
    require(context.get("root") == TRANSIT, "Selected-consumer evidence must come from transit State.")
    rows = validate_state(context, state, expected_resources, upstream_states)
    inventory = Inventory(context, aws_call)
    scope = original_resources(expected_resources, TRANSIT)
    proof = _transit_inventory(context, rows, scope, upstream_states, inventory)
    firewall = None
    if _ids(scope, "aws_vpc"):
        firewall = _firewall_inventory(context, rows, scope, None, inventory)
        _inspection_vpc_inventory(rows, scope, proof, firewall, inventory)
    return {"vpcs": proof, "firewall": firewall, "resources": normalize_resources(state), "inventory_counts": inventory.counts,
            "requires_unfiltered_apply_recheck": True, "limits": LIMITS}


def _peer_resources(rows):
    """State-computed VPC defaults are immutable relationship evidence.

    Peer HCL deliberately manages neither the default NACL nor default route table.
    Their exact IDs are computed on its owned aws_vpc; only those AWS defaults are
    admitted for the base consumer inventory, without editing Terraform State.
    """
    result = copy.deepcopy(rows)
    for row in rows:
        if row["type"] != "aws_vpc":
            continue
        value = row["values"]
        for field, kind, prefix in (("default_network_acl_id", "aws_default_network_acl", "acl"),
                                    ("default_route_table_id", "aws_default_route_table", "rtb")):
            identity = value.get(field)
            require(isinstance(identity, str) and re.fullmatch(prefix + r"-(?:[0-9a-f]{8}|[0-9a-f]{17})", identity),
                    "Peer VPC default-resource identities are missing from managed State.")
            result.append({"address": "__derived_default__." + kind, "type": kind, "name": "verified_default",
                           "values": {"id": identity, "vpc_id": value["id"]}})
    return result


def _check_dependents(workspace, context, aws_call, load_state):
    try:
        graph = json.loads((Path(workspace) / "ci/deploy-roots.json").read_text())["dependencies"]
    except (OSError, ValueError, KeyError):
        raise SafeError("The dependency registry is missing or invalid.") from None
    graph = object_value(graph)
    root = context["root"]
    require(root in graph, "The network root is absent from the dependency registry.")
    require(all(isinstance(k, str) and isinstance(v, list) and all(isinstance(p, str) and p in graph and p.split("/")[:3] == k.split("/")[:3] for p in v) for k, v in graph.items()),
            "Dependency registry has an unknown or cross-environment edge.")
    closure = {root}
    while True:
        new = closure | {k for k, v in graph.items() if set(v) & closure}
        if new == closure:
            break
        closure = new
    reader = load_state or _vpc.VersionedStateReader(context["backend"]["bucket"], context["account"], context["backend"]["region"], aws_call=aws_call)
    result = {}
    for dependent in sorted(closure - {root}):
        loaded = object_value(reader(dependent.removeprefix("terraform/environments/dev/") + "/terraform.tfstate"))
        fingerprint = object_value(loaded.get("fingerprint"))
        require(type(fingerprint.get("exists")) is bool, "Dependent State existence is unknown.")
        if fingerprint["exists"]:
            require(isinstance(fingerprint.get("version"), str) and fingerprint["version"] not in ("", "null") and
                    loaded.get("state") is not None, "Dependent State must be pinned to an exact object version.")
            require(not managed_resources(loaded["state"]), "A dependent root still has managed State; destroy consumers first.")
        else:
            require(loaded.get("state") is None, "Dependent State absence evidence is inconsistent.")
        result[dependent] = fingerprint
    return result


def guard_destroy(workspace, context, state, plan, expected_resources=None, upstream_states=None, aws_call=None, load_state=None):
    rows = validate_state(context, state, expected_resources, upstream_states)
    validate_destroy(state, plan, expected_resources)
    scope = original_resources(expected_resources, context["root"]) if expected_resources is not None else normalize_resources(state)
    inventory = Inventory(context, aws_call)
    dependents = _check_dependents(workspace, context, inventory.aws, load_state)
    if context["root"] == PEER:
        vpcs = _ids(scope, "aws_vpc")
        require(len(vpcs) == 1, "Exactly one original peer VPC identity is required.")
        vpc_id = next(iter(vpcs))
        resources = _peer_resources(rows)
        counts = _vpc.inventory_consumers(resources, vpc_id, inventory.account, inventory.region, inventory.aws,
                                          expected_resources=scope)
        return {"vpc_id": vpc_id, "dependent_states": dependents, "inventory_counts": counts, "limits": LIMITS}
    proof = _transit_inventory(context, rows, scope, upstream_states, inventory)
    firewall = None
    if _ids(scope, "aws_vpc"):
        firewall = _firewall_inventory(context, rows, scope, None, inventory)
        _inspection_vpc_inventory(rows, scope, proof, firewall, inventory)
    return {"vpcs": proof, "firewall": firewall, "dependent_states": dependents, "inventory_counts": inventory.counts, "limits": LIMITS}


def verify_absent(context, expected_resources, aws_call=None):
    scope = original_resources(expected_resources, context.get("root"))
    inventory = Inventory(context, aws_call)
    if context["root"] == PEER:
        vpcs = _ids(scope, "aws_vpc")
        require(len(vpcs) == 1, "An exact original peer VPC identity is required.")
        require(not inventory.filtered("describe-vpcs", "Vpcs", "vpc-id", vpcs), "The pinned peer VPC is not confirmed absent.")
    else:
        gateways = _ids(scope, "aws_ec2_transit_gateway")
        attachments = _ids(scope, "aws_ec2_transit_gateway_vpc_attachment")
        tables = _ids(scope, "aws_ec2_transit_gateway_route_table")
        for ids, operation, key, field in (
            (gateways, "describe-transit-gateways", "TransitGateways", "transit-gateway-id"),
            (attachments, "describe-transit-gateway-attachments", "TransitGatewayAttachments", "transit-gateway-attachment-id"),
            (tables, "describe-transit-gateway-route-tables", "TransitGatewayRouteTables", "transit-gateway-route-table-id"),
        ):
            if ids:
                require(all(r.get("State") == "deleted" for r in inventory.filtered(operation, key, field, ids)), "Pinned transit resources are not confirmed absent.")
        if gateways:
            require(not _active(inventory.filtered("describe-transit-gateway-attachments", "TransitGatewayAttachments", "transit-gateway-id", gateways)),
                    "A residual attachment still targets the pinned TGW.")
            for table in inventory.rows("describe-route-tables", "RouteTables"):
                require(not any(object_value(route).get("TransitGatewayId") in gateways for route in array(table.get("Routes"))),
                        "A residual VPC route still targets the pinned TGW.")
        if _ids(scope, "aws_vpc"):
            _verify_firewall_absent(scope, inventory)
    return {"absent": True, "resources": scope, "inventory_counts": inventory.counts}


def validate_plan_contracts(context, plan, upstream_states=None):
    """Check evaluated source/Up scope before any saved plan can be applied.

    Computed identities of newly created owned resources may be unknown. Mode,
    retention boundaries, routing defaults and external upstream identities may
    not. Checks cover changes as well as planned values, so absent current State
    and unknown creation IDs cannot bypass exact managed resource boundaries.
    This does not replace the caller's creation/update-only Up action policy.
    """
    account, region = validate_context(context)
    plan = object_value(plan)
    require(str(plan.get("format_version", "")).split(".")[0] == "1" and
            plan.get("errored", False) is False and plan.get("complete", True) is True and
            not plan.get("deferred_changes"), "The evaluated network plan is incomplete or deferred.")
    root = context["root"]
    variables = object_value(plan.get("variables", {}))
    for key, expected in (("expected_account_id", account), ("environment", "dev"), ("region", region)):
        if key in variables:
            require(object_value(variables[key]).get("value") == expected,
                    "A protected network plan input differs from the lifecycle context.")
    if root == TRANSIT and "enable_inspection" in variables:
        require(type(object_value(variables["enable_inspection"]).get("value")) is bool,
                "The inspection-mode input must be an explicit known boolean.")
    planned = managed_resources({"format_version": "1.0", "values": object_value(plan.get("planned_values"))})
    candidates = {row["address"]: row for row in planned}
    unknowns = {}
    changes = set()
    additional = []
    for row in array(plan.get("resource_changes", [])):
        row = object_value(row)
        require(row.get("mode") in ("managed", "data"), "A planned network resource mode is invalid.")
        if row["mode"] == "data":
            continue
        _allowed(root, row.get("address"), row.get("type"))
        require(row["address"] not in changes and not row.get("deposed") and not row.get("previous_address"),
                "Duplicate, moved or deposed network plan resources are unsupported.")
        changes.add(row["address"])
        detail = object_value(row.get("change"))
        unknown = detail.get("after_unknown", {})
        require(isinstance(unknown, dict), "Whole-resource unknown network changes are not supported.")
        unknowns[row["address"]] = unknown
        after = detail.get("after")
        before = detail.get("before")
        values = object_value(after if after is not None else before)
        if row["address"] in candidates:
            require(candidates[row["address"]]["type"] == row["type"], "Network plan identity is inconsistent.")
            additional.append({"address": row["address"], "type": row["type"], "values": values})
        else:
            candidates[row["address"]] = {"address": row["address"], "type": row["type"], "values": values}
    rows = list(candidates.values()) + additional
    for row in rows:
        _allowed(root, row["address"], row["type"])
    inspection = root == TRANSIT and any(r["type"] == "aws_vpc" or r["type"].startswith("aws_networkfirewall_") for r in rows)
    upstream = _upstream(upstream_states) if root == TRANSIT else []
    upstream_vpcs = {r["root"]: r["values"]["id"] for r in upstream if r["type"] == "aws_vpc"}
    upstream_subnets = {r["values"]["id"]: r["values"] for r in upstream if r["type"] == "aws_subnet"}
    upstream_tables = {r["values"]["id"]: r["values"] for r in upstream if r["type"] in ("aws_route_table", "aws_default_route_table")}
    own_ids = {}
    for row in planned:
        identity = row["values"].get("id")
        if isinstance(identity, str) and identity:
            own_ids.setdefault(row["type"], set()).add(identity)
    for row in rows:
        kind, value = row["type"], row["values"]
        unknown = unknowns.get(row["address"], {})
        if value.get("owner_id"):
            require(value["owner_id"] == account, "A planned network resource belongs to another account.")
        if value.get("arn"):
            _arn(value["arn"], account, region)
        if kind == "terraform_data":
            require(not unknown.get("input"), "The planned transit mode is unknown.")
            if row["address"] == "terraform_data.lifecycle":
                require(value.get("input") in (("inspection",) if inspection else ("disabled", "direct")), "The planned transit mode is outside the supported boundary.")
            else:
                require(object_value(value.get("input")).get("mode") == ("inspection" if inspection else "direct"), "The planned transit contract disagrees with its managed resource mode.")
        if kind == "aws_ec2_transit_gateway":
            require(all(value.get(field) == "disable" and not unknown.get(field) for field in
                        ("default_route_table_association", "default_route_table_propagation", "auto_accept_shared_attachments")),
                    "Planned TGW automatic routing or sharing is enabled or unknown.")
        if kind == "aws_ec2_transit_gateway_vpc_attachment":
            require(set(upstream_vpcs) == {VPC, PEER}, "Planned transit attachments require both exact upstream States.")
            inspection_attachment = row["address"] == "aws_ec2_transit_gateway_vpc_attachment.inspection[0]"
            require(value.get("appliance_mode_support") == ("enable" if inspection_attachment else "disable") and
                    value.get("dns_support") == "enable" and value.get("ipv6_support") == "disable" and
                    not any(unknown.get(k) for k in ("appliance_mode_support", "dns_support", "ipv6_support")),
                    "Planned attachment appliance, DNS or IPv4 settings are unverified.")
            if not inspection_attachment:
                key = json.loads(row["address"].split(".edge", 1)[1])[0]
                vpc_id = upstream_vpcs[VPC if key == "workload" else PEER]
                require(value.get("vpc_id") == vpc_id and not unknown.get("vpc_id"), "A planned attachment VPC is foreign or unknown.")
                subnets = array(value.get("subnet_ids"))
                require(not unknown.get("subnet_ids") and len(subnets) == 3 and len(set(subnets)) == 3 and
                        all(s in upstream_subnets and upstream_subnets[s].get("vpc_id") == vpc_id for s in subnets) and
                        {upstream_subnets[s].get("availability_zone") for s in subnets} == {region + az for az in "abc"},
                        "Planned attachment subnet identities or AZs are unverified.")
            else:
                require(value.get("vpc_id") in own_ids.get("aws_vpc", set()) or unknown.get("vpc_id") is True,
                        "Planned inspection attachment VPC is not owned by its root.")
                if value.get("subnet_ids") is not None and not unknown.get("subnet_ids"):
                    require(set(array(value["subnet_ids"])) <= own_ids.get("aws_subnet", set()) and len(value["subnet_ids"]) == 3,
                            "Planned inspection attachment subnets are unowned.")
                else:
                    require(bool(unknown.get("subnet_ids")), "Planned inspection attachment subnets are missing.")
            require(all(value.get(field) is False and not unknown.get(field) for field in
                        ("transit_gateway_default_route_table_association", "transit_gateway_default_route_table_propagation")),
                    "Planned attachment automatic routing is enabled or unknown.")
        if kind == "aws_route":
            table = value.get("route_table_id")
            edge = row["address"].startswith("aws_route.edge")
            ingress = row["address"].startswith("aws_route.inspection_in")
            if edge:
                require(table in upstream_tables and not unknown.get("route_table_id"), "A planned edge route's upstream table is unknown or unowned.")
            else:
                require(table in own_ids.get("aws_route_table", set()) or unknown.get("route_table_id") is True,
                        "Planned inspection route table ownership is unverified.")
            destination = _cidr(value.get("destination_cidr_block"))
            require(not unknown.get("destination_cidr_block") and destination in {
                r["values"].get("cidr_block") for r in upstream if r["type"] == "aws_vpc" and
                (not edge or r["values"]["id"] != upstream_tables[table].get("vpc_id"))},
                "A planned route destination is not an exact managed upstream VPC CIDR.")
            forbidden = ("gateway_id", "nat_gateway_id", "vpc_peering_connection_id", "network_interface_id", "instance_id", "egress_only_gateway_id", "core_network_arn")
            require(not any(value.get(field) or unknown.get(field) for field in forbidden), "A planned route has an unsupported alternative target.")
            if ingress:
                require(not value.get("transit_gateway_id") and not unknown.get("transit_gateway_id") and
                        (value.get("vpc_endpoint_id") or unknown.get("vpc_endpoint_id") is True),
                        "Inspection ingress must target an exact or newly computed firewall endpoint.")
            else:
                require(not value.get("vpc_endpoint_id") and not unknown.get("vpc_endpoint_id"), "An egress route targets an unexpected endpoint.")
        if kind == "aws_networkfirewall_firewall":
            require(value.get("delete_protection") is False and not unknown.get("delete_protection"),
                    "Firewall protection changes need a separate reviewed plan before lifecycle use.")
            require(value.get("vpc_id") in own_ids.get("aws_vpc", set()) or unknown.get("vpc_id") is True,
                    "A planned firewall refers to an unowned inspection VPC.")
            require(value.get("firewall_policy_arn") in own_ids.get("aws_networkfirewall_firewall_policy", set()) or unknown.get("firewall_policy_arn") is True,
                    "A planned firewall policy reference is unowned.")
            mappings = array(value.get("subnet_mapping"))
            require(len(mappings) == 3, "The planned firewall must own exactly three subnet mappings.")
            unknown_mappings = unknown.get("subnet_mapping", [])
            for index, mapping in enumerate(mappings):
                subnet = object_value(mapping).get("subnet_id")
                if subnet:
                    require(subnet in own_ids.get("aws_subnet", set()), "A planned firewall subnet is outside its managed root.")
                else:
                    require(isinstance(unknown_mappings, list) and len(unknown_mappings) == 3 and
                            object_value(unknown_mappings[index]).get("subnet_id") is True,
                            "A planned firewall subnet reference is missing.")
        if kind == "aws_networkfirewall_firewall_policy":
            policy = _single_block(value, "firewall_policy")
            refs = array(policy.get("stateful_rule_group_reference"))
            require(len(refs) == 1 and not policy.get("stateless_rule_group_reference") and not policy.get("tls_inspection_configuration_arn"),
                    "The planned firewall policy includes unsupported rule or TLS resources.")
            reference = object_value(refs[0]).get("resource_arn")
            if reference:
                require(reference in own_ids.get("aws_networkfirewall_rule_group", set()), "A planned firewall policy uses an unowned known rule group.")
            else:
                unknown_policy = _single_block(unknown, "firewall_policy")
                unknown_refs = array(unknown_policy.get("stateful_rule_group_reference"))
                require(len(unknown_refs) == 1 and object_value(unknown_refs[0]).get("resource_arn") is True,
                        "The planned firewall policy lacks its owned computed rule-group reference.")
        if kind == "aws_networkfirewall_rule_group":
            require(value.get("type") == "STATEFUL" and not unknown.get("type"), "Only the course stateful rule group is supported.")
        if kind == "aws_networkfirewall_logging_configuration":
            require(value.get("firewall_arn") in own_ids.get("aws_networkfirewall_firewall", set()) or unknown.get("firewall_arn") is True,
                    "A planned firewall logging configuration refers outside managed State.")
            destinations = _logging_destinations(value)
            planned_names = {r["values"].get("name") for r in planned if r["type"] == "aws_cloudwatch_log_group"}
            require(set(destinations.values()) == planned_names, "Planned firewall log destinations are not the exact owned course groups.")
        if kind == "aws_cloudwatch_log_group":
            require(isinstance(value.get("name"), str) and value["name"] and not unknown.get("name") and
                    value.get("skip_destroy", False) is False and not unknown.get("skip_destroy"),
                    "The exact disposable firewall log-group identity or retention semantics are unknown.")
        required_links = {
            "aws_ec2_transit_gateway_vpc_attachment": ("transit_gateway_id",),
            "aws_ec2_transit_gateway_route_table": ("transit_gateway_id",),
            "aws_ec2_transit_gateway_route_table_association": ("transit_gateway_attachment_id", "transit_gateway_route_table_id"),
            "aws_ec2_transit_gateway_route": ("transit_gateway_attachment_id", "transit_gateway_route_table_id"),
            "aws_route": (("vpc_endpoint_id",) if row["address"].startswith("aws_route.inspection_in") else ("transit_gateway_id",)),
        }.get(kind, ())
        require(all(value.get(field) or unknown.get(field) is True for field in required_links),
                "A required planned transit relationship is missing.")
        if kind == "aws_ec2_transit_gateway_route":
            require(_cidr(value.get("destination_cidr_block")) in {r["values"].get("cidr_block") for r in upstream if r["type"] == "aws_vpc"} and
                    not unknown.get("destination_cidr_block") and value.get("blackhole", False) is False and not unknown.get("blackhole"),
                    "A planned TGW route is not an exact explicit managed-VPC route.")
        for field, target_type in (("transit_gateway_id", "aws_ec2_transit_gateway"),
                                   ("transit_gateway_attachment_id", "aws_ec2_transit_gateway_vpc_attachment"),
                                   ("transit_gateway_route_table_id", "aws_ec2_transit_gateway_route_table")):
            if value.get(field):
                require(value[field] in own_ids.get(target_type, set()), "A planned transit relationship targets an unowned known resource.")
        if root == PEER or kind in ("aws_subnet", "aws_default_security_group", "aws_route_table", "aws_route_table_association"):
            for field, target_type in (("vpc_id", "aws_vpc"), ("subnet_id", "aws_subnet"), ("route_table_id", "aws_route_table")):
                if value.get(field):
                    require(value[field] in own_ids.get(target_type, set()), "A planned peer relationship targets a foreign known resource.")
    return {"managed_addresses": sorted(candidates), "inspection_supported": True, "mode": "inspection" if inspection else "direct-or-disabled",
            "cloudwatch_policy": "owned-disposable" if any(r["type"] == "aws_cloudwatch_log_group" for r in rows) else "none"}


class ResourcePolicyAbsent(SafeError):
    """Typed DescribeResourcePolicy miss; never a generic resource absence proof."""


FIREWALL_READ_OPERATIONS = frozenset({
    ("network-firewall", "list-firewalls"), ("network-firewall", "describe-firewall"),
    ("network-firewall", "list-firewall-policies"), ("network-firewall", "describe-firewall-policy"),
    ("network-firewall", "list-rule-groups"), ("network-firewall", "describe-rule-group"),
    ("network-firewall", "describe-resource-policy"),
    ("network-firewall", "list-vpc-endpoint-associations"),
    ("network-firewall", "describe-logging-configuration"),
    ("logs", "describe-log-groups"),
})
READ_OPERATIONS = READ_OPERATIONS | FIREWALL_READ_OPERATIONS


def _firewall_state_endpoints(value):
    statuses = array(value.get("firewall_status"))
    require(len(statuses) == 1, "Firewall endpoint identity is missing from managed State.")
    syncs = array(object_value(statuses[0]).get("sync_states"))
    result = {}
    for sync in syncs:
        sync = object_value(sync)
        attachments = array(sync.get("attachment"))
        require(len(attachments) == 1, "Firewall State endpoint attachment is ambiguous.")
        attachment = object_value(attachments[0])
        endpoint = attachment.get("endpoint_id")
        require(isinstance(endpoint, str) and re.fullmatch(r"vpce-(?:[0-9a-f]{8}|[0-9a-f]{17})", endpoint) and endpoint not in result,
                "Firewall State endpoint identity is invalid or duplicated.")
        result[endpoint] = {"subnet_id": attachment.get("subnet_id"), "availability_zone": sync.get("availability_zone")}
    require(len(result) == 3, "The course firewall requires three exact managed endpoint identities.")
    return result


def _single_block(value, field):
    blocks = array(value.get(field))
    require(len(blocks) == 1, "A managed firewall block is absent or ambiguous.")
    return object_value(blocks[0])


def _logging_destinations(values):
    block = _single_block(values, "logging_configuration")
    result = {}
    for item in array(block.get("log_destination_config")):
        item = object_value(item)
        kind = item.get("log_type")
        destination = object_value(item.get("log_destination"))
        require(kind in ("ALERT", "FLOW") and kind not in result and item.get("log_destination_type") == "CloudWatchLogs" and
                set(destination) == {"logGroup"} and isinstance(destination["logGroup"], str) and destination["logGroup"],
                "Only exact retained CloudWatch ALERT/FLOW log destinations are supported.")
        result[kind] = destination["logGroup"]
    require(set(result) == {"ALERT", "FLOW"}, "Both course firewall log destinations must be configured.")
    return result


def _retained_firewall_logs(context, retained_log_state, destinations, inventory):
    require(retained_log_state is not None, "The exact retained firewall-log State is required.")
    if isinstance(retained_log_state, list):
        rows = retained_log_state
    else:
        state = object_value(retained_log_state)
        if "state" in state:
            state = object_value(state["state"])
        rows = managed_resources(state)
    logs = {}
    for row in rows:
        if row["type"] != "aws_cloudwatch_log_group":
            continue
        value = row["values"]
        name = value.get("id")
        require(isinstance(name, str) and name == value.get("name") and name not in logs,
                "Retained log-group managed ownership is ambiguous.")
        _arn(value.get("arn"), inventory.account, inventory.region)
        logs[name] = value
    for name in destinations.values():
        require(name in logs, "A firewall log destination is not owned by the pinned retained State.")
        response = inventory.call("logs", "describe-log-groups", "--log-group-name-prefix", name)
        groups = complete_list(response, "logGroups")
        require(all(isinstance(object_value(row).get("logGroupName"), str) and row["logGroupName"] for row in groups),
                "CloudWatch log-group listing has unknown identities.")
        found = [object_value(row) for row in groups if object_value(row).get("logGroupName") == name]
        require(len(found) == 1, "A retained firewall log group is missing or duplicated.")
        live = found[0]
        live_arn = live.get("arn") or live.get("logGroupArn")
        require(isinstance(live_arn, str) and live_arn.removesuffix(":*") == logs[name]["arn"].removesuffix(":*"),
                "A retained log-group ARN differs from its pinned State identity.")
        if logs[name].get("retention_in_days") not in (None, 0):
            require(live.get("retentionInDays") == logs[name]["retention_in_days"], "Retained log-group retention differs from State.")
    return dict(sorted(destinations.items()))


def _no_firewall_resource_sharing(inventory, arn, describe_operation, describe_option, original_response):
    """A precise policy miss is valid only between matching positive object reads."""
    try:
        response = inventory.call("network-firewall", "describe-resource-policy", "--resource-arn", arn)
    except ResourcePolicyAbsent:
        again = inventory.call("network-firewall", describe_operation, describe_option, arn)
        require(isinstance(original_response.get("UpdateToken"), str) and original_response.get("UpdateToken") and
                again.get("UpdateToken") == original_response["UpdateToken"],
                "Firewall ownership changed while absence of a sharing policy was checked.")
        summary_field, arn_field = {"describe-firewall": ("Firewall", "FirewallArn"),
                                   "describe-firewall-policy": ("FirewallPolicyResponse", "FirewallPolicyArn"),
                                   "describe-rule-group": ("RuleGroupResponse", "RuleGroupArn")}[describe_operation]
        require(object_value(again.get(summary_field)).get(arn_field) == arn,
                "Firewall resource identity changed during sharing-policy absence verification.")
        return
    # Missing or empty policy data is not accepted as an absence proof.
    require("Policy" in response and isinstance(response["Policy"], str) and response["Policy"],
            "Firewall sharing-policy absence was not verified.")
    try:
        policy = object_value(json.loads(response["Policy"]))
    except (ValueError, TypeError):
        raise SafeError("Firewall resource policy could not be verified.") from None
    require(policy.get("Version") in ("2008-10-17", "2012-10-17") and policy.get("Statement") == [],
            "A firewall resource-sharing policy exists; separate its consumers before destruction.")


def prove_firewall_ownership(context, state, expected_resources, upstream_states, retained_log_state, aws_call=None):
    """Exact PRIVATE firewall ownership proof, without any TGW ENI exemption.

    This helper does not by itself authorize deleting the inspection VPC. The
    caller must additionally prove all VPC consumers, including TGW-created ENIs.
    """
    rows = validate_state(context, state, expected_resources, upstream_states)
    require(context["root"] == TRANSIT, "Firewall ownership proof belongs to the transit root.")
    scope = original_resources(expected_resources, TRANSIT)
    inventory = Inventory(context, aws_call)
    return _firewall_inventory(context, rows, scope, retained_log_state, inventory)


def _firewall_inventory(context, rows, scope, retained_log_state, inventory):
    own_vpcs = _ids(scope, "aws_vpc")
    require(len(own_vpcs) == 1, "Inspection requires exactly one original managed inspection VPC.")
    vpc_id = next(iter(own_vpcs))
    values = {r["type"]: r["values"] for r in rows if r["type"].startswith("aws_networkfirewall_")}
    require(len(values) == len([r for r in rows if r["type"].startswith("aws_networkfirewall_")]),
            "Multiple firewall resources of one kind are outside the course topology.")
    original_firewalls = _ids(scope, "aws_networkfirewall_firewall")
    original_policies = _ids(scope, "aws_networkfirewall_firewall_policy")
    original_groups = _ids(scope, "aws_networkfirewall_rule_group")
    for identity in original_firewalls | original_policies | original_groups:
        _arn(identity, inventory.account, inventory.region)
    own_firewalls = _ids(rows, "aws_networkfirewall_firewall")
    own_policies = _ids(rows, "aws_networkfirewall_firewall_policy")
    own_groups = _ids(rows, "aws_networkfirewall_rule_group")

    def listing(operation, key, *args):
        result = complete_list(inventory.call("network-firewall", operation, *args), key)
        require(all(isinstance(r, dict) for r in result), "Firewall listing is malformed.")
        inventory.counts[operation] = len(result)
        return result

    firewalls = listing("list-firewalls", "Firewalls")
    policies = listing("list-firewall-policies", "FirewallPolicies")
    groups = listing("list-rule-groups", "RuleGroups", "--scope", "ACCOUNT")
    for listed, field, original, current in ((firewalls, "FirewallArn", original_firewalls, own_firewalls),
                                            (policies, "Arn", original_policies, own_policies),
                                            (groups, "Arn", original_groups, own_groups)):
        require(all(isinstance(r.get(field), str) and r[field] for r in listed) and len({r[field] for r in listed}) == len(listed),
                "A firewall listing has ambiguous identities.")
        _exact([r for r in listed if r[field] in original], field, current, "Original firewall identities and live resources differ from State.")
    endpoint_proof = {}
    live_firewall = None
    live_policy_uses = {arn: 0 for arn in own_policies}
    for metadata in firewalls:
        response = inventory.call("network-firewall", "describe-firewall", "--firewall-arn", metadata["FirewallArn"])
        firewall = object_value(response.get("Firewall"))
        require(firewall.get("FirewallArn") == metadata["FirewallArn"] and isinstance(firewall.get("FirewallPolicyArn"), str),
                "A listed firewall's identity or policy reference is unknown.")
        arn = firewall["FirewallArn"]
        if arn not in own_firewalls:
            require(firewall.get("VpcId") != vpc_id and firewall["FirewallPolicyArn"] not in original_policies,
                    "An unmanaged firewall consumes the inspection VPC or its policy.")
            continue
        live_firewall = firewall
        state = values["aws_networkfirewall_firewall"]
        require(firewall.get("VpcId") == vpc_id and state.get("vpc_id") == vpc_id and
                firewall["FirewallPolicyArn"] == state.get("firewall_policy_arn") and firewall["FirewallPolicyArn"] in own_policies,
                "Firewall VPC or policy ownership differs from managed State.")
        require(firewall.get("DeleteProtection") is False and state.get("delete_protection") is False,
                "Firewall delete protection must already be disabled through a separately reviewed plan.")
        require(not firewall.get("TransitGatewayId") and not firewall.get("TransitGatewayOwnerAccountId") and
                not firewall.get("NatGatewayMappings") and not firewall.get("NoSourcePreservation") and not firewall.get("VpcEndpoint"),
                "Only the course subnet-attached firewall topology is supported.")
        require(type(firewall.get("NumberOfAssociations")) is int and firewall["NumberOfAssociations"] == 0,
                "The firewall is consumed by additional VPC endpoint associations.")
        require(not listing("list-vpc-endpoint-associations", "VpcEndpointAssociations", "--firewall-arn", arn),
                "A shared or additional firewall VPC endpoint association exists.")
        _no_firewall_resource_sharing(inventory, arn, "describe-firewall", "--firewall-arn", response)
        live_policy_uses[firewall["FirewallPolicyArn"]] += 1
        status = object_value(response.get("FirewallStatus"))
        require(status.get("Status") == "READY" and status.get("ConfigurationSyncStateSummary") == "IN_SYNC",
                "Firewall endpoint configuration is not stable and ready.")
        syncs = object_value(status.get("SyncStates"))
        state_endpoints = _firewall_state_endpoints(state)
        subnet_values = {r["values"]["id"]: r["values"] for r in rows if r["type"] == "aws_subnet" and r["address"].startswith("aws_subnet.inspection_firewall")}
        mappings = array(firewall.get("SubnetMappings"))
        require(len(mappings) == 3 and {object_value(m).get("SubnetId") for m in mappings} == set(subnet_values) and
                all(m.get("IPAddressType", "IPV4") == "IPV4" for m in mappings), "Firewall live subnet mappings differ from exact managed subnets.")
        require(set(syncs) == {inventory.region + az for az in "abc"}, "Firewall AZ endpoint coverage differs from the course contract.")
        for az, sync in syncs.items():
            attachment = object_value(object_value(sync).get("Attachment"))
            endpoint = attachment.get("EndpointId")
            subnet = attachment.get("SubnetId")
            require(endpoint in state_endpoints and endpoint not in endpoint_proof and attachment.get("Status") == "READY" and
                    subnet in subnet_values and subnet_values[subnet].get("availability_zone") == az and
                    state_endpoints[endpoint] == {"subnet_id": subnet, "availability_zone": az},
                    "Firewall service endpoint identity differs from managed State.")
            endpoint_proof[endpoint] = {"subnet_id": subnet, "availability_zone": az, "firewall_arn": arn}
        require(set(endpoint_proof) == set(state_endpoints), "Firewall service endpoint identities are incomplete.")
    live_group_uses = {arn: 0 for arn in own_groups}
    for metadata in policies:
        response = inventory.call("network-firewall", "describe-firewall-policy", "--firewall-policy-arn", metadata["Arn"])
        summary = object_value(response.get("FirewallPolicyResponse"))
        policy = object_value(response.get("FirewallPolicy"))
        arn = summary.get("FirewallPolicyArn")
        require(arn == metadata["Arn"], "Firewall policy identity differs from the live listing.")
        references = array(policy.get("StatefulRuleGroupReferences", [])) + array(policy.get("StatelessRuleGroupReferences", []))
        group_refs = [object_value(r).get("ResourceArn") for r in references]
        require(all(isinstance(r, str) and r for r in group_refs), "Firewall policy rule-group ownership is unknown.")
        if arn not in own_policies:
            require(not set(group_refs) & original_groups, "An unmanaged firewall policy consumes the managed rule group.")
            continue
        require(summary.get("FirewallPolicyStatus") == "ACTIVE" and type(summary.get("NumberOfAssociations")) is int and
                summary["NumberOfAssociations"] == live_policy_uses[arn], "A managed firewall policy has unknown or shared consumers.")
        require(not policy.get("StatelessRuleGroupReferences") and len(group_refs) == 1 and set(group_refs) == own_groups and
                not policy.get("TLSInspectionConfigurationArn"), "The firewall policy references unowned rule groups or TLS data.")
        for reference in group_refs:
            live_group_uses[reference] += 1
        _no_firewall_resource_sharing(inventory, arn, "describe-firewall-policy", "--firewall-policy-arn", response)
    for metadata in groups:
        if metadata["Arn"] not in own_groups:
            continue
        response = inventory.call("network-firewall", "describe-rule-group", "--rule-group-arn", metadata["Arn"])
        summary = object_value(response.get("RuleGroupResponse"))
        require(summary.get("RuleGroupArn") == metadata["Arn"] and summary.get("RuleGroupStatus") == "ACTIVE" and
                summary.get("Type") == "STATEFUL" and type(summary.get("NumberOfAssociations")) is int and
                summary["NumberOfAssociations"] == live_group_uses[metadata["Arn"]], "A managed firewall rule group has unknown or shared consumers.")
        _no_firewall_resource_sharing(inventory, metadata["Arn"], "describe-rule-group", "--rule-group-arn", response)
    # EC2 establishes the exact endpoint -> service ENI relationship. No name,
    # description, tag, subnet-only match, or ENI interface type grants ownership.
    endpoints = inventory.filtered("describe-vpc-endpoints", "VpcEndpoints", "vpc-id", {vpc_id})
    _exact(endpoints, "VpcEndpointId", endpoint_proof, "An unknown or missing endpoint consumes the inspection VPC.")
    eni_ids = set()
    for endpoint in endpoints:
        identity = endpoint["VpcEndpointId"]
        require(endpoint.get("VpcId") == vpc_id and endpoint.get("OwnerId") == inventory.account and endpoint.get("State") == "available" and
                endpoint.get("VpcEndpointType") == "GatewayLoadBalancer" and endpoint.get("RequesterManaged") is True and
                array(endpoint.get("SubnetIds")) == [endpoint_proof[identity]["subnet_id"]], "Firewall endpoint live ownership or subnet relationship is unverified.")
        enis = array(endpoint.get("NetworkInterfaceIds"))
        require(len(enis) == 1 and isinstance(enis[0], str) and re.fullmatch(r"eni-(?:[0-9a-f]{8}|[0-9a-f]{17})", enis[0]) and enis[0] not in eni_ids,
                "Firewall endpoint ENI relationship is missing or ambiguous.")
        eni_ids.add(enis[0]); endpoint_proof[identity]["network_interface_ids"] = enis
    if eni_ids:
        enis = inventory.filtered("describe-network-interfaces", "NetworkInterfaces", "network-interface-id", eni_ids)
        _exact(enis, "NetworkInterfaceId", eni_ids, "Firewall endpoint ENIs are missing or duplicated.")
        by_eni = {entry["network_interface_ids"][0]: entry for entry in endpoint_proof.values()}
        for eni in enis:
            require(eni.get("VpcId") == vpc_id and eni.get("OwnerId") == inventory.account and eni.get("RequesterManaged") is True and
                    eni.get("InterfaceType") == "gateway_load_balancer_endpoint" and eni.get("SubnetId") == by_eni[eni["NetworkInterfaceId"]]["subnet_id"] and not object_value(eni.get("Attachment", {})).get("InstanceId"),
                    "A firewall endpoint ENI has a foreign VPC, owner, subnet or workload attachment.")
    expected_endpoint_routes = {(r["values"].get("route_table_id"), r["values"].get("destination_cidr_block"), r["values"].get("vpc_endpoint_id"))
                                for r in rows if r["type"] == "aws_route" and r["values"].get("vpc_endpoint_id")}
    require(all(target in endpoint_proof for _, _, target in expected_endpoint_routes), "A managed inspection route targets an unowned firewall endpoint.")
    found_endpoint_routes = []
    for table in inventory.rows("describe-route-tables", "RouteTables"):
        for route in array(table.get("Routes")):
            route = object_value(route)
            targets = [route[k] for k in ("GatewayId", "VpcEndpointId") if route.get(k) in endpoint_proof]
            if not targets:
                continue
            require(len(targets) == 1, "A firewall route target is ambiguous.")
            identity = (table.get("RouteTableId"), route.get("DestinationCidrBlock"), targets[0])
            require(identity in expected_endpoint_routes and table.get("VpcId") == vpc_id and table.get("OwnerId") == inventory.account and
                    route.get("State") == "active" and not any(route.get(k) for k in ("TransitGatewayId", "NatGatewayId", "NetworkInterfaceId", "VpcPeeringConnectionId")),
                    "An unknown, foreign or unstable route consumes a firewall endpoint.")
            found_endpoint_routes.append(identity)
    require(len(found_endpoint_routes) == len(set(found_endpoint_routes)) and set(found_endpoint_routes) == expected_endpoint_routes,
            "Live firewall endpoint routes differ from exact managed routes.")
    log_destinations = {}
    owned_log_rows = [r for r in rows if r["type"] == "aws_cloudwatch_log_group"]
    owned_destinations = {json.loads(r["address"].split(".firewall", 1)[1])[0]: r["values"]["id"] for r in owned_log_rows}
    if owned_log_rows:
        require(all(r["values"].get("skip_destroy", False) is False for r in owned_log_rows),
                "Mixed retained/disposable CloudWatch group semantics require separate reviewed ownership.")
        _retained_firewall_logs(context, owned_log_rows, owned_destinations, inventory)
    if live_firewall:
        logging = inventory.call("network-firewall", "describe-logging-configuration", "--firewall-arn", live_firewall["FirewallArn"])
        require(logging.get("FirewallArn") == live_firewall["FirewallArn"], "Firewall logging identity differs from the managed firewall.")
        live_logs = array(object_value(logging.get("LoggingConfiguration")).get("LogDestinationConfigs"))
        if "aws_networkfirewall_logging_configuration" in values:
            value = values["aws_networkfirewall_logging_configuration"]
            require(value.get("firewall_arn") == live_firewall["FirewallArn"], "Managed firewall logging refers to a foreign firewall.")
            destinations = _logging_destinations(value)
            require(len(live_logs) == len(destinations), "Live firewall log destinations differ from managed State.")
            seen = set()
            for log in live_logs:
                log = object_value(log)
                kind = log.get("LogType")
                require(kind in destinations and kind not in seen and log.get("LogDestinationType") == "CloudWatchLogs" and
                        log.get("LogDestination") == {"logGroup": destinations[kind]}, "Live firewall logging sends to an unapproved destination.")
                seen.add(kind)
            if owned_log_rows:
                require(destinations == owned_destinations, "Firewall logging destinations differ from exact owned CloudWatch groups.")
                log_destinations = dict(destinations)
            else:
                log_destinations = _retained_firewall_logs(context, retained_log_state, destinations, inventory)
        else:
            require(not live_logs, "Firewall logging exists outside the remaining managed State.")
    return {"vpc_id": vpc_id, "endpoints": endpoint_proof, "log_destinations": log_destinations,
            "log_policy": "owned-disposable" if owned_log_rows else "externally-retained" if log_destinations else "no-remaining-log-destinations",
            "cloudwatch_groups_to_delete": sorted(owned_destinations.values()),
            "tgw_eni_ownership_limit": "complete attachment/subnet/account/type relationship; no immutable ENI parent ID",
            "inventory_counts": inventory.counts, "requires_full_vpc_consumer_check": True}

READ_OPERATIONS = READ_OPERATIONS | frozenset({
    ("ec2", "describe-flow-logs"), ("ec2", "get-subnet-cidr-reservations"),
    ("route53resolver", "list-resolver-query-log-config-associations"),
})


def _inspection_vpc_inventory(rows, scope, transit_proof, firewall_proof, inventory):
    """Run the existing full VPC guard with proven same-plan service ownership.

    Only exact firewall endpoint identities and approved, exhaustively enumerated
    TGW service relationships are adapted. The original VPC guard remains intact.
    No service ENI is deleted directly. A residual after its owning attachment has
    disappeared blocks retry until AWS completes cleanup or separate recovery.
    """
    vpc_id = firewall_proof["vpc_id"]
    resources = _peer_resources([r for r in rows if r["type"] in _vpc.NETWORK_TYPES])
    original = [r for r in scope if r["type"] in _vpc.NETWORK_TYPES]
    endpoints = firewall_proof["endpoints"]
    for identity, value in endpoints.items():
        resources.append({"type": "aws_vpc_endpoint", "address": "__derived_firewall_endpoint__." + identity,
                          "name": "verified_firewall_endpoint", "values": {"id": identity, "vpc_id": vpc_id,
                          "network_interface_ids": value["network_interface_ids"]}})
    selected = transit_proof.get(vpc_id, {"attachment_ids": [], "transit_gateway_ids": [], "subnet_ids": [], "routes": []})
    attachment_ids = set(selected["attachment_ids"])
    require(len(attachment_ids) <= 1, "Multiple inspection TGW attachments are outside the course topology.")
    owned_subnets = {r["values"]["id"] for r in rows if r["type"] == "aws_subnet" and r["address"].startswith("aws_subnet.inspection_transit")}
    expected_subnets = set(selected["subnet_ids"])
    require(not attachment_ids or expected_subnets == owned_subnets and len(expected_subnets) == 3,
            "Inspection attachment subnet ownership is incomplete.")

    def tgw_enis(response):
        enis = complete_list(response, "NetworkInterfaces")
        result = []
        for eni in enis:
            eni = object_value(eni)
            if eni.get("InterfaceType") != "transit_gateway":
                continue
            require(isinstance(eni.get("NetworkInterfaceId"), str) and
                    re.fullmatch(r"eni-(?:[0-9a-f]{8}|[0-9a-f]{17})", eni["NetworkInterfaceId"]) and
                    eni.get("VpcId") == vpc_id and eni.get("OwnerId") == inventory.account and
                    eni.get("RequesterManaged") is True and eni.get("Status") == "in-use" and
                    eni.get("SubnetId") in expected_subnets and not eni.get("Groups") and
                    not object_value(eni.get("Attachment", {})).get("InstanceId"),
                    "An unknown, foreign or unstable transit service ENI consumes the inspection VPC.")
            result.append(eni)
        require(len(result) == len(expected_subnets) and {r["SubnetId"] for r in result} == expected_subnets and
                len({r["NetworkInterfaceId"] for r in result}) == len(result),
                "Inspection transit ENIs do not exactly cover the selected attachment subnets.")
        return result

    first_enis = inventory.call("ec2", "describe-network-interfaces", "--filters", "Name=vpc-id,Values=" + vpc_id)
    service_enis = tgw_enis(first_enis)
    exact_service_ids = {r["NetworkInterfaceId"] for r in service_enis}
    current_attachments = {r["values"]["id"]: r["values"] for r in rows if r["type"] == "aws_ec2_transit_gateway_vpc_attachment" and r["values"].get("vpc_id") == vpc_id}
    owned_routes = {(r["route_table_id"], r["destination_cidr_block"], r["transit_gateway_id"]) for r in selected["routes"]}

    def adapted(service, operation, *args):
        response = object_value(inventory.aws(service, operation, *args))
        if service != "ec2":
            return response
        response = copy.deepcopy(response)
        if operation == "describe-network-interfaces":
            current = tgw_enis(response)
            require({r["NetworkInterfaceId"] for r in current} == exact_service_ids,
                    "Inspection transit service ENI identities changed during the guard.")
            response["NetworkInterfaces"] = [r for r in complete_list(response, "NetworkInterfaces") if r.get("NetworkInterfaceId") not in exact_service_ids]
        elif operation == "describe-transit-gateway-vpc-attachments":
            live = _active(complete_list(response, "TransitGatewayVpcAttachments"))
            _exact(live, "TransitGatewayAttachmentId", attachment_ids, "An unknown transit attachment consumes the inspection VPC.")
            for attachment in live:
                value = current_attachments[attachment["TransitGatewayAttachmentId"]]
                require(attachment.get("State") == "available" and attachment.get("VpcOwnerId") == inventory.account and
                        attachment.get("VpcId") == vpc_id and attachment.get("TransitGatewayId") == value["transit_gateway_id"] and
                        set(array(attachment.get("SubnetIds"))) == set(value["subnet_ids"]),
                        "Inspection attachment ownership changed during the full VPC check.")
            response["TransitGatewayVpcAttachments"] = [r for r in response["TransitGatewayVpcAttachments"] if r.get("TransitGatewayAttachmentId") not in attachment_ids]
        elif operation == "describe-vpc-endpoints":
            live = complete_list(response, "VpcEndpoints")
            _exact(live, "VpcEndpointId", endpoints, "Inspection endpoints changed during the full VPC check.")
            for endpoint in live:
                proof = endpoints[endpoint["VpcEndpointId"]]
                require(endpoint.get("VpcEndpointType") == "GatewayLoadBalancer" and endpoint.get("RequesterManaged") is True and
                        endpoint.get("State") == "available" and endpoint.get("OwnerId") == inventory.account and endpoint.get("VpcId") == vpc_id and
                        array(endpoint.get("SubnetIds")) == [proof["subnet_id"]] and array(endpoint.get("NetworkInterfaceIds")) == proof["network_interface_ids"] and
                        not endpoint.get("Groups") and not endpoint.get("RouteTableIds"), "Firewall endpoint relationship changed during the full VPC check.")
                # The base guard's Interface branch is used only after the exact
                # GatewayLoadBalancer service parent and ENIs have been proven.
                endpoint["VpcEndpointType"] = "Interface"
                endpoint["Groups"] = []; endpoint["RouteTableIds"] = []
        elif operation == "describe-route-tables":
            found = set()
            for table in complete_list(response, "RouteTables"):
                kept = []
                for route in array(table.get("Routes")):
                    identity = (table.get("RouteTableId"), route.get("DestinationCidrBlock"), route.get("TransitGatewayId"))
                    if identity in owned_routes:
                        require(identity not in found and table.get("VpcId") == vpc_id and table.get("OwnerId") == inventory.account and route.get("State") == "active",
                                "Inspection TGW route identity changed during the full VPC check.")
                        found.add(identity)
                    else:
                        kept.append(route)
                table["Routes"] = kept
            require(found == owned_routes, "An inspection TGW route disappeared during the full VPC check.")
        return response

    counts = _vpc.inventory_consumers(resources, vpc_id, inventory.account, inventory.region, adapted, expected_resources=original)
    inventory.counts.update({"inspection:" + key: value for key, value in counts.items()})
    flow_resources = {vpc_id} | {r["values"]["id"] for r in rows if r["type"] == "aws_subnet"} | {
        r["NetworkInterfaceId"] for r in complete_list(first_enis, "NetworkInterfaces")}
    require(not complete_list(inventory.call("ec2", "describe-flow-logs", "--filter", "Name=resource-id,Values=" + ",".join(sorted(flow_resources))), "FlowLogs"),
            "An unowned flow-log subscription consumes inspection infrastructure.")
    require(not complete_list(inventory.call("route53resolver", "list-resolver-query-log-config-associations", "--filters", "Name=ResourceId,Values=" + vpc_id),
                              "ResolverQueryLogConfigAssociations"), "An unowned Resolver logging association consumes the inspection VPC.")
    for subnet in sorted({r["values"]["id"] for r in rows if r["type"] == "aws_subnet"}):
        reservations = inventory.call("ec2", "get-subnet-cidr-reservations", "--subnet-id", subnet)
        require(not complete_list(reservations, "SubnetIpv4CidrReservations") and not complete_list(reservations, "SubnetIpv6CidrReservations"),
                "An unowned subnet reservation consumes inspection infrastructure.")
    return {"tgw_eni_ids": sorted(exact_service_ids), "ownership_basis": "complete State-owned attachment/subnet/account/type inventory"}


def _verify_firewall_absent(scope, inventory):
    vpcs = _ids(scope, "aws_vpc")
    require(len(vpcs) == 1 and not inventory.filtered("describe-vpcs", "Vpcs", "vpc-id", vpcs), "The inspection VPC is not confirmed absent.")
    for kind, operation, key, field in (
        ("aws_networkfirewall_firewall", "list-firewalls", "Firewalls", "FirewallArn"),
        ("aws_networkfirewall_firewall_policy", "list-firewall-policies", "FirewallPolicies", "Arn"),
        ("aws_networkfirewall_rule_group", "list-rule-groups", "RuleGroups", "Arn"),
    ):
        original = _ids(scope, kind)
        if not original:
            continue
        args = ("--scope", "ACCOUNT") if kind == "aws_networkfirewall_rule_group" else ()
        rows = complete_list(inventory.call("network-firewall", operation, *args), key)
        require(all(isinstance(object_value(row).get(field), str) for row in rows) and not {r[field] for r in rows} & original,
                "An original firewall resource is not confirmed absent.")
    for name in _ids(scope, "aws_cloudwatch_log_group"):
        groups = complete_list(inventory.call("logs", "describe-log-groups", "--log-group-name-prefix", name), "logGroups")
        require(all(isinstance(object_value(row).get("logGroupName"), str) and row["logGroupName"] for row in groups),
                "CloudWatch absence listing has unknown identities.")
        require(not any(object_value(row).get("logGroupName") == name for row in groups), "An original disposable firewall log group remains.")
    require(not inventory.filtered("describe-vpc-endpoints", "VpcEndpoints", "vpc-id", vpcs) and
            not inventory.filtered("describe-network-interfaces", "NetworkInterfaces", "vpc-id", vpcs),
            "A firewall endpoint or service ENI remains in the original inspection VPC.")
