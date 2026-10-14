#!/usr/bin/env python3
"""Fail-closed, read-only guard for the dev network/vpc saved destroy plan.

Run once when creating the private plan and again immediately before its apply.
The caller owns the main-SHA, backend lock, saved-plan digest/version and approval
checks. This guard never deletes a resource, edits State, or prints State/plan.
It intentionally rejects non-network resources (including BU03 logging/S3/IAM).

Coverage is bounded: registered dependent roots plus regional VPC topology,
ENIs, EKS, EC2 instances, ELB/ELBv2, peerings, TGW/VPN/IPv6 gateways and direct
Route53 private-zone and Route53 Profiles VPC associations. It is not an
account-wide service dependency proof or an atomic lock against manual changes.
Unknown/missing API fields, denied reads, incomplete pagination and unsupported
managed types block. There is no bypass/force option.

Exact service-created ENI relationships (never descriptions or tag matching):
https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-nat-gateways.html
https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html
https://docs.aws.amazon.com/cli/latest/reference/route53profiles/list-profile-associations.html
Provider fields checked against hashicorp/aws v6.62.0:
https://github.com/hashicorp/terraform-provider-aws/blob/v6.62.0/internal/service/ec2/vpc_nat_gateway.go
https://github.com/hashicorp/terraform-provider-aws/blob/v6.62.0/internal/service/ec2/vpc_endpoint.go
"""
import json
import os
from pathlib import Path
import re
import subprocess
import threading

ROOT = "terraform/environments/dev/network/vpc"
STATE_KEY = "network/vpc/terraform.tfstate"
ENCRYPTION = {"AES256", "aws:kms", "aws:kms:dsse"}
MAX_STATE_BYTES = 64 * 1024 * 1024
# No IAM, S3, KMS, Secrets, logs, Resolver, EKS, compute, transit or peer resources.
NETWORK_TYPES = frozenset({
    "terraform_data", "aws_vpc", "aws_subnet", "aws_internet_gateway",
    "aws_route_table", "aws_default_route_table", "aws_route_table_association",
    "aws_route", "aws_eip", "aws_nat_gateway", "aws_default_security_group",
    "aws_security_group", "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
    "aws_default_network_acl", "aws_network_acl", "aws_network_acl_rule",
    "aws_network_acl_association", "aws_vpc_endpoint",
    "aws_vpc_endpoint_route_table_association", "aws_vpc_endpoint_subnet_association",
    "aws_vpc_endpoint_security_group_association", "aws_network_interface",
})
READ_OPERATIONS = frozenset({
    ("sts", "get-caller-identity"),
    ("s3api", "list-objects-v2"), ("s3api", "head-object"),
    ("ec2", "describe-vpcs"), ("ec2", "describe-subnets"),
    ("ec2", "describe-security-groups"), ("ec2", "describe-network-acls"),
    ("ec2", "describe-route-tables"), ("ec2", "describe-internet-gateways"),
    ("ec2", "describe-nat-gateways"), ("ec2", "describe-vpc-endpoints"),
    ("ec2", "describe-network-interfaces"), ("ec2", "describe-instances"),
    ("ec2", "describe-addresses"),
    ("ec2", "describe-vpc-peering-connections"),
    ("ec2", "describe-transit-gateway-vpc-attachments"),
    ("ec2", "describe-vpn-gateways"),
    ("ec2", "describe-egress-only-internet-gateways"),
    ("eks", "list-clusters"), ("eks", "describe-cluster"),
    ("elb", "describe-load-balancers"), ("elbv2", "describe-load-balancers"),
    ("route53", "list-hosted-zones-by-vpc"),
    ("route53profiles", "list-profile-associations"),
})
LIMITS = (
    "Registered dev dependency closure and documented regional VPC consumer APIs only; "
    "not a universal service inventory. "
    "Read failures/unknown ownership fail closed. "
    "Freeze other writers and rerun immediately before apply; AWS reads are not atomic."
)


class SafeError(Exception):
    """Fixed diagnostics only: safe for a public runner log."""


def require(ok, message):
    if not ok:
        raise SafeError(message)


def object_value(value):
    require(isinstance(value, dict), "Invalid private object or API response.")
    return value


def array(value):
    require(isinstance(value, list), "Invalid private array or incomplete API response.")
    return value


def aws_read(service, operation, *args):
    """AWS CLI auto-pagination stays enabled; never expose stdout/stderr on error."""
    require((service, operation) in READ_OPERATIONS, "The consumer guard permits only approved read APIs.")
    result = subprocess.run(
        ["aws", service, operation, *args, "--output", "json", "--no-cli-pager"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    require(result.returncode == 0, "A required consumer read failed; destruction is blocked.")
    try:
        return object_value(json.loads(result.stdout))
    except (ValueError, TypeError):
        raise SafeError("A required consumer read returned invalid JSON.") from None


def complete_list(response, key):
    response = object_value(response)
    require(not any(response.get(k) for k in ("NextToken", "nextToken", "NextMarker", "Marker", "ContinuationToken", "NextContinuationToken")),
            "A consumer read was incomplete; destruction is blocked.")
    require(response.get("IsTruncated") is not True, "A consumer read was truncated; destruction is blocked.")
    return array(response.get(key))


def read_object_memory(bucket, account, region, key, version):
    """Read one exact S3 object version into an anonymous Linux pipe, not a file."""
    read_fd, write_fd = os.pipe()
    chunks, oversized, errors = [], [], []

    def drain():
        total = 0
        try:
            with os.fdopen(read_fd, "rb") as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total <= MAX_STATE_BYTES:
                        chunks.append(chunk)
                    else:
                        oversized.append(True)
        except Exception:
            errors.append(True)

    reader = threading.Thread(target=drain)
    reader.start()
    process = None
    try:
        process = subprocess.Popen([
            "aws", "s3api", "get-object", "--bucket", bucket,
            "--expected-bucket-owner", account, "--region", region,
            "--key", key, "--version-id", version, f"/proc/self/fd/{write_fd}",
            "--output", "json", "--no-cli-pager",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(write_fd,))
    finally:
        os.close(write_fd)
        if process is None:
            reader.join()
    metadata, _private_error = process.communicate()
    reader.join()
    require(process.returncode == 0 and not errors and not oversized,
            "A private dependent State read failed; destruction is blocked.")
    try:
        return object_value(json.loads(b"".join(chunks))), object_value(json.loads(metadata))
    except (ValueError, TypeError):
        raise SafeError("A dependent State or its private metadata is invalid.") from None


class VersionedStateReader:
    """Callable(key) -> {state: raw State or None, fingerprint: private metadata}."""
    def __init__(self, bucket, account, region, *, aws_call=None, object_reader=None):
        self.bucket, self.account, self.region = bucket, account, region
        self.aws = aws_call or aws_read
        self.object_reader = object_reader or read_object_memory

    def call(self, operation, key):
        option = "--prefix" if operation == "list-objects-v2" else "--key"
        # Keep the service's IsTruncated/KeyCount proof (AWS CLI aggregation can
        # discard it). The prefix is one exact State key; a truncated first page
        # blocks rather than being mistaken for an absent State.
        pagination = ("--no-paginate",) if operation == "list-objects-v2" else ()
        return self.aws("s3api", operation, "--bucket", self.bucket,
                        "--expected-bucket-owner", self.account, "--region", self.region, option, key, *pagination)

    @staticmethod
    def fingerprint(metadata):
        metadata = object_value(metadata)
        require(isinstance(metadata.get("VersionId"), str) and metadata["VersionId"] not in ("", "null"),
                "Dependent State must have an exact non-null S3 version.")
        require(metadata.get("ServerSideEncryption") in ENCRYPTION,
                "Dependent State encryption was not verified.")
        require(isinstance(metadata.get("ETag"), str) and bool(metadata["ETag"]) and
                type(metadata.get("ContentLength")) is int and 0 < metadata["ContentLength"] <= MAX_STATE_BYTES,
                "Dependent State metadata is incomplete.")
        return {"exists": True, "version": metadata["VersionId"],
                "etag": metadata["ETag"], "size": metadata["ContentLength"]}

    def __call__(self, key):
        require(bool(re.fullmatch(r"[a-z0-9][a-z0-9/_-]*/terraform\.tfstate", key)) and ".." not in key,
                "Invalid dependent State key.")
        listed = object_value(self.call("list-objects-v2", key))
        # An empty S3 listing omits Contents; errors are never treated as empty.
        require(type(listed.get("KeyCount")) is int and listed["KeyCount"] >= 0 and
                listed.get("IsTruncated") is False,
                "Dependent State listing completeness could not be verified.")
        listed.setdefault("Contents", [])
        contents = complete_list(listed, "Contents")
        require(all(isinstance(item, dict) and isinstance(item.get("Key"), str) for item in contents),
                "Dependent State listing is invalid.")
        if not any(item["Key"] == key for item in contents):
            return {"state": None, "fingerprint": {"exists": False}}
        before = self.fingerprint(self.call("head-object", key))
        state, metadata = self.object_reader(self.bucket, self.account, self.region, key, before["version"])
        require(self.fingerprint(metadata) == before,
                "The pinned dependent State metadata changed during read.")
        after = self.fingerprint(self.call("head-object", key))
        require(before == after, "Dependent State changed during the consumer check.")
        require(state.get("version") == 4 and isinstance(state.get("lineage"), str) and bool(state["lineage"]) and
                type(state.get("serial")) is int and state["serial"] >= 0,
                "Dependent State has an unsupported format or identity.")
        return {"state": state, "fingerprint": before}


def managed_resources(state):
    """Normalize raw State v4 or Terraform show -json values; never use outputs."""
    state = object_value(state)
    result = []
    if "values" in state:
        require(str(state.get("format_version", "")).split(".")[0] == "1",
                "Unsupported Terraform JSON State format.")

        def visit(module):
            module = object_value(module)
            for resource in array(module.get("resources", [])):
                resource = object_value(resource)
                require(resource.get("mode") in ("managed", "data"), "Invalid State resource mode.")
                if resource["mode"] == "managed":
                    result.append({"address": resource.get("address"), "type": resource.get("type"),
                                   "values": resource.get("values"), "name": resource.get("name")})
            for child in array(module.get("child_modules", [])):
                visit(child)
        visit(object_value(state["values"]).get("root_module", {}))
    else:
        require(state.get("version") == 4, "Unsupported Terraform State format.")
        for resource in array(state.get("resources", [])):
            resource = object_value(resource)
            require(resource.get("mode") in ("managed", "data"), "Invalid State resource mode.")
            if resource["mode"] != "managed":
                continue
            require(isinstance(resource.get("type"), str) and isinstance(resource.get("name"), str),
                    "Invalid managed State resource.")
            prefix = resource.get("module", "")
            require(isinstance(prefix, str), "Invalid managed State module.")
            address = (prefix + "." if prefix else "") + resource["type"] + "." + resource["name"]
            for instance in array(resource.get("instances")):
                instance = object_value(instance)
                require(not instance.get("deposed"), "Deposed State instances require separate recovery before lifecycle use.")
                suffix = ""
                if "index_key" in instance:
                    index = instance["index_key"]
                    require(type(index) in (int, str), "Invalid State instance index.")
                    suffix = "[" + json.dumps(index, ensure_ascii=False, separators=(",", ":")) + "]"
                result.append({"address": address + suffix, "type": resource["type"],
                               "values": instance.get("attributes"), "name": resource["name"]})
    addresses = set()
    for resource in result:
        require(isinstance(resource["address"], str) and bool(resource["address"]) and
                isinstance(resource["type"], str) and isinstance(resource["values"], dict),
                "Managed State identity is missing.")
        require(resource["address"] not in addresses, "Duplicate managed State identities are not supported.")
        addresses.add(resource["address"])
    return result


def validate_context(context):
    context = object_value(context)
    require(context.get("root") == ROOT and context.get("environment") == ROOT.split("/")[2] and
            context.get("workspace") == "default", "Lifecycle is restricted to the exact registered network/vpc root and default workspace.")
    account = context.get("account", "")
    require(isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account) is not None,
            "A configured 12-digit dev account is required.")
    backend = object_value(context.get("backend"))
    require(backend.get("key") == STATE_KEY and isinstance(backend.get("bucket"), str) and bool(backend["bucket"]) and
            isinstance(backend.get("region"), str) and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", backend["region"]) is not None,
            "The lifecycle backend or region is invalid.")
    return account, backend["region"]


def normalize_resources(state):
    """Return a minimal private address/type/id list for the pinned control record."""
    return sorted(({"address": r["address"], "type": r["type"], "id": r["values"].get("id")}
                   for r in managed_resources(state)), key=lambda r: r["address"])


def original_resources(expected_resources):
    records = array(expected_resources)
    seen = set()
    for record in records:
        record = object_value(record)
        require(set(record) == {"address", "type", "id"} and
                all(isinstance(record[k], str) and bool(record[k]) for k in ("address", "type", "id")),
                "Invalid original resource identity in the lifecycle control record.")
        require(record["address"] not in seen and record["type"] in NETWORK_TYPES,
                "Original control identities are duplicated or outside the supported network scope.")
        seen.add(record["address"])
    return records


def validate_network_state(context, state, *, expected_resources=None):
    """Validate root/account/type and resource relationships without AWS calls.

    Return normalized managed resources. On partial-down retries, the caller may
    supply the original pinned identity map to prove the remaining identities belong
    to the approved VPC. An expected VPC ID by itself is not sufficient evidence.
    """
    account, region = validate_context(context)
    resources = managed_resources(state)
    for resource in resources:
        require(not resource["type"].startswith("aws_iam"),
                "IAM exists in VPC State; preserve and separate it before lifecycle use.")
        require(resource["type"] in NETWORK_TYPES,
                "Unsupported managed resources exist in VPC State; preservation must be resolved first.")
        if resource["type"] == "terraform_data":
            require(resource["address"] == "terraform_data.workspace_guard",
                    "Only the course workspace guard is allowed as a built-in resource.")
        require(isinstance(resource["values"].get("id"), str) and bool(resource["values"]["id"]),
                "A managed resource has no exact State identity.")
        values = resource["values"]
        if values.get("owner_id"):
            require(values["owner_id"] == account, "Managed resource owner differs from the configured dev account.")
        if values.get("arn"):
            parts = values["arn"].split(":", 5)
            require(len(parts) == 6 and parts[0] == "arn" and parts[3] in ("", region) and parts[4] in ("", account),
                    "Managed resource ARN is outside the configured account or region.")
    scope = normalize_resources(state)
    if expected_resources is not None:
        scope = original_resources(expected_resources)
        approved = {r["address"]: (r["type"], r["id"]) for r in scope}
        require(all(approved.get(r["address"]) == (r["type"], r["values"]["id"]) for r in resources),
                "Remaining State is not a subset of the original approved VPC identities.")
    by_type = {}
    for resource in scope:
        by_type.setdefault(resource["type"], set()).add(resource["id"])

    def ids(*types):
        return set().union(*(by_type.get(t, set()) for t in types))

    vpcs = ids("aws_vpc")
    require(len(vpcs) <= 1, "Multiple managed VPC identities are not supported.")
    if resources:
        require(len(vpcs) == 1, "Resources without an original managed VPC require separate recovery.")
    for resource in resources:
        value, kind = resource["values"], resource["type"]
        if value.get("vpc_id"):
            require(value["vpc_id"] in vpcs, "Managed resource refers to a different VPC.")
        for field, owned in (
            ("subnet_id", ids("aws_subnet")),
            ("route_table_id", ids("aws_route_table", "aws_default_route_table")),
            ("network_acl_id", ids("aws_network_acl", "aws_default_network_acl")),
            ("security_group_id", ids("aws_security_group", "aws_default_security_group")),
            ("vpc_endpoint_id", ids("aws_vpc_endpoint")),
            ("nat_gateway_id", ids("aws_nat_gateway")),
        ):
            if value.get(field):
                require(value[field] in owned, "Managed resource references network infrastructure outside the approved State.")
        if kind in ("aws_subnet", "aws_route_table", "aws_default_route_table", "aws_security_group",
                    "aws_default_security_group", "aws_network_acl", "aws_default_network_acl", "aws_vpc_endpoint"):
            require(value.get("vpc_id") in vpcs, "A managed network resource has no exact VPC relationship.")
    return resources


def validate_destroy(state, plan, *, expected_vpc_id=None, expected_resources=None):
    resources = managed_resources(state)
    source = original_resources(expected_resources) if expected_resources is not None else normalize_resources(state)
    vpcs = [resource for resource in source if resource["type"] == "aws_vpc"]
    require(len(vpcs) == 1 and re.fullmatch(r"vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})", vpcs[0]["id"]) is not None,
            "Exactly one original managed VPC identity is required; outputs and tags are not authority.")
    vpc_id = vpcs[0]["id"]
    if expected_vpc_id is not None:
        require(expected_vpc_id == vpc_id, "The original managed VPC does not match the lifecycle control record.")
    if not any(r["type"] == "aws_vpc" for r in resources):
        require(expected_resources is not None and expected_vpc_id is not None,
                "Missing VPC State requires the original pinned resource map and VPC control identity.")
    plan = object_value(plan)
    require(str(plan.get("format_version", "")).split(".")[0] == "1" and
            plan.get("errored", False) is False and plan.get("complete", True) is True and not plan.get("deferred_changes"),
            "The destroy plan is incomplete or unsupported.")
    identities = {r["address"]: (r["type"], r["values"]["id"]) for r in resources}
    # Terraform 1.16 omits prior_state entirely for an already-empty State.
    prior = [] if not resources and "prior_state" not in plan else managed_resources(object_value(plan.get("prior_state")))
    require({r["address"]: (r["type"], r["values"].get("id")) for r in prior} == identities,
            "Destroy plan prior State differs from the current managed State.")
    changes = {}
    for change in array(plan.get("resource_changes", [])):
        change = object_value(change)
        require(change.get("mode") in ("managed", "data"), "Invalid planned resource mode.")
        if change["mode"] != "managed":
            continue
        require(not change.get("deposed") and not change.get("previous_address"),
                "Moved or deposed instances are not supported by this lifecycle.")
        detail = object_value(change.get("change"))
        require(detail.get("actions") == ["delete"] and detail.get("after") is None,
                "Lifecycle Down accepts a complete delete-only saved plan.")
        before = object_value(detail.get("before"))
        address = change.get("address")
        require(isinstance(address, str) and address not in changes, "Invalid or duplicate planned identity.")
        changes[address] = (change.get("type"), before.get("id"))
    require(changes == identities, "Every managed State object must match the exact destroy plan.")
    remaining = {"format_version": "1.0", "values": object_value(plan.get("planned_values"))}
    require(not managed_resources(remaining), "The destroy plan leaves managed resources behind.")
    return resources, vpc_id


def dependent_roots(workspace):
    try:
        graph = json.loads((Path(workspace) / "ci/deploy-roots.json").read_text())["dependencies"]
    except (OSError, ValueError, KeyError):
        raise SafeError("The dependency registry is missing or invalid.") from None
    graph = object_value(graph)
    require(ROOT in graph, "VPC is absent from the dependency registry.")
    for root, upstream in graph.items():
        require(isinstance(root, str) and re.fullmatch(r"terraform/environments/(dev|prod)/[a-z0-9][a-z0-9/_-]*", root) is not None,
                "Invalid root in the dependency registry.")
        require(isinstance(upstream, list) and all(isinstance(p, str) and p in graph and p.split("/")[2] == root.split("/")[2] for p in upstream),
                "Dependency registry has an unknown or cross-environment dependency.")
    closure = {ROOT}
    while True:
        expanded = closure | {root for root, upstream in graph.items() if set(upstream) & closure}
        if expanded == closure:
            break
        closure = expanded
    return sorted(closure - {ROOT})


def check_dependents(workspace, loader):
    evidence = {}
    for root in dependent_roots(workspace):
        key = "/".join(root.split("/")[3:]) + "/terraform.tfstate"
        loaded = object_value(loader(key))
        fingerprint = object_value(loaded.get("fingerprint"))
        state = loaded.get("state")
        require(type(fingerprint.get("exists")) is bool, "Dependent State existence is unknown.")
        if fingerprint["exists"]:
            require(state is not None and bool(fingerprint.get("version")) and fingerprint["version"] != "null",
                    "Dependent State was not read at an exact version.")
            require(not managed_resources(state), "A dependent root still has managed State; destroy consumers first.")
        else:
            require(state is None, "Dependent State evidence is inconsistent.")
        evidence[root] = fingerprint
    return evidence


def inventory_consumers(resources, vpc_id, account, region, aws_call, *, expected_resources=None):
    counts = {}
    by_type = {}
    for resource in resources:
        by_type.setdefault(resource["type"], {})[resource["values"]["id"]] = resource["values"]
    # These adoption resources leave the AWS defaults alive when Terraform
    # forgets them during destroy. Only the exact ORIGINAL default identities
    # can survive a partial retry, and only while the managed VPC still exists.
    if by_type.get("aws_vpc") and expected_resources is not None:
        for resource in original_resources(expected_resources):
            if resource["type"] in ("aws_default_security_group", "aws_default_network_acl", "aws_default_route_table"):
                by_type.setdefault(resource["type"], {}).setdefault(resource["id"], {"id": resource["id"]})

    def ids(*types):
        return set().union(*(set(by_type.get(t, {})) for t in types))

    def read(service, operation, key, *args):
        rows = complete_list(aws_call(service, operation, *args, "--region", region), key)
        require(all(isinstance(row, dict) for row in rows), "Malformed consumer inventory.")
        counts[service + ":" + operation] = counts.get(service + ":" + operation, 0) + len(rows)
        return rows

    def ec2(operation, key, filter_name="vpc-id"):
        return read("ec2", operation, key, "--filters", "Name=" + filter_name + ",Values=" + vpc_id)

    def exact(rows, field, owned, *, vpc_field="VpcId", owner_field="OwnerId"):
        found = set()
        for row in rows:
            value = row.get(field)
            require(isinstance(value, str) and value in owned and value not in found,
                    "A foreign or ambiguous VPC resource was found.")
            found.add(value)
            if vpc_field:
                require(row.get(vpc_field) == vpc_id, "A resource is outside the State-owned VPC.")
            if owner_field:
                require(row.get(owner_field) == account, "VPC resource ownership could not be verified.")
        require(found == owned, "State-owned resources and the live VPC differ; refresh and review before retrying.")

    # A successful filtered empty result proves absence; InvalidVpcID.NotFound or
    # AccessDenied from another request is never converted into absence.
    vpcs = ec2("describe-vpcs", "Vpcs")
    exact(vpcs, "VpcId", ids("aws_vpc"))
    if vpcs:
        require(vpcs[0].get("IsDefault") is False and vpcs[0].get("State") == "available",
                "Only an available, non-default VPC can use this lifecycle.")
        # Account-owned AND service-owned zones block. No name/tag inference.
        require(not read("route53", "list-hosted-zones-by-vpc", "HostedZoneSummaries",
                         "--vpc-id", vpc_id, "--vpc-region", region),
                "A private hosted-zone association still consumes the VPC.")
        # ListHostedZonesByVPC excludes Profile-based associations. Check the
        # exact VPC attachment separately, including shared/cross-account Profiles.
        require(not read("route53profiles", "list-profile-associations", "ProfileAssociations",
                         "--resource-id", vpc_id),
                "A Route53 Profiles association still consumes the VPC.")
    subnets = ec2("describe-subnets", "Subnets")
    exact(subnets, "SubnetId", ids("aws_subnet"))
    groups = ec2("describe-security-groups", "SecurityGroups")
    exact(groups, "GroupId", ids("aws_security_group", "aws_default_security_group"))
    acls = ec2("describe-network-acls", "NetworkAcls")
    exact(acls, "NetworkAclId", ids("aws_network_acl", "aws_default_network_acl"))
    tables = ec2("describe-route-tables", "RouteTables")
    exact(tables, "RouteTableId", ids("aws_route_table", "aws_default_route_table"))
    gateways = ec2("describe-internet-gateways", "InternetGateways", "attachment.vpc-id")
    gateway_ids = ids("aws_internet_gateway")
    require(all(g.get("InternetGatewayId") in gateway_ids for g in gateways), "A foreign internet gateway is attached to the VPC.")
    # A failed earlier DeleteInternetGateway may have detached the owned IGW.
    # Exact-ID reads distinguish that recoverable state from a missing/foreign IGW.
    if gateway_ids:
        gateways = read("ec2", "describe-internet-gateways", "InternetGateways", "--internet-gateway-ids", *sorted(gateway_ids))
    exact(gateways, "InternetGatewayId", gateway_ids, vpc_field=None)
    for gateway in gateways:
        require(all(a.get("VpcId") == vpc_id for a in array(gateway.get("Attachments"))),
                "Internet gateway attachment is inconsistent.")

    nats = ec2("describe-nat-gateways", "NatGateways")
    nats = [n for n in nats if n.get("State") != "deleted"]
    exact(nats, "NatGatewayId", ids("aws_nat_gateway"), owner_field=None)
    owned_enis = ids("aws_network_interface")
    for nat in nats:
        value = by_type["aws_nat_gateway"][nat["NatGatewayId"]]
        require(nat.get("State") == "available" and nat.get("SubnetId") in ids("aws_subnet") and
                nat["SubnetId"] == value.get("subnet_id"), "NAT gateway is unstable or outside owned subnets.")
        addresses = array(nat.get("NatGatewayAddresses"))
        require(bool(addresses), "NAT gateway ENI ownership is unknown.")
        live_enis = {a.get("NetworkInterfaceId") for a in addresses}
        require(live_enis == {value.get("network_interface_id")} and all(isinstance(v, str) and v for v in live_enis),
                "NAT gateway ENI identity differs from managed State.")
        for address in addresses:
            require(address.get("AllocationId") in ids("aws_eip"), "A NAT gateway uses an EIP outside managed State.")
        owned_enis |= live_enis

    endpoints = ec2("describe-vpc-endpoints", "VpcEndpoints")
    endpoints = [e for e in endpoints if str(e.get("State", "")).lower() != "deleted"]
    exact(endpoints, "VpcEndpointId", ids("aws_vpc_endpoint"))
    for endpoint in endpoints:
        value = by_type["aws_vpc_endpoint"][endpoint["VpcEndpointId"]]
        require(str(endpoint.get("State", "")).lower() == "available" and
                endpoint.get("VpcEndpointType") in ("Gateway", "Interface"),
                "An endpoint is unstable or outside this lifecycle scope.")
        live_enis = set(array(endpoint.get("NetworkInterfaceIds")))
        require(live_enis == set(array(value.get("network_interface_ids"))) and
                all(isinstance(v, str) and v for v in live_enis), "Endpoint ENI identity differs from managed State.")
        require(set(array(endpoint.get("SubnetIds"))).issubset(ids("aws_subnet")) and
                set(array(endpoint.get("RouteTableIds"))).issubset(ids("aws_route_table", "aws_default_route_table")),
                "An endpoint uses resources outside managed State.")
        require(all(g.get("GroupId") in ids("aws_security_group", "aws_default_security_group")
                    for g in array(endpoint.get("Groups"))), "An endpoint uses a foreign security group.")
        owned_enis |= live_enis

    enis = ec2("describe-network-interfaces", "NetworkInterfaces")
    exact(enis, "NetworkInterfaceId", owned_enis)
    for eni in enis:
        require(eni.get("SubnetId") in ids("aws_subnet") and
                not object_value(eni.get("Attachment", {})).get("InstanceId"),
                "An ENI is attached to a workload or outside managed subnets.")
        require(all(g.get("GroupId") in ids("aws_security_group", "aws_default_security_group")
                    for g in array(eni.get("Groups"))), "An ENI uses a foreign security group.")
        if eni["NetworkInterfaceId"] in ids("aws_network_interface"):
            require(eni.get("RequesterManaged") is False and eni.get("InterfaceType") == "interface" and not eni.get("Attachment"),
                    "A directly managed ENI is in use or is owned by an unsupported service.")

    eips = ids("aws_eip")
    if eips:
        addresses = read("ec2", "describe-addresses", "Addresses", "--allocation-ids", *sorted(eips))
        exact(addresses, "AllocationId", eips, vpc_field=None, owner_field=None)
        for address in addresses:
            require(address.get("Domain") == "vpc" and not address.get("InstanceId") and
                    (not address.get("NetworkInterfaceId") or address["NetworkInterfaceId"] in owned_enis),
                    "A managed EIP is associated with a foreign consumer.")

    # Routes to unmanaged services are blocked even if their ENIs have disappeared.
    allowed_targets = ids("aws_internet_gateway", "aws_nat_gateway", "aws_vpc_endpoint") | {"local"}
    target_fields = ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
                     "NetworkInterfaceId", "InstanceId", "EgressOnlyInternetGatewayId", "LocalGatewayId",
                     "CarrierGatewayId", "CoreNetworkArn", "VpcEndpointId")
    for table in tables:
        for route in array(table.get("Routes")):
            targets = [route[k] for k in target_fields if route.get(k)]
            require(len(targets) == 1 and targets[0] in allowed_targets,
                    "A VPC route targets an unmanaged consumer.")
        for association in array(table.get("Associations")):
            require(not association.get("SubnetId") or association["SubnetId"] in ids("aws_subnet"),
                    "A route table is associated with a foreign subnet.")
    for acl in acls:
        require(all(a.get("SubnetId") in ids("aws_subnet") for a in array(acl.get("Associations"))),
                "A network ACL is associated with a foreign subnet.")

    for reservation in ec2("describe-instances", "Reservations"):
        for instance in array(reservation.get("Instances")):
            require(object_value(instance.get("State")).get("Name") == "terminated",
                    "EC2 instances still consume the VPC.")
    for side in ("requester", "accepter"):
        peers = ec2("describe-vpc-peering-connections", "VpcPeeringConnections", side + "-vpc-info.vpc-id")
        require(all(object_value(p.get("Status")).get("Code") in ("deleted", "rejected", "expired", "failed") for p in peers),
                "VPC peering still consumes the VPC.")
    attachments = ec2("describe-transit-gateway-vpc-attachments", "TransitGatewayVpcAttachments")
    require(all(a.get("State") in ("deleted", "rejected", "failed") for a in attachments),
            "A transit gateway attachment still consumes the VPC.")
    require(not ec2("describe-vpn-gateways", "VpnGateways", "attachment.vpc-id"),
            "A VPN gateway still consumes the VPC.")
    # This API has no VPC filter. Read every page, then inspect exact attachment IDs.
    egress = read("ec2", "describe-egress-only-internet-gateways", "EgressOnlyInternetGateways")
    for gateway in egress:
        require(all(isinstance(a.get("VpcId"), str) and a["VpcId"] != vpc_id for a in array(gateway.get("Attachments"))),
                "An IPv6 egress gateway still consumes the VPC.")
    for service, key, field in (("elb", "LoadBalancerDescriptions", "VPCId"), ("elbv2", "LoadBalancers", "VpcId")):
        require(all(isinstance(row.get(field), str) and row[field] != vpc_id
                    for row in read(service, "describe-load-balancers", key)),
                "A load balancer consumes the VPC or its VPC identity is unknown.")
    names = complete_list(aws_call("eks", "list-clusters", "--region", region), "clusters")
    require(all(isinstance(name, str) and bool(name) for name in names), "EKS inventory is incomplete.")
    counts["eks:list-clusters"] = len(names)
    for name in names:
        cluster = object_value(aws_call("eks", "describe-cluster", "--name", name, "--region", region)).get("cluster")
        config = object_value(object_value(cluster).get("resourcesVpcConfig"))
        require(isinstance(config.get("vpcId"), str) and config["vpcId"] != vpc_id,
                "An EKS cluster consumes the VPC or its ownership is unknown.")
    return counts


def verify_vpc_absent(context, vpc_id, *, aws_call=None):
    """Prove the pinned VPC is absent after Down; denied/unknown reads never pass."""
    account, region = validate_context(context)
    require(isinstance(vpc_id, str) and re.fullmatch(r"vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})", vpc_id) is not None,
            "An exact pinned VPC identity is required for absence verification.")
    call = aws_call or aws_read
    require(object_value(call("sts", "get-caller-identity", "--region", region)).get("Account") == account,
            "AWS caller account differs from the configured dev account.")
    rows = complete_list(call("ec2", "describe-vpcs", "--filters", "Name=vpc-id,Values=" + vpc_id,
                              "--region", region), "Vpcs")
    require(not rows, "The pinned VPC is not confirmed absent; Down is incomplete.")
    return {"vpc_id": vpc_id, "absent": True}


def guard_destroy(workspace, context, state_json, plan_json, *, aws_call=None, load_state=None,
                  expected_vpc_id=None, expected_resources=None):
    """Return PRIVATE evidence only on success. Every dependency read must succeed."""
    account, region = validate_context(context)
    validate_network_state(context, state_json, expected_resources=expected_resources)
    resources, vpc_id = validate_destroy(state_json, plan_json, expected_vpc_id=expected_vpc_id,
                                       expected_resources=expected_resources)
    call = aws_call or aws_read
    identity = object_value(call("sts", "get-caller-identity", "--region", region))
    require(identity.get("Account") == account, "AWS caller account differs from the configured dev account.")
    loader = load_state or VersionedStateReader(context["backend"]["bucket"], account, region, aws_call=call)
    dependent_states = check_dependents(workspace, loader)
    counts = inventory_consumers(resources, vpc_id, account, region, call, expected_resources=expected_resources)
    return {"vpc_id": vpc_id, "dependent_states": dependent_states, "inventory_counts": counts, "limits": LIMITS}
