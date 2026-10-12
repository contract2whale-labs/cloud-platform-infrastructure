#!/usr/bin/env python3
"""Verify protected queue/Cognito provisioning metadata; write only nonsecret tfvars."""
import argparse
import json
import os
import sys
from pathlib import Path
from provision import validate, token

def verify_cognito(request, receipt, session):
    expected = {"schema_version", "request_id", "environment", "account_id", "region", "operation", "client_id", "secret_version_id"}
    if set(receipt) != expected or receipt.get("schema_version") != 1:
        raise ValueError("unrecognized Cognito receipt schema")
    for key in ["request_id", "environment", "account_id", "region", "operation"]:
        if receipt.get(key) != request[key]:raise ValueError("receipt differs from the approved request")
    if session.client("sts").get_caller_identity()["Account"] != request["account_id"]:
        raise ValueError("authenticated AWS account differs")
    version = receipt["secret_version_id"]
    if version != token(request, "cognito-client"):raise ValueError("receipt version differs from request")
    metadata = session.client("secretsmanager", region_name=request["region"]).describe_secret(SecretId=request["secret_arn"])
    if metadata.get("ARN") != request["secret_arn"] or "AWSCURRENT" not in metadata.get("VersionIdsToStages", {}).get(version, []):
        raise ValueError("credential version is not the approved current version")
    client = session.client("cognito-idp", region_name=request["region"]).describe_user_pool_client(UserPoolId=request["user_pool_id"], ClientId=receipt["client_id"])["UserPoolClient"]
    # Cognito's response may include ClientSecret. Inspect in memory, never print or persist it.
    flow = "client_credentials" if request["operation"] == "cognito-verifier" else "code"
    if client.get("ClientId") != receipt["client_id"] or client.get("ClientName") != request["client_name"] + "-" + request["request_id"]:
        raise ValueError("client identity differs from the approved request")
    if client.get("AllowedOAuthFlows") != [flow] or set(client.get("AllowedOAuthScopes", [])) != set(request["scopes"]):
        raise ValueError("client OAuth configuration differs")
    if request["operation"] == "cognito-argocd" and set(client.get("CallbackURLs", [])) != set(request["callback_urls"]):
        raise ValueError("client callbacks differ")
    del client
    variable = "verifier_client_id" if request["operation"] == "cognito-verifier" else "argocd_oidc_client_id"
    return {variable: receipt["client_id"]}

def verify(request, receipt, session):
    if request["operation"] in ["cognito-verifier", "cognito-argocd"]:
        return verify_cognito(request, receipt, session)
    expected = {"schema_version", "request_id", "environment", "account_id", "region", "operation", "secret_version_ids"}
    if set(receipt) != expected or receipt.get("schema_version") != 1:
        raise ValueError("unrecognized receipt schema")
    for key in ["request_id", "environment", "account_id", "region", "operation"]:
        if receipt.get(key) != request[key]:
            raise ValueError("receipt does not belong to the approved request")
    if request["operation"] != "queue-scram" or set(receipt["secret_version_ids"]) != {"writer", "reader"}:
        raise ValueError("queue receipt required")
    if session.client("sts").get_caller_identity()["Account"] != request["account_id"]:
        raise ValueError("authenticated AWS account differs")
    sm = session.client("secretsmanager", region_name=request["region"])
    for purpose, user in request["users"].items():
        version_id = receipt["secret_version_ids"][purpose]
        if version_id != token(request, purpose):
            raise ValueError("receipt version does not match the approved request ID")
        metadata = sm.describe_secret(SecretId=user["secret_arn"])
        if metadata.get("ARN", user["secret_arn"]) != user["secret_arn"]:
            raise ValueError("resolved Secret ARN differs")
        if "AWSCURRENT" not in metadata.get("VersionIdsToStages", {}).get(version_id, []):
            raise ValueError("receipt version is not AWSCURRENT")
    fields = ["request_id", "environment", "account_id", "region", "secret_version_ids"]
    return {"credentials_receipt": {key: receipt[key] for key in fields}}

def prepare_output(path):
    if path.exists() or path.is_symlink():
        raise FileExistsError("approved output already exists; preserve it and choose a new approved path")
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("approved output parent must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)


def write_output(path, result):
    # Read-only verification may already have happened if this late create fails.
    # Preserve the previous output; never replace it as an implicit input update.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--expect-account", required=True)
    parser.add_argument("--expect-environment", choices=["dev", "prod"], required=True)
    parser.add_argument("--tfvars", type=Path, required=True)
    args = parser.parse_args()
    request = validate(json.loads(args.request.read_text()), args.expect_account, args.expect_environment)
    prepare_output(args.tfvars)
    import boto3
    result = verify(request, json.loads(args.receipt.read_text()), boto3.Session())
    write_output(args.tfvars, result)
    print("VERIFIED_METADATA_TFVARS", args.tfvars)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("RECEIPT_VERIFICATION_FAILED type=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
