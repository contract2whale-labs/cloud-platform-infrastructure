#!/usr/bin/env python3
"""Protected credential producer. Request/output contain metadata, never values."""
import argparse
import hashlib
import json
import os
import re
import secrets
import sys
from pathlib import Path

COMMON = {"schema_version", "request_id", "environment", "account_id", "region", "operation"}

def validate(request, account, environment):
    if request.get("schema_version") != 1:
        raise ValueError("unsupported request schema")
    if request.get("account_id") != account or request.get("environment") != environment:
        raise ValueError("request account/environment does not match the approved target")
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValueError("account must be a 12-digit account ID")
    if environment not in {"dev", "prod"} or not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,62}", request.get("request_id", "")):
        raise ValueError("invalid environment/request ID")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", request.get("region", "")):
        raise ValueError("invalid region")
    operation = request.get("operation")
    if operation == "queue-scram":
        allowed = COMMON | {"users"}
        if not isinstance(request.get("users"), dict) or set(request["users"]) != {"writer", "reader"}:
            raise ValueError("queue request must specify writer and reader")
        for user in request["users"].values():
            if set(user) != {"secret_arn", "username"}:
                raise ValueError("queue user accepts references and username only")
            if not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", user["username"]):
                raise ValueError("invalid SCRAM username")
            check_secret_arn(user["secret_arn"], request)
    elif operation in {"cognito-verifier", "cognito-argocd"}:
        allowed = COMMON | {"user_pool_id", "client_name", "secret_arn", "token_endpoint", "scopes", "callback_urls"}
        check_secret_arn(request.get("secret_arn", ""), request)
        if not request.get("user_pool_id", "").startswith(request["region"] + "_"):
            raise ValueError("Cognito pool belongs to another region")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", request.get("client_name", "")):
            raise ValueError("invalid client name")
        if not request.get("scopes") or not all(isinstance(scope, str) and scope for scope in request["scopes"]):
            raise ValueError("OAuth scopes required")
        if operation == "cognito-verifier" and ("openid" in request["scopes"] or request.get("callback_urls")):
            raise ValueError("client_credentials uses API scopes, no user callbacks")
        if operation == "cognito-verifier" and not re.fullmatch(r"https://[A-Za-z0-9.-]+/oauth2/token", request.get("token_endpoint", "")):
            raise ValueError("HTTPS token endpoint required")
        if operation == "cognito-argocd":
            urls = request.get("callback_urls")
            if not urls or not all(url.startswith("https://") or url.startswith("http://localhost:") for url in urls):
                raise ValueError("Argo callbacks must be HTTPS or the approved localhost forwarding endpoint")
    else:
        raise ValueError("unsupported protected operation")
    if set(request) - allowed:
        raise ValueError("unknown request fields; credentials cannot be passed as input")
    return request

def check_secret_arn(arn, request):
    prefix = "arn:aws:secretsmanager:%s:%s:secret:" % (request["region"], request["account_id"])
    if not isinstance(arn, str) or not arn.startswith(prefix) or len(arn) <= len(prefix):
        raise ValueError("Secret ARN outside approved account/region")

def token(request, identity):
    # Only the same complete approved payload is an idempotent retry.
    # Changing a username, ARN or OAuth input must never adopt its old receipt.
    payload = json.dumps({"request": request, "identity": identity},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode()).hexdigest()

def version_exists(sm, arn, version_id):
    pages = sm.get_paginator("list_secret_version_ids")
    for page in pages.paginate(SecretId=arn, IncludeDeprecated=True):
        for version in page["Versions"]:
            if version["VersionId"] == version_id:
                if "AWSCURRENT" not in version.get("VersionStages", []):
                    raise ValueError("request version is no longer current; refuse to roll back a later rotation")
                return True
    return False

def initialize_queue(request, sm):
    ids = {}
    for purpose, user in request["users"].items():
        arn = user["secret_arn"]
        metadata = sm.describe_secret(SecretId=arn)
        if not metadata["Name"].startswith("AmazonMSK_") or not metadata.get("KmsKeyId") or metadata["KmsKeyId"] == "alias/aws/secretsmanager":
            raise ValueError("MSK requires an AmazonMSK_ secret with a customer managed key")
        version_id = token(request, purpose)
        if not version_exists(sm, arn, version_id):
            credential = {"username": user["username"], "password": secrets.token_urlsafe(36)}
            sm.put_secret_value(SecretId=arn, ClientRequestToken=version_id, SecretString=json.dumps(credential))
            del credential
        ids[purpose] = version_id
    return {"secret_version_ids": ids}

def find_client(cognito, pool, name):
    found = []
    next_token = None
    while True:
        params = {"UserPoolId": pool, "MaxResults": 60}
        if next_token:
            params["NextToken"] = next_token
        page = cognito.list_user_pool_clients(**params)
        found.extend(client for client in page["UserPoolClients"] if client["ClientName"] == name)
        next_token = page.get("NextToken")
        if not next_token:
            break
    if len(found) > 1:
        raise ValueError("ambiguous confidential client name; review before retrying")
    return found[0]["ClientId"] if found else None

def initialize_cognito(request, sm, cognito):
    # Include request ID in the client name: a rotation creates a parallel client.
    # The old client's retirement is a separate reviewed operation after consumer verification.
    name = request["client_name"] + "-" + request["request_id"]
    if len(name) > 128:
        raise ValueError("combined client name exceeds Cognito limit")
    pool = request["user_pool_id"]
    client_id = find_client(cognito, pool, name)
    if not client_id:
        params = {"UserPoolId": pool, "ClientName": name, "GenerateSecret": True,
                  "AllowedOAuthFlowsUserPoolClient": True,
                  "AllowedOAuthFlows": ["client_credentials" if request["operation"] == "cognito-verifier" else "code"],
                  "AllowedOAuthScopes": request["scopes"], "PreventUserExistenceErrors": "ENABLED",
                  "AccessTokenValidity": 60, "IdTokenValidity": 60, "RefreshTokenValidity": 8,
                  "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "hours"}}
        if request["operation"] == "cognito-argocd":
            params.update(SupportedIdentityProviders=["COGNITO"], CallbackURLs=request["callback_urls"],
                          LogoutURLs=[url.replace("/auth/callback", "/") for url in request["callback_urls"]],
                          EnableTokenRevocation=True)
        client = cognito.create_user_pool_client(**params)["UserPoolClient"]
        client_id = client["ClientId"]
    else:
        client = cognito.describe_user_pool_client(UserPoolId=pool, ClientId=client_id)["UserPoolClient"]
    expected_flow = "client_credentials" if request["operation"] == "cognito-verifier" else "code"
    if client.get("AllowedOAuthFlows") != [expected_flow] or set(client.get("AllowedOAuthScopes", [])) != set(request["scopes"]):
        raise ValueError("existing request client does not match the approved OAuth configuration")
    if not client.get("ClientSecret"):
        raise ValueError("confidential client has no client secret")
    if request["operation"] == "cognito-argocd" and set(client.get("CallbackURLs", [])) != set(request["callback_urls"]):
        raise ValueError("existing client callbacks differ from approved configuration")
    version_id = token(request, "cognito-client")
    if not version_exists(sm, request["secret_arn"], version_id):
        value = {"client_id": client_id}
        if request["operation"] == "cognito-verifier":
            value.update(client_secret=client["ClientSecret"], token_endpoint=request["token_endpoint"], scope=" ".join(request["scopes"]))
        else:
            value["clientSecret"] = client["ClientSecret"]
        sm.put_secret_value(SecretId=request["secret_arn"], ClientRequestToken=version_id, SecretString=json.dumps(value))
        del value
    del client
    return {"client_id": client_id, "secret_version_id": version_id}

def execute(request, session):
    account = session.client("sts").get_caller_identity()["Account"]
    if account != request["account_id"]:
        raise ValueError("authenticated AWS account differs from approved request")
    sm = session.client("secretsmanager", region_name=request["region"])
    if request["operation"] == "queue-scram":
        result = initialize_queue(request, sm)
    else:
        result = initialize_cognito(request, sm, session.client("cognito-idp", region_name=request["region"]))
    return {"schema_version": 1, "request_id": request["request_id"], "environment": request["environment"],
            "account_id": account, "region": request["region"], "operation": request["operation"], **result}

def prepare_receipt(path):
    if path.exists() or path.is_symlink():
        raise ValueError("receipt already exists; preserve the previous attempt")
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("receipt parent symlink is forbidden")
    path.parent.mkdir(parents=True, exist_ok=True)

def write_receipt(path, result):
    # A late collision may follow an actual AWS mutation. Preserve the other
    # receipt and investigate current AWS metadata; never blindly repeat execute.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps(result, indent=2) + "\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--expect-account", required=True)
    parser.add_argument("--expect-environment", required=True, choices=["dev", "prod"])
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    request = validate(json.loads(args.request.read_text()), args.expect_account, args.expect_environment)
    prepare_receipt(args.receipt)
    import boto3
    result = execute(request, boto3.Session())
    write_receipt(args.receipt, result)
    print("PROVISION_METADATA_RECEIPT", args.receipt)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # AWS response/request payloads can carry client secrets. Never print the exception.
        print("PROVISION_FAILED type=" + type(error).__name__ + "; inspect protected runner diagnostics", file=sys.stderr)
        raise SystemExit(1)
