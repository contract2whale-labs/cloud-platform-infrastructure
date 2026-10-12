#!/usr/bin/env python3
"""Verify an existing ECR operator image; emit only a public Terraform digest input."""
import argparse
import base64
import tempfile
import json
import os
import re
import subprocess
import sys
from pathlib import Path

def signing_target(delivery, account, region, environment, session):
    if (delivery["account_id"], delivery["region"], delivery["environment"]) != (account, region, environment):
        raise ValueError("delivery contract target differs")
    arn = delivery["signing_key_arn"]  # e.g. arn:aws:kms:ap-northeast-2:111111111111:key/<UUID>
    alias = delivery["signing_key_alias"]  # e.g. alias/delivery-signing
    if not re.fullmatch(r"arn:aws:kms:" + re.escape(region) + ":" + re.escape(account) + r":key/[0-9a-f-]{36}", arn):
        raise ValueError("signing key must belong to the same account and Region")
    if alias != "alias/delivery-signing":
        raise ValueError("unexpected signing key alias")
    kms = session.client("kms", region_name=region)
    for identifier in (arn, alias):
        metadata = kms.describe_key(KeyId=identifier)["KeyMetadata"]
        if (metadata.get("Arn") != arn or metadata.get("KeyUsage") != "SIGN_VERIFY"
                or metadata.get("KeySpec") != "ECC_NIST_P256" or metadata.get("KeyState") != "Enabled"
                or metadata.get("Enabled") is not True):
            raise ValueError("signing key or alias does not resolve to the approved enabled ECC signing key")
    return arn


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in {"TF_LOG", "TF_LOG_PATH", "TF_LOG_CORE", "TF_LOG_PROVIDER"}}


def read_contract(repo, environment, root, name, run=subprocess.run):
    result = run(["terraform", "-chdir=" + str(repo / f"terraform/environments/{environment}/{root}"),
                  "output", "-json"], env=clean_environment(), capture_output=True, text=True, check=True)
    output = json.loads(result.stdout)[name]
    if output.get("sensitive") is not False:
        raise ValueError("sensitive or unclassified output refused")
    return output["value"]


def require_spdx23_attestation(stdout, digest):
    # Cosign verify-attestation prints verified DSSE envelopes. Inspect only verified output.
    decoder=json.JSONDecoder()
    remainder=stdout.strip()
    envelopes=[]
    while remainder:
        value,index=decoder.raw_decode(remainder)
        if not isinstance(value,dict):raise ValueError("verified output must contain JSON object envelopes")
        envelopes.append(value)
        remainder=remainder[index:].lstrip()
    if not envelopes:raise ValueError("verified SPDX attestation is missing")
    for envelope in envelopes:
        if not isinstance(envelope,dict) or not isinstance(envelope.get("payload"),str):
            raise ValueError("invalid verified attestation envelope")
        statement=json.loads(base64.b64decode(envelope["payload"],validate=True))
        if not isinstance(statement,dict):raise ValueError("invalid verified attestation statement")
        if (statement.get("predicateType")=="https://spdx.dev/Document"
                and isinstance(statement.get("predicate"),dict)
                and statement["predicate"].get("spdxVersion")=="SPDX-2.3"
                and any(isinstance(subject,dict) and isinstance(subject.get("digest"),dict) and subject["digest"].get("sha256")==digest.removeprefix("sha256:")
                        for subject in statement.get("subject",[]))):
            return
    raise ValueError("verified attestation does not satisfy the SPDX-2.3 image predicate")


def verify(contract, delivery, account, region, environment, digest, session, run=subprocess.run, env=None):
    if (contract["account_id"],contract["region"],contract["environment"]) != (account,region,environment):
        raise ValueError("data contract target differs")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}",digest):raise ValueError("immutable digest required")
    if session.client("sts").get_caller_identity()["Account"] != account:raise ValueError("authenticated account differs")
    key = signing_target(delivery, account, region, environment, session)
    repository=contract["operator"]
    expected=account+".dkr.ecr."+region+".amazonaws.com/"+repository["repository_name"]
    if repository["repository_url"] != expected:raise ValueError("operator repository differs")
    result=session.client("ecr",region_name=region).describe_images(repositoryName=repository["repository_name"],imageIds=[{"imageDigest":digest}])
    details=result.get("imageDetails",[])
    if len(details)!=1 or details[0].get("imageDigest")!=digest:raise ValueError("published image not found")
    reference = expected + "@" + digest
    if env is None:
        registry=account+".dkr.ecr."+region+".amazonaws.com"
        with tempfile.TemporaryDirectory(prefix="operator-verification-") as config:
            isolated=clean_environment()
            isolated.update(DOCKER_CONFIG=config,AWS_REGION=region,AWS_DEFAULT_REGION=region)
            authorization=session.client("ecr",region_name=region).get_authorization_token(registryIds=[account])["authorizationData"]
            if len(authorization)!=1 or authorization[0]["proxyEndpoint"]!="https://"+registry:
                raise ValueError("registry authorization target differs")
            username,password=base64.b64decode(authorization[0]["authorizationToken"]).decode().split(":",1)
            if username!="AWS":raise ValueError("registry authorization user differs")
            run(["docker","login","--username","AWS","--password-stdin",registry],input=password,env=isolated,text=True,capture_output=True,check=True)
            del password,authorization
            try:
                return verify(contract,delivery,account,region,environment,digest,session,run,isolated)
            finally:
                run(["docker","logout",registry],env=isolated,capture_output=True,text=True)
    command_env=env
    run(["cosign", "verify", "--key", "awskms:///" + key, "--insecure-ignore-tlog", reference],
        env=command_env, capture_output=True, text=True, check=True)
    attestation=run(["cosign", "verify-attestation", "--key", "awskms:///" + key, "--insecure-ignore-tlog",
         "--type", "spdxjson", reference], env=command_env, capture_output=True, text=True, check=True)
    require_spdx23_attestation(attestation.stdout,digest)
    return {"operator_image_digest":digest}

def require_new_output(path):
    if path.exists() or path.is_symlink():
        raise FileExistsError("existing operator output must be preserved and reviewed")


def write_new_output(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(payload, indent=2) + "\n")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--environment",choices=["dev","prod"],required=True)
    parser.add_argument("--expect-account",required=True)
    parser.add_argument("--region",required=True)
    parser.add_argument("--digest",required=True)
    parser.add_argument("--tfvars",type=Path,required=True)
    args=parser.parse_args();repo=Path(__file__).resolve().parents[1]
    require_new_output(args.tfvars)
    contract=read_contract(repo,args.environment,"data","data_contract")
    delivery=read_contract(repo,args.environment,"delivery","delivery_contract")
    import boto3
    tfvars=verify(contract,delivery,args.expect_account,args.region,args.environment,args.digest,boto3.Session())
    write_new_output(args.tfvars, tfvars)
    print("Verified published operator image metadata prepared.")

if __name__=="__main__":
    try:main()
    except Exception as error:
        print("OPERATOR_IMAGE_VERIFICATION_FAILED type="+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
