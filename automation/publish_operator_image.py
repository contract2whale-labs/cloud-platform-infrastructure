#!/usr/bin/env python3
"""Protected first publication of the reviewed database-operator artifact, not deployment."""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from verify_operator_image import verify, signing_target, read_contract, require_new_output, write_new_output

def publish(contract, delivery, account, region, environment, revision, repo, session, run=subprocess.run):
    if (contract["account_id"],contract["region"],contract["environment"])!=(account,region,environment):
        raise ValueError("data contract target differs")
    if not re.fullmatch(r"[0-9a-f]{40}",revision):raise ValueError("approved full Git revision required")
    if session.client("sts").get_caller_identity()["Account"]!=account:raise ValueError("authenticated account differs")
    head=run(["git","-C",str(repo),"rev-parse","HEAD"],capture_output=True,text=True,check=True).stdout.strip()
    if head!=revision:raise ValueError("checkout is not the approved revision")
    run(["git","-C",str(repo),"diff","--exit-code","HEAD"],capture_output=True,text=True,check=True)
    extra=run(["git","-C",str(repo),"status","--porcelain","--untracked-files=all","--ignored=matching","--","tools/database-operator","data/lib","data/operator"],capture_output=True,text=True,check=True).stdout.strip()
    if extra:raise ValueError("operator build inputs contain unreviewed files")
    coordinates=contract["operator"];registry=account+".dkr.ecr."+region+".amazonaws.com"
    if coordinates["repository_url"]!=registry+"/"+coordinates["repository_name"]:raise ValueError("operator repository differs")
    key=signing_target(delivery,account,region,environment,session)
    tag=coordinates["repository_url"]+":"+revision
    ecr=session.client("ecr",region_name=region)
    env={key:value for key,value in os.environ.items() if key not in {"TF_LOG","TF_LOG_PATH","TF_LOG_CORE","TF_LOG_PROVIDER"}}
    # An isolated config prevents the initial publication from changing a person's Docker login.
    with tempfile.TemporaryDirectory(prefix="operator-registry-") as config:
        env.update(DOCKER_CONFIG=config,AWS_REGION=region,AWS_DEFAULT_REGION=region)
        run(["bash",str(repo/"tools/database-operator/build.sh"),"operator",tag],cwd=repo,env=env,check=True)
        authorization=ecr.get_authorization_token(registryIds=[account])["authorizationData"]
        if len(authorization)!=1 or authorization[0]["proxyEndpoint"]!="https://"+registry:raise ValueError("registry authorization target differs")
        username,password=base64.b64decode(authorization[0]["authorizationToken"]).decode().split(":",1)
        if username!="AWS":raise ValueError("registry authorization user differs")
        run(["docker","login","--username","AWS","--password-stdin",registry],input=password,env=env,text=True,capture_output=True,check=True)
        del password,authorization
        try:
            run(["docker","push",tag],env=env,check=True)
            details=ecr.describe_images(repositoryName=coordinates["repository_name"],imageIds=[{"imageTag":revision}])["imageDetails"]
            if len(details)!=1:raise ValueError("published image result is ambiguous")
            digest=details[0]["imageDigest"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}",digest):raise ValueError("invalid published digest")
            reference=coordinates["repository_url"]+"@"+digest
            sbom=Path(config)/"sbom.spdx.json"
            run(["syft",reference,"-o","spdx-json="+str(sbom)],env=env,capture_output=True,text=True,check=True)
            document=json.loads(sbom.read_text())
            if not isinstance(document,dict) or document.get("spdxVersion")!="SPDX-2.3":
                raise ValueError("generated SBOM must be an SPDX-2.3 JSON document")
            # Cosign 3.1.3 legacy signature/attestation tags match the existing Kyverno policy.
            flags=["--key","awskms:///"+key,"--tlog-upload=false","--use-signing-config=false","--new-bundle-format=false","--yes"]
            run(["cosign","sign",*flags,reference],env=env,capture_output=True,text=True,check=True)
            run(["cosign","attest",*flags,"--type","spdxjson","--predicate",str(sbom),reference],env=env,capture_output=True,text=True,check=True)
            verify(contract,delivery,account,region,environment,digest,session,run,env)
        finally:
            run(["docker","logout",registry],env=env,capture_output=True,text=True)
    return {"schema_version":1,"environment":environment,"account_id":account,"region":region,"source_revision":revision,"repository":coordinates["repository_url"],"operator_image_digest":digest,"signing_key_arn":key,"signature_verified":True,"spdx_attestation_verified":True}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--environment",choices=["dev","prod"],required=True)
    parser.add_argument("--expect-account",required=True)
    parser.add_argument("--region",required=True)
    parser.add_argument("--approved-revision",required=True)
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args();repo=Path(__file__).resolve().parents[1]
    require_new_output(args.receipt)
    contract=read_contract(repo,args.environment,"data","data_contract")
    delivery=read_contract(repo,args.environment,"delivery","delivery_contract")
    import boto3
    receipt=publish(contract,delivery,args.expect_account,args.region,args.environment,args.approved_revision,repo,boto3.Session())
    write_new_output(args.receipt, receipt)
    print("Published reviewed operator image; signature and SPDX attestation verified; public receipt written.")

if __name__=="__main__":
    try:main()
    except Exception as error:
        # Registry tokens and SDK payloads never enter an exception log.
        print("OPERATOR_ARTIFACT_PUBLICATION_FAILED type="+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
