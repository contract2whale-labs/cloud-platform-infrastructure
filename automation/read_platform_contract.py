#!/usr/bin/env python3
"""Read selected noncredential Terraform fields for diagnosis; never export shell source."""
import argparse
import json
import os
import subprocess
from pathlib import Path
COMPONENTS={
    "queue":("terraform/environments/{environment}/platform/queue","queue_managed_contract",["cluster_arn","cluster_name","bootstrap_brokers_scram","kms_key_arn","topic_name","partitions"]),
    "gateway":("terraform/environments/{environment}/platform/gateway","platform_input_values",["cluster_name","region","vpc_id","nlb_scheme","nlb_subnet_ids_csv","nlb_security_group_id","dns_zone_id","dns_zone_name","dns_zone_type"]),
    "observability":("terraform/environments/{environment}/platform/observability","platform_input_values",["metrics_bucket","logs_bucket","traces_bucket","region","metrics_prefix","trace_prefix","trace_epoch2_prefix","trace_epoch3_prefix","s3_endpoint"]),
}

def select(outputs, component):
    _,output,fields=COMPONENTS[component]
    item=outputs[output]
    if item.get("sensitive") is not False:
        raise ValueError("sensitive or unclassified Terraform output is refused")
    value=item["value"]
    if not isinstance(value,dict) or any(key not in value or value[key] is None for key in fields):
        raise ValueError("required diagnostic fields are absent")
    return {key:value[key] for key in fields}

def main():
    p=argparse.ArgumentParser();p.add_argument("--component",choices=list(COMPONENTS),required=True)
    p.add_argument("--environment",choices=["dev","prod"],default="dev");p.add_argument("--expect-account",required=True)
    args=p.parse_args();repo=Path(__file__).resolve().parents[1]
    child_env={key:value for key,value in os.environ.items() if key not in {"TF_LOG","TF_LOG_PATH","TF_LOG_CORE","TF_LOG_PROVIDER"}}
    identity=json.loads(subprocess.check_output(["aws","sts","get-caller-identity"],text=True,env=child_env))
    if identity["Account"]!=args.expect_account:raise ValueError("authenticated account differs")
    directory,_,_=COMPONENTS[args.component]
    # Full output is inspected only in memory so the sensitive flag is available.
    raw=subprocess.check_output(["terraform","-chdir="+str(repo/directory.format(environment=args.environment)),"output","-json"],text=True,env=child_env)
    print(json.dumps(select(json.loads(raw),args.component)))

if __name__=="__main__":main()
