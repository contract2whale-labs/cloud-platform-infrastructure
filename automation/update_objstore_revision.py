#!/usr/bin/env python3
"""Update only reviewed pod annotations for a fixed-name noncredential objstore config."""
import argparse
import hashlib
from io import StringIO
from pathlib import Path
from ruamel.yaml import YAML

KEY = "platform.example/objstore-config-sha256"
DESTINATIONS = {
    "sidecar": ("gitops/platform/monitoring/values/{environment}.yaml", ["prometheus", "prometheusSpec", "podMetadata", "annotations"]),
    "store": ("gitops/platform/thanos/overlays/{environment}/statefulset-platform-thanos-storegateway.yaml", ["spec", "template", "metadata", "annotations"]),
    "compactor": ("gitops/platform/thanos/overlays/{environment}/deployment-platform-thanos-compactor.yaml", ["spec", "template", "metadata", "annotations"]),
}

def revision(repo, environment, consumers):
    yaml=YAML();yaml.preserve_quotes=True
    path=repo/f"gitops/platform/monitoring/overlays/{environment}/objstore.yml"
    text=path.read_text();obj=yaml.load(text)
    cfg=obj["config"]
    if cfg.get("aws_sdk_auth") is not True or any(key in cfg for key in ["access_key", "secret_key", "session_token"]):
        raise ValueError("only the noncredential SDK-auth object store source is supported")
    digest=hashlib.sha256(text.encode()).hexdigest()
    edits=[]
    for consumer in consumers:
        file,keys=DESTINATIONS[consumer];target=repo/file.format(environment=environment)
        # Do not silently skip a consumer requested by the current reviewed stage.
        data=yaml.load(target.read_text());current=data
        for key in keys:current=current.setdefault(key,{})
        current[KEY]=digest
        output=StringIO();yaml.dump(data,output);edits.append((target,output.getvalue()))
    for target,text in edits:target.write_text(text)
    return digest,[str(target.relative_to(repo)) for target,_ in edits]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",type=Path,required=True)
    parser.add_argument("--environment",choices=["dev","prod"],required=True)
    parser.add_argument("--consumers",nargs="+",choices=list(DESTINATIONS),required=True)
    args=parser.parse_args()
    digest,files=revision(args.repo.resolve(),args.environment,args.consumers)
    print("OBJSTORE_CONFIG_REVISION",digest)
    for file in files:print("ANNOTATION_UPDATED",file)

if __name__=="__main__":main()
