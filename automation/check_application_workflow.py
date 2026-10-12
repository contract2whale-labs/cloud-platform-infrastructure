#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate the app PR permission boundary, independently of file length."""
import argparse
import re
from pathlib import Path
from ruamel.yaml import YAML

def validate(document):
    events=document.get("on",{})
    events=[events] if isinstance(events,str) else list(events)
    if "pull_request_target" in events:
        raise ValueError("PR code must not run with the protected pull_request_target context")
    if not any(event in events for event in ("pull_request","merge_group")):
        raise ValueError("Expected a PR validation workflow")
    if not document.get("jobs"):
        raise ValueError("No PR validation jobs declared")
    for name,job in document["jobs"].items():
        permission=job.get("permissions",document.get("permissions"))
        if not isinstance(permission,dict) or permission.get("contents")!="read":
            raise ValueError(name+": explicitly declare contents: read")
        if any(value=="write" for value in permission.values()):
            raise ValueError(name+": PR validation cannot grant write/OIDC permissions")
        for step in job.get("steps",[]):
            use=step.get("uses","")
            if use and not use.startswith("./") and not re.search(r"@[a-f0-9]{40}$",use):
                raise ValueError(name+": remote action must use the reviewed commit SHA")
            if re.search(r"\$\{\{\s*secrets\.",str(step)):
                raise ValueError(name+": app PR code must not receive repository credentials")
            if re.search(r"configure-aws-credentials|azure/login|google-github-actions/auth",use):
                raise ValueError(name+": deployment cloud identity belongs to the approved publisher")
        if re.search(r"\$\{\{\s*secrets\.",str(job.get("env",{}))):
            raise ValueError(name+": actual database/deployment secrets cannot be PR job inputs")
    return True

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--workflow",type=Path,required=True)
    args=parser.parse_args()
    try:
        document=YAML(typ="safe").load(args.workflow.read_text())
        validate(document)
    except (OSError,ValueError) as error:
        parser.exit(1,str(args.workflow)+": "+str(error)+"\n")
    print("PR workflow permission and credential boundary valid")

if __name__=="__main__":main()
