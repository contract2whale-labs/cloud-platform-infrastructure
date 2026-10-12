#!/usr/bin/env python3
"""Verify documented app env names against parsed Kubernetes config and secret keys."""
import argparse
import json
from pathlib import Path
import re
from ruamel.yaml import YAML

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--example", required=True, type=Path)
    parser.add_argument("--overlay", required=True, type=Path)
    parser.add_argument("--external-secret", required=True, type=Path)
    parser.add_argument("--runtime-manifest", required=True, type=Path)
    parser.add_argument("--report-only", action="store_true", help="Report an intermediate contract gap without treating it as deployment approval")
    args = parser.parse_args()
    expected = {line.split("=", 1)[0] for line in args.example.read_text().splitlines() if re.match(r"^[A-Z_][A-Z_0-9]*=", line)}
    yaml = YAML(typ="safe")
    overlay = yaml.load(args.overlay.read_text())
    actual = {item.split("=", 1)[0] for gen in overlay.get("configMapGenerator", []) for item in gen.get("literals", [])}
    for secret in yaml.load_all(args.external_secret.read_text()):
        if isinstance(secret, dict) and secret.get("kind") == "ExternalSecret":
            actual.update(secret.get("spec", {}).get("target", {}).get("template", {}).get("data", {}))
    for resource in yaml.load_all(args.runtime_manifest.read_text()):
        if not isinstance(resource, dict):
            continue
        spec = resource.get("spec", {}).get("template", {}).get("spec", {})
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            actual.update(item["name"] for item in container.get("env", []) if isinstance(item, dict) and "name" in item)
    missing = sorted(expected - actual)
    result = {"result": "REVIEW_REQUIRED" if missing else "PASS", "missing_from_deployment": missing,
              "deployment_only_keys": sorted(actual - expected)}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if missing and not args.report_only:
        raise SystemExit("environment keys missing from deployment config/secret: " + ", ".join(missing))

if __name__ == "__main__":
    main()
