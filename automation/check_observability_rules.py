#!/usr/bin/env python3
"""Check authored PrometheusRule sources and their time/label regression tests."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
from ruamel.yaml import YAML

PAIRS = {
    "application": "80-application-rules.yaml",
    "operations": "10-operations-alerts.yaml",
    "tempo": "tempo-monitors.yaml",
    "alerting-path": "90-alerting-path-rules.yaml",
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--environment", choices=("dev", "prod"), default="dev")
    parser.add_argument("--suite", choices=tuple(PAIRS), action="append")
    args = parser.parse_args()
    repo = args.repo.resolve()
    sources = repo / "gitops/platform/monitoring-resources/overlays" / args.environment
    selected = args.suite or [name for name, filename in PAIRS.items() if (sources / filename).is_file()]
    if not selected:
        print("SKIPPED: no observability rule source has been introduced")
        return
    tool = shutil.which("promtool")
    if tool is None:
        raise SystemExit("promtool is required; reopen the repository in its reviewed DevContainer")
    yaml = YAML(typ="safe")
    with tempfile.TemporaryDirectory(prefix="observability-rules-") as directory:
        work = Path(directory)
        for name in selected:
            source = sources / PAIRS[name]
            if not source.is_file():
                raise SystemExit(f"missing source: {source}")
            manifest = yaml.load(source.read_text())
            if not isinstance(manifest, dict) or manifest.get("kind") != "PrometheusRule":
                raise SystemExit(f"expected PrometheusRule: {source}")
            groups = manifest.get("spec", {}).get("groups")
            if not isinstance(groups, list) or not groups:
                raise SystemExit(f"missing spec.groups: {source}")
            rule = work / f"{name}-rules.yaml"
            with rule.open("w") as stream:
                yaml.dump({"groups": groups}, stream)
            fixture = repo / f"tests/observability/{name}-rules.test.yaml"
            if not fixture.is_file():
                raise SystemExit(f"missing behavior regression test: {fixture}")
            target = work / fixture.name
            shutil.copyfile(fixture, target)
            print(f"checking {source.relative_to(repo)}", flush=True)
            subprocess.run([tool, "check", "rules", str(rule)], cwd=work, check=True)
            subprocess.run([tool, "test", "rules", str(target)], cwd=work, check=True)
            print(f"verified: {name} rule syntax and alert behavior", flush=True)

if __name__ == "__main__":
    main()
