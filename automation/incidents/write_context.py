#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write reviewed non-secret incident coordinates for a separate investigator shell."""
import argparse
import os
from pathlib import Path
import re
import shlex

ALLOW = {
    "APPROVED_IMAGE", "DRILL_DIGEST", "DRILL_REPO", "MISSING_DIGEST", "MISSING_REF",
    "NORMAL_APP_REF", "NORMAL_REF", "BARRIER", "BASE_TRACE", "DRAIN_BEFORE",
    "METRICS_BUCKET", "OBSERVABILITY_CLUSTER", "WRITER_ROLE", "DENY_UNTIL",
    "OPERATOR_IMAGE", "OPERATOR_REPO", "OPERATOR_REPOSITORY_NAME", "REGION_ID",
    "APPROVED_MAX", "APPROVED_MIN", "CLUSTER_NAME", "EXPECTED_ACCOUNT", "NODEGROUP",
    "N_PROBE", "POD_CPU_MILLI", "POD_MEMORY_MI", "S_CURRENT", "UPDATE_ID", "WORK",
    "PK", "WEB_REPOSITORY_NAME", "DEV_CLUSTER_NAME", "KUBE_CONTEXT",
    "TEMPO_RELEASE", "DRAIN_SOURCE", "TRACE_TOPIC", "BUILDER", "BUILDER_REPLICAS",
}

def permitted(name):
    if re.search(r"PASSWORD|PRIVATE|TOKEN|COOKIE|JWT|ACCESS_KEY|SESSION_KEY", name):
        return False
    return name in ALLOW or name.startswith("INCIDENT_")

def write_context(destination, names, environment):
    invalid = [name for name in names if not permitted(name)]
    if invalid:
        raise ValueError("Credential or unreviewed context field: " + ", ".join(invalid))
    entries = []
    for name in names:
        if name not in environment or environment[name] == "":
            continue
        value = environment[name]
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("Context coordinates must be single-line: " + name)
        entries.append("export " + name + "=" + shlex.quote(value))
    if not entries:
        raise ValueError("No incident coordinates are available")
    destination = Path(destination)
    # Preserve every previous attempt, including a dangling symlink.
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Incident context already exists; retain it and use an approved new attempt path")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = "# Non-secret incident coordinates; not a diagnosis.\n" + "\n".join(entries) + "\n"
    # Exclusive creation closes the race after the early existence check.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)
    return len(entries)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--names", nargs="+", required=True)
    args = parser.parse_args()
    try:
        write_context(args.output, args.names, os.environ)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
    print("Incident context saved; values were not printed.")

if __name__ == "__main__":
    main()
