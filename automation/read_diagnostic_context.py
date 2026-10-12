#!/usr/bin/env python3
"""Read bounded public operational coordinates; never evaluate shell text."""
import argparse
import json
import re
import shlex
from pathlib import Path

CREDENTIAL_NAME = re.compile(r"PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY")
CREDENTIAL_VALUE = re.compile(r"-----BEGIN|(?:AKIA|ASIA)[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

def registry_variables(registry=None, component=None):
    registry = registry or Path(__file__).with_name("diagnostic-mappings.json")
    mappings = json.loads(Path(registry).read_text())
    if component is not None:
        if component not in mappings:
            raise ValueError("unknown diagnostic component")
        mappings = {component: mappings[component]}
    return {name for mapping in mappings.values() for name in mapping["variables"]}

def read_context(path, *, registry=None, component=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
        raise ValueError("diagnostic input must be a bounded regular file")
    allowed = registry_variables(registry, component)
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)", line)
        if match is None:
            raise ValueError("malformed diagnostic assignment")
        name, raw = match.groups()
        if name not in allowed or CREDENTIAL_NAME.search(name):
            raise ValueError("field is outside the nonsecret diagnostic allowlist")
        if name in result:
            raise ValueError("duplicate diagnostic field: " + name)
        if "$(" in raw or "`" in raw or "\x00" in raw:
            raise ValueError("diagnostic value must be literal")
        parts = shlex.split(raw, comments=True, posix=True)
        if len(parts) != 1:
            raise ValueError("diagnostic assignment must contain one literal scalar")
        value = parts[0]
        if len(value) > 2048 or any(ord(char) < 32 for char in value) or CREDENTIAL_VALUE.search(value):
            raise ValueError("diagnostic value is not a bounded nonsecret scalar")
        result[name] = value
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--field", required=True)
    args = parser.parse_args()
    try:
        values = read_context(args.file)
        if args.field not in registry_variables() or args.field not in values:
            raise ValueError("required diagnostic field is absent or not allowlisted")
        print(values[args.field])
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, "DIAGNOSTIC_READ_FAILED: " + str(error) + "\n")

if __name__ == "__main__":
    main()
