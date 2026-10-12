#!/usr/bin/env python3
"""Validate an image promotion by parsed fields rather than changed line counts."""
import argparse
from pathlib import Path
import re
import subprocess
from ruamel.yaml import YAML

def validate(before, after, name, repository, digest):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or digest == "sha256:" + "0" * 64:
        raise ValueError("expected a real image digest")
    old = [item for item in before.get("images", []) if item.get("name") == name]
    new = [item for item in after.get("images", []) if item.get("name") == name]
    if len(old) != 1 or len(new) != 1:
        raise ValueError("image name must identify exactly one declared image")
    if new[0].get("digest") != digest or new[0].get("newName") != repository:
        raise ValueError("promotion digest or repository does not match the reviewed image")
    expected = YAML(typ="safe").load(YAML_text(before))
    match = next(item for item in expected["images"] if item.get("name") == name)
    match["digest"] = digest
    if expected != after:
        raise ValueError("promotion changes fields other than the selected image digest")
    if old[0].get("digest") == digest:
        raise ValueError("image is already at this digest")

def YAML_text(value):
    from io import StringIO
    stream = StringIO()
    YAML(typ="safe").dump(value, stream)
    return stream.getvalue()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--overlay", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    file = (repo / args.overlay / "kustomization.yaml").resolve()
    relative = file.relative_to(repo).as_posix()
    run = ["git", "-c", f"safe.directory={repo}", "-C", str(repo)]
    changed = subprocess.check_output(run + ["diff", "--name-only", "HEAD"], text=True).splitlines()
    if changed != [relative]:
        raise SystemExit("only the selected overlay may change: " + repr(changed))
    before_text = subprocess.check_output(run + ["show", "HEAD:" + relative], text=True)
    yaml = YAML(typ="safe")
    validate(yaml.load(before_text), yaml.load(file.read_text()), args.image, args.expected_repository, args.expected_digest)
    print("verified: selected image digest and unchanged manifest fields")

if __name__ == "__main__":
    main()
