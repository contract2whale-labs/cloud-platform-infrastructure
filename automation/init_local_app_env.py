#!/usr/bin/env python3
"""Initialize only a byte-identical approved local template; never rotate existing keys."""
import argparse
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile

KEYS = ("DATABASE_URL", "JWT_SECRET", "COOKIE_SECRET")

def regular_without_links(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError("symlink target or parent is not allowed")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("a regular local file is required")
    return path

def initialize(target, example):
    # The caller must hold an exclusive local editing window. This is not a lock.
    target = regular_without_links(target)
    example = regular_without_links(example)
    if target == example:
        raise ValueError("target must be the ignored copy, not the approved example")
    original = target.read_bytes()
    template = example.read_bytes()
    identity = target.stat()
    if original != template:
        raise ValueError("existing configuration differs from the approved first-use template")
    text = template.decode("utf-8")
    for key in KEYS:
        matches = re.findall(r"^" + key + r"=(.*)$", text, re.M)
        if matches != [""]:
            raise ValueError("approved template requires exactly one empty credential placeholder per key")
    updates = {"DATABASE_URL": "postgres://medusa:medusa_local_password@localhost:5432/commerce",
               "JWT_SECRET": secrets.token_hex(32), "COOKIE_SECRET": secrets.token_hex(32)}
    for key, value in updates.items():
        text = re.sub(r"^" + key + r"=.*$", key + "=" + value, text, flags=re.M)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".local-env-", dir=target.parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text.encode())
            stream.flush()
            os.fsync(stream.fileno())
        regular_without_links(target)
        regular_without_links(example)
        current = target.stat()
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino) or target.read_bytes() != original or example.read_bytes() != template:
            raise ValueError("source or target changed; preserve original and investigate")
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)
    print("local development configuration written; credential values are not logged")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--example", required=True, type=Path)
    args = parser.parse_args()
    try:
        initialize(args.file, args.example)
    except (OSError, ValueError, UnicodeError) as error:
        raise SystemExit("local initialization blocked; preserve files and inspect the approved template/ownership: " + type(error).__name__)

if __name__ == "__main__":
    main()
