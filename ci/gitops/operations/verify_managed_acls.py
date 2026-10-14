#!/usr/bin/env python3
"""Read kafka-acls --list and verify the exact application-principal boundary."""
import argparse
import re
import sys


def expected_acls(topic, writer, reader, release):
    expected = set()

    def add(kind, name, pattern, user, permission, operations):
        for operation in operations:
            expected.add((kind, name, pattern, f"User:{user}", "*", operation, permission))

    add("TOPIC", topic, "LITERAL", writer, "ALLOW", ["WRITE", "DESCRIBE"])
    add("TOPIC", "*", "LITERAL", writer, "DENY", ["CREATE"])
    add("CLUSTER", "kafka-cluster", "LITERAL", writer, "DENY", ["CREATE"])
    add("TOPIC", topic, "LITERAL", reader, "ALLOW", ["READ", "DESCRIBE"])
    add("TOPIC", "*", "LITERAL", reader, "DENY", ["WRITE", "CREATE", "DELETE"])
    add("CLUSTER", "kafka-cluster", "LITERAL", reader, "DENY", ["CREATE"])
    for group in ["block-builder", "metrics-generator"]:
        add("GROUP", group, "LITERAL", reader, "ALLOW", ["READ", "DESCRIBE"])
    for zone in "abc":
        add("GROUP", f"{release}-live-store-zone-{zone}", "PREFIXED", reader, "ALLOW", ["READ", "DESCRIBE"])
    return expected


def parse_acls(text):
    resources = re.compile(r"ResourcePattern\(resourceType=(\w+), name=([^,]+), patternType=(\w+)\)")
    entries = re.compile(r"\(principal=([^,]+), host=([^,]+), operation=(\w+), permissionType=(\w+)\)")
    current = None
    found = set()
    for line in text.splitlines():
        resource = resources.search(line)
        if resource:
            current = resource.groups()
        if "principal=" in line:
            entry = entries.search(line)
            if not current or not entry:
                raise ValueError("unrecognized ACL output; inspect Kafka CLI version and raw report")
            found.add((*current, *entry.groups()))
    if not found:
        raise ValueError("no ACL entries in successful query")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["topic", "writer", "reader", "release"]:
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        actual = parse_acls(sys.stdin.read())
    except ValueError as error:
        print(f"INCONCLUSIVE {error}", file=sys.stderr)
        return 2
    expected = expected_acls(args.topic, args.writer, args.reader, args.release)
    principals = {f"User:{args.writer}", f"User:{args.reader}", "User:*"}
    actual = {entry for entry in actual if entry[3] in principals}
    missing, extra = expected - actual, actual - expected
    for label, entries in [("missing", missing), ("unexpected", extra)]:
        for entry in sorted(entries):
            print(f"DIFF ACL {label}: {' / '.join(entry)}")
    if missing or extra:
        return 1
    print("PASS ACL topic, principal, operation, permission, host and group pattern match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
