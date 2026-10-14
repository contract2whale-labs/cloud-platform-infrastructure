#!/usr/bin/env python3
"""부모 공개 Zone의 dev/app NS 두 레코드만 승인 후 갱신합니다."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def aws(*args):
    result = subprocess.run(["aws", *args, "--output", "json"], check=True, text=True, capture_output=True)
    return json.loads(result.stdout)


def name(value):
    if not isinstance(value, str):
        raise ValueError("DNS 이름은 문자열이어야 합니다.")
    result = value.lower().rstrip(".") + "."
    if len(result) > 254 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+", result):
        raise ValueError("DNS 이름 형식이 잘못되었습니다.")
    return result


def normalize(record, *, desired=True):
    allowed = {"Name", "Type", "TTL", "ResourceRecords"}
    if set(record) != allowed or record["Type"] != "NS":
        raise ValueError("단순 NS 레코드만 변경합니다. 별칭·라우팅 정책은 별도 검토합니다.")
    ttl = record["TTL"]
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise ValueError("TTL은 정수여야 합니다.")
    if desired and not 60 <= ttl <= 86400:
        raise ValueError("새 TTL은 60~86400초여야 합니다.")
    if not desired and not 0 <= ttl <= 2147483647:
        raise ValueError("기존 TTL 범위를 확인합니다.")
    rr = record["ResourceRecords"]
    if not isinstance(rr, list) or not rr or any(not isinstance(x, dict) or set(x) != {"Value"} for x in rr):
        raise ValueError("NS 레코드 값을 확인합니다.")
    if desired and len(rr) != 4:
        raise ValueError("자식 Zone에서 조회한 NS 네 개가 필요합니다.")
    values = sorted(name(x["Value"]) for x in rr)
    if len(set(values)) != len(values):
        raise ValueError("NS 네 개는 서로 달라야 합니다.")
    return {"Name": name(record["Name"]), "Type": "NS", "TTL": ttl,
            "ResourceRecords": [{"Value": v} for v in values]}


def prepare(zone, desired, records):
    if zone["Config"]["PrivateZone"]:
        raise ValueError("공개 부모 Zone만 허용합니다.")
    if not isinstance(desired, list) or len(desired) != 2:
        raise ValueError("Dev와 Prod 위임 두 개가 필요합니다.")
    target = sorted([normalize(r) for r in desired], key=lambda r: r["Name"])
    expected = sorted(["dev." + name(zone["Name"]), "app." + name(zone["Name"])])
    if [r["Name"] for r in target] != expected:
        raise ValueError("부모 바로 아래의 dev와 app NS만 허용합니다.")
    before = []
    for record in target:
        existing = [r for r in records if name(r["Name"]) == record["Name"] and r["Type"] in ("NS", "CNAME")]
        if len(existing) > 1 or any(r["Type"] == "CNAME" for r in existing):
            raise ValueError("기존 CNAME 또는 복수 NS 소유권을 먼저 확인합니다.")
        before.append(normalize(existing[0], desired=False) if existing else None)
    return target, before


def snapshot(zone_id, desired):
    zone = aws("route53", "get-hosted-zone", "--id", zone_id)["HostedZone"]
    records = aws("route53", "list-resource-record-sets", "--hosted-zone-id", zone_id)["ResourceRecordSets"]
    target, before = prepare(zone, desired, records)
    return {"zone_id": zone_id, "parent_name": name(zone["Name"]), "desired": target, "before": before}


def identity():
    account = aws("sts", "get-caller-identity")["Account"]
    if account != os.environ["EXPECTED_ACCOUNT_ID"]:
        raise ValueError("Network 계정이 일치하지 않습니다.")
    return account


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["plan", "apply"])
    args = parser.parse_args()
    account = identity()
    work = Path("dns-review")
    work.mkdir(exist_ok=True)
    if args.mode == "plan":
        zone_id = os.environ["PARENT_ZONE_ID"]
        if not re.fullmatch(r"Z[A-Z0-9]+", zone_id):
            raise ValueError("부모 Zone ID 형식을 확인합니다.")
        payload = snapshot(zone_id, json.loads(os.environ["DELEGATIONS_JSON"]))
        payload.update(account_id=account, commit=os.environ["GITHUB_SHA"])
        plan = work / "plan.json"
        plan.write_text(json.dumps(payload, indent=2) + "\n")
        (work / "plan.sha256").write_text(digest(payload) + "\n")
        changes = []
        for old, new in zip(payload["before"], payload["desired"]):
            changes.append({"Action": "UPSERT" if old else "DELETE", "ResourceRecordSet": old or new})
        (work / "rollback.json").write_text(json.dumps({"Comment": "Requires separate rollback approval", "Changes": changes}, indent=2) + "\n")
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("## 부모 NS 위임 검토\n\n기존 NS와 새 NS, 계정, SHA를 대조한 뒤 승인합니다.\n\n")
            f.write("```json\n" + json.dumps(payload, indent=2) + "\n```\n\nSHA256: " + digest(payload) + "\n")
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("plan_sha=" + digest(payload) + "\n")
    else:
        payload = json.loads((work / "plan.json").read_text())
        expected_hash = os.environ["EXPECTED_PLAN_SHA"]
        if digest(payload) != expected_hash or (work / "plan.sha256").read_text().strip() != expected_hash:
            raise ValueError("승인한 위임 plan 해시가 다릅니다.")
        if payload["account_id"] != account or payload["commit"] != os.environ["GITHUB_SHA"]:
            raise ValueError("승인한 계정 또는 Git SHA가 다릅니다.")
        current = snapshot(payload["zone_id"], payload["desired"])
        for field in ("zone_id", "parent_name", "before", "desired"):
            if current[field] != payload[field]:
                raise ValueError("승인 이후 부모 NS가 바뀌었습니다. 새 실행으로 재검토합니다.")
        changes = [{"Action": "UPSERT", "ResourceRecordSet": r} for r in payload["desired"]]
        batch = work / "change.json"
        batch.write_text(json.dumps({"Comment": "Approved run " + os.environ["GITHUB_RUN_ID"], "Changes": changes}))
        result = aws("route53", "change-resource-record-sets", "--hosted-zone-id", payload["zone_id"], "--change-batch", "file://" + str(batch))
        change_id = result["ChangeInfo"]["Id"]
        subprocess.run(["aws", "route53", "wait", "resource-record-sets-changed", "--id", change_id], check=True)
        applied = snapshot(payload["zone_id"], payload["desired"])
        if applied["before"] != payload["desired"]:
            raise ValueError("적용 후 NS 값이 승인한 값과 다릅니다.")
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("## 부모 NS 반영 확인\n\nChange ID: " + change_id + "\n\n상태: INSYNC, 두 NS 레코드 대조 완료\n")
        print("부모 NS 두 건을 반영하고 INSYNC 및 실제 레코드를 확인했습니다.")


if __name__ == "__main__":
    main()
