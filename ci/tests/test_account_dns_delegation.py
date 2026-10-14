"""AWS를 호출하지 않고 위임 입력의 안전 경계를 검사합니다."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("delegation", Path(__file__).parents[1] / "account_dns_delegation.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def record(child):
    return {"Name": child + ".example.com.", "Type": "NS", "TTL": 300,
            "ResourceRecords": [{"Value": f"ns-{i}.example.net."} for i in range(1, 5)]}


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.zone = {"Name": "example.com.", "Config": {"PrivateZone": False}}
        self.desired = [record("dev"), record("app")]

    def test_new_delegations(self):
        desired, before = m.prepare(self.zone, self.desired, [])
        self.assertEqual(before, [None, None])
        self.assertEqual(desired[0]["Name"], "app.example.com.")

    def test_existing_records_normalized(self):
        desired, before = m.prepare(self.zone, self.desired, list(reversed(self.desired)))
        self.assertEqual(desired, before)

    def test_private_zone_rejected(self):
        self.zone["Config"]["PrivateZone"] = True
        with self.assertRaises(ValueError):
            m.prepare(self.zone, self.desired, [])

    def test_other_child_rejected(self):
        self.desired[0]["Name"] = "other.example.com."
        with self.assertRaises(ValueError):
            m.prepare(self.zone, self.desired, [])

    def test_cname_rejected(self):
        current = [{"Name": "dev.example.com.", "Type": "CNAME"}]
        with self.assertRaises(ValueError):
            m.prepare(self.zone, self.desired, current)

    def test_duplicate_ns_rejected(self):
        self.desired[0]["ResourceRecords"][0] = self.desired[0]["ResourceRecords"][1]
        with self.assertRaises(ValueError):
            m.prepare(self.zone, self.desired, [])

    def test_routing_policy_rejected(self):
        self.desired[0]["SetIdentifier"] = "weighted"
        with self.assertRaises(ValueError):
            m.prepare(self.zone, self.desired, [])

    def test_existing_long_ttl_preserved(self):
        current = [record("dev")]
        current[0]["TTL"] = 172800
        desired, before = m.prepare(self.zone, self.desired, current)
        self.assertEqual(before[1]["TTL"], 172800)
        self.assertEqual(desired[1]["TTL"], 300)

    def test_new_long_ttl_rejected(self):
        self.desired[0]["TTL"] = 172800
        with self.assertRaises(ValueError):
            m.prepare(self.zone, self.desired, [])

    def test_changed_target_records_detected(self):
        desired, before = m.prepare(self.zone, self.desired, [])
        _, after = m.prepare(self.zone, self.desired, [record("dev")])
        self.assertNotEqual(before, after)

    def test_hash_changes_with_values(self):
        old = m.digest(self.desired)
        self.desired[0]["TTL"] = 600
        self.assertNotEqual(old, m.digest(self.desired))


if __name__ == "__main__":
    unittest.main()
